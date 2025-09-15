import time
from dataclasses import dataclass
from typing import Any, Callable, Dict, Generic, List, Optional, Tuple, TypeVar

import requests
from limiter import get_limiter, limit

from .models import AS, Certificate, Domain, Host, NistCVEData, Profile
from .response import Error, FieldError, Response

T = TypeVar("T")


@dataclass
class SearchResults(Generic[T]):
    """Generic search results container with pagination metadata."""

    results: List[T]
    total_items: Optional[int] = None
    search_id: Optional[str] = None
    has_more: bool = False

    @property
    def count(self) -> int:
        """Return the number of results in this batch."""
        return len(self.results)


class RateLimiter:
    """Simple rate limiter with exponential backoff."""

    def __init__(self, initial_capacity: int = 1, frame_seconds: int = 1):
        self.limiter = get_limiter(rate=frame_seconds, capacity=initial_capacity)
        self._capacity = initial_capacity

    def update_capacity(self, new_capacity: int) -> None:
        """Update rate limit capacity based on account limits."""
        self._capacity = new_capacity
        self.limiter._capacity = new_capacity

    def wait_if_needed(self) -> None:
        """Wait if rate limit would be exceeded."""
        with limit(self.limiter, consume=1):
            pass


class Client:
    """Modern Python client for Recona API with improved error handling and pagination."""

    DEFAULT_BASE_URL = "https://api.recona.io"
    MAX_LIMIT = 100
    SEARCH_RESULTS_LIMIT = 10000
    RATE_LIMIT_FRAME_IN_SECONDS = 1

    def __init__(
        self,
        api_token: Optional[str],
        base_url: str = DEFAULT_BASE_URL,
        user_agent: str = "recona-python",
    ):
        """Initialize the API client.

        Args:
            api_token: Your Recona API token
            base_url: API base URL (default: https://api.recona.io)
            user_agent: Custom user agent string
        """
        self.session = requests.Session()
        self.session.headers.update(
            {
                "Authorization": f"Bearer {api_token}",
                "User-Agent": user_agent,
                "Content-Type": "application/json",
            }
        )
        self.base_url = base_url.rstrip("/")

        # Initialize rate limiter
        self.rate_limiter = RateLimiter(
            initial_capacity=1, frame_seconds=self.RATE_LIMIT_FRAME_IN_SECONDS
        )

        # Get account info and update rate limiter
        self.account = self._initialize_account()

    def _initialize_account(self) -> Optional[Profile]:
        """Initialize account information and update rate limiter."""
        try:
            account = self.get_profile()
            if account and hasattr(account, "requests_rate_limit"):
                self.rate_limiter.update_capacity(account.requests_rate_limit)
            return account
        except Exception as e:
            print(f"Warning: Could not fetch account quotas: {e}")
            return None

    def _make_request(
        self, method: str, endpoint: str, **kwargs: Any
    ) -> Tuple[Optional[Dict[str, Any]], Optional[Error]]:
        self.rate_limiter.wait_if_needed()

        try:
            response = self.session.request(method, endpoint, **kwargs)
            response.raise_for_status()
            return response.json(), None

        except requests.exceptions.HTTPError as e:
            error_data: dict = {}
            try:
                error_data = response.json().get("error", {})
            except Exception:
                pass

            err = Error(
                status=error_data.get("status"),
                code=error_data.get("code"),
                message=str(e),
                errors=[
                    FieldError(
                        code=f.get("code"),
                        location=f.get("location"),
                        message=f.get("message"),
                    )
                    for f in error_data.get("errors", [])
                    if isinstance(f, dict)
                ]
                or None,
            )
            return None, err

        except requests.exceptions.RequestException as e:
            err = Error(status=None, code=None, message=str(e), errors=None)
            return None, err

    def _get(self, endpoint: str) -> Response:
        data, err = self._make_request("GET", endpoint)
        return Response.from_dict(data, error=err)

    def _search(
        self, endpoint: str, query: str, limit: int = MAX_LIMIT, offset: int = 0
    ) -> Response:
        payload = {"query": query, "limit": limit, "offset": offset}

        data, err = self._make_request("POST", endpoint, json=payload)

        return Response.from_dict(data, error=err)

    def set_user_agent(self, user_agent: str) -> None:
        self.session.headers.update({"User-Agent": user_agent})

    def get_profile(self) -> Optional[Profile]:
        response = self._get(f"{self.base_url}/customers/account")
        response.check_errors()

        return Profile.from_dict(response.raw) if response.raw else None  # type: ignore[attr-defined]

    def get_autonomous_system_details(self, asn: int) -> Optional[AS]:
        response = self._get(f"{self.base_url}/autonomous-system/{asn}")
        response.check_errors()

        if response:
            return AS.from_dict(response.raw) if response.raw else None  # type: ignore[attr-defined]

        return None

    def search_autonomous_systems(
        self, query: str, limit: int = MAX_LIMIT, offset: int = 0
    ) -> SearchResults[AS]:
        response = self._search(
            f"{self.base_url}/autonomous-system/search", query, limit, offset
        )
        response.check_errors()

        # Parse each item into Domain objects
        raw_results = response.raw.get("autonomous_systems", [])
        results = [AS(**item) for item in raw_results]

        total_items = response.raw.get("total_items", []).get("value", []) or 0
        has_more = (offset + len(results)) < min(
            total_items, getattr(self, "SEARCH_RESULTS_LIMIT", total_items)
        )

        return SearchResults(
            results=results, total_items=total_items, has_more=has_more
        )

    def get_all_autonomous_systems(
        self, query: str, batch_size: int = MAX_LIMIT
    ) -> SearchResults[AS]:
        return self._get_all_results(
            "autonomous_systems", query, batch_size, self.search_autonomous_systems
        )

    def get_domain_details(self, domain_name: str) -> Optional[Domain]:
        response = self._get(f"{self.base_url}/domains/{domain_name}")
        response.check_errors()

        if response:
            return Domain.from_dict(response.raw) if response.raw else None  # type: ignore[attr-defined]

        return None

    def search_domains(
        self, query: str, limit: int = MAX_LIMIT, offset: int = 0
    ) -> SearchResults[Domain]:
        response = self._search(f"{self.base_url}/domains/search", query, limit, offset)
        response.check_errors()

        raw_results = response.raw.get("domains", [])
        results = [Domain(**item) for item in raw_results]

        total_items = response.raw.get("total_items", []).get("value", []) or 0
        has_more = (offset + len(results)) < min(
            total_items, getattr(self, "SEARCH_RESULTS_LIMIT", total_items)
        )

        return SearchResults(
            results=results, total_items=total_items, has_more=has_more
        )

    def get_all_domains(
        self, query: str, batch_size: int = MAX_LIMIT
    ) -> SearchResults[Domain]:
        """Get all domains matching the query (up to 10k limit)."""
        return self._get_all_results("domains", query, batch_size, self.search_domains)

    # IP methods
    def get_ip_details(self, ip: str) -> Optional[Host]:
        response = self._get(f"{self.base_url}/hosts/{ip}")
        response.check_errors()

        return Host.from_dict(response.raw) if response.raw else None  # type: ignore[attr-defined]

    def search_ip(
        self, query: str, limit: int = MAX_LIMIT, offset: int = 0
    ) -> SearchResults[Host]:
        response = self._search(f"{self.base_url}/hosts/search", query, limit, offset)
        response.check_errors()

        raw_results = response.raw.get("hosts", [])
        results = [Host(**item) for item in raw_results]

        total_items = response.raw.get("total_items", []).get("value", []) or 0
        has_more = (offset + len(results)) < min(
            total_items, getattr(self, "SEARCH_RESULTS_LIMIT", total_items)
        )

        return SearchResults(
            results=results, total_items=total_items, has_more=has_more
        )

    def get_all_ips(
        self, query: str, batch_size: int = MAX_LIMIT
    ) -> SearchResults[Host]:
        return self._get_all_results("hosts", query, batch_size, self.search_ip)

    def get_certificate_details(self, fingerprint_sha256: str) -> Optional[Certificate]:
        response = self._get(f"{self.base_url}/certificates/{fingerprint_sha256}")
        response.check_errors()

        return Certificate.from_dict(response.raw) if response.raw else None  # type: ignore[attr-defined]

    def search_certificates(
        self, query: str, limit: int = MAX_LIMIT, offset: int = 0
    ) -> SearchResults[Certificate]:
        response = self._search(
            f"{self.base_url}/certificates/search", query, limit, offset
        )
        response.check_errors()

        raw_results = response.raw.get("certificates", [])
        results = [Certificate(**item) for item in raw_results]

        total_items = response.raw.get("total_items", []).get("value", []) or 0
        has_more = (offset + len(results)) < min(
            total_items, getattr(self, "SEARCH_RESULTS_LIMIT", total_items)
        )

        return SearchResults(
            results=results, total_items=total_items, has_more=has_more
        )

    def get_all_certificates(
        self, query: str, batch_size: int = MAX_LIMIT
    ) -> SearchResults[Certificate]:
        return self._get_all_results(
            "certificates", query, batch_size, self.search_certificates
        )

    def get_cve_details(self, cve_id: str) -> Optional[NistCVEData]:
        response = self._get(f"{self.base_url}/cve/{cve_id}")
        response.check_errors()

        return NistCVEData.from_dict(response.raw) if response.raw else None  # type: ignore[attr-defined]

    def search_cve(
        self, query: str, limit: int = MAX_LIMIT, offset: int = 0
    ) -> SearchResults[NistCVEData]:
        response = self._search(f"{self.base_url}/cve/search", query, limit, offset)
        response.check_errors()

        raw_results = response.raw.get("cve_list", [])
        results = [NistCVEData(**item) for item in raw_results]

        total_items = response.raw.get("total_items", []).get("value", []) or 0
        has_more = (offset + len(results)) < min(
            total_items, getattr(self, "SEARCH_RESULTS_LIMIT", total_items)
        )

        return SearchResults(
            results=results, total_items=total_items, has_more=has_more
        )

    def get_all_cves(
        self, query: str, batch_size: int = MAX_LIMIT
    ) -> SearchResults[NistCVEData]:
        return self._get_all_results("cves", query, batch_size, self.search_cve)

    def _get_all_results(
        self,
        resource_type: str,
        query: str,
        batch_size: int,
        search_method: Callable[[str, int, int], SearchResults[T]],
    ) -> SearchResults[T]:
        all_results: List[T] = []
        offset = 0
        total_items: Optional[int] = None

        while len(all_results) < self.SEARCH_RESULTS_LIMIT:
            batch = search_method(query, batch_size, offset)

            if not batch.results:
                break

            all_results.extend(batch.results)
            total_items = batch.total_items

            if not batch.has_more or len(batch.results) < batch_size:
                break

            offset += len(batch.results)

            time.sleep(0.1)

            has_more = bool(
                self.SEARCH_RESULTS_LIMIT <= len(all_results) < (total_items or 0)
            )
        return SearchResults(
            results=all_results[: self.SEARCH_RESULTS_LIMIT],
            total_items=total_items,
            has_more=has_more,
        )
