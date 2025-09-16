import json
from collections.abc import Iterator
from typing import Tuple
from unittest.mock import Mock, patch

import pytest
from requests.exceptions import ConnectionError, HTTPError, Timeout

from .client import Client, RateLimiter, SearchResults
from .response import Error


class TestSearchResults:
    """Test the SearchResults generic container."""

    def test_search_results_initialization(self) -> None:
        """Test SearchResults initialization with default values."""
        results = SearchResults(results=[1, 2, 3])

        assert results.results == [1, 2, 3]
        assert results.total_items is None
        assert results.search_id is None
        assert results.has_more is False
        assert results.count == 3

    def test_search_results_with_all_fields(self) -> None:
        """Test SearchResults initialization with all fields."""
        results = SearchResults(
            results=[1, 2, 3], total_items=100, search_id="search-123", has_more=True
        )

        assert results.results == [1, 2, 3]
        assert results.total_items == 100
        assert results.search_id == "search-123"
        assert results.has_more is True
        assert results.count == 3

    def test_search_results_empty(self) -> None:
        """Test SearchResults with empty results."""
        results: SearchResults[str] = SearchResults(results=[])

        assert results.results == []
        assert results.count == 0


class TestRateLimiter:
    """Test the RateLimiter class."""

    @patch("recona.client.get_limiter")
    @patch("recona.client.limit")
    def test_rate_limiter_initialization(
        self, mock_limit: Mock, mock_get_limiter: Mock
    ) -> None:
        """Test RateLimiter initialization."""
        mock_limiter = Mock()
        mock_get_limiter.return_value = mock_limiter

        rate_limiter = RateLimiter(initial_capacity=5, frame_seconds=2)

        mock_get_limiter.assert_called_once_with(rate=2, capacity=5)
        assert rate_limiter._capacity == 5
        assert rate_limiter.limiter == mock_limiter

    @patch("recona.client.get_limiter")
    def test_rate_limiter_update_capacity(self, mock_get_limiter: Mock) -> None:
        """Test updating rate limiter capacity."""
        mock_limiter = Mock()
        mock_get_limiter.return_value = mock_limiter

        rate_limiter = RateLimiter()
        rate_limiter.update_capacity(10)

        assert rate_limiter._capacity == 10
        assert mock_limiter._capacity == 10

    @patch("recona.client.get_limiter")
    @patch("recona.client.limit")
    def test_wait_if_needed(self, mock_limit: Mock, mock_get_limiter: Mock) -> None:
        """Test wait_if_needed method."""
        mock_limiter = Mock()
        mock_get_limiter.return_value = mock_limiter

        rate_limiter = RateLimiter()
        rate_limiter.wait_if_needed()

        mock_limit.assert_called_once_with(mock_limiter, consume=1)


class TestClient:
    """Test the Client class."""

    @pytest.fixture
    def mock_session(self) -> Iterator[Mock]:
        """Create a mock requests session."""
        with patch("requests.Session") as mock_session_class:
            mock_session = Mock()
            mock_session_class.return_value = mock_session
            yield mock_session

    @pytest.fixture
    def mock_rate_limiter(self) -> Iterator[Mock]:
        """Create a mock rate limiter."""
        with patch("recona.client.RateLimiter") as mock_rate_limiter_class:
            mock_rate_limiter = Mock()
            mock_rate_limiter_class.return_value = mock_rate_limiter
            yield mock_rate_limiter

    def test_client_initialization_default(
        self, mock_session: Mock, mock_rate_limiter: Mock
    ) -> None:
        """Test Client initialization with default parameters."""
        with patch.object(Client, "_initialize_account", return_value=None):
            client = Client("test-token")

        # Check session headers
        expected_headers = {
            "Authorization": "Bearer test-token",
            "User-Agent": "recona-python",
            "Content-Type": "application/json",
        }
        mock_session.headers.update.assert_called_with(expected_headers)

        assert client.base_url == "https://api.recona.io"

    def test_client_initialization_custom(
        self, mock_session: Mock, mock_rate_limiter: Mock
    ) -> None:
        """Test Client initialization with custom parameters."""
        with patch.object(Client, "_initialize_account", return_value=None):
            client = Client(
                "test-token",
                base_url="https://custom.api.com/",
                user_agent="custom-agent",
            )

        expected_headers = {
            "Authorization": "Bearer test-token",
            "User-Agent": "custom-agent",
            "Content-Type": "application/json",
        }
        mock_session.headers.update.assert_called_with(expected_headers)

        assert client.base_url == "https://custom.api.com"

    def test_initialize_account_success(
        self, mock_session: Mock, mock_rate_limiter: Mock
    ) -> None:
        """Test successful account initialization."""
        mock_profile = Mock()
        mock_profile.requests_rate_limit = 10

        with patch.object(Client, "get_profile", return_value=mock_profile):
            client = Client("test-token")

        mock_rate_limiter.update_capacity.assert_called_once_with(10)
        assert client.account == mock_profile

    def test_initialize_account_no_rate_limit(
        self, mock_session: Mock, mock_rate_limiter: Mock
    ) -> None:
        """Test account initialization when profile has no rate limit attribute."""
        mock_profile = Mock()
        del mock_profile.requests_rate_limit  # Simulate missing attribute

        with patch.object(Client, "get_profile", return_value=mock_profile):
            client = Client("test-token")

        mock_rate_limiter.update_capacity.assert_not_called()
        assert client.account == mock_profile

    @patch("builtins.print")
    def test_initialize_account_exception(
        self, mock_print: Mock, mock_session: Mock, mock_rate_limiter: Mock
    ) -> None:
        """Test account initialization when get_profile raises exception."""
        with patch.object(Client, "get_profile", side_effect=Exception("API Error")):
            client = Client("test-token")

        mock_print.assert_called_once_with(
            "Warning: Could not fetch account quotas: API Error"
        )
        assert client.account is None

    def test_make_request_success(
        self, mock_session: Mock, mock_rate_limiter: Mock
    ) -> None:
        """Test successful API request."""
        # Setup mock response
        mock_response = Mock()
        mock_response.json.return_value = {"data": "test"}
        mock_session.request.return_value = mock_response

        with patch.object(Client, "_initialize_account", return_value=None):
            client = Client("test-token")

        data, error = client._make_request("GET", "/test", param="value")

        mock_rate_limiter.wait_if_needed.assert_called_once()
        mock_session.request.assert_called_once_with("GET", "/test", param="value")
        mock_response.raise_for_status.assert_called_once()

        assert data == {"data": "test"}
        assert error is None

    def test_make_request_http_error(
        self, mock_session: Mock, mock_rate_limiter: Mock
    ) -> None:
        """Test HTTP error handling in API request."""
        # Setup mock response with HTTP error
        mock_response = Mock()
        mock_response.raise_for_status.side_effect = HTTPError("404 Not Found")
        mock_response.json.return_value = {
            "error": {
                "status": 404,
                "code": "NOT_FOUND",
                "errors": [
                    {
                        "code": "INVALID_PARAM",
                        "location": "query",
                        "message": "Invalid parameter",
                    }
                ],
            }
        }
        mock_session.request.return_value = mock_response

        with patch.object(Client, "_initialize_account", return_value=None):
            client = Client("test-token")

        data, error = client._make_request("GET", "/test")

        assert data is None
        assert isinstance(error, Error)
        assert error.status == 404
        assert error.code == "NOT_FOUND"
        assert error.message == "404 Not Found"
        assert len(error.errors or []) == 1
        assert (error.errors or [])[0].code == "INVALID_PARAM"
        assert (error.errors or [])[0].location == "query"
        assert (error.errors or [])[0].message == "Invalid parameter"

    def test_make_request_http_error_no_json(
        self, mock_session: Mock, mock_rate_limiter: Mock
    ) -> None:
        """Test HTTP error handling when response has no JSON."""
        mock_response = Mock()
        mock_response.raise_for_status.side_effect = HTTPError("500 Server Error")
        mock_response.json.side_effect = json.JSONDecodeError("Invalid JSON", "", 0)
        mock_session.request.return_value = mock_response

        with patch.object(Client, "_initialize_account", return_value=None):
            client = Client("test-token")

        data, error = client._make_request("GET", "/test")

        assert data is None
        assert isinstance(error, Error)
        assert error.status is None
        assert error.code is None
        assert error.message == "500 Server Error"
        assert error.errors is None

    def test_make_request_connection_error(
        self, mock_session: Mock, mock_rate_limiter: Mock
    ) -> None:
        """Test connection error handling."""
        mock_session.request.side_effect = ConnectionError("Connection failed")

        with patch.object(Client, "_initialize_account", return_value=None):
            client = Client("test-token")

        data, error = client._make_request("GET", "/test")

        assert data is None
        assert isinstance(error, Error)
        assert error.status is None
        assert error.code is None
        assert error.message == "Connection failed"
        assert error.errors is None

    def test_make_request_timeout_error(
        self, mock_session: Mock, mock_rate_limiter: Mock
    ) -> None:
        """Test timeout error handling."""
        mock_session.request.side_effect = Timeout("Request timed out")

        with patch.object(Client, "_initialize_account", return_value=None):
            client = Client("test-token")

        data, error = client._make_request("GET", "/test")

        assert data is None
        assert isinstance(error, Error)
        assert error.message == "Request timed out"

    def test_get_method(self, mock_session: Mock, mock_rate_limiter: Mock) -> None:
        """Test _get method."""
        with patch.object(Client, "_initialize_account", return_value=None):
            client = Client("test-token")

        with patch.object(
            client, "_make_request", return_value=({"data": "test"}, None)
        ) as mock_make_request:
            with patch("recona.client.Response.from_dict") as mock_from_dict:
                mock_response = Mock()
                mock_from_dict.return_value = mock_response

                result = client._get("/test")

                mock_make_request.assert_called_once_with("GET", "/test")
                mock_from_dict.assert_called_once_with({"data": "test"}, error=None)
                assert result == mock_response

    def test_search_method(self, mock_session: Mock, mock_rate_limiter: Mock) -> None:
        """Test _search method."""
        with patch.object(Client, "_initialize_account", return_value=None):
            client = Client("test-token")

        expected_payload = {"query": "test query", "limit": 50, "offset": 10}

        with patch.object(
            client, "_make_request", return_value=({"data": "test"}, None)
        ) as mock_make_request:
            with patch("recona.client.Response.from_dict") as mock_from_dict:
                mock_response = Mock()
                mock_from_dict.return_value = mock_response

                result = client._search("/search", "test query", limit=50, offset=10)

                mock_make_request.assert_called_once_with(
                    "POST", "/search", json=expected_payload
                )
                mock_from_dict.assert_called_once_with({"data": "test"}, error=None)
                assert result == mock_response

    def test_set_user_agent(self, mock_session: Mock, mock_rate_limiter: Mock) -> None:
        """Test set_user_agent method."""
        with patch.object(Client, "_initialize_account", return_value=None):
            client = Client("test-token")

        client.set_user_agent("new-agent")

        mock_session.headers.update.assert_called_with({"User-Agent": "new-agent"})


class TestClientProfileMethods:
    """Test Client methods related to profile management."""

    @pytest.fixture
    def client(self) -> Client:
        """Create a client instance with mocked dependencies."""
        with (
            patch("requests.Session"),
            patch("recona.client.RateLimiter"),
            patch.object(Client, "_initialize_account", return_value=None),
        ):
            return Client("test-token")

    def test_get_profile_success(self, client: Mock) -> None:
        """Test successful profile retrieval."""
        mock_response = Mock()
        mock_response.raw = {"id": "123", "name": "Test User"}
        mock_response.check_errors.return_value = None

        mock_profile = Mock()

        with (
            patch.object(client, "_get", return_value=mock_response),
            patch(
                "recona.client.Profile.from_dict", return_value=mock_profile
            ) as mock_from_dict,
        ):

            result = client.get_profile()

            client._get.assert_called_once_with(
                "https://api.recona.io/customers/account"
            )
            mock_response.check_errors.assert_called_once()
            mock_from_dict.assert_called_once_with(mock_response.raw)
            assert result == mock_profile

    def test_get_profile_no_data(self, client: Mock) -> None:
        """Test profile retrieval with no data."""
        mock_response = Mock()
        mock_response.raw = None
        mock_response.check_errors.return_value = None

        with patch.object(client, "_get", return_value=mock_response):
            result = client.get_profile()

            assert result is None

    def test_get_profile_error(self, client: Mock) -> None:
        """Test profile retrieval with error."""
        mock_response = Mock()
        mock_response.check_errors.side_effect = Exception("API Error")

        with patch.object(client, "_get", return_value=mock_response):
            with pytest.raises(Exception, match="API Error"):
                client.get_profile()


class TestClientASMethods:
    """Test Client methods for Autonomous Systems."""

    @pytest.fixture
    def client(self) -> Client:
        with (
            patch("requests.Session"),
            patch("recona.client.RateLimiter"),
            patch.object(Client, "_initialize_account", return_value=None),
        ):
            return Client("test-token")

    def test_get_autonomous_system_details_success(self, client: Mock) -> None:
        """Test successful AS details retrieval."""
        mock_response = Mock()
        mock_response.raw = {"asn": 123, "name": "Test AS"}
        mock_response.check_errors.return_value = None
        mock_response.__bool__ = lambda self: True

        mock_as = Mock()

        with (
            patch.object(client, "_get", return_value=mock_response),
            patch("recona.client.AS.from_dict", return_value=mock_as) as mock_from_dict,
        ):

            result = client.get_autonomous_system_details(123)

            client._get.assert_called_once_with(
                "https://api.recona.io/autonomous-system/123"
            )
            mock_response.check_errors.assert_called_once()
            mock_from_dict.assert_called_once_with(mock_response.raw)
            assert result == mock_as

    def test_get_autonomous_system_details_not_found(self, client: Mock) -> None:
        """Test AS details retrieval when not found."""
        mock_response = Mock()
        mock_response.check_errors.return_value = None
        mock_response.__bool__ = lambda self: False

        with patch.object(client, "_get", return_value=mock_response):
            result = client.get_autonomous_system_details(123)

            assert result is None

    def test_search_autonomous_systems(self, client: Mock) -> None:
        """Test AS search functionality."""
        mock_response = Mock()
        mock_response.raw = {
            "autonomous_systems": [
                {"asn": 123, "name": "AS1"},
                {"asn": 456, "name": "AS2"},
            ],
            "total_items": {"value": 100},
        }
        mock_response.check_errors.return_value = None

        with (
            patch.object(client, "_search", return_value=mock_response),
            patch("recona.client.AS") as mock_as,
        ):
            mock_as.side_effect = lambda **kwargs: Mock(**kwargs)

            result = client.search_autonomous_systems("test query", limit=50, offset=10)

            client._search.assert_called_once_with(
                "https://api.recona.io/autonomous-system/search", "test query", 50, 10
            )
            mock_response.check_errors.assert_called_once()

            assert isinstance(result, SearchResults)
            assert len(result.results) == 2
            assert result.total_items == 100
            assert result.has_more is True  # (10 + 2) < min(100, 10000)

    def test_search_autonomous_systems_no_more_results(self, client: Mock) -> None:
        """Test AS search when there are no more results."""
        mock_response = Mock()
        mock_response.raw = {
            "autonomous_systems": [{"asn": 123, "name": "AS1"}],
            "total_items": {"value": 1},
        }
        mock_response.check_errors.return_value = None

        with (
            patch.object(client, "_search", return_value=mock_response),
            patch("recona.client.AS") as mock_as,
        ):
            mock_as.return_value = Mock()

            result = client.search_autonomous_systems("test query", limit=50, offset=0)

            assert result.has_more is False  # (0 + 1) >= min(1, 10000)

    def test_get_all_autonomous_systems(self, client: Mock) -> None:
        """Test getting all AS results."""
        mock_search_results = Mock()

        with patch.object(
            client, "_get_all_results", return_value=mock_search_results
        ) as mock_get_all:
            result = client.get_all_autonomous_systems("test query", batch_size=25)

            mock_get_all.assert_called_once_with(
                "autonomous_systems", "test query", 25, client.search_autonomous_systems
            )
            assert result == mock_search_results


class TestClientDomainMethods:
    """Test Client methods for domains."""

    @pytest.fixture
    def client(self) -> Client:
        with (
            patch("requests.Session"),
            patch("recona.client.RateLimiter"),
            patch.object(Client, "_initialize_account", return_value=None),
        ):
            return Client("test-token")

    def test_get_domain_details_success(self, client: Mock) -> None:
        """Test successful domain details retrieval."""
        mock_response = Mock()
        mock_response.raw = {"domain": "example.com", "registrar": "Test Registrar"}
        mock_response.check_errors.return_value = None
        mock_response.__bool__ = lambda self: True

        mock_domain = Mock()

        with (
            patch.object(client, "_get", return_value=mock_response),
            patch(
                "recona.client.Domain.from_dict", return_value=mock_domain
            ) as mock_from_dict,
        ):

            result = client.get_domain_details("example.com")

            client._get.assert_called_once_with(
                "https://api.recona.io/domains/example.com"
            )
            mock_from_dict.assert_called_once_with(mock_response.raw)
            assert result == mock_domain

    def test_get_domain_details_not_found(self, client: Mock) -> None:
        """Test domain details retrieval when not found."""
        mock_response = Mock()
        mock_response.check_errors.return_value = None
        mock_response.__bool__ = lambda self: False

        with patch.object(client, "_get", return_value=mock_response):
            result = client.get_domain_details("nonexistent.com")

            assert result is None

    def test_search_domains(self, client: Mock) -> None:
        """Test domain search functionality."""
        mock_response = Mock()
        mock_response.raw = {
            "domains": [{"domain": "example1.com"}, {"domain": "example2.com"}],
            "total_items": {"value": 50},
        }
        mock_response.check_errors.return_value = None

        with (
            patch.object(client, "_search", return_value=mock_response),
            patch("recona.client.Domain") as mock_domain,
        ):
            mock_domain.side_effect = lambda **kwargs: Mock(**kwargs)

            result = client.search_domains("example", limit=25, offset=5)

            client._search.assert_called_once_with(
                "https://api.recona.io/domains/search", "example", 25, 5
            )

            assert isinstance(result, SearchResults)
            assert len(result.results) == 2
            assert result.total_items == 50

    def test_get_all_domains(self, client: Mock) -> None:
        """Test getting all domain results."""
        mock_search_results = Mock()

        with patch.object(
            client, "_get_all_results", return_value=mock_search_results
        ) as mock_get_all:
            result = client.get_all_domains("example", batch_size=30)

            mock_get_all.assert_called_once_with(
                "domains", "example", 30, client.search_domains
            )
            assert result == mock_search_results


class TestClientIPMethods:
    """Test Client methods for IP addresses."""

    @pytest.fixture
    def client(self) -> Client:
        with (
            patch("requests.Session"),
            patch("recona.client.RateLimiter"),
            patch.object(Client, "_initialize_account", return_value=None),
        ):
            return Client("test-token")

    def test_get_ip_details_success(self, client: Mock) -> None:
        """Test successful IP details retrieval."""
        mock_response = Mock()
        mock_response.raw = {"ip": "192.168.1.1", "hostname": "test.com"}
        mock_response.check_errors.return_value = None

        mock_host = Mock()

        with (
            patch.object(client, "_get", return_value=mock_response),
            patch(
                "recona.client.Host.from_dict", return_value=mock_host
            ) as mock_from_dict,
        ):

            result = client.get_ip_details("192.168.1.1")

            client._get.assert_called_once_with(
                "https://api.recona.io/hosts/192.168.1.1"
            )
            mock_from_dict.assert_called_once_with(mock_response.raw)
            assert result == mock_host

    def test_search_ip(self, client: Mock) -> None:
        """Test IP search functionality."""
        mock_response = Mock()
        mock_response.raw = {
            "hosts": [{"ip": "192.168.1.1"}, {"ip": "192.168.1.2"}],
            "total_items": {"value": 25},
        }
        mock_response.check_errors.return_value = None

        with (
            patch.object(client, "_search", return_value=mock_response),
            patch("recona.client.Host") as mock_host,
        ):
            mock_host.side_effect = lambda **kwargs: Mock(**kwargs)

            result = client.search_ip("192.168.1", limit=20, offset=0)

            client._search.assert_called_once_with(
                "https://api.recona.io/hosts/search", "192.168.1", 20, 0
            )

            assert isinstance(result, SearchResults)
            assert len(result.results) == 2
            assert result.total_items == 25

    def test_get_all_ips(self, client: Mock) -> None:
        """Test getting all IP results."""
        mock_search_results = Mock()

        with patch.object(
            client, "_get_all_results", return_value=mock_search_results
        ) as mock_get_all:
            result = client.get_all_ips("192.168", batch_size=40)

            mock_get_all.assert_called_once_with(
                "hosts", "192.168", 40, client.search_ip
            )
            assert result == mock_search_results


class TestClientCertificateMethods:
    """Test Client methods for certificates."""

    @pytest.fixture
    def client(self) -> Client:
        with (
            patch("requests.Session"),
            patch("recona.client.RateLimiter"),
            patch.object(Client, "_initialize_account", return_value=None),
        ):
            return Client("test-token")

    def test_get_certificate_details_success(self, client: Mock) -> None:
        """Test successful certificate details retrieval."""
        fingerprint = "abc123def456"
        mock_response = Mock()
        mock_response.raw = {"fingerprint": fingerprint, "issuer": "Test CA"}
        mock_response.check_errors.return_value = None

        mock_cert = Mock()

        with (
            patch.object(client, "_get", return_value=mock_response),
            patch(
                "recona.client.Certificate.from_dict", return_value=mock_cert
            ) as mock_from_dict,
        ):

            result = client.get_certificate_details(fingerprint)

            client._get.assert_called_once_with(
                f"https://api.recona.io/certificates/{fingerprint}"
            )
            mock_from_dict.assert_called_once_with(mock_response.raw)
            assert result == mock_cert

    def test_search_certificates(self, client: Mock) -> None:
        """Test certificate search functionality."""
        mock_response = Mock()
        mock_response.raw = {
            "certificates": [{"fingerprint": "abc123"}, {"fingerprint": "def456"}],
            "total_items": {"value": 15},
        }
        mock_response.check_errors.return_value = None

        with (
            patch.object(client, "_search", return_value=mock_response),
            patch("recona.client.Certificate") as mock_cert,
        ):
            mock_cert.side_effect = lambda **kwargs: Mock(**kwargs)

            result = client.search_certificates("example.com", limit=10, offset=5)

            client._search.assert_called_once_with(
                "https://api.recona.io/certificates/search", "example.com", 10, 5
            )

            assert isinstance(result, SearchResults)
            assert len(result.results) == 2
            assert result.total_items == 15

    def test_get_all_certificates(self, client: Mock) -> None:
        """Test getting all certificate results."""
        mock_search_results = Mock()

        with patch.object(
            client, "_get_all_results", return_value=mock_search_results
        ) as mock_get_all:
            result = client.get_all_certificates("example.com", batch_size=35)

            mock_get_all.assert_called_once_with(
                "certificates", "example.com", 35, client.search_certificates
            )
            assert result == mock_search_results


class TestClientCVEMethods:
    """Test Client methods for CVE data."""

    @pytest.fixture
    def client(self) -> Client:
        with (
            patch("requests.Session"),
            patch("recona.client.RateLimiter"),
            patch.object(Client, "_initialize_account", return_value=None),
        ):
            return Client("test-token")

    def test_get_cve_details_success(self, client: Mock) -> None:
        """Test successful CVE details retrieval."""
        cve_id = "CVE-2023-1234"
        mock_response = Mock()
        mock_response.raw = {"cve_id": cve_id, "description": "Test vulnerability"}
        mock_response.check_errors.return_value = None

        mock_cve = Mock()

        with (
            patch.object(client, "_get", return_value=mock_response),
            patch(
                "recona.client.NistCVEData.from_dict", return_value=mock_cve
            ) as mock_from_dict,
        ):

            result = client.get_cve_details(cve_id)

            client._get.assert_called_once_with(f"https://api.recona.io/cve/{cve_id}")
            mock_from_dict.assert_called_once_with(mock_response.raw)
            assert result == mock_cve

    def test_search_cve(self, client: Mock) -> None:
        """Test CVE search functionality."""
        mock_response = Mock()
        mock_response.raw = {
            "cve_list": [{"cve_id": "CVE-2023-1234"}, {"cve_id": "CVE-2023-5678"}],
            "total_items": {"value": 75},
        }
        mock_response.check_errors.return_value = None

        with (
            patch.object(client, "_search", return_value=mock_response),
            patch("recona.client.NistCVEData") as mock_cve,
        ):
            mock_cve.side_effect = lambda **kwargs: Mock(**kwargs)

            result = client.search_cve("apache", limit=15, offset=10)

            client._search.assert_called_once_with(
                "https://api.recona.io/cve/search", "apache", 15, 10
            )

            assert isinstance(result, SearchResults)
            assert len(result.results) == 2
            assert result.total_items == 75

    def test_get_all_cves(self, client: Mock) -> None:
        """Test getting all CVE results."""
        mock_search_results = Mock()

        with patch.object(
            client, "_get_all_results", return_value=mock_search_results
        ) as mock_get_all:
            result = client.get_all_cves("apache", batch_size=45)

            mock_get_all.assert_called_once_with(
                "cves", "apache", 45, client.search_cve
            )
            assert result == mock_search_results


class TestClientGetAllResults:
    """Test the _get_all_results method which handles pagination."""

    @pytest.fixture
    def client(self) -> Client:
        with (
            patch("requests.Session"),
            patch("recona.client.RateLimiter"),
            patch.object(Client, "_initialize_account", return_value=None),
        ):
            return Client("test-token")

    @patch("time.sleep")
    def test_get_all_results_single_batch(self, mock_sleep: Mock, client: Mock) -> None:
        """Test _get_all_results with results fitting in single batch."""

        # Mock search method that returns all results in first call
        def mock_search_method(
            query: str, batch_size: int, offset: int
        ) -> SearchResults:
            if offset == 0:
                return SearchResults(
                    results=[f"item_{i}" for i in range(5)],
                    total_items=5,
                    has_more=False,
                )
            return SearchResults(results=[], total_items=5, has_more=False)

        result = client._get_all_results("test", "query", 10, mock_search_method)

        assert len(result.results) == 5
        assert result.total_items == 5
        assert result.has_more is False
        mock_sleep.assert_not_called()  # Should not sleep for single batch

    @patch("time.sleep")
    def test_get_all_results_multiple_batches(
        self, mock_sleep: Mock, client: Mock
    ) -> None:
        """Test _get_all_results with multiple batches."""
        call_count = 0

        def mock_search_method(
            query: str, batch_size: int, offset: int
        ) -> SearchResults:
            nonlocal call_count
            call_count += 1

            if call_count == 1:  # First call
                return SearchResults(
                    results=[f"item_{i}" for i in range(10)],
                    total_items=25,
                    has_more=True,
                )
            elif call_count == 2:  # Second call
                return SearchResults(
                    results=[f"item_{i}" for i in range(10, 20)],
                    total_items=25,
                    has_more=True,
                )
            elif call_count == 3:  # Third call
                return SearchResults(
                    results=[f"item_{i}" for i in range(20, 25)],
                    total_items=25,
                    has_more=False,
                )
            return SearchResults(results=[], total_items=25, has_more=False)

        result = client._get_all_results("test", "query", 10, mock_search_method)

        assert len(result.results) == 25
        assert result.total_items == 25
        assert result.has_more is False
        assert mock_sleep.call_count == 2  # Should sleep between batches

    @patch("time.sleep")
    def test_get_all_results_hit_search_limit(
        self, mock_sleep: Mock, client: Mock
    ) -> None:
        """Test _get_all_results when hitting SEARCH_RESULTS_LIMIT."""
        client.SEARCH_RESULTS_LIMIT = 15  # Set low limit for testing

        call_count = 0

        def mock_search_method(
            query: str, batch_size: int, offset: int
        ) -> SearchResults:
            nonlocal call_count
            call_count += 1

            if call_count == 1:
                return SearchResults(
                    results=[f"item_{i}" for i in range(10)],
                    total_items=100,
                    has_more=True,
                )
            elif call_count == 2:
                return SearchResults(
                    results=[f"item_{i}" for i in range(10, 20)],
                    total_items=100,
                    has_more=True,
                )
            return SearchResults(results=[], total_items=100, has_more=False)

        result = client._get_all_results("test", "query", 10, mock_search_method)

        # Should truncate to SEARCH_RESULTS_LIMIT
        assert len(result.results) == 15
        assert result.total_items == 100
        assert result.has_more is True  # More results available but limited

    @patch("time.sleep")
    def test_get_all_results_empty_batch(self, mock_sleep: Mock, client: Mock) -> None:
        """Test _get_all_results when search returns empty batch."""

        def mock_search_method(
            query: str, batch_size: int, offset: int
        ) -> SearchResults:
            if offset == 0:
                return SearchResults(
                    results=[f"item_{i}" for i in range(5)],
                    total_items=10,
                    has_more=True,
                )
            # Second call returns empty
            return SearchResults(results=[], total_items=10, has_more=False)

        result = client._get_all_results("test", "query", 10, mock_search_method)

        assert len(result.results) == 5
        assert result.total_items == 10
        assert result.has_more is False

    @patch("time.sleep")
    def test_get_all_results_partial_last_batch(
        self, mock_sleep: Mock, client: Mock
    ) -> None:
        """Test _get_all_results with partial last batch."""
        call_count = 0

        def mock_search_method(
            query: str, batch_size: int, offset: int
        ) -> SearchResults:
            nonlocal call_count
            call_count += 1

            if call_count == 1:
                return SearchResults(
                    results=[f"item_{i}" for i in range(10)],
                    total_items=15,
                    has_more=True,
                )
            elif call_count == 2:
                # Last batch with fewer items than batch_size
                return SearchResults(
                    results=[f"item_{i}" for i in range(10, 15)],
                    total_items=15,
                    has_more=False,
                )
            return SearchResults(results=[], total_items=15, has_more=False)

        result = client._get_all_results("test", "query", 10, mock_search_method)

        assert len(result.results) == 15
        assert result.total_items == 15
        assert result.has_more is False


class TestClientEdgeCases:
    """Test edge cases and error scenarios."""

    @pytest.fixture
    def client(self) -> Client:
        with (
            patch("requests.Session"),
            patch("recona.client.RateLimiter"),
            patch.object(Client, "_initialize_account", return_value=None),
        ):
            return Client("test-token")

    def test_search_with_missing_total_items(self, client: Mock) -> None:
        """Test search when total_items is missing from response."""
        mock_response = Mock()
        mock_response.raw = {
            "domains": [{"domain": "example.com"}],
            # Missing total_items
        }
        mock_response.check_errors.return_value = None

        with (
            patch.object(client, "_search", return_value=mock_response),
            patch("recona.client.Domain") as mock_domain,
        ):
            mock_domain.return_value = Mock()

            result = client.search_domains("example")

            assert result.total_items == 0  # Should default to 0
            assert result.has_more is False

    def test_search_with_none_api_token(self) -> None:
        """Test client initialization with None API token."""
        with (
            patch("requests.Session") as mock_session_class,
            patch("recona.client.RateLimiter"),
            patch.object(Client, "_initialize_account", return_value=None),
        ):

            mock_session = Mock()
            mock_session_class.return_value = mock_session

            client = Client(None)  # noqa: F841

            expected_headers = {
                "Authorization": "Bearer None",
                "User-Agent": "recona-python",
                "Content-Type": "application/json",
            }
            mock_session.headers.update.assert_called_with(expected_headers)

    def test_base_url_trailing_slash_removal(self) -> None:
        """Test that trailing slashes are removed from base_url."""
        with (
            patch("requests.Session"),
            patch("recona.client.RateLimiter"),
            patch.object(Client, "_initialize_account", return_value=None),
        ):

            client = Client("token", base_url="https://api.example.com/")

            assert client.base_url == "https://api.example.com"

    def test_search_with_zero_limit(self, client: Mock) -> None:
        """Test search with zero limit."""
        mock_response = Mock()
        mock_response.raw = {"domains": [], "total_items": {"value": 0}}
        mock_response.check_errors.return_value = None

        with patch.object(client, "_search", return_value=mock_response):
            result = client.search_domains("example", limit=0)

            assert len(result.results) == 0
            assert result.has_more is False


class TestClientConstants:
    """Test client constants and class attributes."""

    def test_client_constants(self) -> None:
        """Test that client constants are correctly defined."""
        assert Client.DEFAULT_BASE_URL == "https://api.recona.io"
        assert Client.MAX_LIMIT == 100
        assert Client.SEARCH_RESULTS_LIMIT == 10000
        assert Client.RATE_LIMIT_FRAME_IN_SECONDS == 1


class TestClientIntegration:
    """Integration tests for client functionality."""

    @pytest.fixture
    def client(self) -> Client:
        with (
            patch("requests.Session") as mock_session_class,
            patch("recona.client.RateLimiter") as mock_rate_limiter_class,
        ):

            mock_session = Mock()
            mock_session_class.return_value = mock_session

            mock_rate_limiter = Mock()
            mock_rate_limiter_class.return_value = mock_rate_limiter

            # Mock successful account initialization
            with patch.object(Client, "get_profile") as mock_get_profile:
                mock_profile = Mock()
                mock_profile.requests_rate_limit = 10
                mock_get_profile.return_value = mock_profile

                return Client("test-token")

    def test_full_domain_search_workflow(self, client: Mock) -> None:
        """Test complete domain search workflow."""
        # Mock successful search response
        mock_response = Mock()
        mock_response.json.return_value = {
            "domains": [
                {"domain": "example1.com", "registrar": "Registrar1"},
                {"domain": "example2.com", "registrar": "Registrar2"},
            ],
            "total_items": {"value": 2},
        }
        client.session.request.return_value = mock_response

        # Mock Domain creation
        with patch("recona.client.Domain") as mock_domain_class:
            mock_domain1 = Mock()
            mock_domain1.domain = "example1.com"
            mock_domain2 = Mock()
            mock_domain2.domain = "example2.com"

            mock_domain_class.side_effect = [mock_domain1, mock_domain2]

            result = client.search_domains("example")

            # Verify rate limiter was called
            client.rate_limiter.wait_if_needed.assert_called()

            # Verify request was made correctly
            client.session.request.assert_called_once_with(
                "POST",
                "https://api.recona.io/domains/search",
                json={"query": "example", "limit": 100, "offset": 0},
            )

            # Verify results
            assert len(result.results) == 2
            assert result.total_items == 2
            assert result.results[0] == mock_domain1
            assert result.results[1] == mock_domain2

    def test_error_propagation(self, client: Mock) -> None:
        """Test that errors are properly propagated."""
        # Mock HTTP error response
        mock_response = Mock()
        mock_response.raise_for_status.side_effect = HTTPError("404 Not Found")
        mock_response.json.return_value = {
            "error": {"status": 404, "code": "NOT_FOUND", "errors": []}
        }
        client.session.request.return_value = mock_response

        # Mock Response.from_dict to simulate error checking
        with patch("recona.client.Response.from_dict") as mock_from_dict:
            mock_response_obj = Mock()
            mock_response_obj.check_errors.side_effect = Exception("Domain not found")
            mock_from_dict.return_value = mock_response_obj

            with pytest.raises(Exception, match="Domain not found"):
                client.search_domains("nonexistent")


class TestClientRetryAndRateLimit:
    """Test retry logic and rate limiting behavior."""

    @pytest.fixture
    def client(self) -> Tuple[Client, Mock]:
        with (
            patch("requests.Session"),
            patch("recona.client.RateLimiter") as mock_rate_limiter_class,
            patch.object(Client, "_initialize_account", return_value=None),
        ):

            mock_rate_limiter = Mock()
            mock_rate_limiter_class.return_value = mock_rate_limiter

            client = Client("test-token")
            return client, mock_rate_limiter

    def test_rate_limiter_called_on_each_request(self, client: Mock) -> None:
        """Test that rate limiter is called for each request."""
        client_obj, mock_rate_limiter = client

        # Mock successful response
        mock_response = Mock()
        mock_response.json.return_value = {"data": "test"}
        client_obj.session.request.return_value = mock_response

        # Make multiple requests
        client_obj._make_request("GET", "/test1")
        client_obj._make_request("POST", "/test2", json={})
        client_obj._make_request("GET", "/test3")

        # Verify rate limiter was called for each request
        assert mock_rate_limiter.wait_if_needed.call_count == 3


class TestClientSpecialCases:
    """Test special cases and boundary conditions."""

    @pytest.fixture
    def client(self) -> Client:
        with (
            patch("requests.Session"),
            patch("recona.client.RateLimiter"),
            patch.object(Client, "_initialize_account", return_value=None),
        ):
            return Client("test-token")

    def test_search_with_special_characters_in_query(self, client: Mock) -> None:
        """Test search with special characters in query."""
        special_query = "test@domain.com & <script>alert('xss')</script>"

        with patch.object(
            client, "_make_request", return_value=({"domains": []}, None)
        ):
            client._search("/test", special_query)

            # Verify the payload contains the special characters
            expected_payload = {
                "query": special_query,
                "limit": 100,  # default
                "offset": 0,  # default
            }
            client._make_request.assert_called_once_with(
                "POST", "/test", json=expected_payload
            )

    def test_empty_response_handling(self, client: Mock) -> None:
        """Test handling of completely empty responses."""
        mock_response = Mock()
        mock_response.raw = {}
        mock_response.check_errors.return_value = None

        with patch.object(client, "_search", return_value=mock_response):
            result = client.search_domains("example")

            # Should handle missing keys gracefully
            assert len(result.results) == 0
            assert result.total_items == 0
            assert result.has_more is False

    def test_malformed_response_data(self, client: Client) -> None:
        """Test handling of malformed response data."""
        mock_response = Mock()
        mock_response.raw = {
            "domains": "not_a_list",  # Should be a list
            "total_items": "not_a_dict",  # Should be a dict
        }
        mock_response.check_errors.return_value = None

        with patch.object(client, "_search", return_value=mock_response):
            # Should handle malformed data without crashing
            with pytest.raises(TypeError):  # Will fail when trying to iterate "domains"
                client.search_domains("example")


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"])
