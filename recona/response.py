from dataclasses import dataclass
from typing import Any, Dict, List, Optional

from dataclasses_json import dataclass_json


@dataclass_json
@dataclass
class FieldError:
    code: Optional[str] = None
    location: Optional[str] = None
    message: Optional[str] = None


@dataclass_json
@dataclass
class Error:
    status: Optional[int] = None
    code: Optional[str] = None
    message: Optional[str] = None
    errors: Optional[List[FieldError]] = None


class ReconaError(Exception):
    def __init__(self, message: Optional[str] = None):
        self.message = message
        super().__init__(message)


class BadRequestError(ReconaError):
    pass


class ParamsValidationError(ReconaError):
    pass


class RequestLimitReachedError(ReconaError):
    pass


class DownloadsLimitReachedError(ReconaError):
    pass


class SearchParamsLimitReachedError(ReconaError):
    pass


class UnauthorizedError(ReconaError):
    pass


class ForbiddenError(ReconaError):
    pass


class InternalServerError(ReconaError):
    pass


class RateLimitError(ReconaError):
    pass


class UnknownError(ReconaError):
    pass


class Response:
    CODE_BAD_REQUEST = "bad_request"
    CODE_VALIDATION_ERROR = "validation_error"
    CODE_REQUESTS_LIMIT_REACHED = "requests_limit_reached"
    CODE_DOWNLOADS_LIMIT_REACHED = "downloads_limit_reached"
    CODE_SEARCH_PARAMS_LIMIT_REACHED = "search_params_limit_reached"
    CODE_UNAUTHORIZED = "unauthorized"
    CODE_FORBIDDEN = "forbidden"
    CODE_INTERNAL_SERVER_ERROR = "internal_server_error"
    CODE_RATE_LIMIT_ERROR = "too_many_requests"

    raw: Dict[str, Any]
    total_items: Optional[int] = None
    error: Optional[Error] = None

    def __init__(self, raw: Any = None, error: Optional[Error] = None):
        self.raw = raw
        self.error = error

    def check_errors(self) -> None:
        if not self.error:
            return

        errors_list = getattr(self.error, "errors", None)
        msg = (
            errors_list[0].message
            if errors_list and len(errors_list) > 0
            else getattr(self.error, "message", str(self.error))
        )

        code = getattr(self.error, "code", None)
        if code == self.CODE_BAD_REQUEST:
            raise BadRequestError(msg)
        elif code == self.CODE_VALIDATION_ERROR:
            raise ParamsValidationError(msg)
        elif code == self.CODE_REQUESTS_LIMIT_REACHED:
            raise RequestLimitReachedError(msg)
        elif code == self.CODE_DOWNLOADS_LIMIT_REACHED:
            raise DownloadsLimitReachedError(msg)
        elif code == self.CODE_SEARCH_PARAMS_LIMIT_REACHED:
            raise SearchParamsLimitReachedError(msg)
        elif code == self.CODE_UNAUTHORIZED:
            raise UnauthorizedError(msg)
        elif code == self.CODE_FORBIDDEN:
            raise ForbiddenError(msg)
        elif code == self.CODE_INTERNAL_SERVER_ERROR:
            raise InternalServerError(msg)
        elif code == self.CODE_RATE_LIMIT_ERROR:
            raise RateLimitError(msg)
        else:
            raise UnknownError(msg)

    @classmethod
    def from_dict(cls, d: Any = None, error: Optional["Error"] = None) -> "Response":
        if error:
            return cls(raw=None, error=error)

        if isinstance(d, dict) and "error" in d:
            err_data = d["error"]
            field_errors = [
                FieldError(
                    code=e.get("code"),
                    location=e.get("location"),
                    message=e.get("message"),
                )
                for e in err_data.get("errors", [])
                if isinstance(e, dict)
            ] or None

            error_obj = Error(
                status=err_data.get("status"),
                code=err_data.get("code"),
                message=err_data.get("message"),
                errors=field_errors,
            )
            return cls(raw=None, error=error_obj)

        return cls(raw=d)
