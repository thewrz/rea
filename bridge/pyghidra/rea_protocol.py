"""Wire framing and request-field validation shared by every bridge operation."""
import hmac
import json
from dataclasses import dataclass

MAX_SAFE_INTEGER = 9007199254740991
REQUEST_KEYS = frozenset({"id", "token", "method", "params"})
INVALID_REQUEST_ID = 1


class RequestFailure(Exception):
    """A failure reported to the client as {ok: false, error: {code, message}}."""

    def __init__(self, code, message):
        super().__init__(message)
        self.code = code
        self.message = message


@dataclass(frozen=True)
class Request:
    id: int
    token: str
    method: str
    params: dict


def _is_integer(value):
    return type(value) is int


def decode_request(line):
    """Parse one frame; raise ValueError when its structure is invalid."""
    parsed = json.loads(line.decode("utf-8"))
    if not isinstance(parsed, dict) or set(parsed) != REQUEST_KEYS:
        raise ValueError("Bridge request fields are invalid")
    request_id = parsed["id"]
    if not _is_integer(request_id) or request_id <= 0:
        raise ValueError("Bridge request id is invalid")
    if not isinstance(parsed["token"], str) or not isinstance(parsed["method"], str):
        raise ValueError("Bridge request token or method is invalid")
    if not isinstance(parsed["params"], dict):
        raise ValueError("Bridge request parameters are invalid")
    return Request(request_id, parsed["token"], parsed["method"], parsed["params"])


def token_matches(provided, expected):
    return hmac.compare_digest(provided.encode("utf-8"), expected.encode("utf-8"))


def encode_response(request_id, result=None, error=None):
    response = {"id": request_id, "ok": error is None}
    if error is None:
        response["result"] = result
    else:
        response["error"] = error
    # ensure_ascii escapes every non-ASCII unit, so ill-formed UTF-16 text stays lossless.
    return (json.dumps(response, separators=(",", ":")) + "\n").encode("ascii")


def failure_payload(code, message):
    return {"code": code, "message": message}


def require_keys(params, keys):
    if set(params) != set(keys):
        raise RequestFailure("invalid_request", "Bridge request fields are invalid")


def optional_string(params, name):
    value = params.get(name)
    if value is None:
        return None
    if not isinstance(value, str):
        raise RequestFailure("invalid_request", f"{name} must be a string or null")
    if value == "":
        raise RequestFailure("invalid_request", f"{name} cannot be empty")
    return value


def require_string(params, name):
    value = params.get(name)
    if not isinstance(value, str):
        raise RequestFailure("invalid_request", f"{name} must be a string")
    if value == "":
        raise RequestFailure("invalid_request", f"{name} cannot be empty")
    return value


def require_boolean(params, name):
    value = params.get(name)
    if not isinstance(value, bool):
        raise RequestFailure("invalid_request", f"{name} must be a boolean")
    return value


def require_bounded_integer(params, name, minimum, maximum):
    value = params.get(name)
    if not _is_integer(value):
        raise RequestFailure("invalid_request", f"{name} must be an integer")
    if value < minimum or value > maximum:
        raise RequestFailure("invalid_request", f"{name} is outside its supported range")
    return value
