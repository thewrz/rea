"""Session descriptor: the launcher's only channel into the bridge."""
import os
import re
from dataclasses import dataclass
from typing import Optional

REQUIRED_KEYS = frozenset(
    {
        "transport",
        "endpoint_path",
        "token",
        "run_id",
        "target_sha256",
        "provider_version",
        "profile_digest",
    }
)
OPTIONAL_KEYS = frozenset(
    {
        "language_id",
        "compiler_spec_id",
        "disabled_analyzers",
        "seed_paths",
        "analysis_extensions",
        "mips_soft_float",
    }
)
EXTENSION_KEYS = frozenset({"id", "entry_class", "sha256", "integration_api", "path"})
_SHA256 = re.compile(r"[a-f0-9]{64}")


@dataclass(frozen=True)
class Descriptor:
    endpoint_path: str
    token: str
    run_id: str
    target_sha256: str
    provider_version: str
    profile_digest: str
    language_id: Optional[str]
    compiler_spec_id: Optional[str]
    disabled_analyzers: tuple
    seed_paths: tuple
    analysis_extensions: tuple
    mips_soft_float: bool


def _string(raw, name):
    value = raw[name]
    if not isinstance(value, str) or value == "":
        raise ValueError(f"REA session descriptor field {name} must be a non-empty string")
    return value


def _optional_string(raw, name):
    return _string(raw, name) if name in raw else None


def _string_list(raw, name):
    values = raw.get(name, [])
    if not isinstance(values, list) or not all(
        isinstance(item, str) and item != "" for item in values
    ):
        raise ValueError(f"REA session descriptor field {name} must be a list of non-empty strings")
    return tuple(values)


def _extensions(raw):
    values = raw.get("analysis_extensions", [])
    if not isinstance(values, list) or not all(
        isinstance(item, dict) and set(item) == EXTENSION_KEYS for item in values
    ):
        raise ValueError("REA session descriptor field analysis_extensions is invalid")
    return tuple(values)


def parse_descriptor(raw):
    if not isinstance(raw, dict):
        raise ValueError("REA session descriptor is invalid")
    keys = set(raw)
    if not REQUIRED_KEYS <= keys or not keys <= REQUIRED_KEYS | OPTIONAL_KEYS:
        raise ValueError("REA session descriptor fields are invalid")
    # The Windows authenticated-loopback transport is outside the pyGhidra bridge's Phase 1 scope.
    if _string(raw, "transport") != "unix-socket":
        raise ValueError("REA pyGhidra bridge supports only the unix-socket transport")
    target_sha256 = _string(raw, "target_sha256")
    if not _SHA256.fullmatch(target_sha256):
        raise ValueError("target_sha256 must be lowercase SHA-256")
    endpoint_path = _string(raw, "endpoint_path")
    if not os.path.isabs(endpoint_path):
        raise ValueError("endpoint_path must be absolute")
    language_id = _optional_string(raw, "language_id")
    compiler_spec_id = _optional_string(raw, "compiler_spec_id")
    if compiler_spec_id is not None and language_id is None:
        raise ValueError("compiler_spec_id requires language_id")
    seed_paths = _string_list(raw, "seed_paths")
    if len(seed_paths) > 1 or not all(os.path.isabs(path) for path in seed_paths):
        raise ValueError("seed_paths admits at most one absolute seed snapshot")
    mips_soft_float = raw.get("mips_soft_float", False)
    if not isinstance(mips_soft_float, bool):
        raise ValueError("mips_soft_float must be a boolean")
    return Descriptor(
        endpoint_path=endpoint_path,
        token=_string(raw, "token"),
        run_id=_string(raw, "run_id"),
        target_sha256=target_sha256,
        provider_version=_string(raw, "provider_version"),
        profile_digest=_string(raw, "profile_digest"),
        language_id=language_id,
        compiler_spec_id=compiler_spec_id,
        disabled_analyzers=_string_list(raw, "disabled_analyzers"),
        seed_paths=seed_paths,
        analysis_extensions=_extensions(raw),
        mips_soft_float=mips_soft_float,
    )
