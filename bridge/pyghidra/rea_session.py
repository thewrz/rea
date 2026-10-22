"""State shared by every operation of one bridge session."""
import functools
from dataclasses import dataclass, field
from typing import Any

from rea_addresses import AddressCodec


def iterate(java_iterator):
    while java_iterator.hasNext():
        yield java_iterator.next()


def compare_addresses(left, right):
    return left.compareTo(right)


address_order = functools.cmp_to_key(compare_addresses)


def utf16_order(text):
    """Order strings by UTF-16 code unit, as Java's String.compareTo does."""
    return text.encode("utf-16-be", "surrogatepass")


def exception_label(exception):
    getter = getattr(exception, "getClass", None)
    kind = str(getter().getSimpleName()) if getter else type(exception).__name__
    message = str(exception)
    return f"{kind}: {message if message.strip() else 'operation failed'}"


@dataclass
class Session:
    program: Any
    monitor: Any
    target_sha256: str
    profile_digest: str
    addresses: AddressCodec
    extensions: Any
    decompiler: Any = None
    target_sources: list = field(default_factory=list)
    _inventories: dict = field(default_factory=dict)

    def cached(self, key, build):
        if key not in self._inventories:
            self._inventories[key] = build()
        return self._inventories[key]

    def invalidate_caches(self):
        self._inventories.clear()
        if self.decompiler is not None:
            self.decompiler.flushCache()
