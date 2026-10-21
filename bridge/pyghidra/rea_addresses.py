"""Canonical REA address text for one Ghidra Program.

Default-space addresses are 0x<hex>; others are <percent-encoded-space>:0x<hex>.
"""
from urllib.parse import quote, unquote_to_bytes

from rea_protocol import RequestFailure

UNRESERVED = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789._~-"
_HEX_DIGITS = frozenset("0123456789abcdefABCDEF")
_SPACE_CHARS = frozenset(UNRESERVED)


def unsigned_offset(address):
    return int(address.getOffset()) & 0xFFFFFFFFFFFFFFFF


def is_hexadecimal(value):
    return value != "" and all(char in _HEX_DIGITS for char in value)


def _encode_space(name):
    return quote(name, safe=UNRESERVED)


def _decode_space(value):
    if not _is_encoded_space(value):
        raise RequestFailure("invalid_request", "Address space encoding is invalid")
    return unquote_to_bytes(value).decode("utf-8")


def _is_encoded_space(value):
    index = 0
    while index < len(value):
        char = value[index]
        if char == "%":
            if index + 2 >= len(value) or not is_hexadecimal(value[index + 1:index + 3]):
                return False
            index += 3
        elif char in _SPACE_CHARS:
            index += 1
        else:
            return False
    return True


def is_explicit_address(value):
    """True for 0x<hex> or <encoded-space>:0x<hex>; a bare name or bare hex is not explicit."""
    if value[:2].lower() == "0x" and is_hexadecimal(value[2:]):
        return True
    separator = value.lower().rfind(":0x")
    if separator <= 0 or not is_hexadecimal(value[separator + 3:]):
        return False
    return _is_encoded_space(value[:separator])


class AddressCodec:
    def __init__(self, program):
        self._factory = program.getAddressFactory()
        self.default_space = self._factory.getDefaultAddressSpace()

    def format(self, address):
        return self.format_offset(address.getAddressSpace(), unsigned_offset(address))

    def format_offset(self, space, offset):
        text = f"0x{offset:x}"
        if space.equals(self.default_space):
            return text
        return f"{_encode_space(str(space.getName()))}:{text}"

    def try_parse(self, value):
        """Return the Address, or None when the text does not name one in this Program."""
        spaceless = value
        space_name = None
        separator = value.lower().rfind(":0x")
        if separator >= 0:
            space_name = _decode_space(value[:separator])
            spaceless = value[separator + 3:]
        elif value[:2].lower() == "0x":
            spaceless = value[2:]
        if not is_hexadecimal(spaceless):
            return None
        space = (
            self.default_space
            if space_name is None
            else self._factory.getAddressSpace(space_name)
        )
        if space is None:
            return None
        try:
            address = space.getAddress(spaceless)
        except Exception:
            return None
        if address is None:
            return None
        if int(spaceless, 16) != unsigned_offset(address):
            raise RequestFailure(
                "invalid_request",
                "Ghidra address offset cannot be represented without truncation in space "
                f"{space.getName()}: requested {value}, parsed {self.format(address)}",
            )
        return address

    def parse(self, value):
        address = self.try_parse(value)
        if address is None:
            raise RequestFailure(
                "invalid_request", f"Unknown or invalid Ghidra address: {value}"
            )
        return address
