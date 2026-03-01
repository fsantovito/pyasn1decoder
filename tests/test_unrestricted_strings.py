import pytest
from asn1decoder.asn1parser import parse_encoding
from asn1decoder.asn1values.octet_string import OctetStringParserError
from asn1decoder.asn1values import parse_utf8string, UTF8StringParserError

# -------------------------
# UTF8String (UNIVERSAL 12)
# -------------------------


def test_utf8string_primitive_ascii():
    """UTF8String primitive ASCII"""
    data = memoryview(
        bytes(
            [
                0b00001100,  # UNIVERSAL PRIMITIVE 12
                0b00000100,  # length = 4
                0b01000001,  # 'A' = 0x41
                0b01000010,  # 'B' = 0x42
                0b01000011,  # 'C' = 0x43
                0b01000100,  # 'D' = 0x44
            ]
        )
    )
    encoding = parse_encoding(data=data, offset=0)
    value = parse_utf8string(encoding)
    assert value == "ABCD"


def test_utf8string_primitive_multibyte():
    """UTF8String primitive multibyte (é = C3 A9, € = E2 82 AC)"""
    data = memoryview(
        bytes(
            [
                0b00001100,  # UNIVERSAL PRIMITIVE 12
                0b00001000,  # length = 8 bytes
                0b01000011,  # 'C'
                0b01000001,  # 'A'
                0b01100110,  # 'f'
                0b11000011,  # 0xC3
                0b10101001,  # 0xA9 -> 'é'
                0b11100010,  # 0xE2
                0b10000010,  # 0x82
                0b10101100,  # 0xAC -> '€'
            ]
        )
    )
    encoding = parse_encoding(data=data, offset=0)
    value = parse_utf8string(encoding)
    assert value == "CAfé€"


def test_utf8string_constructed_indefinite():
    """UTF8String constructed indefinite length (BER)"""
    data = memoryview(
        bytes(
            [
                0b00101100,  # UNIVERSAL CONSTRUCTED 12
                0b10000000,  # indefinite length
                0b00000100,  # OCTET STRING
                0b00000010,  # length = 2
                0b01000001,  # 'A'
                0b01000010,  # 'B'
                0b00000100,  # OCTET STRING
                0b00000010,  # length = 2
                0b01000011,  # 'C'
                0b01000100,  # 'D'
                0b00000000,  # EOC
                0b00000000,
            ]
        )
    )
    encoding = parse_encoding(data=data, offset=0)
    value = parse_utf8string(encoding)
    assert value == "ABCD"


def test_utf8string_constructed_definite():
    """UTF8String constructed definite length (BER)"""
    data = memoryview(
        bytes(
            [
                0b00101100,  # UNIVERSAL CONSTRUCTED 12
                0b00001000,  # length = 8 (4 OCTET STRING × 2 byte ciascuno)
                0b00000100,  # OCTET STRING
                0b00000010,
                0b01000001,  # 'A'
                0b01000010,  # 'B'
                0b00000100,
                0b00000010,
                0b01000011,  # 'C'
                0b01000100,  # 'D'
            ]
        )
    )
    encoding = parse_encoding(data=data, offset=0)
    value = parse_utf8string(encoding)
    assert value == "ABCD"


def test_utf8string_empty_primitive():
    """UTF8String primitive zero length"""
    data = memoryview(
        bytes(
            [
                0b00001100,  # UNIVERSAL PRIMITIVE 12
                0b00000000,  # length = 0
            ]
        )
    )
    encoding = parse_encoding(data=data, offset=0)
    value = parse_utf8string(encoding)
    assert value == ""


def test_utf8string_constructed_empty():
    """UTF8String constructed indefinite with zero-length OCTET STRING"""
    data = memoryview(
        bytes(
            [
                0b00101100,  # UNIVERSAL CONSTRUCTED 12
                0b10000000,  # indefinite length
                0b00000100,  # OCTET STRING
                0b00000000,  # length 0
                0b00000000,  # EOC
                0b00000000,
            ]
        )
    )
    encoding = parse_encoding(data=data, offset=0)
    value = parse_utf8string(encoding)
    assert value == ""


def test_utf8string_invalid_utf8():
    """UTF8String with invalid UTF-8 sequence"""
    data = memoryview(
        bytes(
            [
                0b00001100,  # UNIVERSAL PRIMITIVE 12
                0b00000010,  # length = 2
                0b11000011,  # start of multibyte
                0b00000000,  # invalid continuation byte
            ]
        )
    )
    encoding = parse_encoding(data=data, offset=0)
    with pytest.raises(UTF8StringParserError):
        parse_utf8string(encoding)
