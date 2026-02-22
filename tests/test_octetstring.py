import pytest
from asn1decoder.asn1parser import parse_encoding
from asn1decoder.asn1values import parse_octetstring, OctetStringParserError


def test_octetstring_primitive_empty():
    """Primitive OCTET STRING with zero length"""
    data = memoryview(
        bytes(
            [
                0b00000100,  # UNIVERSAL 4 primitive
                0b00000000,  # length 0
            ]
        )
    )
    encoding = parse_encoding(data=data, offset=0)
    assert parse_octetstring(encoding) == b""


def test_octetstring_primitive_single_byte():
    """Primitive OCTET STRING with one byte"""
    data = memoryview(
        bytes(
            [
                0b00000100,
                0b00000001,
                0b10101010,
            ]
        )
    )
    encoding = parse_encoding(data=data, offset=0)
    assert parse_octetstring(encoding) == b"\xaa"


def test_octetstring_primitive_multiple_bytes():
    """Primitive OCTET STRING with multiple bytes"""
    data = memoryview(
        bytes(
            [
                0b00000100,
                0b00000100,
                0b11011110,
                0b10101101,
                0b10111110,
                0b11101111,
            ]
        )
    )
    encoding = parse_encoding(data=data, offset=0)
    assert parse_octetstring(encoding) == b"\xde\xad\xbe\xef"


def test_octetstring_constructed_definite():
    """Constructed OCTET STRING definite length"""
    data = memoryview(
        bytes(
            [
                0b00100100,  # Constructed UNIVERSAL 4
                0b00001000,  # length 8
                0b00000100,  # primitive segment
                0b00000010,
                0b11011110,
                0b10101101,
                0b00000100,  # primitive segment
                0b00000010,
                0b10111110,
                0b11101111,
            ]
        )
    )
    encoding = parse_encoding(data=data, offset=0)
    assert parse_octetstring(encoding) == b"\xde\xad\xbe\xef"


def test_octetstring_constructed_indefinite():
    """Constructed OCTET STRING indefinite length"""
    data = memoryview(
        bytes(
            [
                0b00100100,  # Constructed UNIVERSAL 4
                0b10000000,  # indefinite length
                0b00000100,
                0b00000010,
                0b11011110,
                0b10101101,
                0b00000100,
                0b00000010,
                0b10111110,
                0b11101111,
                0b00000000,  # EOC
                0b00000000,
            ]
        )
    )
    encoding = parse_encoding(data=data, offset=0)
    assert parse_octetstring(encoding) == b"\xde\xad\xbe\xef"


def test_octetstring_constructed_with_empty_segment():
    """Constructed OCTET STRING containing empty segment"""
    data = memoryview(
        bytes(
            [
                0b00100100,
                0b00000010,  # length 2
                0b00000100,
                0b00000000,
            ]
        )
    )
    encoding = parse_encoding(data=data, offset=0)
    assert parse_octetstring(encoding) == b""


def test_octetstring_nested_constructed():
    """Constructed OCTET STRING containing constructed segment"""
    data = memoryview(
        bytes(
            [
                0b00100100,  # outer constructed
                0b00001010,  # length 10
                0b00100100,  # inner constructed
                0b00001000,  # length 8
                0b00000100,
                0b00000010,
                0b00000001,
                0b00000010,
                0b00000100,
                0b00000010,
                0b00000011,
                0b00000100,
            ]
        )
    )
    encoding = parse_encoding(data=data, offset=0)
    assert parse_octetstring(encoding) == b"\x01\x02\x03\x04"


def test_octetstring_wrong_tag():
    """Wrong tag should raise"""
    data = memoryview(
        bytes(
            [
                0b00000010,  # INTEGER
                0b00000001,
                0b00000001,
            ]
        )
    )
    encoding = parse_encoding(data=data, offset=0)
    with pytest.raises(OctetStringParserError):
        parse_octetstring(encoding)


def test_octetstring_primitive_raw_tlv_like_content():
    """Primitive OCTET STRING must treat content as raw bytes"""
    data = memoryview(
        bytes(
            [
                0b00000100,
                0b00000100,
                0b00000100,
                0b00000001,
                0b00000001,
                0b00000000,
            ]
        )
    )
    encoding = parse_encoding(data=data, offset=0)

    assert parse_octetstring(encoding) == b"\x04\x01\x01\x00"
