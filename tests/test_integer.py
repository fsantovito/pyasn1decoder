import pytest
from asn1decoder.asn1parser import parse_encoding
from asn1decoder.asn1values import parse_integer, IntegerParserError


def test_integer_zero():
    """INTEGER value 0"""
    data = memoryview(
        bytes(
            [
                0b00000010,  # UNIVERSAL PRIMITIVE 2 (INTEGER)
                0b00000001,  # length 1
                0b00000000,  # value 0
            ]
        )
    )

    encoding = parse_encoding(data=data, offset=0)
    value = parse_integer(encoding=encoding)
    assert value == 0


def test_integer_positive_small():
    """INTEGER small positive value (<128)"""
    data = memoryview(
        bytes(
            [
                0b00000010,  # UNIVERSAL PRIMITIVE 2
                0b00000001,  # length 1
                0b00000101,  # value 5
            ]
        )
    )

    encoding = parse_encoding(data=data, offset=0)
    value = parse_integer(encoding=encoding)
    assert value == 5


def test_integer_negative_small():
    """INTEGER small negative value (-1)"""
    data = memoryview(
        bytes(
            [
                0b00000010,  # UNIVERSAL PRIMITIVE 2
                0b00000001,  # length 1
                0b11111111,  # value -1 (two's complement)
            ]
        )
    )

    encoding = parse_encoding(data=data, offset=0)
    value = parse_integer(encoding=encoding)
    assert value == -1


def test_integer_positive_multibyte():
    """INTEGER positive value requiring multiple bytes (128)"""
    # 128 = 0x0080 (leading 0x00 required to keep value positive)
    data = memoryview(
        bytes(
            [
                0b00000010,  # UNIVERSAL PRIMITIVE 2
                0b00000010,  # length 2
                0b00000000,  # leading zero to avoid negative interpretation
                0b10000000,  # 128
            ]
        )
    )

    encoding = parse_encoding(data=data, offset=0)
    value = parse_integer(encoding=encoding)
    assert value == 128


def test_integer_negative_multibyte():
    """INTEGER negative value requiring multiple bytes (-129)"""
    # -129 = 0xFF7F in two's complement
    data = memoryview(
        bytes(
            [
                0b00000010,  # UNIVERSAL PRIMITIVE 2
                0b00000010,  # length 2
                0b11111111,
                0b01111111,
            ]
        )
    )

    encoding = parse_encoding(data=data, offset=0)
    value = parse_integer(encoding=encoding)
    assert value == -129


def test_integer_non_minimal_positive():
    """INTEGER positive value not minimally encoded (leading 0x00 not required)"""
    # 5 encoded as 0x00 0x05 → invalid (non-minimal)
    data = memoryview(
        bytes(
            [
                0b00000010,  # UNIVERSAL PRIMITIVE 2
                0b00000010,  # length 2
                0b00000000,
                0b00000101,
            ]
        )
    )

    encoding = parse_encoding(data=data, offset=0)
    with pytest.raises(IntegerParserError, match="not minimally encoded"):
        parse_integer(encoding=encoding)


def test_integer_non_minimal_negative():
    """INTEGER negative value not minimally encoded (leading 0xFF not required)"""
    # -1 encoded as 0xFF 0xFF → invalid (non-minimal)
    data = memoryview(
        bytes(
            [
                0b00000010,  # UNIVERSAL PRIMITIVE 2
                0b00000010,  # length 2
                0b11111111,
                0b11111111,
            ]
        )
    )

    encoding = parse_encoding(data=data, offset=0)
    with pytest.raises(IntegerParserError, match="not minimally encoded"):
        parse_integer(encoding=encoding)
