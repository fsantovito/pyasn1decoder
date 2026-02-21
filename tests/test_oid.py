import pytest
from asn1decoder.asn1parser import parse_encoding
from asn1decoder.asn1values import parse_oid, OIDParserError


# ############################################################################
# 8.19 Encoding of an object identifier value
# ############################################################################
def test_8_19_5():
    """The numerical value of the ith subidentifier, (2 <= i <= N) is that of the (i + 1)th object identifier component."""

    data: memoryview = memoryview(
        bytes(
            [
                0b00000110,  # UNIVERSAL PRIMITIVE 6 (OID)
                0b00000011,  # DEFINITE 3
                0b10001000,  # VALUE 0x88
                0b00110111,  # VALUE 0x37
                0b00000011,  # VALUE 0x03
            ]
        )
    )

    encoding = parse_encoding(data=data, offset=0)
    oid = parse_oid(encoding=encoding)
    assert oid == "2.999.3"


# ############################################################################
# extra
# ############################################################################


def test_oid_small_values():
    """OID with small subidentifier values (<128), all single-byte"""
    data = memoryview(
        bytes(
            [
                0b00000110,  # UNIVERSAL PRIMITIVE 6
                0b00000010,  # length 2
                0b00101010,  # 1*40 + 2 = 42 → 1.2
                0b00000011,  # subidentifier 3
            ]
        )
    )
    encoding = parse_encoding(data=data, offset=0)
    oid = parse_oid(encoding)
    assert oid == "1.2.3"


def test_oid_non_minimal_encoding():
    """Non-minimal subidentifier encoding should raise ParserError"""
    data = memoryview(
        bytes(
            [
                0b00000110,  # UNIVERSAL PRIMITIVE 6
                0b00000010,  # length 2
                0b10000000,  # non-minimal first byte
                0b00000001,  # second byte
            ]
        )
    )
    encoding = parse_encoding(data=data, offset=0)
    with pytest.raises(OIDParserError, match="not minimally encoded"):
        parse_oid(encoding)


def test_oid_last_byte_continuation_bit():
    """Last byte with MSB=1 should raise ParserError"""
    data = memoryview(
        bytes(
            [
                0b00000110,  # UNIVERSAL PRIMITIVE 6
                0b00000001,  # length 1
                0b10000001,  # MSB=1 invalid as last byte
            ]
        )
    )
    encoding = parse_encoding(data=data, offset=0)
    with pytest.raises(OIDParserError, match="continuation bit set on last byte"):
        parse_oid(encoding)
