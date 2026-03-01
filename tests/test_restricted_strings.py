import pytest
from asn1decoder.asn1parser import parse_encoding
from asn1decoder.asn1values.octet_string import OctetStringParserError
from asn1decoder.asn1values import parse_numericstring, NumericStringParserError
from asn1decoder.asn1values import parse_printablestring, PrintableStringParserError
from asn1decoder.asn1values import parse_ia5string, IA5StringParserError
from asn1decoder.asn1values import parse_visiblestring, VisibleStringParserError
from asn1decoder.asn1values import parse_generalstring, GeneralStringParserError


# -------------------------
# NumericString (UNIVERSAL 18)
# -------------------------


def test_numericstring_primitive():
    """NumericString primitive with digits and spaces"""

    data = memoryview(
        bytes(
            [
                0b00010010,  # UNIVERSAL 18 NumericString
                0b00000101,  # length 5
                0b00110001,  # 1
                0b00110010,  # 2
                0b00110011,  # 3
                0b00100000,  # ' '
                0b00110100,  # 4
            ]
        )
    )
    encoding = parse_encoding(data=data, offset=0)
    value = parse_numericstring(encoding)
    assert value == "123 4"


def test_numericstring_constructed_definite():
    """NumericString constructed definite length"""
    data = memoryview(
        bytes(
            [
                0b00110010,  # Constructed, UNIVERSAL 18 NumericString
                0b00001000,  # total length 8 bytes
                # first segment OCTET STRING TLV
                0b00000100,  # tag OCTET STRING
                0b00000011,  # length 3
                0b00110001,  # '1'
                0b00110010,  # '2'
                0b00110011,  # '3'
                # second segment OCTET STRING TLV
                0b00000100,  # tag OCTET STRING
                0b00000001,  # length 1
                0b00110100,  # '4'
            ]
        )
    )
    encoding = parse_encoding(data=data, offset=0)
    value = parse_numericstring(encoding)
    assert value == "1234"


def test_numericstring_constructed_indefinite():
    """NumericString constructed indefinite length"""
    data = memoryview(
        bytes(
            [
                0b00110010,  # Constructed, UNIVERSAL 18 NumericString
                0b10000000,  # indefinite length
                0b00000100,  # OCTET STRING (UNIVERSAL 4)
                0b00000011,  # length 3
                0b00110001,  # '1'
                0b00110010,  # '2'
                0b00110011,  # '3'
                0b00000100,  # OCTET STRING (UNIVERSAL 4)
                0b00000001,  # length 1
                0b00110100,  # '4'
                0b00000000,  # EOC
                0b00000000,  # EOC
            ]
        )
    )
    encoding = parse_encoding(data=data, offset=0)
    value = parse_numericstring(encoding)
    assert value == "1234"


def test_numericstring_invalid_char():
    """NumericString with invalid character"""
    data = memoryview(
        bytes(
            [
                0b00010010,  # UNIVERSAL 18 NumericString (primitive)
                0b00000011,  # length 3
                0b00110001,  # '1'
                0b01000001,  # 'A' (invalid for NumericString)
                0b00110010,  # '2'
            ]
        )
    )
    encoding = parse_encoding(data=data, offset=0)
    with pytest.raises(NumericStringParserError):
        parse_numericstring(encoding)


def test_numericstring_empty():
    """NumericString empty"""
    data = memoryview(
        bytes(
            [
                0b00010010,  # UNIVERSAL 18 NumericString
                0b00000000,  # length 0
            ]
        )
    )
    encoding = parse_encoding(data=data, offset=0)
    value = parse_numericstring(encoding)
    assert value == ""


# -------------------------
# PrintableString (UNIVERSAL 19)
# -------------------------
def test_printablestring_primitive():
    """PrintableString primitive"""
    data = memoryview(
        bytes(
            [
                0b00010011,  # UNIVERSAL 19 PrintableString (primitive)
                0b00000101,  # length 5
                0b01001010,  # 'J'
                0b01101111,  # 'o'
                0b01101110,  # 'n'
                0b01100101,  # 'e'
                0b01110011,  # 's'
            ]
        )
    )
    encoding = parse_encoding(data=data, offset=0)
    value = parse_printablestring(encoding)
    assert value == "Jones"


def test_printablestring_constructed_definite():
    """PrintableString constructed definite length"""
    data = memoryview(
        bytes(
            [
                0b00110011,  # Constructed, UNIVERSAL 19 PrintableString
                0b00001000,  # total length 8 (4 bytes + 4 bytes)
                0b00000100,  # OCTET STRING (primitive, UNIVERSAL 4)
                0b00000010,  # length 2
                0b01001010,  # 'J'
                0b01101111,  # 'o'
                0b00000100,  # OCTET STRING
                0b00000010,  # length 2
                0b01101110,  # 'n'
                0b01100101,  # 'e'
            ]
        )
    )
    encoding = parse_encoding(data=data, offset=0)
    value = parse_printablestring(encoding)
    assert value == "Jone"


def test_printablestring_constructed_indefinite():
    """PrintableString constructed indefinite length"""
    data = memoryview(
        bytes(
            [
                0b00110011,  # Constructed PrintableString
                0b10000000,  # indefinite length
                0b00000100,  # OCTET STRING
                0b00000011,  # length 3
                0b01001010,  # 'J'
                0b01101111,  # 'o'
                0b01101110,  # 'n'
                0b00000100,  # OCTET STRING
                0b00000010,  # length 2
                0b01100101,  # 'e'
                0b01110011,  # 's'
                0b00000000,  # EOC
                0b00000000,  # EOC
            ]
        )
    )
    encoding = parse_encoding(data=data, offset=0)
    value = parse_printablestring(encoding)
    assert value == "Jones"


def test_printablestring_invalid_char():
    """PrintableString invalid character"""
    data = memoryview(
        bytes(
            [
                0b00010011,  # PrintableString primitive
                0b00000011,  # length 3
                0b01001010,  # 'J'
                0b01100001,  # 'a'
                0b10000000,  # invalid ASCII / not allowed in PrintableString
            ]
        )
    )
    encoding = parse_encoding(data=data, offset=0)
    with pytest.raises(PrintableStringParserError):
        parse_printablestring(encoding)


def test_printablestring_empty():
    """PrintableString empty"""
    data = memoryview(
        bytes(
            [
                0b00010011,  # PrintableString primitive
                0b00000000,  # length 0
            ]
        )
    )
    encoding = parse_encoding(data=data, offset=0)
    value = parse_printablestring(encoding)
    assert value == ""


# -------------------------
# IA5String (UNIVERSAL 22)
# -------------------------
def test_ia5string_primitive():
    """IA5String primitive"""
    data = memoryview(
        bytes(
            [
                0b00010110,  # UNIVERSAL PRIMITIVE 22 (IA5String)
                0b00000100,  # length = 4
                0b01001000,  # 'H'
                0b01100101,  # 'e'
                0b01101100,  # 'l'
                0b01101100,  # 'l'
            ]
        )
    )
    encoding = parse_encoding(data=data, offset=0)
    value = parse_ia5string(encoding)
    assert value == "Hell"


def test_ia5string_constructed_indefinite():
    """IA5String constructed indefinite length"""
    data = memoryview(
        bytes(
            [
                0b00110110,  # UNIVERSAL CONSTRUCTED 22 (IA5String)
                0b10000000,  # indefinite length
                0b00000100,  # UNIVERSAL PRIMITIVE 4 (OCTET STRING)
                0b00000010,  # length = 2
                0b01001000,  # 'H'
                0b01100101,  # 'e'
                0b00000100,  # UNIVERSAL PRIMITIVE 4 (OCTET STRING)
                0b00000010,  # length = 2
                0b01101100,  # 'l'
                0b01101100,  # 'l'
                0b00000000,  # EOC
                0b00000000,
            ]
        )
    )
    encoding = parse_encoding(data=data, offset=0)
    value = parse_ia5string(encoding)
    assert value == "Hell"


def test_ia5string_invalid_char():
    """IA5String invalid character (>0x7F)"""
    data = memoryview(
        bytes(
            [
                0b00010110,  # UNIVERSAL PRIMITIVE 22 (IA5String)
                0b00000010,  # length = 2
                0b01001000,  # 'H'
                0b10000001,  # invalid IA5 (> 0x7F)
            ]
        )
    )
    encoding = parse_encoding(data=data, offset=0)
    with pytest.raises(IA5StringParserError):
        parse_ia5string(encoding)


# -------------------------
# VisibleString (UNIVERSAL 26)
# -------------------------


def test_visiblestring_primitive():
    """VisibleString primitive"""
    data = memoryview(
        bytes(
            [
                0b00011010,  # UNIVERSAL PRIMITIVE 26 (VisibleString)
                0b00000100,  # length = 4
                0b01001000,  # 'H'
                0b01100101,  # 'e'
                0b01101100,  # 'l'
                0b01101100,  # 'l'
            ]
        )
    )
    encoding = parse_encoding(data=data, offset=0)
    value = parse_visiblestring(encoding)
    assert value == "Hell"


def test_visiblestring_constructed_indefinite():
    """VisibleString constructed indefinite length"""
    data = memoryview(
        bytes(
            [
                0b00111010,  # UNIVERSAL CONSTRUCTED 26
                0b10000000,  # indefinite length
                0b00000100,  # UNIVERSAL PRIMITIVE 4 (OCTET STRING)
                0b00000010,  # length = 2
                0b01001000,  # 'H'
                0b01100101,  # 'e'
                0b00000100,  # UNIVERSAL PRIMITIVE 4 (OCTET STRING)
                0b00000010,  # length = 2
                0b01101100,  # 'l'
                0b01101100,  # 'l'
                0b00000000,  # EOC
                0b00000000,
            ]
        )
    )
    encoding = parse_encoding(data=data, offset=0)
    value = parse_visiblestring(encoding)
    assert value == "Hell"


def test_visiblestring_constructed_definite():
    """VisibleString constructed definite length"""
    data = memoryview(
        bytes(
            [
                0b00111010,  # UNIVERSAL CONSTRUCTED 26
                0b00001100,  # length = 12 bytes (4 * 3)
                0b00000100,  # OCTET STRING
                0b00000001,  # length = 1
                0b01001010,  # 'J'
                0b00000100,  # OCTET STRING
                0b00000001,  # length = 1
                0b01101111,  # 'o'
                0b00000100,  # OCTET STRING
                0b00000001,  # length = 1
                0b01101110,  # 'n'
                0b00000100,  # OCTET STRING
                0b00000001,  # length = 1
                0b01100101,  # 'e'
            ]
        )
    )
    encoding = parse_encoding(data=data, offset=0)
    value = parse_visiblestring(encoding)
    assert value == "Jone"


def test_visiblestring_invalid_control_char():
    """VisibleString invalid char < 0x20"""
    data = memoryview(
        bytes(
            [
                0b00011010,
                0b00000010,
                0b01001000,  # 'H'
                0b00011111,  # 0x1F
            ]
        )
    )
    encoding = parse_encoding(data=data, offset=0)
    with pytest.raises(VisibleStringParserError):
        parse_visiblestring(encoding)


def test_visiblestring_invalid_0x7f():
    """VisibleString invalid char = 0x7F"""
    data = memoryview(
        bytes(
            [
                0b00011010,
                0b00000010,
                0b01001000,
                0b01111111,  # 0x7F
            ]
        )
    )
    encoding = parse_encoding(data=data, offset=0)
    with pytest.raises(VisibleStringParserError):
        parse_visiblestring(encoding)


def test_visiblestring_invalid_above_7f():
    """VisibleString invalid char > 0x7F"""
    data = memoryview(
        bytes(
            [
                0b00011010,
                0b00000010,
                0b01001000,
                0b10000001,
            ]
        )
    )
    encoding = parse_encoding(data=data, offset=0)
    with pytest.raises(VisibleStringParserError):
        parse_visiblestring(encoding)


def test_visiblestring_constructed_invalid_subtag():
    """VisibleString constructed with invalid sub-tag (not OCTET STRING)"""
    data = memoryview(
        bytes(
            [
                0b00111010,
                0b10000000,
                0b00011010,  # wrong tag (VisibleString instead of OCTET STRING)
                0b00000001,
                0b01000001,  # 'A'
                0b00000000,
                0b00000000,
            ]
        )
    )
    encoding = parse_encoding(data=data, offset=0)
    with pytest.raises(OctetStringParserError):
        parse_visiblestring(encoding)


# # -------------------------
# # GraphicString (UNIVERSAL 25)
# # -------------------------
# def test_graphicstring_primitive():
#     """GraphicString primitive"""
#
#
# def test_graphicstring_constructed_indefinite():
#     """GraphicString constructed indefinite"""

# -------------------------
# GeneralString (UNIVERSAL 27)
# -------------------------


def test_generalstring_primitive():
    """GeneralString primitive"""
    data = memoryview(
        bytes(
            [
                0b00011011,  # UNIVERSAL PRIMITIVE 27 (GeneralString)
                0b00000100,  # length = 4
                0b01000001,  # 'A'
                0b01000010,  # 'B'
                0b11000011,  # 0xC3
                0b01000100,  # 'D'
            ]
        )
    )
    encoding = parse_encoding(data=data, offset=0)
    value = parse_generalstring(encoding)
    assert value == bytes([0x41, 0x42, 0xC3, 0x44])


def test_generalstring_constructed_indefinite():
    """GeneralString constructed indefinite length"""
    data = memoryview(
        bytes(
            [
                0b00111011,  # UNIVERSAL CONSTRUCTED 27
                0b10000000,  # indefinite length
                0b00000100,  # OCTET STRING
                0b00000010,  # length = 2
                0b01000001,  # 'A'
                0b01000010,  # 'B'
                0b00000100,  # OCTET STRING
                0b00000010,  # length = 2
                0b11000011,  # 0xC3
                0b01000100,  # 'D'
                0b00000000,  # EOC
                0b00000000,
            ]
        )
    )
    encoding = parse_encoding(data=data, offset=0)
    value = parse_generalstring(encoding)
    assert value == bytes([0x41, 0x42, 0xC3, 0x44])


def test_generalstring_constructed_definite():
    """GeneralString constructed definite length"""
    data = memoryview(
        bytes(
            [
                0b00111011,  # UNIVERSAL CONSTRUCTED 27
                0b00001100,  # length = 12 (4 OCTET STRING × 3 byte ciascuno)
                0b00000100,  # OCTET STRING
                0b00000001,
                0b01000001,  # 'A'
                0b00000100,
                0b00000001,
                0b01000010,  # 'B'
                0b00000100,
                0b00000001,
                0b01000011,  # 'C'
                0b00000100,
                0b00000001,
                0b01000100,  # 'D'
            ]
        )
    )
    encoding = parse_encoding(data=data, offset=0)
    value = parse_generalstring(encoding)
    assert value == bytes([0x41, 0x42, 0x43, 0x44])


def test_generalstring_empty_primitive():
    """GeneralString primitive with zero length"""
    data = memoryview(
        bytes(
            [
                0b00011011,  # Primitive
                0b00000000,  # length = 0
            ]
        )
    )
    encoding = parse_encoding(data=data, offset=0)
    value = parse_generalstring(encoding)
    assert value == b""


def test_generalstring_constructed_empty():
    """GeneralString constructed indefinite with zero-length OCTET STRING"""
    data = memoryview(
        bytes(
            [
                0b00111011,  # Constructed
                0b10000000,  # indefinite
                0b00000100,  # OCTET STRING
                0b00000000,  # length 0
                0b00000000,  # EOC
                0b00000000,
            ]
        )
    )
    encoding = parse_encoding(data=data, offset=0)
    value = parse_generalstring(encoding)
    assert value == b""


def test_generalstring_constructed_invalid_subtag():
    """GeneralString constructed with invalid subtag (not OCTET STRING)"""
    data = memoryview(
        bytes(
            [
                0b00111011,  # Constructed 27
                0b10000000,  # indefinite
                0b00011011,  # wrong tag (GeneralString primitive instead of OCTET STRING)
                0b00000001,
                0b01000001,  # 'A'
                0b00000000,
                0b00000000,  # EOC
            ]
        )
    )
    encoding = parse_encoding(data=data, offset=0)
    with pytest.raises(OctetStringParserError):
        parse_generalstring(encoding)
