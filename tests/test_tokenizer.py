import pytest
from dataclasses import fields
from asn1decoder.asn1types import (
    IdentifierComponent,
    EncodingType,
    LengthForm,
    TagClass,
)
from asn1decoder.tokenizer import (
    parse_identifier_component,
    parse_length_component,
    TokenizerError,
)


# ############################################################################
# 8.1.2 Identifier Octets
# ############################################################################


def test_8_1_2_1():
    """8.1.2.1 The identifier octets shall encode the ASN.1 tag
    (class and number) of the type of the data value."""

    attributes = (field.name for field in fields(IdentifierComponent))
    assert "tag_class" in attributes
    assert "tag_number" in attributes


def test_8_1_2_2():
    """8.1.2.2 For tags with a number ranging from zero to 30 (inclusive), the identifier octets shall comprise a single octet encoded
    as follows:
    a)bits 8 and 7 shall be encoded to represent the class of the tag as specified in Table 1;

    b)bit 6 shall be a zero or a one according to the rules of 8.1.2.5;

    c)bits 5 to 1 shall encode the number of the tag as a binary integer with bit 5 as the most significant bit."""

    data: memoryview = memoryview(bytes([0b00_0_11110]))
    identifier_component = parse_identifier_component(data=data, offset=0)
    assert identifier_component.header.length == 1
    assert identifier_component.tag_class == TagClass.UNIVERSAL
    assert identifier_component.encoding_type == EncodingType.PRIMITIVE
    assert identifier_component.tag_number == 30

    data: memoryview = memoryview(bytes([0b01_1_11110]))
    identifier_component = parse_identifier_component(data=data, offset=0)
    assert identifier_component.header.length == 1
    assert identifier_component.tag_class == TagClass.APPLICATION
    assert identifier_component.encoding_type == EncodingType.CONSTRUCTED
    assert identifier_component.tag_number == 30

    data: memoryview = memoryview(bytes([0b10_1_11110]))
    identifier_component = parse_identifier_component(data=data, offset=0)
    assert identifier_component.header.length == 1
    assert identifier_component.tag_class == TagClass.CONTEXT_SPECIFIC
    assert identifier_component.encoding_type == EncodingType.CONSTRUCTED
    assert identifier_component.tag_number == 30

    data: memoryview = memoryview(bytes([0b11_1_11110]))
    identifier_component = parse_identifier_component(data=data, offset=0)
    assert identifier_component.header.length == 1
    assert identifier_component.tag_class == TagClass.PRIVATE
    assert identifier_component.encoding_type == EncodingType.CONSTRUCTED
    assert identifier_component.tag_number == 30


def test_8_1_2_4_2():
    """8.1.2.4.2 The subsequent octets shall encode the number of the tag as follows:
    a)bit 8 of each octet shall be set to one unless it is the last octet of the identifier octets;

    b)bits 7 to 1 of the first subsequent octet, followed by bits 7 to 1 of the second subsequent octet, followed in turn
    by bits 7 to 1 of each further octet, up to and including the last subsequent octet in the identifier octets shall be
    the encoding of an unsigned binary integer equal to the tag number, with bit 7 of the first subsequent octet as
    the most significant bit;

    c)bits 7 to 1 of the first subsequent octet shall not all be zero.
    """
    # 4321 = 0b0001_0000_1110_0001

    data: memoryview = memoryview(bytes([0b11_1_11111, 0b1_0100001, 0b0_1100001]))
    identifier_component = parse_identifier_component(data=data, offset=0)
    assert identifier_component.header.length == 3
    assert identifier_component.tag_class == TagClass.PRIVATE
    assert identifier_component.encoding_type == EncodingType.CONSTRUCTED
    assert identifier_component.tag_number == 4321

    with pytest.raises(TokenizerError):
        data: memoryview = memoryview(bytes([0b11_1_11111, 0b1_0000000]))
        parse_identifier_component(data=data, offset=0)


# ############################################################################
# 8.1.3 Length Octets
# ############################################################################


def test_8_1_3_1():
    """8.1.3.1 Two forms of length octets are specified. These are:
    a)the definite form (see 8.1.3.3); and
    b)the indefinite form (see 8.1.3.6)."""

    assert LengthForm.DEFINITE.name == "DEFINITE"
    assert LengthForm.INDEFINITE.name == "INDEFINITE"


# def test_8_1_3_2():
#     """8.1.3.2 A sender shall:
#     a)use the definite form (see 8.1.3.3) if the encoding is primitive;
#
#     b)use either the definite form (see 8.1.3.3) or the indefinite form (see 8.1.3.6), a sender's option, if the encoding
#     is constructed and all immediately available;
#
#     c)use the indefinite form (see 8.1.3.6) if the encoding is constructed and is not all immediately available.
#     """
#
#     parse_length_octet()
