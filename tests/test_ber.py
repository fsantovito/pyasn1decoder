import pytest
from dataclasses import fields
from asn1decoder.asn1types import (
    IdentifierComponent,
    EncodingType,
    LengthForm,
    TagClass,
)
from asn1decoder.asn1parser import (
    EOCError,
    LengthError,
    TagNumberError,
    parse_encoding,
    parse_identifier_component,
    parse_length_component,
    ASN1ParserError,
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
    assert identifier_component.tag_class == TagClass.UNIVERSAL
    assert identifier_component.encoding_type == EncodingType.PRIMITIVE
    assert identifier_component.tag_number == 30
    assert identifier_component.header.length == len(data)

    data: memoryview = memoryview(bytes([0b01_1_11110]))
    identifier_component = parse_identifier_component(data=data, offset=0)
    assert identifier_component.tag_class == TagClass.APPLICATION
    assert identifier_component.encoding_type == EncodingType.CONSTRUCTED
    assert identifier_component.tag_number == 30
    assert identifier_component.header.length == len(data)

    data: memoryview = memoryview(bytes([0b10_1_11110]))
    identifier_component = parse_identifier_component(data=data, offset=0)
    assert identifier_component.tag_class == TagClass.CONTEXT_SPECIFIC
    assert identifier_component.encoding_type == EncodingType.CONSTRUCTED
    assert identifier_component.tag_number == 30
    assert identifier_component.header.length == len(data)

    data: memoryview = memoryview(bytes([0b11_1_11110]))
    identifier_component = parse_identifier_component(data=data, offset=0)
    assert identifier_component.tag_class == TagClass.PRIVATE
    assert identifier_component.encoding_type == EncodingType.CONSTRUCTED
    assert identifier_component.tag_number == 30
    assert identifier_component.header.length == len(data)


def test_8_1_2_4_2():
    """8.1.2.4.2 The subsequent octets shall encode the number of the tag as follows:
    a)bit 8 of each octet shall be set to one unless it is the last octet of the identifier octets;

    b)bits 7 to 1 of the first subsequent octet, followed by bits 7 to 1 of the second subsequent octet, followed in turn
    by bits 7 to 1 of each further octet, up to and including the last subsequent octet in the identifier octets shall be
    the encoding of an unsigned binary integer equal to the tag number, with bit 7 of the first subsequent octet as
    the most significant bit;

    c)bits 7 to 1 of the first subsequent octet shall not all be zero.
    """

    data: memoryview = memoryview(bytes([0b11_1_11111, 0b1_0100001, 0b0_1100001]))
    identifier_component = parse_identifier_component(data=data, offset=0)
    assert identifier_component.tag_class == TagClass.PRIVATE
    assert identifier_component.encoding_type == EncodingType.CONSTRUCTED
    assert identifier_component.tag_number == 4321
    assert identifier_component.header.length == len(data)

    # c)bits 7 to 1 of the first subsequent octet shall not all be zero.
    with pytest.raises(TagNumberError):
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


def test_8_1_3_2():
    """8.1.3.2 A sender shall:
    a)use the definite form (see 8.1.3.3) if the encoding is primitive;

    b)use either the definite form (see 8.1.3.3) or the indefinite form (see 8.1.3.6), a sender's option, if the encoding
    is constructed and all immediately available;

    c)use the indefinite form (see 8.1.3.6) if the encoding is constructed and is not all immediately available.
    """

    data: memoryview = memoryview(
        bytes(
            [
                0b00_0_00010,  # UNIVERSAL PRIMITIVE 2 (INTEGER)
                0b0_0000001,  # DEFINITE 1
                0b0000_0111,  # VALUE 7
            ]
        )
    )

    encoding = parse_encoding(data=data, offset=0)
    assert encoding.tag_class is TagClass.UNIVERSAL
    assert encoding.encoding_type is EncodingType.PRIMITIVE
    assert encoding.tag_number == 2
    assert encoding.length_form is LengthForm.DEFINITE
    assert encoding.content_length == 1
    assert encoding.content == int(7).to_bytes()
    assert encoding.header.length == len(data)

    data: memoryview = memoryview(
        bytes(
            [
                0b00_1_10000,  # UNIVERSAL CONSTRUCTED 16 (SEQUENCE)
                0b1_0000000,  # INDEFINITE
                #
                0b00_0_00010,  # UNIVERSAL PRIMITIVE 2 (INTEGER)
                0b0_0000001,  # DEFINITE 1
                0b0000_0111,  # VALUE 7
                #
                0b00_0_00010,  # UNIVERSAL PRIMITIVE 2 (INTEGER)
                0b0_0000001,  # DEFINITE 1
                0b0000_0110,  # VALUE 6
                #
                0b0_0000000,
                0b0_0000000,  # EOC
            ]
        )
    )

    encoding = parse_encoding(data=data, offset=0)
    assert encoding.tag_class is TagClass.UNIVERSAL
    assert encoding.encoding_type is EncodingType.CONSTRUCTED
    assert encoding.tag_number == 16
    assert encoding.length_form is LengthForm.INDEFINITE
    assert encoding.content_length is None
    assert encoding.header.length == len(data)

    data: memoryview = memoryview(
        bytes(
            [
                0b00_1_10000,  # UNIVERSAL CONSTRUCTED 16 (SEQUENCE)
                0b0_0000110,  # DEFINITE 6
                #
                0b00_0_00010,  # UNIVERSAL PRIMITIVE 2 (INTEGER)
                0b0_0000001,  # DEFINITE 1
                0b0000_0111,  # VALUE 7
                #
                0b00_0_00010,  # UNIVERSAL PRIMITIVE 2 (INTEGER)
                0b0_0000001,  # DEFINITE 1
                0b0000_0110,  # VALUE 6
            ]
        )
    )

    encoding = parse_encoding(data=data, offset=0)
    assert encoding.tag_class is TagClass.UNIVERSAL
    assert encoding.encoding_type is EncodingType.CONSTRUCTED
    assert encoding.tag_number == 16
    assert encoding.length_form is LengthForm.DEFINITE
    assert encoding.content_length == 6
    assert encoding.header.length == len(data)

    # a)use the definite form (see 8.1.3.3) if the encoding is primitive;
    with pytest.raises(LengthError):
        data: memoryview = memoryview(bytes([0b00_0_11110, 0b1000_0000]))
        parse_encoding(data=data, offset=0)


def test_8_1_3_3():
    """8.1.3.3 For the definite form, the length octets shall consist of one or more octets, and shall represent the number of octets
    in the contents octets using either the short form (see 8.1.3.4) or the long form (see 8.1.3.5) as a sender's option.
    NOTE – The short form can only be used if the number of octets in the contents octets is less than or equal to 127."""

    data: memoryview = memoryview(
        bytes(
            [
                0b00_1_10000,  # UNIVERSAL CONSTRUCTED 16 (SEQUENCE)
                0b0_0000110,  # DEFINITE 6 -- short form
                #
                0b00_0_00010,  # UNIVERSAL PRIMITIVE 2 (INTEGER)
                0b0_0000001,  # DEFINITE 1
                0b0000_0111,  # VALUE 7
                #
                0b00_0_00010,  # UNIVERSAL PRIMITIVE 2 (INTEGER)
                0b0_0000001,  # DEFINITE 1
                0b0000_0110,  # VALUE 6
            ]
        )
    )

    encoding = parse_encoding(data=data, offset=0)
    assert encoding.tag_class is TagClass.UNIVERSAL
    assert encoding.encoding_type is EncodingType.CONSTRUCTED
    assert encoding.tag_number == 16
    assert encoding.length_form is LengthForm.DEFINITE
    assert encoding.content_length == 6
    assert encoding.header.length == len(data)
    assert encoding.length_component.header.length == 1  # short form

    data: memoryview = memoryview(
        bytes(
            [
                0b00_1_10000,  # UNIVERSAL CONSTRUCTED 16 (SEQUENCE)
                0b1_0000001,  # DEFINITE  -- long form
                0b00000110,  # LENGTH VALUE 6
                #
                0b00_0_00010,  # UNIVERSAL PRIMITIVE 2 (INTEGER)
                0b0_0000001,  # DEFINITE 1
                0b0000_0111,  # VALUE 7
                #
                0b00_0_00010,  # UNIVERSAL PRIMITIVE 2 (INTEGER)
                0b0_0000001,  # DEFINITE 1
                0b0000_0110,  # VALUE 6
            ]
        )
    )

    encoding = parse_encoding(data=data, offset=0)
    assert encoding.tag_class is TagClass.UNIVERSAL
    assert encoding.encoding_type is EncodingType.CONSTRUCTED
    assert encoding.tag_number == 16
    assert encoding.length_form is LengthForm.DEFINITE
    assert encoding.content_length == 6
    assert encoding.header.length == len(data)
    assert encoding.length_component.header.length == 2  # long form

    data: memoryview = memoryview(
        bytes(
            [
                0b00_1_10000,  # UNIVERSAL CONSTRUCTED 16 (SEQUENCE)
                0b1_0000000,  # INDEFINITE
                #
                0b00_0_00010,  # UNIVERSAL PRIMITIVE 2 (INTEGER)
                0b0_0000001,  # DEFINITE 1
                0b0000_0111,  # VALUE 7
                #
                0b00_0_00010,  # UNIVERSAL PRIMITIVE 2 (INTEGER)
                0b0_0000001,  # DEFINITE 1
                0b0000_0110,  # VALUE 6
                #
                0b0_0000000,
                0b0_0000000,  # EOC
            ]
        )
    )

    encoding = parse_encoding(data=data, offset=0)
    assert encoding.tag_class is TagClass.UNIVERSAL
    assert encoding.encoding_type is EncodingType.CONSTRUCTED
    assert encoding.tag_number == 16
    assert encoding.length_form is LengthForm.INDEFINITE
    assert encoding.content_length is None
    assert encoding.header.length == len(data)


def test_8_1_3_5():
    """8.1.3.5 In the long form, the length octets shall consist of an initial octet and one or more subsequent octets. The initial
    octet shall be encoded as follows:

    a)bit 8 shall be one;

    b)bits 7 to 1 shall encode the number of subsequent octets in the length octets, as an unsigned binary integer with
    bit 7 as the most significant bit;

    c)the value 11111111 shall not be used.
    NOTE 1 – This restriction is introduced for possible future extension."""

    data: memoryview = memoryview(
        bytes(
            [
                0b00_1_10000,  # UNIVERSAL CONSTRUCTED 16 (SEQUENCE)
                0b1111_1111,  # DEFINITE  -- long form
                0b00000110,  # LENGTH VALUE 6
                #
                0b00_0_00010,  # UNIVERSAL PRIMITIVE 2 (INTEGER)
                0b0_0000001,  # DEFINITE 1
                0b0000_0111,  # VALUE 7
                #
                0b00_0_00010,  # UNIVERSAL PRIMITIVE 2 (INTEGER)
                0b0_0000001,  # DEFINITE 1
                0b0000_0110,  # VALUE 6
            ]
        )
    )

    with pytest.raises(LengthError):
        parse_encoding(data=data, offset=0)


# ############################################################################
# 8.1.4 Contents Octets
# ############################################################################


def test_8_1_4():
    """8.1.4 Contents octets
    The contents octets shall consist of zero, one or more octets, and shall encode the data value as specified in subsequent clauses.
    NOTE – The contents octets depend on the type of the data value; subsequent clauses follow the same sequence as the definition of
    types in ASN.1."""

    data: memoryview = memoryview(
        bytes(
            [
                0b00_1_10000,  # UNIVERSAL CONSTRUCTED 16 (SEQUENCE)
                0b0_0000000,  # DEFINITE 0
            ]
        )
    )

    identifier_component = parse_identifier_component(data=data, offset=0)
    assert identifier_component.tag_class is TagClass.UNIVERSAL
    assert identifier_component.encoding_type is EncodingType.CONSTRUCTED
    assert identifier_component.tag_number == 16

    length_component = parse_length_component(data=data, offset=1)
    assert length_component.form is LengthForm.DEFINITE
    assert length_component.content_length == 0
    assert length_component.header.length == 1

    encoding = parse_encoding(data=data, offset=0)
    assert encoding.tag_class is TagClass.UNIVERSAL
    assert encoding.encoding_type is EncodingType.CONSTRUCTED
    assert encoding.tag_number == 16
    assert encoding.length_form is LengthForm.DEFINITE
    assert encoding.content_length == 0
    assert encoding.header.length == len(data)


# ############################################################################
# 8.1.5 Contents Octets
# ############################################################################


def test_8_1_5():
    """8.1.5 End-of-contents octets
    The end-of-contents octets shall be present if the length is encoded as specified in 8.1.3.6, otherwise they shall not be present."""

    data: memoryview = memoryview(
        bytes(
            [
                0b00_1_10000,  # UNIVERSAL CONSTRUCTED 16 (SEQUENCE)
                0b1_0000000,  # INDEFINITE
                #
                0b00_0_00010,  # UNIVERSAL PRIMITIVE 2 (INTEGER)
                0b0_0000001,  # DEFINITE 1
                0b0000_0111,  # VALUE 7
                #
                0b00_0_00010,  # UNIVERSAL PRIMITIVE 2 (INTEGER)
                0b0_0000001,  # DEFINITE 1
                0b0000_0110,  # VALUE 6
                #
                0b0_0000000,
                0b0_0000000,  # EOC
            ]
        )
    )

    encoding = parse_encoding(data=data, offset=0)
    assert encoding.tag_class is TagClass.UNIVERSAL
    assert encoding.encoding_type is EncodingType.CONSTRUCTED
    assert encoding.tag_number == 16
    assert encoding.length_form is LengthForm.INDEFINITE
    assert encoding.content_length is None
    assert encoding.header.length == len(data)

    data: memoryview = memoryview(
        bytes(
            [
                0b00_1_10000,  # UNIVERSAL CONSTRUCTED 16 (SEQUENCE)
                0b1_0000000,  # INDEFINITE
                #
                0b00_0_00010,  # UNIVERSAL PRIMITIVE 2 (INTEGER)
                0b0_0000001,  # DEFINITE 1
                0b0000_0111,  # VALUE 7
                #
                0b00_0_00010,  # UNIVERSAL PRIMITIVE 2 (INTEGER)
                0b0_0000001,  # DEFINITE 1
                0b0000_0110,  # VALUE 6
            ]
        )
    )

    with pytest.raises(EOCError):
        parse_encoding(data=data, offset=0)
