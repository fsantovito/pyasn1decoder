from typing import List, Tuple
from asn1decoder.asn1types import (
    Header,
    IdentifierComponent,
    LengthComponent,
    ContentComponent,
    EOCComponent,
    TagClass,
    EncodingType,
    LengthForm,
    ASN1Encoding,
)


class ASN1ParserError(ValueError):
    pass


class TagNumberError(ASN1ParserError):
    pass


class LengthError(ASN1ParserError):
    pass


class EOCError(ASN1ParserError):
    pass


def _ensure_valid_offset(data: memoryview, offset: int, length: int | None = None):
    if offset >= len(data):
        raise ASN1ParserError(
            f"Unexpected end of data. Requested {offset=} in {len(data)} bytes"
        )

    if length is not None and offset + length > len(data):
        raise ASN1ParserError(
            f"Unexpected end of data. Requested {length} bytes from offset {offset} in {len(data)} bytes"
        )


def parse_tag_class(identifier_octet: int) -> TagClass:
    match identifier_octet & 0b1100_0000:
        case 0b0000_0000:
            ec = TagClass.UNIVERSAL
        case 0b0100_0000:
            ec = TagClass.APPLICATION
        case 0b1000_0000:
            ec = TagClass.CONTEXT_SPECIFIC
        case 0b1100_0000:
            ec = TagClass.PRIVATE
        case _:
            raise AssertionError("unreachable")
    return ec


def parse_encoding_type(identifier_octet: int) -> EncodingType:
    match identifier_octet & 0b0010_0000:
        case 0b0000_0000:
            et = EncodingType.PRIMITIVE
        case 0b0010_0000:
            et = EncodingType.CONSTRUCTED
        case _:
            raise AssertionError("unreachable")
    return et


def parse_high_tag_number(data: memoryview, offset: int) -> Tuple[int, int]:
    """
    Parse ASN.1 high-tag-number form

    Returns:
        (tag_number, bytes_consumed)
    """
    _ensure_valid_offset(data=data, offset=offset)

    first_octet = data[offset]
    tag_part = first_octet & 0b0001_1111

    if tag_part != 0b0001_1111:
        raise TagNumberError("Not a high-tag-number form (low 5 bits must be 11111)")

    tag_number = 0
    bytes_used = 1

    while True:
        offset += 1
        _ensure_valid_offset(data=data, offset=offset)

        byte = data[offset]
        bytes_used += 1

        value = byte & 0b0111_1111

        # 8.1.2.4.2 c) first subsequent octet bits 7–1 shall not be all zero
        if bytes_used == 2 and value == 0:
            raise TagNumberError("First subsequent octet cannot have bits 7–1 all zero")

        tag_number = (tag_number << 7) | value

        # 8.1.2.4.2 a) bit 8 of each octet shall be set to one unless it is the last octet of the identifier octets
        if byte & 0b1000_0000 == 0:
            break

    return tag_number, bytes_used


def parse_tag_number(data: memoryview, offset: int) -> Tuple[int, int]:
    """
    Parses an ASN.1 identifier octet from `data` starting at `offset`.

    Returns:
        (int, int): the decoded tag number and the number of bytes consumed
    """

    _ensure_valid_offset(data=data, offset=offset)

    first_octet = data[offset]
    tag_number = first_octet & 0b0001_1111

    if tag_number <= 30:
        bytes_used = 1
    else:
        tag_number, bytes_used = parse_high_tag_number(data=data, offset=offset)

    return tag_number, bytes_used


def parse_identifier_component(data: memoryview, offset: int) -> IdentifierComponent:
    """
    Parses an ASN.1 identifier octet from `data` starting at `offset`.

    Returns:
        IdentifierComponent: the decoded identifier component
    """

    _ensure_valid_offset(data=data, offset=offset)

    identifier_octet = data[offset]
    encoding_class = parse_tag_class(identifier_octet=identifier_octet)
    encoding_type = parse_encoding_type(identifier_octet=identifier_octet)
    tag_number, used_bytes = parse_tag_number(data=data, offset=offset)

    return IdentifierComponent(
        tag_class=encoding_class,
        tag_number=tag_number,
        encoding_type=encoding_type,
        header=Header(offset=offset, length=used_bytes),
    )


def parse_length_component(data: memoryview, offset: int) -> LengthComponent:
    """
    Parses an ASN.1 length octet from `data` starting at `offset`.

    Returns:
        LengthComponent: the decoded length component
    """

    _ensure_valid_offset(data=data, offset=offset)

    byte = data[offset]

    if byte == 0b1000_0000:
        return LengthComponent(
            form=LengthForm.INDEFINITE,
            content_length=None,
            header=Header(offset=offset, length=1),
        )

    if byte & 0b1000_0000:
        if byte == 0b1111_1111:
            raise LengthError(
                "first byte of the long form of the length octet cannot be 0xFF"
            )

        bytes_used = (byte & 0b0111_1111) + 1
        length_form = LengthForm.DEFINITE
        start = offset + 1
        end = offset + bytes_used
        _ensure_valid_offset(data=data, offset=start)
        _ensure_valid_offset(data=data, offset=start, length=end - start)
        content_length = int.from_bytes(data[start:end], "big")

    else:
        length_form = LengthForm.DEFINITE
        content_length = byte
        bytes_used = 1

    return LengthComponent(
        form=length_form,
        content_length=content_length,
        header=Header(offset=offset, length=bytes_used),
    )


def parse_eoc_octet(data: memoryview, offset: int) -> EOCComponent:
    _ensure_valid_offset(data=data, offset=offset)
    _ensure_valid_offset(data=data, offset=offset, length=2)
    first_byte = data[offset]
    second_byte = data[offset + 1]

    if first_byte != 0 or second_byte != 0:
        raise EOCError(f"invalid EOC at offset {offset}")

    return EOCComponent(header=Header(offset=offset, length=2))


def parse_primitive_value(
    data: memoryview, offset: int, length: int
) -> ContentComponent:
    _ensure_valid_offset(data=data, offset=offset)
    _ensure_valid_offset(data=data, offset=offset, length=length)
    content = data[offset : offset + length]
    return ContentComponent(
        content=content, header=Header(offset=offset, length=length)
    )


def parse_encoding(data: memoryview, offset: int = 0) -> ASN1Encoding:
    """
    Parses an ASN.1 encoding from `data` starting at `offset`.

    Returns:
        ASN1Encoding: the decoded encoding
    """

    current_offset = offset
    _ensure_valid_offset(data=data, offset=current_offset)

    identifier_component = parse_identifier_component(data=data, offset=current_offset)
    current_offset += identifier_component.header.length

    length_component = parse_length_component(data=data, offset=current_offset)
    current_offset += length_component.header.length

    if (
        identifier_component.encoding_type is EncodingType.PRIMITIVE
        and length_component.form is LengthForm.INDEFINITE
    ):
        raise LengthError("Primitive with indefinite length is invalid in BER")

    if identifier_component.encoding_type is EncodingType.PRIMITIVE:
        if (
            length_component.form is LengthForm.INDEFINITE
            or length_component.content_length is None
        ):
            raise LengthError("Primitive with indefinite length is invalid in BER")

        content_component = parse_primitive_value(
            data=data,
            offset=current_offset,
            length=length_component.content_length,
        )
        current_offset += content_component.header.length
        return ASN1Encoding(
            identifier_component=identifier_component,
            length_component=length_component,
            content_component=content_component,
            eoc_component=None,
            header=Header(offset=offset, length=current_offset - offset),
        )

    # if identifier_component.encoding_type is EncodingType.CONSTRUCTED:
    else:  # EncodingType.CONSTRUCTED
        if length_component.form is LengthForm.INDEFINITE:
            start = current_offset
            children: List[ASN1Encoding] = []

            while True:
                try:
                    _ensure_valid_offset(data=data, offset=current_offset, length=2)
                except ASN1ParserError:
                    raise EOCError("missing required EOC")

                # check EOC
                if data[current_offset] == 0 and data[current_offset + 1] == 0:
                    eoc = parse_eoc_octet(data, current_offset)
                    current_offset += eoc.header.length
                    break

                child = parse_encoding(data, current_offset)
                children.append(child)
                current_offset += child.header.length

            content_component = ContentComponent(
                content=children,
                header=Header(
                    offset=start,
                    length=current_offset - start - 2,  # exclude EOC
                ),
            )

            return ASN1Encoding(
                identifier_component=identifier_component,
                length_component=length_component,
                content_component=content_component,
                eoc_component=eoc,
                header=Header(offset=offset, length=current_offset - offset),
            )

        else:  # LengthForm.DEFINITE
            if length_component.content_length is None:
                raise LengthError("DEFINITE without content_length")

            end_offset = current_offset + length_component.content_length

            children: List[ASN1Encoding] = []

            while current_offset < end_offset:
                child = parse_encoding(data=data, offset=current_offset)
                children.append(child)
                current_offset += child.header.length

            if current_offset != end_offset:
                raise LengthError("Constructed content length mismatch")

            content_component = ContentComponent(
                content=children,
                header=Header(
                    offset=identifier_component.header.offset
                    + identifier_component.header.length
                    + length_component.header.length,
                    length=length_component.content_length,
                ),
            )

            return ASN1Encoding(
                identifier_component=identifier_component,
                length_component=length_component,
                content_component=content_component,
                eoc_component=None,
                header=Header(offset=offset, length=current_offset - offset),
            )


