from enum import IntEnum
from dataclasses import dataclass
from typing import Dict, List, Tuple
import logging

logger = logging.getLogger(__name__)


class TokenizerError(ValueError):
    pass


class EncodingClass(IntEnum):
    UNIVERSAL = 0
    APPLICATION = 1
    CONTEXT_SPECIFIC = 2
    PRIVATE = 3


class EncodingType(IntEnum):
    PRIMITIVE = 0
    CONSTRUCTED = 1


class LengthForm(IntEnum):
    DEFINITE = 0
    INDEFINITE = 1


class EncodingKind(IntEnum):
    TLV = 0
    EOC = 1


@dataclass()
class IdentifierOctet:
    encoding_class: EncodingClass
    encoding_type: EncodingType
    tag_number: int

    def __str__(self) -> str:
        return (
            f"{self.encoding_class.name} {self.encoding_type.name} [{self.tag_number}]"
        )


@dataclass()
class ASN1EncodingMeta:
    offset: int
    header_length: int


@dataclass()
class ASN1Encoding:
    identifier_octet: IdentifierOctet
    length_form: LengthForm
    length: int | None
    content: bytes | None
    kind: EncodingKind
    meta: ASN1EncodingMeta

    def __str__(self) -> str:
        encoding_class = self.identifier_octet.encoding_class
        encoding_type = self.identifier_octet.encoding_type
        tag_number = self.identifier_octet.tag_number

        if encoding_class == EncodingClass.UNIVERSAL:
            tag_name = f"{ASN1TypeNames.get(tag_number, '')}[{tag_number}]"
        else:
            tag_name = f"[{tag_number}]"

        if self.kind is EncodingKind.EOC:
            return f"os={self.meta.offset} hl={self.meta.header_length} {encoding_class.name.ljust(16)} {encoding_type.name.ljust(11)} {tag_name.ljust(20)}".ljust(
                20
            )

        length_form = self.length_form.name
        length = self.length if self.length is not None else ""
        content = self.content if self.content is not None else ""

        if self.length_form is LengthForm.DEFINITE:
            length_form += f"={length}"

        return f"os={self.meta.offset} hl={self.meta.header_length} {encoding_class.name.ljust(16)} {encoding_type.name.ljust(11)} {tag_name.ljust(20)} {length_form} {content}"


ASN1TypeNames: Dict[int, str] = {
    0: "EOC",
    1: "BOOLEAN",
    2: "INTEGER",
    3: "BIT-STRING",
    4: "OCTET-STRING",
    5: "NULL",
    6: "OBJECT-IDENTIFIER",
    7: "OBJECT-DESCRIPTOR",
    8: "EXTERNAL",
    9: "REAL",
    10: "ENUMERATED",
    11: "EMBEDDED-PDV",
    12: "UTF8-STRING",
    13: "RELATIVE-OID",
    14: "TIME",
    15: "RESERVED",
    16: "SEQUENCE",
    17: "SET",
    18: "NUMERIC-STRING",
    19: "PRINTABLE-STRING",
    20: "TELETEX-STRING",
    21: "VIDEOTEX-STRING",
    22: "IA5-STRING",
    23: "UTC-TIME",
    24: "GENERALIZED-TIME",
    25: "GRAPHIC-STRING",
    26: "VISIBLE-STRING",
    27: "GENERAL-STRING",
    28: "UNIVERSAL-STRING",
    29: "CHARACTER-STRING",
    30: "BMP-STRING",
}


def _ensure_valid_offset(data: bytes, offset: int):
    if offset >= len(data):
        raise TokenizerError(
            f"Unexpected end of data. Requested {offset=} in {len(data)} bytes"
        )


def parse_encoding_class(identifier_octet: int) -> EncodingClass:
    match identifier_octet & 0b1100_0000:
        case 0b0000_0000:
            ec = EncodingClass.UNIVERSAL
        case 0b0100_0000:
            ec = EncodingClass.APPLICATION
        case 0b1000_0000:
            ec = EncodingClass.CONTEXT_SPECIFIC
        case 0b1100_0000:
            ec = EncodingClass.PRIVATE
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


def parse_tag_number(data: bytes, offset: int) -> Tuple[int, int]:
    """
    Parses an ASN.1 identifier octet from `data` starting at `offset`.

    Returns:
        (int, int): the decoded tag number and the number of bytes consumed
    """
    logger.debug(f"parsing tag number at offset {offset}")

    _ensure_valid_offset(data=data, offset=offset)

    first_octect = data[offset]
    logger.debug(f"first octet {first_octect:08b}")

    tag_number = first_octect & 0b0001_1111
    match tag_number:
        case n if n < 31:
            return tag_number, 1

        case _:
            raise NotImplementedError("tag number with multiple octets")


def parse_identifier_octet(data: bytes, offset: int) -> Tuple[IdentifierOctet, int]:
    """
    Parses an ASN.1 identifier octet from `data` starting at `offset`.

    Returns:
        (IdentifierOctet, int): the decoded identifier octet and the number of bytes consumed
    """

    logger.debug(f"parsing identifier octet at offset {offset}")

    _ensure_valid_offset(data=data, offset=offset)

    identifier_octet = data[offset]
    logger.debug(f"identifier octet {identifier_octet:08b}")

    encoding_class = parse_encoding_class(identifier_octet=identifier_octet)
    logger.debug(f"encoding class is {encoding_class.name}")

    encoding_type = parse_encoding_type(identifier_octet=identifier_octet)
    logger.debug(f"encoding type is {encoding_type.name}")

    tag_number, used_bytes = parse_tag_number(data=data, offset=offset)
    logger.debug(f"tag number = '{tag_number}' bytes used = '{used_bytes}'")

    return IdentifierOctet(
        encoding_class=encoding_class,
        encoding_type=encoding_type,
        tag_number=tag_number,
    ), used_bytes


def parse_length_octet(data: bytes, offset: int) -> Tuple[LengthForm, int | None, int]:
    """
    Parses an ASN.1 length octet from `data` starting at `offset`.

    Returns:
        (LengthForm, int | None, int): the length form, the length of the content of the tag_number
        and the number of bytes consumed
    """
    logger.debug(f"parsing length octet at offset {offset}")

    _ensure_valid_offset(data=data, offset=offset)

    byte = data[offset]
    logger.debug(f"length octet is {byte:08b}")

    if byte == 0b1000_0000:
        length_form = LengthForm.INDEFINITE
        content_length = None
        bytes_used = 1
        logger.debug(f"{length_form.name=}, {content_length=}, {bytes_used=}")
        return length_form, content_length, bytes_used

    if byte & 0b1000_0000:
        bytes_used = (byte & 0b0111_1111) + 1
        length_form = LengthForm.DEFINITE
        start = offset + 1
        end = offset + bytes_used
        _ensure_valid_offset(data=data, offset=start)
        _ensure_valid_offset(data=data, offset=end - 1)
        content_length = int.from_bytes(data[start:end], "big")

    else:
        length_form = LengthForm.DEFINITE
        content_length = byte
        bytes_used = 1

    logger.debug(f"{length_form.name=}, {content_length=}, {bytes_used=}")
    return length_form, content_length, bytes_used


def parse_encoding(data: bytes, offset: int) -> Tuple[ASN1Encoding, int]:
    """
    Parses an ASN.1 encoding from `data` starting at `offset`.

    Returns:
        (ASN1Encoding, int): the decoded encoding and the number of bytes consumed
    """

    _ensure_valid_offset(data=data, offset=offset)

    # --- Identifier ---
    identifier_octet, io_used_bytes = parse_identifier_octet(data, offset)

    # --- Length ---
    length_form, content_length, lo_used_bytes = parse_length_octet(
        data, offset + io_used_bytes
    )

    header_length = io_used_bytes + lo_used_bytes
    total_used_bytes = header_length

    # --- BER validity check ---
    if (
        identifier_octet.encoding_type is EncodingType.PRIMITIVE
        and length_form is LengthForm.INDEFINITE
    ):
        raise TokenizerError("Primitive with indefinite length is invalid in BER")

    # --- EOC handling (EARLY RETURN) ---
    if (
        identifier_octet.encoding_class is EncodingClass.UNIVERSAL
        and identifier_octet.tag_number == 0
        and identifier_octet.encoding_type is EncodingType.PRIMITIVE
        and content_length == 0
    ):
        encoding = ASN1Encoding(
            identifier_octet=identifier_octet,
            length_form=LengthForm.DEFINITE,
            length=0,
            content=None,
            kind=EncodingKind.EOC,
            meta=ASN1EncodingMeta(
                offset=offset,
                header_length=header_length,
            ),
        )
        return encoding, total_used_bytes

    # --- Normal TLV ---
    kind = EncodingKind.TLV
    content = None

    if (
        identifier_octet.encoding_type is EncodingType.CONSTRUCTED
        and length_form is LengthForm.DEFINITE
    ):
        if content_length is None:
            raise TokenizerError(
                "CONSTRUCTED types with DEFINITE length form must have a definite content length"
            )

        if offset + header_length + content_length > len(data):
            raise TokenizerError("Invalid content length")

    if (
        identifier_octet.encoding_type is EncodingType.PRIMITIVE
        and content_length is not None
    ):
        content_start = offset + total_used_bytes
        content_end = content_start + content_length
        content = data[content_start:content_end]

        bit_string = " ".join(f"{x:08b}" for x in content)
        logger.debug(f"content: {bit_string}")

        if len(content) != content_length:
            raise TokenizerError(
                f"For {identifier_octet} {content_length=} differs from {len(content)=}"
            )

        total_used_bytes += content_length

    encoding = ASN1Encoding(
        identifier_octet=identifier_octet,
        length_form=length_form,
        length=content_length,
        content=content,
        kind=kind,
        meta=ASN1EncodingMeta(offset=offset, header_length=header_length),
    )

    return encoding, total_used_bytes


def asn1_tlv(data: bytes) -> List[ASN1Encoding]:
    logger.debug(f"parsing {len(data)} bytes")

    tlv = []
    offset = 0
    while offset < len(data):
        logger.debug("")
        encoding, bytes_used = parse_encoding(data=data, offset=offset)
        if bytes_used <= 0:
            raise TokenizerError(
                f"lexer consumed an invalid amount of bytes: {bytes_used}"
            )
        tlv.append(encoding)
        offset += bytes_used
    return tlv
