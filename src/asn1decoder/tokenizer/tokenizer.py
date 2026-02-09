from enum import IntEnum
from dataclasses import dataclass
from typing import Dict, List, Tuple


class TokenizerException(Exception):
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


@dataclass()
class ASN1Encoding:
    identifier_octet: IdentifierOctet
    length_form: LengthForm
    length: int | None
    content: bytes | None
    kind: EncodingKind

    def __str__(self) -> str:
        encoding_class = self.identifier_octet.encoding_class
        encoding_type = self.identifier_octet.encoding_type
        tag_number = self.identifier_octet.tag_number

        if encoding_class == EncodingClass.UNIVERSAL:
            tag_name = f"{ASN1TypeNames.get(tag_number, '')}[{tag_number}]"
        else:
            tag_name = f"[{tag_number}]"

        if self.kind is EncodingKind.EOC:
            return f"{encoding_class.name.ljust(16)} {encoding_type.name.ljust(11)} {tag_name.ljust(20)}".ljust(
                20
            )

        length_form = self.length_form.name
        length = self.length if self.length is not None else ""
        content = self.content if self.content is not None else ""

        if self.length_form is LengthForm.DEFINITE:
            length_form += f"={length}"

        return f"{encoding_class.name.ljust(16)} {encoding_type.name.ljust(11)} {tag_name.ljust(20)} {length_form} {content}"


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


def parse_tag_number(data: bytes) -> Tuple[int, int]:
    first_octect = data[0]
    tag_number = first_octect & 0b0001_1111
    used_bytes = 1
    match tag_number:
        case n if n < 31:
            tn = n
        case _:
            raise NotImplementedError("ottetti multipli!!")
    return tn, used_bytes


def parse_identifier_octet(data: bytes) -> Tuple[IdentifierOctet, bytes]:
    identifier_octet = data[0]
    encoding_class = parse_encoding_class(identifier_octet=identifier_octet)
    encoding_type = parse_encoding_type(identifier_octet=identifier_octet)
    tag_number, used_bytes = parse_tag_number(data=data)

    return IdentifierOctet(
        encoding_class=encoding_class,
        encoding_type=encoding_type,
        tag_number=tag_number,
    ), data[used_bytes:]


def parse_length_octect(data: bytes) -> Tuple[LengthForm, int | None, bytes]:
    byte = data[0]
    used_bytes = 1

    if byte == 0b1000_0000:
        return LengthForm.INDEFINITE, None, data[used_bytes:]

    if byte & 0b1000_0000:
        n_bytes = byte & 0b0111_1111
        length = int.from_bytes(data[1 : 1 + n_bytes], "big")
        return LengthForm.DEFINITE, length, data[used_bytes + n_bytes :]
    else:
        return LengthForm.DEFINITE, byte, data[used_bytes:]


def parse_encoding(data: bytes) -> Tuple[ASN1Encoding, bytes]:
    identifier_octet, data = parse_identifier_octet(data)
    length_form, length, data = parse_length_octect(data)

    if (
        identifier_octet.encoding_type is EncodingType.PRIMITIVE
        and length_form is LengthForm.INDEFINITE
    ):
        raise TokenizerException("Primitive with indefinite length is invalid in BER")

    if (
        identifier_octet.encoding_class is EncodingClass.UNIVERSAL
        and identifier_octet.tag_number == 0
        and identifier_octet.encoding_type is EncodingType.PRIMITIVE
        and length == 0
    ):
        kind = EncodingKind.EOC
    else:
        kind = EncodingKind.TLV

    content = None
    if identifier_octet.encoding_type is EncodingType.PRIMITIVE and length is not None:
        content = data[:length]
        data = data[length:]

        if length != len(content):
            raise TokenizerException(
                f"For {identifier_octet} {length=} differs from byte's {len(content)=}"
            )

    encoding = ASN1Encoding(
        identifier_octet=identifier_octet,
        length_form=length_form,
        length=length,
        content=content,
        kind=kind,
    )
    return encoding, data


def asn1_tlv(data: bytes) -> List[ASN1Encoding]:
    tlv = []
    while data:
        encoding, data = parse_encoding(data)
        tlv.append(encoding)
    return tlv
