from typing import Dict, List
from enum import IntEnum
from dataclasses import dataclass


class TagClass(IntEnum):
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


@dataclass(slots=True)
class Header:
    offset: int
    length: int


@dataclass(slots=True)
class IdentifierComponent:
    header: Header
    tag_class: TagClass
    encoding_type: EncodingType
    tag_number: int


@dataclass(slots=True)
class LengthComponent:
    header: Header
    form: LengthForm
    content_length: int | None


@dataclass(slots=True)
class ContentComponent:
    header: Header
    content: "memoryview | List[ASN1Encoding]"


@dataclass(slots=True)
class EOCComponent:
    header: Header


@dataclass(slots=True)
class ASN1Encoding:
    header: Header
    identifier_component: IdentifierComponent
    length_component: LengthComponent
    content_component: ContentComponent | None
    eoc_component: EOCComponent | None

    def __str__(self) -> str:
        class_name = self.identifier_component.tag_class.name
        type_name = self.identifier_component.encoding_type.name
        tag_number = self.identifier_component.tag_number

        if self.identifier_component.tag_class is TagClass.UNIVERSAL:
            tag_name = ASN1TypeNames.get(tag_number, tag_number)
        else:
            tag_name = f"[{tag_number}]"

        if self.identifier_component.encoding_type is EncodingType.PRIMITIVE:
            length_form = ""
            content = self.content or ""

        else:
            content = ""
            length_form = self.length_component.form.name
        return f"{class_name} {type_name} {tag_name} {length_form} {content}"

    @property
    def tag_class(self) -> TagClass:
        return self.identifier_component.tag_class

    @property
    def encoding_type(self) -> EncodingType:
        return self.identifier_component.encoding_type

    @property
    def tag_number(self) -> int:
        return self.identifier_component.tag_number

    @property
    def length_form(self) -> LengthForm:
        return self.length_component.form

    @property
    def content_length(self) -> int | None:
        return self.length_component.content_length

    @property
    def content(self) -> bytes | None:
        if self.content_component is not None:
            if isinstance(self.content_component.content, memoryview):
                return self.content_component.content.tobytes()

    @property
    def inner_encodings(self) -> List["ASN1Encoding"] | None:
        if self.content_component is not None:
            if isinstance(self.content_component.content, list):
                return self.content_component.content


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
