import string
from typing import List
from asn1decoder.asn1types import ASN1Encoding, EncodingType
from asn1decoder.asn1parser import ASN1ParserError
from asn1decoder.asn1values.octet_string import parse_octetstring


class NumericStringParserError(ASN1ParserError):
    pass


def decode_byte(value: int) -> str:
    if not 0 <= value <= 255:
        raise ValueError(f"invalid byte '{value.to_bytes().hex()}'")

    try:
        char = value.to_bytes().decode("ascii")
    except UnicodeDecodeError:
        raise ValueError(
            f"byte '{value.to_bytes().hex()}' is not valid for a NumericString"
        )

    return char


def is_valid_char(char: str) -> bool:
    if len(char) > 1:
        raise ValueError(f"expected a character but got a string: '{char}'")

    return char in string.digits + " "


def parse_primitive_numericstring(encoding: ASN1Encoding) -> str:
    if encoding.content_length is None:
        raise NumericStringParserError("NumericString declared with null length.")

    if encoding.content_length == 0 and encoding.content is not None:
        raise NumericStringParserError("NumericString with content_length mismatch")

    if encoding.content is None:
        return ""

    chars = []
    for byte in encoding.content:
        try:
            char = decode_byte(byte)
        except ValueError as e:
            raise NumericStringParserError(str(e))

        if not is_valid_char(char):
            raise NumericStringParserError(
                f"char '{char}' is not valid for a NumericString"
            )

        chars.append(char)

    return "".join(chars)


def parse_constructed_numericstring(encoding: ASN1Encoding) -> str:
    if encoding.inner_encodings is None:
        raise NumericStringParserError("NumericString with invalid octets string")

    chars: List[str] = []

    for inner_encoding in encoding.inner_encodings:
        data = parse_octetstring(inner_encoding)

        try:
            chars.extend([decode_byte(byte) for byte in data])
        except ValueError as e:
            raise NumericStringParserError(str(e))

    return "".join(chars)


def parse_numericstring(encoding: ASN1Encoding) -> str:
    if encoding.tag_number != 18:
        raise NumericStringParserError(
            f"NumericString can be initialized only with encoding having tag number = 18. Got {encoding.tag_number}."
        )

    if encoding.encoding_type is EncodingType.PRIMITIVE:
        chars = parse_primitive_numericstring(encoding)
    else:
        chars = parse_constructed_numericstring(encoding)

    return chars
