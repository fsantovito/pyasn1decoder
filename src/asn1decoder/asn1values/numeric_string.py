import string
from asn1decoder.asn1types import ASN1Encoding, EncodingType
from asn1decoder.asn1parser import ASN1ParserError
from asn1decoder.asn1values.octet_string import parse_octet_string


class NumericStringParserError(ASN1ParserError):
    pass


def is_valid_char(char: str) -> bool:
    return char in (string.digits + " ")


def first_invalid_char(chars: str) -> str | None:
    for char in chars:
        if not is_valid_char(char):
            return char


def parse_primitive_numericstring(encoding: ASN1Encoding) -> str:
    if encoding.content_length is None:
        raise NumericStringParserError("NumericString declared with null length.")

    if encoding.content_length == 0 and encoding.content is not None:
        raise NumericStringParserError("NumericString with content_length mismatch")

    if encoding.content is None:
        return ""

    chars = encoding.content.decode("ascii")

    invalid_char = first_invalid_char(chars)
    if invalid_char is not None:
        raise NumericStringParserError(
            f"NumericString with invalid char '{invalid_char}'."
        )

    return chars


def parse_constructed_numericstring(encoding: ASN1Encoding) -> str:
    if encoding.inner_encodings is None:
        raise NumericStringParserError("NumericString with invalid octets string")

    chars = []
    for inner_encoding in encoding.inner_encodings:
        char = parse_octet_string(inner_encoding)

        if not is_valid_char(char):
            raise NumericStringParserError(f"NumericString with invalid char ({char})")

        chars.append(char)
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
