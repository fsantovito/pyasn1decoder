from asn1decoder.asn1types import ASN1Encoding, EncodingType
from asn1decoder.asn1parser import ASN1ParserError


class IntegerParserError(ASN1ParserError):
    pass


def parse_integer(encoding: ASN1Encoding) -> int:
    if encoding.encoding_type is EncodingType.CONSTRUCTED:
        raise IntegerParserError("Integer shall be primitive.")

    if encoding.tag_number != 2:
        raise IntegerParserError(
            f"Integer can be initialized only with encoding having tag number = 2. Got {encoding.tag_number}."
        )

    if encoding.content_length in (None, 0):
        raise IntegerParserError("Integer declared without content.")

    if encoding.content_length != len(encoding.content):
        raise IntegerParserError(
            f"Integer length mismatch. Declared {encoding.content_length} found {len(encoding.content)}."
        )

    if encoding.content_length > 1:
        if (encoding.content[0] << 1 | (encoding.content[1] >> 7)) in (
            0,
            0b1_1111_1111,
        ):
            raise IntegerParserError("Integer not minimally encoded.")

    value = int.from_bytes(encoding.content, byteorder="big", signed=True)
    return value
