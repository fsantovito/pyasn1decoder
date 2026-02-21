from asn1decoder.asn1types import ASN1Encoding, EncodingType
from asn1decoder.asn1parser import ASN1ParserError


class NullParserError(ASN1ParserError):
    pass


def parse_null(encoding: ASN1Encoding) -> None:
    if encoding.encoding_type is EncodingType.CONSTRUCTED:
        raise NullParserError("Null shall be primitive.")

    if encoding.tag_number != 5:
        raise NullParserError(
            f"Null can be initialized only with encoding having tag number = 5. Got {encoding.tag_number}."
        )

    if encoding.content_length is None:
        raise NullParserError("Null declared with null content.")

    if encoding.content_length > 0:
        raise NullParserError("Null declared with non-zero content.")

    return None
