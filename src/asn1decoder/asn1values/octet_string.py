from asn1decoder.asn1types import ASN1Encoding
from asn1decoder.asn1parser import ASN1ParserError


class OctetStringParserError(ASN1ParserError):
    pass


def parse_octet_string(encoding: ASN1Encoding) -> str:
    if encoding.tag_number != 4:
        raise OctetStringParserError(
            f"OctetString can be initialized only with encoding having tag number = 4. Got {encoding.tag_number}."
        )

    if encoding.content_length is None:
        raise OctetStringParserError("OctetString declared with null content.")

    if encoding.content is None:
        raise OctetStringParserError("OctetString declared with null content.")

    if encoding.content_length != len(encoding.content):
        raise OctetStringParserError("OctetString with content_length mismatch")

    return encoding.content.decode("ascii")
