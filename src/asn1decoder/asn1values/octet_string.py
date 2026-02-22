from asn1decoder.asn1types import ASN1Encoding, EncodingType
from asn1decoder.asn1parser import ASN1ParserError


class OctetStringParserError(ASN1ParserError):
    pass


def parse_primitive_octetstring(encoding: ASN1Encoding) -> bytes:
    if encoding.content_length is None:
        raise OctetStringParserError("OctetString declared with null length.")

    if encoding.content_length == 0 and encoding.content is not None:
        raise OctetStringParserError("OctetString with content_length mismatch")

    if encoding.content is None:
        return b""

    return encoding.content


def parse_constructed_octetstring(encoding: ASN1Encoding) -> bytes:
    if encoding.inner_encodings is None:
        raise OctetStringParserError("OctetString with invalid octets string")

    data = []
    for inner_encoding in encoding.inner_encodings:
        data.append(parse_octetstring(inner_encoding))
    return b"".join(data)


def parse_octetstring(encoding: ASN1Encoding) -> bytes:
    if encoding.tag_number != 4:
        raise OctetStringParserError(
            f"OctetString can be initialized only with encoding having tag number = 4. Got {encoding.tag_number}."
        )

    if encoding.encoding_type is EncodingType.PRIMITIVE:
        data = parse_primitive_octetstring(encoding)
    else:
        data = parse_constructed_octetstring(encoding)

    return data
