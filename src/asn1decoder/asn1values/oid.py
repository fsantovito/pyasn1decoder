from typing import List
from asn1decoder.asn1types import ASN1Encoding, EncodingType
from asn1decoder.asn1parser import ASN1ParserError

class OIDParserError(ASN1ParserError):
    pass



def parse_oid_subidentifier(data: List[bytes]) -> int:
    if len(data) > 1 and (int(data[0]) & 0x7F) == 0:
        raise OIDParserError("OID subidentifier not minimally encoded.")

    value = 0
    for byte in data:
        value = (value << 7) | (int(byte) & 0x7F)
    return value


def extract_oid_subidentifiers(data: bytes) -> List[List[bytes]]:
    subidentifiers = []

    subidentifier = []
    for byte in data:
        subidentifier.append(byte)
        if byte & 0b1000_0000 == 0:
            subidentifiers.append(subidentifier)
            subidentifier = []

    return subidentifiers


def parse_oid(encoding: ASN1Encoding) -> str:
    numbers = []

    if encoding.encoding_type is EncodingType.CONSTRUCTED:
        raise OIDParserError("OID shall be primitive.")

    if encoding.tag_number != 6:
        raise OIDParserError(
            f"OID can be initialize only with encoding having tag number = 6. Got {encoding.tag_number}."
        )

    if encoding.content_length in (None, 0):
        raise OIDParserError("OID declared without content.")

    if encoding.content_length != len(encoding.content):
        raise OIDParserError(
            f"OID length mismatch. Declared {encoding.content_length} found {len(encoding.content)}."
        )

    last_byte = encoding.content[-1]
    if last_byte & 0b1000_0000 == 0b1000_0000:
        raise OIDParserError("OID with continuation bit set on last byte")

    subidentifiers = extract_oid_subidentifiers(encoding.content)
    first_subidentifier = subidentifiers[0]
    first_value = parse_oid_subidentifier(first_subidentifier)

    if first_value < 40:
        X = 0
        Y = first_value
    elif first_value < 80:
        X = 1
        Y = first_value - 40
    else:
        X = 2
        Y = first_value - 80

    numbers.extend((X, Y))

    for subidentifier in subidentifiers[1:]:
        value = parse_oid_subidentifier(subidentifier)
        numbers.append(value)

    return ".".join([str(n) for n in numbers])
