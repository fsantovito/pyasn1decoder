from asn1decoder.asn1types import ASN1Encoding
from asn1decoder.asn1values.asn1string import ASN1String, ASN1StringParserError


class IA5StringParserError(ASN1StringParserError):
    pass


class ASN1IA5String(ASN1String):
    TAG_NUMBER = 22
    EXCEPTION_CLASS = IA5StringParserError

    def is_valid_char(self, char: str) -> bool:
        if len(char) > 1:
            raise ValueError(f"expected a character but got a string: '{char}'")

        return ord(char) <= 0x7F


def parse_ia5string(encoding: ASN1Encoding) -> str:
    p = ASN1IA5String(encoding=encoding)
    return p.parse()
