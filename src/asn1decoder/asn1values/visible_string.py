from asn1decoder.asn1types import ASN1Encoding
from asn1decoder.asn1values.asn1string import ASN1String, ASN1StringParserError


class VisibleStringParserError(ASN1StringParserError):
    pass


class ASN1VisibleString(ASN1String):
    TAG_NUMBER = 26
    EXCEPTION_CLASS = VisibleStringParserError

    def is_valid_char(self, char: str) -> bool:
        if len(char) > 1:
            raise ValueError(f"expected a character but got a string: '{char}'")

        return 0x20 <= ord(char) < 0x7F


def parse_visiblestring(encoding: ASN1Encoding) -> str:
    p = ASN1VisibleString(encoding=encoding)
    return p.parse()
