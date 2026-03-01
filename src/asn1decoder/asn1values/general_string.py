from asn1decoder.asn1types import ASN1Encoding
from asn1decoder.asn1values.asn1string import ASN1String, ASN1StringParserError


class GeneralStringParserError(ASN1StringParserError):
    pass


class ASN1GeneralString(ASN1String):
    TAG_NUMBER = 27
    EXCEPTION_CLASS = GeneralStringParserError

    def is_valid_char(self, char: str) -> bool:
        if len(char) > 1:
            raise ValueError(f"expected a character but got a string: '{char}'")

        return True


def parse_generalstring(encoding: ASN1Encoding) -> bytes:
    p = ASN1GeneralString(encoding=encoding)
    return p._extract_bytes()
