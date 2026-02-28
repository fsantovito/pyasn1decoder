import string
from asn1decoder.asn1types import ASN1Encoding
from asn1decoder.asn1values.asn1string import ASN1String, ASN1StringParserError


class PrintableStringParserError(ASN1StringParserError):
    pass


class ASN1PrintableString(ASN1String):
    TAG_NUMBER = 19
    EXCEPTION_CLASS = PrintableStringParserError

    def is_valid_char(self, char: str) -> bool:
        if len(char) > 1:
            raise ValueError(f"expected a character but got a string: '{char}'")

        return char in (string.digits + string.ascii_letters + " '()+,-./:=?")


def parse_printablestring(encoding: ASN1Encoding) -> str:
    p = ASN1PrintableString(encoding=encoding)
    return p.parse()
