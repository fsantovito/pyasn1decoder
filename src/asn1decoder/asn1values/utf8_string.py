from asn1decoder.asn1types import ASN1Encoding
from asn1decoder.asn1values.asn1string import ASN1String, ASN1StringParserError


class UTF8StringParserError(ASN1StringParserError):
    pass


class ASN1UTF8String(ASN1String):
    TAG_NUMBER = 12
    EXCEPTION_CLASS = UTF8StringParserError

    def is_valid_char(self, char: str) -> bool:
        return True


def parse_utf8string(encoding: ASN1Encoding) -> str:
    p = ASN1UTF8String(encoding=encoding)
    try:
        return p._extract_bytes().decode("utf8")
    except UnicodeDecodeError as e:
        raise UTF8StringParserError(str(e))
