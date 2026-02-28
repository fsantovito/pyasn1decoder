from abc import ABC, abstractmethod
from typing import Type
from asn1decoder.asn1types import ASN1Encoding, EncodingType
from asn1decoder.asn1parser import ASN1ParserError, decode_byte
from asn1decoder.asn1values import parse_octetstring


class ASN1StringParserError(ASN1ParserError):
    pass


class ASN1String(ABC):
    TAG_NUMBER: int
    EXCEPTION_CLASS: Type[ASN1StringParserError]

    def __init__(self, encoding: ASN1Encoding) -> None:
        self.encoding = encoding
        self._validate_tag()

    @abstractmethod
    def is_valid_char(self, char: str) -> bool:
        pass

    def parse(self) -> str:
        raw_bytes = self._extract_bytes()
        return self._decode_and_validate(raw_bytes)

    def _extract_bytes(self) -> bytes:
        if self.encoding.encoding_type is EncodingType.PRIMITIVE:
            return self._extract_primitive()
        return self._extract_constructed()

    def _validate_tag(self) -> None:
        if self.encoding.tag_number != self.TAG_NUMBER:
            raise self.EXCEPTION_CLASS(
                f"{self.__class__.__name__} expects tag {self.TAG_NUMBER}, got {self.encoding.tag_number}"
            )

    def _extract_primitive(self) -> bytes:
        if self.encoding.content_length is None:
            raise self.EXCEPTION_CLASS(
                f"{self.__class__.__name__} declared with null length."
            )

        if self.encoding.content_length == 0:
            return b""

        if self.encoding.content is None:
            raise self.EXCEPTION_CLASS(f"{self.__class__.__name__} content missing.")

        return self.encoding.content

    def _extract_constructed(self) -> bytes:
        if self.encoding.inner_encodings is None:
            raise self.EXCEPTION_CLASS(
                f"{self.__class__.__name__} with invalid constructed content."
            )

        chunks = []
        for inner in self.encoding.inner_encodings:
            chunks.append(parse_octetstring(inner))

        return b"".join(chunks)

    def _decode_and_validate(self, data: bytes) -> str:
        chars = []
        for byte in data:
            try:
                char = decode_byte(byte)
            except ValueError as e:
                raise self.EXCEPTION_CLASS(str(e))

            if not self.is_valid_char(char):
                raise self.EXCEPTION_CLASS(
                    f"Invalid character '{char}' for {self.__class__.__name__}"
                )

            chars.append(char)

        return "".join(chars)
