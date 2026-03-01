from datetime import datetime
from typing import Tuple
from asn1decoder.asn1types import ASN1Encoding, EncodingType
from asn1decoder.asn1parser import ASN1ParserError


class UTCTimeParserError(ASN1ParserError):
    pass


def _parse_value(
    name: str, raw_value: str, limit: Tuple[int, int] | None = None
) -> int:
    try:
        value = int(raw_value)
    except ValueError:
        raise UTCTimeParserError(f"UTCTime declared with invalid {name}, {raw_value}.")

    if limit is not None:
        if not limit[0] <= value <= limit[1]:
            raise UTCTimeParserError(f"UTCTime declared with invalid {name}, {value}.")

    return value


def parse_utctime(encoding: ASN1Encoding) -> datetime:
    if encoding.encoding_type is EncodingType.CONSTRUCTED:
        raise UTCTimeParserError("UTCTime shall be primitive.")

    if encoding.tag_number != 23:
        raise UTCTimeParserError(
            f"UTCTime can be initialized only with encoding having tag number = 23. Got {encoding.tag_number}."
        )

    if encoding.content_length in (None, 0):
        raise UTCTimeParserError("UTCTime declared without content.")

    if encoding.content_length != 13:
        raise UTCTimeParserError("UTCTime must be encoded with YYMMDDHHMMSSZ.")

    if encoding.content is None:
        raise UTCTimeParserError("UTCTime declared without content.")

    if encoding.content_length != len(encoding.content):
        raise UTCTimeParserError(
            f"UTCTime length mismatch. Declared {encoding.content_length} found {len(encoding.content)}."
        )

    try:
        raw_value = encoding.content.decode("ascii")
    except UnicodeDecodeError as e:
        raise UTCTimeParserError(str(e))

    if raw_value[-1] != "Z":
        raise UTCTimeParserError("UTCTime not ending with 'Z'.")

    yy = _parse_value("year", raw_value[0:2])
    if 0 <= yy <= 49:
        year = 2000 + yy
    else:
        year = 1900 + yy

    month = _parse_value("month", raw_value[2:4], (1, 12))
    day = _parse_value("day", raw_value[4:6], (1, 31))

    hours = _parse_value("hours", raw_value[6:8], (0, 23))
    minutes = _parse_value("minutes", raw_value[8:10], (0, 59))
    seconds = _parse_value("seconds", raw_value[10:12], (0, 59))

    value = datetime(
        year=year, month=month, day=day, hour=hours, minute=minutes, second=seconds
    )

    return value
