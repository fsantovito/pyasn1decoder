from datetime import datetime
import pytest
from asn1decoder.asn1parser import parse_encoding
from asn1decoder.asn1values import parse_utctime, UTCTimeParserError


# -------------------------
# UTCTime (UNIVERSAL 23)
# -------------------------


def test_utctime_valid_primitive():
    """UTCTime primitive, valid representation"""
    data = memoryview(
        bytes(
            [
                0b00010111,  # UNIVERSAL PRIMITIVE 23
                0b00001101,  # length = 13
                # '920521123456Z'
                0b00111001,  # '9'
                0b00110010,  # '2'
                0b00110000,  # '0'
                0b00110101,  # '5'
                0b00110010,  # '2'
                0b00110001,  # '1'
                0b00110001,  # '1'
                0b00110010,  # '2'
                0b00110011,  # '3'
                0b00110100,  # '4'
                0b00110101,  # '5'
                0b00110110,  # '6'
                0b01011010,  # 'Z'
            ]
        )
    )
    encoding = parse_encoding(data=data, offset=0)
    value = parse_utctime(encoding)
    assert value == datetime(year=1992, month=5, day=21, hour=12, minute=34, second=56)


def test_utctime_invalid_length():
    """UTCTime with missing seconds (length < 13)"""
    data = memoryview(
        bytes(
            [
                0b00010111,  # tag
                0b00001011,  # length = 11
                # '9205211234Z' -> only 10 digits + Z
                0b00111001,  # '9'
                0b00110010,  # '2'
                0b00110000,  # '0'
                0b00110101,  # '5'
                0b00110010,  # '2'
                0b00110001,  # '1'
                0b00110001,  # '1'
                0b00110010,  # '2'
                0b00110011,  # '3'
                0b00110100,  # '4'
                0b01011010,  # 'Z'
            ]
        )
    )
    encoding = parse_encoding(data=data, offset=0)
    with pytest.raises(UTCTimeParserError):
        parse_utctime(encoding)


def test_utctime_invalid_char():
    """UTCTime with invalid character (non-digit before Z)"""
    data = memoryview(
        bytes(
            [
                0b00010111,  # tag
                0b00001101,  # length = 13
                # '92052112X456Z'
                0b00111001,  # '9'
                0b00110010,  # '2'
                0b00110000,  # '0'
                0b00110101,  # '5'
                0b00110010,  # '2'
                0b00110001,  # '1'
                0b00110001,  # '1'
                0b00110010,  # '2'
                0b01011000,  # 'X' -> invalid
                0b00110100,  # '4'
                0b00110101,  # '5'
                0b00110110,  # '6'
                0b01011010,  # 'Z'
            ]
        )
    )
    encoding = parse_encoding(data=data, offset=0)
    with pytest.raises(UTCTimeParserError):
        parse_utctime(encoding)


def test_utctime_invalid_hours():
    """UTCTime with hours > 23"""
    data = memoryview(
        bytes(
            [
                0b00010111,  # tag
                0b00001101,  # length = 13
                # '920521240000Z' -> hours = 24 invalid
                0b00111001,  # '9'
                0b00110010,  # '2'
                0b00110000,  # '0'
                0b00110101,  # '5'
                0b00110010,  # '2'
                0b00110001,  # '1'
                0b00110010,  # '2'
                0b00110100,  # '4' -> hour tens
                0b00110000,  # '0' -> hour units = 24
                0b00110000,  # '0' min tens
                0b00110000,  # '0' min units
                0b00110000,  # '0' sec tens
                0b00110000,  # '0' sec units
                0b01011010,  # 'Z'
            ]
        )
    )
    encoding = parse_encoding(data=data, offset=0)
    with pytest.raises(UTCTimeParserError):
        parse_utctime(encoding)


def test_utctime_invalid_seconds():
    """UTCTime with seconds > 59"""
    data = memoryview(
        bytes(
            [
                0b00010111,  # tag
                0b00001101,  # length = 13
                # '920521123460Z' -> seconds = 60 invalid
                0b00111001,  # '9'
                0b00110010,  # '2'
                0b00110000,  # '0'
                0b00110101,  # '5'
                0b00110010,  # '2'
                0b00110001,  # '1'
                0b00110001,  # '1'
                0b00110010,  # '2'
                0b00110011,  # '3'
                0b00110100,  # '4'
                0b00110101,  # '5'
                0b00110110,  # '6'
                0b00110110,  # '6' -> seconds = 60 invalid
                0b01011010,  # 'Z'
            ]
        )
    )
    encoding = parse_encoding(data=data, offset=0)
    with pytest.raises(UTCTimeParserError):
        parse_utctime(encoding)
