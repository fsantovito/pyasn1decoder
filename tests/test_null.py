import pytest
from asn1decoder.asn1parser import parse_encoding
from asn1decoder.asn1values import parse_null, NullParserError


def test_null_valid():
    """NULL value must have length 0 and no content"""
    data = memoryview(
        bytes(
            [
                0b00000101,  # UNIVERSAL PRIMITIVE 5 (NULL)
                0b00000000,  # length 0
            ]
        )
    )

    # import pudb; pudb.set_trace()
    encoding = parse_encoding(data=data, offset=0)
    value = parse_null(encoding=encoding)
    assert value is None


def test_null_with_non_zero_length():
    """NULL with non-zero length should reise error"""
    data = memoryview(
        bytes(
            [
                0b00000101,  # UNIVERSAL PRIMITIVE 5 (NULL)
                0b00000001,  # length 1 (invalid)
                0b00000000,  # unexpected content
            ]
        )
    )

    encoding = parse_encoding(data=data, offset=0)
    with pytest.raises(NullParserError, match="non-zero content"):
        parse_null(encoding=encoding)


def test_null_with_content_bytes():
    """NULL must not contain any content bytes"""
    data = memoryview(
        bytes(
            [
                0b00000101,  # UNIVERSAL PRIMITIVE 5 (NULL)
                0b00000001,  # length 1
                0b11111111,  # invalid content
            ]
        )
    )

    encoding = parse_encoding(data=data, offset=0)
    with pytest.raises(NullParserError):
        parse_null(encoding=encoding)


def test_null_wrong_tag():
    """Parsing NULL with wrong tag should raise error"""
    data = memoryview(
        bytes(
            [
                0b00000010,  # UNIVERSAL PRIMITIVE 2 (INTEGER)
                0b00000000,  # length 0
            ]
        )
    )

    encoding = parse_encoding(data=data, offset=0)
    with pytest.raises(NullParserError, match="tag number = 5"):
        parse_null(encoding=encoding)
