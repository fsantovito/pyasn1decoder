import logging
from asn1decoder.asn1parser import parse_encoding, print_encoding


logging.basicConfig(
    level=logging.DEBUG,
    # format="%(asctime)s %(levelname)s [%(name)s] %(message)s",
    format="%(levelname)s %(message)s",
)


def main():
    with open("files/bdata_ok.der", "rb") as f:
        data = f.read()

    encoding = parse_encoding(data=memoryview(data))

    print_encoding(encoding)


if __name__ == "__main__":
    main()
