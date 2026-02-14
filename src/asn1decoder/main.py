import logging
from asn1decoder.tokenizer import asn1_tlv


logging.basicConfig(
    level=logging.DEBUG,
    # format="%(asctime)s %(levelname)s [%(name)s] %(message)s",
    format="%(levelname)s %(message)s",
)


def main():
    with open("files/bdata_ok.der", "rb") as f:
        data = f.read()

    tlv = asn1_tlv(data)

    for encoding in tlv:
        print(encoding)


if __name__ == "__main__":
    main()
