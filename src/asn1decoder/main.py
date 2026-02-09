from asn1decoder.tokenizer import asn1_tlv

def main():
    with open("bdata_ok.der", "rb") as f:
        data = f.read()

    tlv = asn1_tlv(data)

    for encoding in tlv:
        print(encoding)


if __name__ == "__main__":
    main()
