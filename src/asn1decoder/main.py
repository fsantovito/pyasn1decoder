import logging
from asn1decoder.asn1parser import parse_encoding, ASN1Encoding
import typer
from pathlib import Path

app = typer.Typer()

logging.basicConfig(
    level=logging.DEBUG,
    # format="%(asctime)s %(levelname)s [%(name)s] %(message)s",
    format="%(levelname)s %(message)s",
)


def dump_encoding(encoding: ASN1Encoding, level: int = 0):
    print(f"{' ' * level}{encoding}")
    if encoding.content_component is not None:
        if isinstance(encoding.content_component.content, list):
            for child in encoding.content_component.content:
                dump_encoding(encoding=child, level=level + 1)


@app.command()
def dump(path: Path):
    with open(path, "rb") as f:
        data = f.read()

    encoding = parse_encoding(data=memoryview(data))

    dump_encoding(encoding)


if __name__ == "__main__":
    app()
