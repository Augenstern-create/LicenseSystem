#!/usr/bin/env python3
"""Independent Python verification of the public Ed25519/CBOR test vector."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey


class CborReader:
    def __init__(self, data: bytes) -> None:
        self.data = data
        self.position = 0

    def _take(self, length: int) -> bytes:
        end = self.position + length
        if end > len(self.data):
            raise ValueError("truncated CBOR")
        value = self.data[self.position : end]
        self.position = end
        return value

    def _argument(self, additional: int) -> int:
        if additional < 24:
            return additional
        sizes = {24: 1, 25: 2, 26: 4, 27: 8}
        if additional not in sizes:
            raise ValueError("indefinite or reserved CBOR argument")
        return int.from_bytes(self._take(sizes[additional]), "big")

    def decode(self) -> Any:
        initial = self._take(1)[0]
        major = initial >> 5
        additional = initial & 0x1F
        argument = self._argument(additional)
        if major == 0:
            return argument
        if major == 1:
            return -1 - argument
        if major == 2:
            return self._take(argument)
        if major == 3:
            return self._take(argument).decode("utf-8")
        if major == 4:
            return [self.decode() for _ in range(argument)]
        if major == 5:
            result: dict[Any, Any] = {}
            for _ in range(argument):
                key = self.decode()
                if key in result:
                    raise ValueError("duplicate CBOR map key")
                result[key] = self.decode()
            return result
        if major == 7 and additional in (20, 21, 22):
            return {20: False, 21: True, 22: None}[additional]
        raise ValueError(f"unsupported CBOR major={major} additional={additional}")


def decode_exact(data: bytes) -> Any:
    reader = CborReader(data)
    result = reader.decode()
    if reader.position != len(data):
        raise ValueError("trailing CBOR data")
    return result


def head(major: int, value: int) -> bytes:
    if value < 24:
        return bytes([(major << 5) | value])
    for additional, size in ((24, 1), (25, 2), (26, 4), (27, 8)):
        if value < 1 << (size * 8):
            return bytes([(major << 5) | additional]) + value.to_bytes(size, "big")
    raise ValueError("integer too large")


def encode_canonical(value: Any) -> bytes:
    if value is None:
        return b"\xf6"
    if value is False:
        return b"\xf4"
    if value is True:
        return b"\xf5"
    if isinstance(value, int) and value >= 0:
        return head(0, value)
    if isinstance(value, int):
        return head(1, -1 - value)
    if isinstance(value, bytes):
        return head(2, len(value)) + value
    if isinstance(value, str):
        encoded = value.encode("utf-8")
        return head(3, len(encoded)) + encoded
    if isinstance(value, list):
        return head(4, len(value)) + b"".join(encode_canonical(item) for item in value)
    if isinstance(value, dict):
        encoded_items = [(encode_canonical(key), encode_canonical(item)) for key, item in value.items()]
        encoded_items.sort(key=lambda item: (len(item[0]), item[0]))
        return head(5, len(value)) + b"".join(key + item for key, item in encoded_items)
    raise TypeError(f"unsupported value: {type(value)!r}")


def main() -> None:
    repository = Path(__file__).resolve().parents[1]
    vector = json.loads((repository / "tests/vectors/ed25519-v1.json").read_text("utf-8"))
    license_bytes = bytes.fromhex(vector["license_hex"])
    assert len(license_bytes) == vector["license_length"]
    assert hashlib.sha256(license_bytes).hexdigest() == vector["license_sha256"]

    envelope = decode_exact(license_bytes)
    assert encode_canonical(envelope) == license_bytes
    assert envelope[0] == "ALIC"
    assert envelope[1] == vector["format_version"]
    assert envelope[2] == "Ed25519"
    assert envelope[3] == vector["key_id"]
    payload_bytes = envelope[4]
    signature = envelope[5]

    domain = vector["domain_separator_utf8_escaped"].replace("\\0", "\0").encode("utf-8")
    public_key = Ed25519PublicKey.from_public_bytes(bytes.fromhex(vector["public_key_hex"]))
    public_key.verify(signature, domain + payload_bytes)

    payload = decode_exact(payload_bytes)
    assert encode_canonical(payload) == payload_bytes
    assert payload[0] == vector["payload"]["schema_version"]
    assert payload[1].hex() == vector["payload"]["license_id"].replace("-", "")
    assert payload[2] == vector["payload"]["product_id"]
    assert payload[16] == vector["payload"]["revocation_epoch"]
    print("python_vector_verification=ok")
    print(f"license_sha256={vector['license_sha256']}")


if __name__ == "__main__":
    main()
