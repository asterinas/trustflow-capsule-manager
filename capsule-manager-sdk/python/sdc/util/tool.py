# Copyright 2023 Ant Group Co., Ltd.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#   http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import base64

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from sdc.util import crypto


def assert_list_len_equal(
    l1: list = None, l2: list = None, msg: str = "the len of list not equal"
):
    if l1 is not None and l2 is not None:
        assert len(l1) == len(l2), msg


def to_hex(data: bytes):
    return "".join("{:02x}".format(x) for x in data)


def encode_base64(input_bytes: bytes, urlsafe: bool = True) -> str:
    """Encode bytes as an unpadded base64 string."""

    if urlsafe:
        encode = base64.urlsafe_b64encode
    else:
        encode = base64.b64encode

    output_bytes = encode(input_bytes)
    output_string = output_bytes.decode("ascii")
    return output_string.rstrip("=")


def decode_base64(input_string: str) -> bytes:
    """Decode an unpadded standard or urlsafe base64 string to bytes."""

    input_bytes = input_string.encode("ascii")
    input_len = len(input_bytes)
    padding = b"=" * (3 - ((input_len + 3) % 4))

    # Passing altchars here allows decoding both standard and urlsafe base64
    output_bytes = base64.b64decode(input_bytes + padding, altchars=b"-_")
    return output_bytes


def generate_party_id(pk: rsa.RSAPublicKey) -> str:
    party_id = base64.b32encode(
        crypto.sha256(
            pk.public_bytes(
                encoding=serialization.Encoding.DER,
                format=serialization.PublicFormat.SubjectPublicKeyInfo,
            )
        )
    )
    return party_id.decode("ascii").rstrip("=")


def generate_party_id_from_cert(cert: bytes, format: str = "PEM") -> str:
    if format == "PEM":
        public_key = x509.load_pem_x509_certificate(cert).public_key()
    elif format == "DER":
        public_key = x509.load_der_x509_certificate(cert).public_key()
    else:
        raise RuntimeError(f"format {format} is not supported")
    return generate_party_id(public_key)
