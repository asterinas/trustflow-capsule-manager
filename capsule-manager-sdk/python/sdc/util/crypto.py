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

import datetime
import os
import secrets
from io import BufferedWriter
from typing import List

from cryptography import x509
from cryptography.hazmat.primitives import hashes, hmac, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
from sdc.crypto import symm
from sdc.util import constants


def bytes2int(buf: bytes):
    res = 0
    for index in range(len(buf)):
        res = res << 8 | buf[len(buf) - index - 1]
    return res


def hmac_sha256(key: bytes, *args: bytes) -> bytes:
    h = hmac.HMAC(key, hashes.SHA256())
    assert (
        len(args) >= 1
    ), "At least one piece of data is involved in the calculation of hmac."
    h.update(args[0])
    for arg in args[1:]:
        h.update(constants.SEPARATOR)
        h.update(arg)
    return h.finalize()


def sha256(*args: bytes) -> bytes:
    h = hashes.Hash(hashes.SHA256())
    assert (
        len(args) >= 1
    ), "At least one piece of data is involved in the calculation of hash."
    h.update(args[0])
    for arg in args[1:]:
        h.update(constants.SEPARATOR)
        h.update(arg)
    return h.finalize()


def gen_key(nbytes: int = 32) -> bytes:
    return secrets.token_bytes(nbytes)


def decrypt_block(buf: bytes, data_key: bytes) -> bytes:
    offset = 0
    # read iv
    iv_len = bytes2int(buf[offset : offset + constants.IvLenBytes])
    offset += constants.IvLenBytes
    iv = buf[offset : offset + iv_len]
    offset += constants.IvFieldBytes

    # read mac
    mac_len = bytes2int(buf[offset : offset + constants.MacLenBytes])
    offset += constants.MacLenBytes
    mac = buf[offset : offset + mac_len]
    offset += constants.MacFieldBytes

    # read data
    data = buf[offset:]
    if len(data_key) == 16:
        return symm.AesGcmDecryptor(data_key, "A128GCM").decrypt(data, iv, b"", mac)
    elif len(data_key) == 32:
        return symm.AesGcmDecryptor(data_key, "A256GCM").decrypt(data, iv, b"", mac)
    else:
        return symm.AesGcmDecryptor(data_key, "Unknown").decrypt(data, iv, b"", mac)


def decrypt_file(source_path: str, dest_path: str, data_key: bytes):
    assert source_path != dest_path, "source_path = dest_path"
    in_ = open(source_path, "rb")
    out_ = open(dest_path, "wb")

    # parse file header
    file_len = os.path.getsize(source_path)
    header_len = (
        constants.VersionBytes
        + constants.SchemaBytes
        + constants.PacketCntBytes
        + constants.BlockLenBytes
    )
    assert file_len > header_len, "File length is less than required header length"

    # skip version and schema
    in_.seek(constants.VersionBytes + constants.SchemaBytes)
    # read packet count
    buf = in_.read(constants.PacketCntBytes)
    packet_cnt = bytes2int(buf)
    # read block len
    buf = in_.read(constants.BlockLenBytes)
    block_len = bytes2int(buf)

    assert (
        file_len - header_len >= (packet_cnt - 1) * block_len
    ), "N - 1 Data block len is more than required file length"
    assert (
        block_len * packet_cnt >= file_len - header_len
    ), "N Data block len is less than required file length"

    for index in range(packet_cnt):
        buf = in_.read(block_len)
        data = decrypt_block(buf, data_key)
        out_.write(data)

    out_.close()
    in_.close()


def encrypt_block(buf: bytes, data_key: bytes, out_: BufferedWriter):
    # iv
    iv = gen_key(constants.IvBytes)
    if len(data_key) == 16:
        (ciphertext, mac) = symm.AesGcmEncryptor(data_key, "A128GCM").encrypt(
            buf, iv, b""
        )
    elif len(data_key) == 32:
        (ciphertext, mac) = symm.AesGcmEncryptor(data_key, "A256GCM").encrypt(
            buf, iv, b""
        )
    else:
        (ciphertext, mac) = symm.AesGcmEncryptor(data_key, "Unknown").encrypt(
            buf, iv, b""
        )

    # write block header
    out_.write(constants.IvBytes.to_bytes(constants.IvLenBytes, "little"))
    out_.write(iv)
    out_.write(constants.Padding.to_bytes(constants.IvFieldBytes - len(iv), "little"))
    out_.write(len(mac).to_bytes(constants.MacLenBytes, "little"))
    out_.write(mac)
    out_.write(constants.Padding.to_bytes(constants.MacFieldBytes - len(mac), "little"))
    out_.write(ciphertext)


def encrypt_file(source_path: str, dest_path: str, data_key: bytes):
    assert source_path != dest_path, "source_path = dest_path"
    in_ = open(source_path, "rb")
    out_ = open(dest_path, "wb")

    # header
    file_len = os.path.getsize(source_path)
    block_header_len = (
        constants.IvLenBytes
        + constants.IvFieldBytes
        + constants.MacLenBytes
        + constants.MacFieldBytes
    )
    block_data_len = constants.BlockBytes - block_header_len
    package_cnt = (int)(file_len / block_data_len) + (file_len % block_data_len != 0)

    # write file header
    out_.write(constants.Version.to_bytes(constants.VersionBytes, "little"))
    out_.write(constants.Schema.to_bytes(constants.SchemaBytes, "little"))
    out_.write(package_cnt.to_bytes(constants.PacketCntBytes, "little"))
    out_.write(constants.BlockBytes.to_bytes(constants.BlockLenBytes, "little"))

    # write data block
    for index in range(package_cnt - 1):
        buf = in_.read(block_data_len)
        encrypt_block(buf, data_key, out_)

    buf = in_.read(file_len - (package_cnt - 1) * block_data_len)
    encrypt_block(buf, data_key, out_)

    out_.close()
    in_.close()


def encrypt_file_inplace(file_path: str, data_key: bytes):
    source_path = file_path
    dest_path = file_path + "encrypted.tmp"
    encrypt_file(source_path, dest_path, data_key)
    os.remove(source_path)
    os.rename(dest_path, source_path)


def decrypt_file_inplace(file_path: str, data_key: bytes):
    source_path = file_path
    dest_path = file_path + "decrypted.tmp"
    decrypt_file(source_path, dest_path, data_key)
    os.remove(source_path)
    os.rename(dest_path, source_path)


def generate_rsa_keypair() -> (bytes, List[bytes]):
    """Generate temp RSA key-pair"""
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=3072,
    )
    public_key = private_key.public_key()

    builder = x509.CertificateBuilder()
    builder = builder.subject_name(
        x509.Name(
            [
                x509.NameAttribute(NameOID.COMMON_NAME, "capsule-manager"),
            ]
        )
    )
    builder = builder.issuer_name(
        x509.Name(
            [
                x509.NameAttribute(NameOID.COMMON_NAME, "capsule-manager"),
            ]
        )
    )
    one_day = datetime.timedelta(1, 0, 0)
    builder = builder.not_valid_before(datetime.datetime.today() - one_day)
    builder = builder.not_valid_after(datetime.datetime.today() + (one_day * 30))
    builder = builder.serial_number(x509.random_serial_number())
    builder = builder.public_key(public_key)
    certificate = builder.sign(
        private_key=private_key,
        algorithm=hashes.SHA256(),
    )
    return (
        private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        ),
        [certificate.public_bytes(encoding=serialization.Encoding.PEM)],
    )


def convert_pem_to_der(pem: bytes) -> bytes:
    cert = x509.load_pem_x509_certificate(pem)
    return cert.public_bytes(encoding=serialization.Encoding.DER)
