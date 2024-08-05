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

import unittest

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from sdc.crypto import asymm
from sdc.util import crypto


class TestAsymmCrypto(unittest.TestCase):
    def __init__(self, *args, **kwargs):
        super(TestAsymmCrypto, self).__init__(*args, **kwargs)

        (private_key_pem, cert_pems) = crypto.generate_rsa_keypair()
        self.private_key = private_key_pem

        cert = x509.load_pem_x509_certificate(cert_pems[0])
        self.pub_key_pem = cert.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )

    def test_rsa_encrypt(self):
        data = b"hello world!"
        secret = asymm.RsaEncryptor(self.pub_key_pem, "RSA-OAEP-256").encrypt(data)
        result = asymm.RsaDecryptor(self.private_key, "RSA-OAEP-256").decrypt(secret)
        self.assertEqual(data, result)

    def test_rsa_sign(self):
        data = b"A message I want to sign"
        sign = asymm.RsaSigner(self.private_key, "RS256").update(data).sign()
        asymm.RsaVerifier(self.pub_key_pem, "RS256").update(data).verify(sign)


if __name__ == "__main__":
    unittest.main()
