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

from sdc.crypto import symm
from sdc.util import crypto


class TestSymmCrypto(unittest.TestCase):
    def __init__(self, *args, **kwargs):
        super(TestSymmCrypto, self).__init__(*args, **kwargs)
        self.secret_key = crypto.gen_key(16)

    def test_aes_gcm_encrypt(self):
        data = b"hello world!"
        iv = crypto.gen_key(12)
        (ciphertext, tag) = symm.AesGcmEncryptor(self.secret_key, "A128GCM").encrypt(
            data, iv, b""
        )
        result = symm.AesGcmDecryptor(self.secret_key, "A128GCM").decrypt(
            ciphertext, iv, b"", tag
        )
        self.assertEqual(data, result)


if __name__ == "__main__":
    unittest.main()
