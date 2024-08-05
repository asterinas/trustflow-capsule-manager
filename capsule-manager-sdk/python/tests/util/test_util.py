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

import os
import unittest

from sdc.util import crypto, file

SourceFilename = "source.dat"
EncryptionFilename = "encryption.dat"
DecryptionFilename = "decryption.dat"


class TestUtil(unittest.TestCase):
    def __init__(self, *args, **kwargs):
        super(TestUtil, self).__init__(*args, **kwargs)
        self.secret_key = crypto.gen_key(16)

    def test_file_encrypt(self):
        raw_data = b"hello world"
        file.write_file(SourceFilename, "wb", raw_data)
        crypto.encrypt_file(SourceFilename, EncryptionFilename, self.secret_key)

        crypto.decrypt_file(EncryptionFilename, DecryptionFilename, self.secret_key)
        data = file.read_file(DecryptionFilename, "rb")
        self.assertEqual(data, raw_data)
        os.remove(SourceFilename)
        os.remove(EncryptionFilename)
        os.remove(DecryptionFilename)

    def test_file_encrypt_inplace(self):
        raw_data = b"hello world"
        file.write_file(SourceFilename, "wb", raw_data)
        crypto.encrypt_file_inplace(SourceFilename, self.secret_key)
        data = file.read_file(SourceFilename, "rb")
        self.assertNotEqual(data, raw_data)

        crypto.decrypt_file_inplace(SourceFilename, self.secret_key)
        data = file.read_file(SourceFilename, "rb")
        self.assertEqual(data, raw_data)
        os.remove(SourceFilename)


if __name__ == "__main__":
    unittest.main()
