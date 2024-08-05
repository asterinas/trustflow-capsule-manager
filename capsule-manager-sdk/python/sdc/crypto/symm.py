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

from abc import ABC, abstractmethod
from typing import Union

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes


class Encryptor(ABC):
    def __init__(self, name: str):
        """init Encryptor

        Args:
            name: encrypt method name
        """
        self.name = name

    @abstractmethod
    def encrypt(self, data: bytes) -> bytes:
        pass

    def name(self) -> str:
        return self.name


class Decryptor(ABC):
    def __init__(self, name: str):
        """init Decryptor

        Args:
            name: decrypt method name
        """
        self.name = name

    @abstractmethod
    def decrypt(self, data: bytes) -> bytes:
        pass

    def name(self) -> str:
        return self.name


class AesGcmEncryptor(Encryptor):
    def __init__(self, secret_key: Union[bytes, str], name: str):
        super().__init__(name)
        if isinstance(secret_key, str):
            self.secret_key = secret_key.encode("utf-8")
        else:
            self.secret_key = secret_key

    def encrypt(self, data: bytes, iv: bytes, aad: bytes) -> (bytes, bytes):
        encryptor = Cipher(
            algorithms.AES(self.secret_key),
            modes.GCM(iv),
        ).encryptor()
        encryptor.authenticate_additional_data(aad)
        ciphertext = encryptor.update(data) + encryptor.finalize()

        return (ciphertext, encryptor.tag)


class AesGcmDecryptor(Decryptor):
    def __init__(self, secret_key: Union[bytes, str], name: str):
        super().__init__(name)
        if isinstance(secret_key, str):
            self.secret_key = secret_key.encode("utf-8")
        else:
            self.secret_key = secret_key

    def decrypt(self, data: bytes, iv: bytes, aad: bytes, tag: bytes) -> bytes:
        decryptor = Cipher(
            algorithms.AES(self.secret_key),
            modes.GCM(iv, tag),
        ).decryptor()
        decryptor.authenticate_additional_data(aad)
        return decryptor.update(data) + decryptor.finalize()
