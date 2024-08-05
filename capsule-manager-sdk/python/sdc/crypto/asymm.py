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

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa, utils
from cryptography.hazmat.primitives.asymmetric.types import PublicKeyTypes


def load_public_key(data: bytes, format: str = "PEM") -> PublicKeyTypes:
    if format == "PEM":
        return serialization.load_pem_public_key(data)
    elif format == "DER":
        return serialization.load_der_public_key(data)
    else:
        raise RuntimeError(f"public key format {format} is not supported")


def load_private_key(data: bytes, format: str = "PEM") -> PublicKeyTypes:
    if format == "PEM":
        return serialization.load_pem_private_key(data, None)
    elif format == "DER":
        return serialization.load_der_private_key(data, None)
    else:
        raise RuntimeError(f"public key format {format} is not supported")


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


class Signer(ABC):
    def __init__(self, name: str):
        """init Signer

        Args:
            name: signer method name
        """
        self.name = name

    @abstractmethod
    def update(self, data: bytes):
        pass

    @abstractmethod
    def sign(self) -> bytes:
        pass

    def name(self) -> str:
        return self.name


class Verifier(ABC):
    def __init__(self, name: str):
        """init Verifier

        Args:
            name: verifier method name
        """
        self.name = name

    @abstractmethod
    def update(self, data: bytes):
        pass

    @abstractmethod
    def verify(self, signature: bytes) -> None:
        pass

    def name(self) -> str:
        return self.name


class RsaEncryptor(Encryptor):
    def __init__(
        self,
        public_key: Union[bytes, str, rsa.RSAPublicKey],
        name: str,
        format: str = "PEM",
    ):
        super().__init__(name)
        if isinstance(public_key, bytes):
            self.public_key = load_public_key(public_key, format)
        elif isinstance(public_key, str):
            self.public_key = load_public_key(public_key.encode("utf-8"), format)
        else:
            self.public_key = public_key

    def encrypt(self, data: bytes) -> bytes:
        if self.name == "RSA-OAEP-256":
            return self.public_key.encrypt(
                data,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None,
                ),
            )
        elif self.name == "RSA-OAEP":
            return self.public_key.encrypt(
                data,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None,
                ),
            )
        else:
            raise RuntimeError(f"encrypted method {self.name} not support")


class RsaDecryptor(Decryptor):
    def __init__(
        self,
        private_key: Union[bytes, str, rsa.RSAPrivateKey],
        name: str,
        format: str = "PEM",
    ):
        super().__init__(name)
        if isinstance(private_key, bytes):
            self.secret_key = load_private_key(private_key, format)
        elif isinstance(private_key, str):
            self.secret_key = load_private_key(private_key.encode("utf-8"), format)
        else:
            self.secret_key = private_key

    def decrypt(self, data: bytes) -> bytes:
        if self.name == "RSA-OAEP-256":
            return self.secret_key.decrypt(
                data,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None,
                ),
            )
        elif self.name == "RSA-OAEP":
            return self.secret_key.decrypt(
                data,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA1()),
                    algorithm=hashes.SHA1(),
                    label=None,
                ),
            )
        else:
            raise RuntimeError(f"decrypt method {self.name} not support")


class RsaVerifier(Verifier):
    def __init__(
        self,
        public_key: Union[bytes, str, rsa.RSAPublicKey],
        name: str,
        format: str = "PEM",
    ):
        super().__init__(name)
        if isinstance(public_key, bytes):
            self.public_key = load_public_key(public_key, format)
        elif isinstance(public_key, str):
            self.public_key = load_public_key(public_key.encode("utf-8"), format)
        else:
            self.public_key = public_key
        self.hasher = hashes.Hash(hashes.SHA256())

    def update(self, data: bytes):
        self.hasher.update(data)
        return self

    def verify(self, signature: bytes) -> None:
        if self.name == "RS256":
            digest = self.hasher.finalize()
            self.public_key.verify(
                signature,
                digest,
                padding.PKCS1v15(),
                utils.Prehashed(hashes.SHA256()),
            )
        else:
            raise RuntimeError(f"verifier method {self.name} not support")


class RsaSigner(Signer):
    def __init__(
        self,
        private_key: Union[bytes, str, rsa.RSAPrivateKey],
        name: str,
        format: str = "PEM",
    ):
        super().__init__(name)
        if isinstance(private_key, bytes):
            self.secret_key = load_private_key(private_key, format)
        elif isinstance(private_key, str):
            self.secret_key = load_private_key(private_key.encode("utf-8"), format)
        else:
            self.secret_key = private_key
        self.hasher = hashes.Hash(hashes.SHA256())

    def update(self, data: bytes):
        self.hasher.update(data)
        return self

    def sign(self) -> bytes:
        if self.name == "RS256":
            digest = self.hasher.finalize()
            return self.secret_key.sign(
                digest, padding.PKCS1v15(), utils.Prehashed(hashes.SHA256())
            )
        else:
            raise RuntimeError(f"signer method {self.name} not support")
