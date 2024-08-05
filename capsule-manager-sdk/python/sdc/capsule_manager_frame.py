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
from dataclasses import dataclass
from typing import List, Union

import grpc
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from google.protobuf import json_format, message
from sdc.crypto import asymm, symm
from sdc.error import CapsuleManagerError
from sdc.util import crypto, tool
from secretflowapis.v2.sdc import jwt_pb2, ual_pb2
from secretflowapis.v2.sdc.capsule_manager import (
    capsule_manager_pb2,
    capsule_manager_pb2_grpc,
)

NONCE_SIZE_IN_SIZE = 32

# tee plat types
TEE_PLAT_SIM = "sim"
TEE_PLAT_SGX = "sgx"
TEE_PLAT_TDX = "tdx"
TEE_PLAT_CSV = "csv"

# tee plat types in UAL Protobuf
UAL_TEE_PLAT_SGX = "SGX_DCAP"
UAL_TEE_PLAT_TDX = "TDX"
UAL_TEE_PLAT_CSV = "CSV"

RESOURCE_URI = "resource_uri"
DATA_KEY_B64 = "data_key_b64"
RULE_ID = "rule_id"
GRANTEE_PARTY_IDS = "grantee_party_ids"
COLUMNS = "columns"
GLOBAL_CONSTRAINTS = "global_constraints"
OP_CONSTRAINS = "op_constraints"
OP_NAME = "op_name"
CONSTRAINTS = "constraints"


@dataclass
class CredentialsConf:
    root_ca: bytes
    private_key: bytes
    cert_chain: bytes


@dataclass
class TeeConstraints:
    mr_plat: str
    mr_boot: str
    mr_ta: str
    mr_signer: str


class CapsuleManagerFrame(object):
    def __init__(
        self,
        host: str,
        tee_plat: str,
        tee_constraints: TeeConstraints,
        conf: CredentialsConf,
    ):
        """CapsuleManager client

        Args:
            host: CapsuleManager endpoint
            tee_plat: Tee platform, sim/sgx/tdx/csv
            tee_constraints: CapsuleManager's measurement constraints
        """
        self.tee_plat = tee_plat
        self.tee_constraints = tee_constraints
        if conf is None:
            channel = grpc.insecure_channel(host)
        else:
            credentials = grpc.ssl_channel_credentials(
                root_certificates=conf.root_ca,
                private_key=conf.private_key,
                certificate_chain=conf.cert_chain,
            )
            channel = grpc.secure_channel(host, credentials)

        self.stub = capsule_manager_pb2_grpc.CapsuleManagerStub(channel)

    @staticmethod
    def create_encrypted_request(
        request: message.Message,
        public_key: bytes,
        private_key: Union[bytes, str, rsa.RSAPrivateKey],
        cert_pems: List[bytes] = None,
    ) -> capsule_manager_pb2.EncryptedRequest:
        """encrypt request

        Args:
            request: the item will be encrypted
            public_key: the public key of capsule manager, it will be used to encrypt data key
            cert_pems: the cert chain of party, it will be used to verify signature and encrypt
            private_key: the private key of party, it will be used to sign and decrypt
        """
        jws = jwt_pb2.Jws()
        jws_JoseHeader = jws.JoseHeader()
        jws_JoseHeader.alg = "RS256"
        if cert_pems is not None:
            cert_chain = [
                # has padding
                base64.standard_b64encode(crypto.convert_pem_to_der(cert_pem)).decode(
                    "utf-8"
                )
                for cert_pem in cert_pems
            ]
            jws_JoseHeader.x5c.extend(cert_chain)
        jws.protected_header = tool.encode_base64(
            json_format.MessageToJson(jws_JoseHeader).encode("utf-8")
        )
        jws.payload = tool.encode_base64(
            json_format.MessageToJson(request).encode("utf-8")
        )

        jws.signature = tool.encode_base64(
            asymm.RsaSigner(private_key, "RS256")
            .update(jws.protected_header.encode("utf-8"))
            .update(b".")
            .update(jws.payload.encode("utf-8"))
            .sign()
        )

        jwe = jwt_pb2.Jwe()
        jwe_header = jwe.JoseHeader()
        jwe_header.alg = "RSA-OAEP-256"
        jwe_header.enc = "A128GCM"
        jwe.protected_header = tool.encode_base64(
            json_format.MessageToJson(jwe_header).encode("utf-8")
        )

        # generate temp data_key, it will be used to encrypt data
        data_key = AESGCM.generate_key(bit_length=128)
        # use public key of capsule manager to encrypt data key
        jwe.encrypted_key = tool.encode_base64(
            asymm.RsaEncryptor(public_key, "RSA-OAEP-256").encrypt(data_key)
        )

        nonce = crypto.gen_key(NONCE_SIZE_IN_SIZE)
        jwe.iv = tool.encode_base64(nonce)
        jwe.aad = ""

        (ciphertext, tag) = symm.AesGcmEncryptor(data_key, "A128GCM").encrypt(
            json_format.MessageToJson(jws).encode("utf-8"), nonce, b""
        )
        jwe.ciphertext = tool.encode_base64(ciphertext)
        jwe.tag = tool.encode_base64(tag)

        encrypted_request = capsule_manager_pb2.EncryptedRequest()
        encrypted_request.message.CopyFrom(jwe)
        encrypted_request.has_signature = True
        return encrypted_request

    @staticmethod
    def parse_from_encrypted_response(
        response: capsule_manager_pb2.EncryptedResponse,
        private_key: Union[bytes, str, rsa.RSAPrivateKey],
        msg: message.Message,
    ):
        """decrypt request

        Args:
            response: the item will be decrypted
            private_key: the private key of party, it will be used to decrypt
        """

        jwe = response.message
        jwe_header = jwe.JoseHeader()
        json_format.Parse(tool.decode_base64(jwe.protected_header), jwe_header)
        iv = tool.decode_base64(jwe.iv)
        ciphertext = tool.decode_base64(jwe.ciphertext)
        tag = tool.decode_base64(jwe.tag)
        add = tool.decode_base64(jwe.aad)

        data_key = asymm.RsaDecryptor(private_key, jwe_header.alg).decrypt(
            tool.decode_base64(jwe.encrypted_key)
        )
        plain_text = symm.AesGcmDecryptor(data_key, jwe_header.enc).decrypt(
            ciphertext, iv, add, tag
        )
        json_format.Parse(plain_text, msg)

    def get_public_key(self) -> bytes:
        """Get CapsuleManager public key"""
        request = capsule_manager_pb2.GetRaCertRequest()
        nonce_bytes = crypto.gen_key(32)
        request.nonce = tool.to_hex(nonce_bytes)
        response = self.stub.GetRaCert(request)
        if response.status.code != 0:
            raise CapsuleManagerError(response.status.code, response.status.message)
        assert len(response.cert) != 0, "The CapsuleManager should have public key."

        if self.tee_plat != TEE_PLAT_SIM:
            from trustflow.attestation.verification import verifier

            policy = ual_pb2.UnifiedAttestationPolicy()
            rule = policy.main_attributes.add()

            user_data = crypto.sha256(
                response.cert.encode("utf-8"), request.nonce.encode("utf-8")
            )
            rule.hex_user_data = tool.to_hex(user_data)

            if self.tee_plat == TEE_PLAT_SGX:
                rule.bool_debug_disabled = "true"
                rule.str_tee_platform = UAL_TEE_PLAT_SGX
                rule.hex_ta_measurement = self.tee_constraints.mr_ta
                rule.hex_signer = self.tee_constraints.mr_signer
            elif self.tee_plat == TEE_PLAT_TDX:
                rule.bool_debug_disabled = "true"
                rule.str_tee_platform = UAL_TEE_PLAT_TDX
                rule.hex_platform_measurement = self.tee_constraints.mr_plat
                rule.hex_boot_measurement = self.tee_constraints.mr_boot
                rule.hex_ta_measurement = self.tee_constraints.mr_ta
            elif self.tee_plat == TEE_PLAT_CSV:
                rule.str_tee_platform = UAL_TEE_PLAT_CSV
                rule.hex_boot_measurement = self.tee_constraints.mr_boot
            else:
                raise ValueError(f"Invalid TEE platform: {self.tee_plat}")

            report_json = json_format.MessageToJson(
                response.attestation_report, including_default_value_fields=True
            )
            policy_json = json_format.MessageToJson(
                policy, including_default_value_fields=True
            )
            verify_status = verifier.attestation_report_verify(report_json, policy_json)
            if verify_status.code != 0:
                raise RuntimeError(
                    f"attestation_report_verify failed. Code:{verify_status.code}, Message:{verify_status.message}, Details:{verify_status.details}."
                )

        cert = x509.load_pem_x509_certificate(response.cert.encode("utf-8"))
        return cert.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )

    def register_cert(
        self,
        owner_party_id: str,
        cert_pems: List[bytes],
        scheme: str,
        private_key: Union[bytes, str, rsa.RSAPrivateKey],
    ):
        """register cert

        Args:
            owner_party_id: data owner
            cert_pems: cert chain. cert_pems[0] is  current cert
            scheme: `RSA`, `SM2`
            private_key: private key of party

        """
        request = capsule_manager_pb2.RegisterCertRequest()
        request.owner_party_id = owner_party_id
        request.certs.extend([cert_pem.decode("utf-8") for cert_pem in cert_pems])
        request.scheme = scheme

        encrypted_response = self.stub.RegisterCert(
            self.create_encrypted_request(
                request, self.get_public_key(), private_key, None
            )
        )
        if encrypted_response.status.code != 0:
            raise CapsuleManagerError(
                encrypted_response.status.code, encrypted_response.status.message
            )

    def create_data_keys(
        self,
        owner_party_id: str,
        data_keys: List[dict],
        cert_pems: List[bytes] = None,
        private_key: Union[bytes, str, rsa.RSAPrivateKey] = None,
    ):
        """create data keys

        Args:
            owner_party_id: data owner
            data_keys: list of data_key, data_key is a dict contains "resource_uri" and "data_key_b64"
            cert_pems: cert chain of party
            private_key: private key of party

        """
        request = capsule_manager_pb2.CreateDataKeysRequest()
        request.owner_party_id = owner_party_id

        for data_key in data_keys:
            request.data_keys.add(
                resource_uri=data_key.get(RESOURCE_URI),
                data_key_b64=data_key.get(DATA_KEY_B64),
            )

        if private_key is None:
            # Generate temp RSA key-pair
            (private_key, cert_pems) = crypto.generate_rsa_keypair()

        encrypted_response = self.stub.CreateDataKeys(
            self.create_encrypted_request(
                request, self.get_public_key(), private_key, cert_pems
            )
        )
        if encrypted_response.status.code != 0:
            raise CapsuleManagerError(
                encrypted_response.status.code, encrypted_response.status.message
            )

    def get_data_policys(
        self,
        owner_party_id: str,
        scope: str,
        cert_pems: List[bytes] = None,
        private_key: Union[bytes, str, rsa.RSAPrivateKey] = None,
    ) -> List[capsule_manager_pb2.Policy]:
        """create data policy

        Args:
            owner_party_id: data policy's owner
            scope: scope
            cert_pems: cert chain of party
            private_key: private key of party

        Returns:
            List[capsule_manager_pb2.Policy]: the list of policy
        """
        request = capsule_manager_pb2.ListDataPolicyRequest()
        request.owner_party_id = owner_party_id
        request.scope = scope

        if private_key is None:
            # Generate temp RSA key-pair
            (private_key, cert_pems) = crypto.generate_rsa_keypair()

        encrypted_response = self.stub.ListDataPolicy(
            self.create_encrypted_request(
                request, self.get_public_key(), private_key, cert_pems
            )
        )
        if encrypted_response.status.code != 0:
            raise CapsuleManagerError(
                encrypted_response.status.code, encrypted_response.status.message
            )
        # decrypt request
        response = capsule_manager_pb2.ListDataPolicyResponse()
        self.parse_from_encrypted_response(encrypted_response, private_key, response)

        return list(response.policies)

    def create_data_policy(
        self,
        owner_party_id: str,
        scope: str,
        data_uuid: str,
        rules: List[dict],
        cert_pems: List[bytes] = None,
        private_key: Union[bytes, str, rsa.RSAPrivateKey] = None,
    ):
        """create data policy

        Args:
            owner_party_id: data owner
            scope: scope
            data_uuid: data id
            rules: list of rule, rule is a dict contains:
              rule_id: id of the rule
              grantee_party_ids: for every rule, the list of party ids being guanteed
              columns: for every rule, specify which columns can be used, if this is a structued data
              global_constraints: for every rule, gobal DSL decribed additional constraints
              op_constraints: list of op_constraint, it has op_name and corresponding constraints
            cert_pems: cert chain of party
            private_key: private key of party

        """
        request = capsule_manager_pb2.CreateDataPolicyRequest()
        request.owner_party_id = owner_party_id
        request.scope = scope
        request.policy.data_uuid = data_uuid

        for rule in rules:
            rule_add = request.policy.rules.add()
            rule_add.rule_id = rule.get(RULE_ID)
            if rule.get(GRANTEE_PARTY_IDS) is not None:
                rule_add.grantee_party_ids.extend(rule.get(GRANTEE_PARTY_IDS))
            if rule.get(COLUMNS) is not None:
                rule_add.columns.extend(rule.get(COLUMNS))
            if rule.get(GLOBAL_CONSTRAINTS) is not None:
                rule_add.global_constraints.extend(rule.get(GLOBAL_CONSTRAINTS))
            if rule.get(OP_CONSTRAINS) is not None:
                for op_constraint in rule.get(OP_CONSTRAINS):
                    constraints = (
                        op_constraint.get(CONSTRAINTS)
                        if op_constraint.get(CONSTRAINTS) is not None
                        else []
                    )
                    rule_add.op_constraints.add(
                        op_name=op_constraint.get(OP_NAME), constraints=constraints
                    )

        if private_key is None:
            # Generate temp RSA key-pair
            (private_key, cert_pems) = crypto.generate_rsa_keypair()

        encrypted_response = self.stub.CreateDataPolicy(
            self.create_encrypted_request(
                request, self.get_public_key(), private_key, cert_pems
            )
        )
        if encrypted_response.status.code != 0:
            raise CapsuleManagerError(
                encrypted_response.status.code, encrypted_response.status.message
            )

    def delete_data_policy(
        self,
        owner_party_id: str,
        scope: str,
        data_uuid: str,
        cert_pems: List[bytes] = None,
        private_key: Union[bytes, str, rsa.RSAPrivateKey] = None,
    ):
        """delete data policy

        Args:
            owner_party_id: data owner
            scope: scope
            data_uuid: data id
            cert_pems: cert chain of party
            private_key: private key of party

        """
        request = capsule_manager_pb2.DeleteDataPolicyRequest()
        request.owner_party_id = owner_party_id
        request.scope = scope
        request.data_uuid = data_uuid

        if private_key is None:
            # Generate temp RSA key-pair
            (private_key, cert_pems) = crypto.generate_rsa_keypair()

        encrypted_response = self.stub.DeleteDataPolicy(
            self.create_encrypted_request(
                request, self.get_public_key(), private_key, cert_pems
            )
        )
        if encrypted_response.status.code != 0:
            raise CapsuleManagerError(
                encrypted_response.status.code, encrypted_response.status.message
            )

    def add_data_rule(
        self,
        owner_party_id: str,
        scope: str,
        data_uuid: str,
        rule: dict,
        cert_pems: List[bytes] = None,
        private_key: Union[bytes, str, rsa.RSAPrivateKey] = None,
    ):
        """add data rule

        Args:
            owner_party_id: data owner
            scope: scope
            data_uuid: data id
            rule: rule is a dict contains:
              rule_id: id of the rule
              grantee_party_ids: for every rule, the list of party ids being guanteed
              columns: for every rule, specify which columns can be used, if this is a structued data
              global_constraints: for every rule, gobal DSL decribed additional constraints
              op_constraints: list of op_constraint, it has op_name and corresponding constraints
            cert_pems: cert chain of party
            private_key: private key of party

        """
        request = capsule_manager_pb2.AddDataRuleRequest()
        request.owner_party_id = owner_party_id
        request.data_uuid = data_uuid
        request.scope = scope

        request.rule.rule_id = rule.get(RULE_ID)
        if rule.get(GRANTEE_PARTY_IDS) is not None:
            request.rule.grantee_party_ids.extend(rule.get(GRANTEE_PARTY_IDS))
        if rule.get(COLUMNS) is not None:
            request.rule.columns.extend(rule.get(COLUMNS))
        if rule.get(GLOBAL_CONSTRAINTS) is not None:
            request.rule.global_constraints.extend(rule.get(GLOBAL_CONSTRAINTS))
        if rule.get(OP_CONSTRAINS) is not None:
            for op_constraint in rule.get(OP_CONSTRAINS):
                constraints = (
                    op_constraint.get(CONSTRAINTS)
                    if op_constraint.get(CONSTRAINTS) is not None
                    else []
                )
                request.rule.op_constraints.add(
                    op_name=op_constraint.get(OP_NAME), constraints=constraints
                )

        if private_key is None:
            # Generate temp RSA key-pair
            (private_key, cert_pems) = crypto.generate_rsa_keypair()

        encrypted_response = self.stub.AddDataRule(
            self.create_encrypted_request(
                request, self.get_public_key(), private_key, cert_pems
            )
        )
        if encrypted_response.status.code != 0:
            raise CapsuleManagerError(
                encrypted_response.status.code, encrypted_response.status.message
            )

    def delete_data_rule(
        self,
        owner_party_id: str,
        scope: str,
        data_uuid: str,
        rule_id: str,
        cert_pems: List[bytes] = None,
        private_key: Union[bytes, str, rsa.RSAPrivateKey] = None,
    ):
        """delete data rule

        Args:
            owner_party_id: data owner
            scope: scope
            data_uuid: data id
            rule_id: identifier of rule
            cert_pems: cert chain of party
            private_key: private key of party

        """
        request = capsule_manager_pb2.DeleteDataRuleRequest()
        request.owner_party_id = owner_party_id
        request.scope = scope
        request.data_uuid = data_uuid
        request.rule_id = rule_id

        if private_key is None:
            # Generate temp RSA key-pair
            (private_key, cert_pems) = crypto.generate_rsa_keypair()

        encrypted_response = self.stub.DeleteDataRule(
            self.create_encrypted_request(
                request, self.get_public_key(), private_key, cert_pems
            )
        )
        if encrypted_response.status.code != 0:
            raise CapsuleManagerError(
                encrypted_response.status.code, encrypted_response.status.message
            )

    def get_export_data_key_b64(
        self,
        request_party_id: str,
        resource_uri: str,
        data_export_certificate: str,
        cert_pems: List[bytes] = None,
        private_key: Union[bytes, str, rsa.RSAPrivateKey] = None,
    ) -> str:
        """get export base64 encoded data key

        Args:
            request_party_id: the request owner
            resource_uri: the identifier of resource
            data_export_certificate: Data Export Certificate, json format
                When the data request exporting party requests to obtain the decryption key
                for accessing the data, they need to obtain the signatures of all the
                original owners of the data, the request information, and the signature of
                the original owner, which together constitute the data export certificate.
        """
        request = capsule_manager_pb2.GetExportDataKeyRequest()
        request.request_party_id = request_party_id
        request.resource_uri = resource_uri
        request.data_export_certificate = data_export_certificate

        if private_key is None:
            # Generate temp RSA key-pair
            (private_key, cert_pems) = crypto.generate_rsa_keypair()

        encrypted_response = self.stub.GetExportDataKey(
            self.create_encrypted_request(
                request, self.get_public_key(), private_key, cert_pems
            )
        )
        if encrypted_response.status.code != 0:
            raise CapsuleManagerError(
                encrypted_response.status.code, encrypted_response.status.message
            )
        # decrypt request
        response = capsule_manager_pb2.GetExportDataKeyResponse()
        self.parse_from_encrypted_response(encrypted_response, private_key, response)
        return response.data_key.data_key_b64

    def delete_data_key(
        self,
        owner_party_id: str,
        resource_uri: str,
        cert_pems: List[bytes] = None,
        private_key: Union[bytes, str, rsa.RSAPrivateKey] = None,
    ):
        """delete data key

        Args:
            owner_party_id: data owner
            resource_uri: the resource uri corresponding to the data key
            cert_pems: cert chain of party
            private_key: private key of party

        """
        request = capsule_manager_pb2.DeleteDataKeyRequest()
        request.owner_party_id = owner_party_id
        request.resource_uri = resource_uri

        if private_key is None:
            # Generate temp RSA key-pair
            (private_key, cert_pems) = crypto.generate_rsa_keypair()

        encrypted_response = self.stub.DeleteDataKey(
            self.create_encrypted_request(
                request, self.get_public_key(), private_key, cert_pems
            )
        )
        if encrypted_response.status.code != 0:
            raise CapsuleManagerError(
                encrypted_response.status.code, encrypted_response.status.message
            )
