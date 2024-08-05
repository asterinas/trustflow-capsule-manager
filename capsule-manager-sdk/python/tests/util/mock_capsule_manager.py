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

from concurrent import futures
from typing import Union

import grpc
from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import rsa
from google.protobuf import json_format, message
from sdc.crypto import asymm, symm
from sdc.util import crypto, tool
from secretflowapis.v2 import status_pb2
from secretflowapis.v2.sdc import jwt_pb2
from secretflowapis.v2.sdc.capsule_manager import (
    capsule_manager_pb2,
    capsule_manager_pb2_grpc,
)


class CapsuleManagerServer(capsule_manager_pb2_grpc.CapsuleManagerServicer):
    def __init__(self):
        (self._pri_key, self._certs) = crypto.generate_rsa_keypair()
        self._data_policys = {}
        self._data_keys = {}
        self._party_cert = {}

    def encrypt_response(
        self,
        msg: message.Message,
        public_key_pem: Union[bytes, rsa.RSAPublicKey],
    ) -> capsule_manager_pb2.EncryptedResponse:
        data_key = crypto.gen_key(16)
        iv = crypto.gen_key(32)
        add = b""

        jwe = jwt_pb2.Jwe()
        jwe_header = jwe.JoseHeader()
        jwe_header.alg = "RSA-OAEP-256"
        jwe_header.enc = "A128GCM"

        (ciphertext, tag) = symm.AesGcmEncryptor(data_key, jwe_header.enc).encrypt(
            json_format.MessageToJson(msg).encode("utf-8"), iv, add
        )
        encrypted_data_key = asymm.RsaEncryptor(public_key_pem, jwe_header.alg).encrypt(
            data_key
        )
        jwe.protected_header = tool.encode_base64(
            json_format.MessageToJson(jwe_header).encode("utf-8")
        )
        jwe.encrypted_key = tool.encode_base64(encrypted_data_key)
        jwe.iv = tool.encode_base64(iv)
        jwe.aad = ""
        jwe.ciphertext = tool.encode_base64(ciphertext)
        jwe.tag = tool.encode_base64(tag)

        return capsule_manager_pb2.EncryptedResponse(
            status=status_pb2.Status(code=0), message=jwe
        )

    def parse_encrypted_request(
        self,
        request: capsule_manager_pb2.EncryptedRequest,
        private_key: Union[bytes, str, rsa.RSAPrivateKey],
        msg: message.Message,
    ):
        jwe = request.message
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

        if not request.has_signature:
            json_format.Parse(plain_text, msg)
        else:
            jws = jwt_pb2.Jws()
            json_format.Parse(plain_text, jws)
            json_format.Parse(tool.decode_base64(jws.payload), msg)

    def GetRaCert(
        self, request: capsule_manager_pb2.GetRaCertRequest, context
    ) -> capsule_manager_pb2.GetRaCertResponse:
        return capsule_manager_pb2.GetRaCertResponse(
            status=status_pb2.Status(code=0),
            attestation_report=None,
            cert=self._certs[0],
        )

    def GetDataKeys(
        self, request: capsule_manager_pb2.EncryptedRequest, context
    ) -> capsule_manager_pb2.EncryptedResponse:
        request_content = capsule_manager_pb2.GetDataKeysRequest()
        self.parse_encrypted_request(request, self._pri_key, request_content)
        resource_uris = [
            resource.resource_uri
            for resource in request_content.resource_request.resources
        ]
        response_content = capsule_manager_pb2.GetDataKeysResponse()
        for resource_uri in resource_uris:
            if resource_uri in self._data_keys:
                response_content.data_keys.add(
                    resource_uri=resource_uri,
                    data_key_b64=self._data_keys[resource_uri][0],
                )
        response_content.cert = self._certs[0]
        return self.encrypt_response(
            response_content,
            x509.load_pem_x509_certificate(
                request_content.cert.encode("utf-8")
            ).public_key(),
        )

    def CreateDataPolicy(
        self, request: capsule_manager_pb2.EncryptedRequest, context
    ) -> capsule_manager_pb2.EncryptedResponse:
        request_content = capsule_manager_pb2.CreateDataPolicyRequest()
        self.parse_encrypted_request(request, self._pri_key, request_content)

        key = "{}/{}".format(request_content.scope, request_content.policy.data_uuid)
        self._data_policys[key] = (
            request_content.policy,
            request_content.owner_party_id,
            request_content.scope,
        )
        return capsule_manager_pb2.EncryptedResponse(
            status=status_pb2.Status(code=0), message=None
        )

    def ListDataPolicy(
        self, request: capsule_manager_pb2.EncryptedRequest, context
    ) -> capsule_manager_pb2.EncryptedResponse:
        request_content = capsule_manager_pb2.ListDataPolicyRequest()
        self.parse_encrypted_request(request, self._pri_key, request_content)
        response_content = capsule_manager_pb2.ListDataPolicyResponse()
        for value in self._data_policys.values():
            (policy, party_id, scope) = (value[0], value[1], value[2])
            if (
                request_content.owner_party_id == party_id
                and request_content.scope == scope
            ):
                response_content.policies.append(policy)
        return self.encrypt_response(
            response_content,
            x509.load_pem_x509_certificate(
                self._party_cert[request_content.owner_party_id].encode("utf-8")
            ).public_key(),
        )

    def AddDataRule(
        self, request: capsule_manager_pb2.EncryptedRequest, context
    ) -> capsule_manager_pb2.EncryptedResponse:
        request_content = capsule_manager_pb2.AddDataRuleRequest()
        self.parse_encrypted_request(request, self._pri_key, request_content)
        key = "{}/{}".format(request_content.scope, request_content.data_uuid)
        if key in self._data_policys:
            if (
                self._data_policys[key][0].data_uuid == request_content.data_uuid
                and self._data_policys[key][1] == request_content.owner_party_id
            ):
                self._data_policys[key][0].rules.append(request_content.rule)
            else:
                raise RuntimeError("data uuid or party id is wrong")
        else:
            self._data_policys[key] = (
                capsule_manager_pb2.Policy(
                    data_uuid=request_content.data_uuid, rules=[request_content.rule]
                ),
                request_content.owner_party_id,
                request_content.scope,
            )
        return capsule_manager_pb2.EncryptedResponse(
            status=status_pb2.Status(code=0), message=None
        )

    def DeleteDataPolicy(
        self, request: capsule_manager_pb2.EncryptedRequest, context
    ) -> capsule_manager_pb2.EncryptedResponse:
        request_content = capsule_manager_pb2.DeleteDataPolicyRequest()
        self.parse_encrypted_request(request, self._pri_key, request_content)
        key = "{}/{}".format(request_content.scope, request_content.data_uuid)
        if key in self._data_policys:
            if (
                self._data_policys[key][0].data_uuid == request_content.data_uuid
                and self._data_policys[key][1] == request_content.owner_party_id
            ):
                self._data_policys.pop(key, None)
            else:
                raise RuntimeError("data uuid or party id is wrong")
        return capsule_manager_pb2.EncryptedResponse(
            status=status_pb2.Status(code=0), message=None
        )

    def DeleteDataRule(
        self, request: capsule_manager_pb2.EncryptedRequest, context
    ) -> capsule_manager_pb2.EncryptedResponse:
        request_content = capsule_manager_pb2.DeleteDataRuleRequest()
        self.parse_encrypted_request(request, self._pri_key, request_content)
        key = "{}/{}".format(request_content.scope, request_content.data_uuid)
        if key in self._data_policys:
            if (
                self._data_policys[key][0].data_uuid == request_content.data_uuid
                and self._data_policys[key][1] == request_content.owner_party_id
            ):
                remove_index = -1
                for index in range(len(self._data_policys[key][0].rules)):
                    if (
                        self._data_policys[key][0].rules[index].rule_id
                        == request_content.rule_id
                    ):
                        remove_index = index
                        break
                if remove_index != -1:
                    del self._data_policys[key][0].rules[remove_index]
            else:
                raise RuntimeError("data uuid or party id is wrong")
        return capsule_manager_pb2.EncryptedResponse(
            status=status_pb2.Status(code=0), message=None
        )

    def CreateDataKeys(
        self, request: capsule_manager_pb2.EncryptedRequest, context
    ) -> capsule_manager_pb2.EncryptedResponse:
        request_content = capsule_manager_pb2.CreateDataKeysRequest()
        self.parse_encrypted_request(request, self._pri_key, request_content)
        for data_key in request_content.data_keys:
            self._data_keys[data_key.resource_uri] = (
                data_key.data_key_b64,
                request_content.owner_party_id,
            )

        return capsule_manager_pb2.EncryptedResponse(
            status=status_pb2.Status(code=0), message=None
        )

    def RegisterCert(
        self, request: capsule_manager_pb2.EncryptedRequest, context
    ) -> capsule_manager_pb2.EncryptedResponse:
        request_content = capsule_manager_pb2.RegisterCertRequest()
        self.parse_encrypted_request(request, self._pri_key, request_content)
        self._party_cert[request_content.owner_party_id] = request_content.certs[0]
        return capsule_manager_pb2.EncryptedResponse(
            status=status_pb2.Status(code=0), message=None
        )


def start_server(port):
    server = grpc.server(futures.ThreadPoolExecutor(max_workers=5))
    capsule_manager_pb2_grpc.add_CapsuleManagerServicer_to_server(
        CapsuleManagerServer(), server
    )
    server.add_insecure_port(f"[::]:{port}")
    server.start()
    return server
