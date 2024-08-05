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
import socket
import unittest

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from sdc.capsule_manager_frame import CapsuleManagerFrame
from sdc.util import crypto
from tests.util.mock_capsule_manager import start_server


def pick_unused_port():
    sock = socket.socket()
    sock.bind(("127.0.0.1", 0))
    return sock.getsockname()[1]


class TestCapsuleManager(unittest.TestCase):
    def __init__(self, *args, **kwargs):
        super(TestCapsuleManager, self).__init__(*args, **kwargs)

        self.port = pick_unused_port()
        self.server = start_server(self.port)

        (self.pri_key_pem, self.cert_pems) = crypto.generate_rsa_keypair()

    def test_get_pk(self):
        auth_frame = CapsuleManagerFrame(
            f"127.0.0.1:{self.port}",
            "sim",
            "1083D6017E951017EB29611024D63D4DF73445DD880D1151E776541FEBE4A776",
            None,
        )
        public_key_pem = auth_frame.get_public_key()
        self.assertGreater(len(public_key_pem), 0)

    def test_data_keys(self):
        auth_frame = CapsuleManagerFrame(
            f"127.0.0.1:{self.port}",
            "sim",
            "1083D6017E951017EB29611024D63D4DF73445DD880D1151E776541FEBE4A776",
            None,
        )
        auth_frame.register_cert("alice", self.cert_pems, "RSA", self.pri_key_pem)
        data_key_b64 = base64.b64encode(AESGCM.generate_key(bit_length=128))
        data_keys = [{"resource_uri": "dataA", "data_key_b64": data_key_b64}]
        auth_frame.create_data_keys("alice", data_keys, None, self.pri_key_pem)
        rules = [
            {
                "rule_id": "rule1",
                "grantee_party_ids": ["bob"],
                "columns": ["id"],
                "global_constraints": None,
                "op_constraints": [{"op_name": "*", "constraints": None}],
            }
        ]
        auth_frame.create_data_policy(
            "alice",
            "default",
            "dataA",
            rules,
            None,
            self.pri_key_pem,
        )

        result = auth_frame.get_data_policys("alice", "default", None, self.pri_key_pem)

        self.assertEqual(len(result), 1)
        self.assertEqual(len(result[0].rules), 1)

        rule = {
            "rule_id": "rule2",
            "grantee_party_ids": ["carol"],
            "columns": ["name"],
            "global_constraints": None,
            "op_constraints": [
                {
                    "op_name": "OP_PSI",
                    "constraints": ["r.env.sgx.mr_enclave=mr_enclave"],
                }
            ],
        }
        auth_frame.add_data_rule(
            "alice",
            "default",
            "dataA",
            rule,
            None,
            self.pri_key_pem,
        )
        result = auth_frame.get_data_policys("alice", "default", None, self.pri_key_pem)

        self.assertEqual(len(result), 1)
        self.assertEqual(len(result[0].rules), 2)

        auth_frame.delete_data_rule(
            "alice", "default", "dataA", "rule1", None, self.pri_key_pem
        )
        result = auth_frame.get_data_policys("alice", "default", None, self.pri_key_pem)

        self.assertEqual(len(result), 1)
        self.assertEqual(len(result[0].rules), 1)

        auth_frame.delete_data_policy(
            "alice", "default", "dataA", None, self.pri_key_pem
        )
        result = auth_frame.get_data_policys("alice", "default", None, self.pri_key_pem)

        self.assertEqual(len(result), 0)


if __name__ == "__main__":
    unittest.main()
