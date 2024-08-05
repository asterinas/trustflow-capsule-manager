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
import json

import click
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from sdc.crypto import asymm
from sdc.util import crypto, file, tool

VOTE_REQUEST = "vote_request"
CERT_CHAIN_FILE = "cert_chain_file"
CERT_CHAIN = "cert_chain"
BODY = "body"
PRIVATE_KEY_FILE = "private_key_file"
VOTE_REQUEST_SIGNATURE = "vote_request_signature"
VOTER_SIGNATURE = "voter_signature"
VOTE_INVITE = "vote_invite"


@click.group()
def cms_util():
    pass


@cms_util.command()
@click.option(
    "--private-key-file",
    type=click.STRING,
    help="file path for storing private key",
)
@click.option(
    "--cert-file",
    type=click.STRING,
    help="file path for storing cert chain which is list",
)
def generate_rsa_keypair(private_key_file, cert_file):
    """
    generate rsa key pair (private_key, cert_chain)
    """
    (
        pri_key_pem,
        cert_pems,
    ) = crypto.generate_rsa_keypair()
    if private_key_file:
        file.write_file(private_key_file, "w", pri_key_pem.decode("utf-8"))
    if cert_file:
        file.write_file(cert_file, "w", cert_pems[0].decode("utf-8"))


@cms_util.command()
@click.option(
    "--cert-file",
    type=click.STRING,
    multiple=True,
    required=True,
    help="a list of cert files, the order is important, the last file is CA cert",
)
def generate_party_id(cert_file):
    """
    generate the party id according to the certificate
    """
    cert_chain = []
    for cert in cert_file:
        cert_chain.append(file.read_file(cert, "r"))
    print(tool.generate_party_id_from_cert(cert_chain[-1].encode("utf-8")))


@cms_util.command()
@click.option(
    "--bit-len", type=click.INT, default=128, help="the bit len of secret key"
)
def generate_data_key_b64(bit_len):
    """
    generate the base64 encode data key
    """
    data_key = AESGCM.generate_key(bit_len)
    print(base64.b64encode(data_key).decode("utf-8"))


@cms_util.command()
@click.option(
    "--source-file",
    type=click.STRING,
    required=True,
    help="the source file which needs to be encrypted",
)
@click.option(
    "--dest-file",
    type=click.STRING,
    help="the dest file which stores encrypted data",
)
@click.option(
    "--data-key-b64",
    type=click.UNPROCESSED,
    required=True,
    help="the secret key used to encrypt data in base64 encode format",
)
def encrypt_file(source_file, dest_file, data_key_b64):
    """
    encrypt file using data key
    """
    data_key: bytes = base64.b64decode(data_key_b64)
    if dest_file is None or len(dest_file) == 0:
        dest_file = source_file + ".enc"
    crypto.encrypt_file(source_file, dest_file, data_key)


@cms_util.command()
@click.option(
    "--source-file",
    type=click.STRING,
    required=True,
    help="the source file which needs to be decrypted",
)
@click.option(
    "--dest-file",
    type=click.STRING,
    help="the dest file which stores decrypted data",
)
@click.option(
    "--data-key-b64",
    type=click.UNPROCESSED,
    required=True,
    help="the secret key used to decrypt data in base64 encode format",
)
def decrypt_file(source_file, dest_file, data_key_b64):
    """
    decrypt file using data key
    """
    data_key: bytes = base64.b64decode(data_key_b64)
    if dest_file is None or len(dest_file) == 0:
        dest_file = source_file + ".dec"
    crypto.decrypt_file(source_file, dest_file, data_key)


@cms_util.command()
@click.option(
    "--file",
    type=click.STRING,
    required=True,
    help="the file which needs to be encrypted",
)
@click.option(
    "--data-key-b64",
    type=click.UNPROCESSED,
    required=True,
    help="the secret key used to decrypt data in base64 encode format",
)
def encrypt_file_inplace(file, data_key_b64):
    """
    encrypt file inplace using data key, it will change origin file
    """
    data_key: bytes = base64.b64decode(data_key_b64)
    crypto.encrypt_file_inplace(file, data_key)


@cms_util.command()
@click.option(
    "--file",
    type=click.STRING,
    required=True,
    help="the file which needs to be decrypted",
)
@click.option(
    "--data-key-b64",
    type=click.UNPROCESSED,
    required=True,
    help="the secret key used to decrypt data in base64 encode format",
)
def decrypt_file_inplace(file, data_key_b64):
    """
    decrypt file inplace using data key, it will change origin file
    """
    data_key: bytes = base64.b64decode(data_key_b64)
    crypto.decrypt_file_inplace(file, data_key)


@cms_util.command()
@click.option(
    "--vote-request-file",
    type=click.STRING,
    required=True,
    help="the original vote request file",
)
@click.option(
    "--signed-vote-request-file",
    type=click.STRING,
    required=True,
    help="the signed vote request file",
)
def sign_vote_request(vote_request_file, signed_vote_request_file):
    """
    generate the vote request with signature when exporting the result data
    """
    config = file.read_yaml_file(vote_request_file)
    vote_request = config[VOTE_REQUEST]
    signed_vote_request = dict()

    cert_chain = list()
    if vote_request.get(CERT_CHAIN_FILE) is not None:
        for filename in vote_request.pop(CERT_CHAIN_FILE):
            cert_chain.append(file.read_file(filename, "r"))
    signed_vote_request[CERT_CHAIN] = cert_chain

    if vote_request.get(PRIVATE_KEY_FILE) is not None:
        private_key = file.read_file(vote_request.pop(PRIVATE_KEY_FILE), "r").encode(
            "utf-8"
        )
        vote_body_str = json.dumps(vote_request)
        vote_body_b64 = base64.b64encode(vote_body_str.encode("utf-8")).decode("utf-8")
        signed_vote_request[BODY] = vote_body_b64

        # vote_request_signature
        signature_b64 = base64.b64encode(
            asymm.RsaSigner(private_key, "RS256")
            .update(vote_body_b64.encode("utf-8"))
            .sign()
        ).decode("utf-8")
        signed_vote_request[VOTE_REQUEST_SIGNATURE] = signature_b64

    file.write_yaml_file(signed_vote_request, signed_vote_request_file)


@cms_util.command()
@click.option(
    "--voter-file", type=click.STRING, required=True, help="the voter's config file"
)
@click.option(
    "--signed-voter-file",
    type=click.STRING,
    required=True,
    help="the voter's signed file",
)
def voter_sign(voter_file, signed_voter_file):
    """
    generate voter signature when exporting the result data
    """
    voter = file.read_yaml_file(voter_file)
    voter_signed = dict()

    cert_chain = list()
    if voter.get(CERT_CHAIN_FILE) is not None:
        for filename in voter.pop(CERT_CHAIN_FILE):
            cert_chain.append(file.read_file(filename, "r"))
    voter_signed[CERT_CHAIN] = cert_chain

    # get private key
    private_key = file.read_file(voter.pop(PRIVATE_KEY_FILE), "r").encode("utf-8")
    # get requester's sign
    request_sign = voter.pop(VOTE_REQUEST_SIGNATURE)

    body_str = json.dumps(voter)
    body_b64 = base64.b64encode(body_str.encode("utf-8")).decode("utf-8")
    voter_signed[BODY] = body_b64

    signature_b64 = base64.b64encode(
        asymm.RsaSigner(private_key, "RS256")
        .update(body_b64.encode("utf-8"))
        .update(request_sign.encode("utf-8"))
        .sign()
    ).decode("utf-8")

    voter_signed[VOTER_SIGNATURE] = signature_b64
    file.write_yaml_file(voter_signed, signed_voter_file)


@cms_util.command()
@click.option(
    "--signed-vote-request-file",
    type=click.STRING,
    required=True,
    help="the signed vote request file",
)
@click.option(
    "--signed-voter-files",
    type=click.STRING,
    required=True,
    multiple=True,
    help="the voter's signed files",
)
@click.option(
    "--vote-result-file",
    type=click.STRING,
    required=True,
    help="the file to store voting result",
)
def generate_vote_result(
    signed_vote_request_file, signed_voter_files, vote_result_file
):
    """
    generate vote result json from signed-vote-request-file and signed-voter-files
    """
    vote_result_config = dict()

    vote_request = dict()
    vote_request_config = file.read_yaml_file(signed_vote_request_file)
    vote_request[CERT_CHAIN] = vote_request_config[CERT_CHAIN]
    vote_request[BODY] = vote_request_config[BODY]
    vote_request[VOTE_REQUEST_SIGNATURE] = vote_request_config[VOTE_REQUEST_SIGNATURE]

    vote_invite = list()
    for signed_voter_file in signed_voter_files:
        signed_voter_config = file.read_yaml_file(signed_voter_file)
        vote_invite_item = dict()
        vote_invite_item[CERT_CHAIN] = signed_voter_config[CERT_CHAIN]
        vote_invite_item[BODY] = signed_voter_config[BODY]
        vote_invite_item[VOTER_SIGNATURE] = signed_voter_config[VOTER_SIGNATURE]
        vote_invite.append(vote_invite_item)

    vote_result_config[VOTE_REQUEST] = vote_request
    vote_result_config[VOTE_INVITE] = vote_invite

    file.write_file(vote_result_file, "w", json.dumps(vote_result_config))


if __name__ == "__main__":
    cms_util()
