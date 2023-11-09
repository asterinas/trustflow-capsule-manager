
# CapsuleManager

CapsuleManager is an Authorization Management Service, which is designed to manage metadata of user data and authorization information.

## Features

- CapsuleManager runs on the Intel SGX Machine, it will be remote attested by the user who uploads data to ensure that the CapsuleManager has no malicious behavior
- CapsuleManager uses signatures, digital envelopes, etc. to prevent communication data from being tampered, and it also supports mTLS
- CapsuleManager manages the data encryption keys and meta-informations. All services which want to get these information must be verified to have the authorization to obtain the data encryption keys and meta-informations, ensuring that the authorization semantics cannot be bypassed
- CapsuleManager supports flexible authorization semantics

## Build And Run By Source Code

there are two modes in the CapsuleManager: simulation mode, production mode

### Prepare

- get submodule in the current directory

```bash
git clone xxx
git submodule init
git submodule update --init --remote --recursive
```

until now, we pull code from github to the directory "capsule-manager-tonic/secretflow_apis/" and "second_party/unified-attestation/"

### Simulation Mode

Remote Attestation is not enabled for this mode

```bash
# create docker image
bash sgx2-ubuntu.sh
# enter docker image
bash sgx2-ubuntu.sh enter
# build exe and occlum
MODE=SIM bash deployment/build.sh
#
cd occlum_release
# enable tls(often skip)
# if you want to use the mTLS, you can refer to the mTLS part
# run service
# if the port is occupied, you can modify the field port in the config.yaml
occlum run /bin/capsule_manager --config_path /host/config.yaml
```

### Production Mode(default mode)

Remote Attestation is enabled for this mode
NOTICE: if you modify any field in the configuration file in occlum release, you must execute command "occlum build -f --sign-key <path_to/your_key.pem>"

```bash
# create docker image
bash sgx2-ubuntu.sh
# enter docker image
bash sgx2-ubuntu.sh enter
# build exe and occlum
bash deployment/build.sh
#
cd occlum_release
# enable tls(often skip)
# if you want to use the mTLS, you can refer to the mTLS part
# connect to pccs service
modify /etc/sgx_default_qcnl.conf pccs_url
modify /etc/sgx_default_qcnl.conf use_secure_cert=false
modify image/etc/kubetee/unified_attestation.json ua_dcap_pccs_url
# Generate a pair of public and private keys
occlum build -f --sign-key <path_to/your_key.pem>
# run service
occlum run /bin/capsule_manager --config_path /host/config.yaml --enable-tls=false
```

## Run Quickly by Docker Image

there are two kinds of docker images, corresponding to simulation mode and production mode

### Simulation Mode Image

```bash
# pull docker image
docker pull xxxx
# enter docker image
sudo docker run -it --net host xxxx
#
cd occlum_release
# enable tls(often skip)
# if you want to use the mTLS, you can refer to the mTLS part
# run service
occlum run /bin/capsule_manager --config_path /host/config.yaml
```

### Production Mode Image

```bash
# pull docker image
docker pull secretflow/capsule-manager-release:latest
# enter docker image
docker run -it --net host -v /dev/sgx_enclave:/dev/sgx/enclave -v /dev/sgx_provision:/dev/sgx/provision --privileged=true secretflow/capsule-manager-release:latest
#
cd occlum_release
# enable tls(often skip)
# if you want to use the mTLS, you can refer to the mTLS part
# connect to pccs service
modify /etc/sgx_default_qcnl.conf pccs_url
modify /etc/sgx_default_qcnl.conf use_secure_cert=false
modify image/etc/kubetee/unified_attestation.json ua_dcap_pccs_url
# Generate a pair of public and private keys
occlum build -f --sign-key <path_to/your_key.pem>
# run service
occlum run /bin/capsule_manager --config_path /host/config.yaml --enable-tls=false
```

## Mutual Tls

you must generate certificate if you want to use mTLS feature of CapsuleManager

- for CapsuleManager, all certificates should be put in the directory whose path is ”capsule-manager/resources“
- for CapsuleManager, the required certificates are the Server Key, the Server Certificate, and the Client CA Certificate which is used to verify the Client Certificate
- for Client, the required certificates are the Client Key, the Client Certificate, and the Server CA Certificate which is used to verify the Server Certificate
- for CapsuleManager, you should modify the field server_cert_path, server_cert_key_path and client_ca_cert_path in the configuration file named config.yaml
- when all is ready, you can enable mTLS by modifying the field enable_tls in the the configuration file named config.yaml to true

## Contributing

Please check [CONTRIBUTING.md](CONTRIBUTING.md)

## License

This project is licensed under the [Apache License](LICENSE)
