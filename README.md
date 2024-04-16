# CapsuleManager
[![CircleCI](https://dl.circleci.com/status-badge/img/gh/secretflow/capsule-manager/tree/main.svg?style=svg)](https://dl.circleci.com/status-badge/redirect/gh/secretflow/capsule-manager/tree/main)

CapsuleManager is an Authorization Management Service, which is designed to manage metadata of user data and authorization information.

## Features

- CapsuleManager supports running on different TEE platforms: Intel SGX2, Intel TDX, and Hygon Csv. It will be remote attested by the user who uploads data to ensure that the CapsuleManager has no malicious behavior.
- CapsuleManager uses signatures, digital envelopes, etc. to prevent communication data from being tampered, and it also supports mTLS
- CapsuleManager manages the data encryption keys and meta-informations. All services which want to get these information must be verified to have the authorization to obtain the data encryption keys and meta-informations, ensuring that the authorization semantics cannot be bypassed
- CapsuleManager supports flexible authorization semantics

## Run Quickly by Docker Image

If you want to try CapsuleManager quickly, you can use the official Docker image directly.

At present, there are four official images: sim/sgx/tdx/csv, which correspond to Simulation mode, Intel SGX2 mode, Intel TDX mode, and Hygon Csv mode.

### Simulation Mode

    ```bash
    # pull docker image
    docker pull secretflow/capsule-manager-sim-ubuntu22.04:latest

    # enter docker container
    docker run -it --name capsule-manager-sim --net host secretflow/capsule-manager-sim-ubuntu22.04:latest bash

    # enable TLS(often skip in simulation mode)
    # if you want to use the mTLS, you can refer to the mTLS part
    # run service
    ./capsule_manager --enable-tls false
    ```

### SGX Mode

1. Pull and run SGX docker image

    ```bash
    # pull docker image
    docker pull secretflow/capsule-manager-sgx-ubuntu22.04:latest

    # enter docker image

    docker run -it --name capsule-manager-sgx --net host \
        -v /dev/sgx_enclave:/dev/sgx/enclave \
        -v /dev/sgx_provision:/dev/sgx/provision \
        --privileged=true \
        secretflow/capsule-manager-sgx-ubuntu22.04:latest \
        bash
    ```

2. Modify PCCS config

* Set real `pccs_url` and set `use_secure_cert` to **false** in /etc/sgx_default_qcnl.conf.

* Copy /etc/sgx_default_qcnl.conf to occlum instance image
    ```bash
    cp /etc/sgx_default_qcnl.conf \
       /home/teeapp/occlum/occlum_instance/image/etc/
    ```
3. Build Occlum
* First, you need to generate a pair of public and private keys for signing Occlum instances. If you do not have one, you can refer to the following command to generate:
  ``` bash
  openssl genrsa -3 -out private_key.pem 3072

  openssl rsa -in private_key.pem -pubout -out public_key.pem
  ```
* Build occlum with your private key:
  ```bash
  occlum build -f --sign-key /path/to/private_key.pem
  ```

4. Run Capsule Manager

    By default, `enable-tls` is **true**. You can configure mTLS by referring to Mutual TLS：
    ```bash
    occlum run /bin/capsule_manager --enable-tls false
    ```

### TDX Mode
1. Pull and run TDX docker image

    ```bash
    # pull docker image
    docker pull secretflow/capsule-manager-tdx-ubuntu22.04:latest

    # enter docker image

    docker run -it --name capsule-manager-tdx --net host \
        -v /dev/tdx_guest:/dev/tdx_guest \
        --privileged=true \
        secretflow/capsule-manager-tdx-ubuntu22.04:latest \
        bash
    ```

2. Modify PCCS config

    Set real `pccs_url` and set `use_secure_cert` to **false** in /etc/sgx_default_qcnl.conf.

3. Run Capsule Manager

    By default, `enable-tls` is **true**. You can configure mTLS by referring to Mutual TLS：
    ```bash
    ./capsule_manager --enable-tls false
    ```

### CSV Mode
1. Pull and run CSV docker image

    ```bash
    # pull docker image
    docker pull secretflow/capsule-manager-csv-ubuntu22.04:latest

    # enter docker image

    docker run -it --name capsule-manager-csv --net host \
        -v /dev/csv-guest:/dev/csv-guest \
        --privileged=true \
        secretflow/capsule-manager-csv-ubuntu22.04:latest \
        bash
    ```
2. Run Capsule Manager

    By default, `enable-tls` is **true**. You can configure mTLS by referring to Mutual TLS：
    ```bash
    ./capsule_manager --enable-tls false
    ```

## Mutual TLS

you must generate certificate if you want to use mTLS feature of CapsuleManager

- for CapsuleManager, all certificates should be put in the directory whose path is ”capsule-manager/resources“
- for CapsuleManager, the required certificates are the Server Key, the Server Certificate, and the Client CA Certificate which is used to verify the Client Certificate
- for Client, the required certificates are the Client Key, the Client Certificate, and the Server CA Certificate which is used to verify the Server Certificate
- for CapsuleManager, you should modify the field server_cert_path, server_cert_key_path and client_ca_cert_path in the configuration file named config.yaml
- when all is ready, you can enable mTLS by modifying the field enable_tls in the the configuration file named config.yaml to true

## Build And Run By Source Code

If you want to build from source code, you can refer to the following, which should be noted that the build process does not need to be hardware dependent, but the run process does need to be hardware dependent. So if you need to run the program after build, and you need to mount the device when creating the container, executing the following script will automatically detect the current machine device and mount the device into the container:

```bash
# create docker container
./env.sh

# enter docker container
./env.sh enter
```

### Simulation Mode

Remote Attestation is not enabled for this mode

1. Build
    ```bash
    ./script/build -p sim
    ```
2. Run
   ```bash
   ./target/release/capsule_manager --enable-tls false
   ```
### SGX Mode
1. Build
    ```bash
    ./script/build -p sgx
    ```
2. Run

   After entering 'script/occlum_instance', it runs in the same way as the chapter (Run Quickly by Docker Image#SGX mode)

### TDX Mode
1. Build
    ```bash
    ./script/build -p tdx
    ```
2. Modify PCCS config

    Set real `pccs_url` and set `use_secure_cert` to **false** in /etc/sgx_default_qcnl.conf.

3. Run
   ```bash
   ./target/release/capsule_manager --enable-tls false
   ```
### CSV Mode
1. Build
    ```bash
    ./script/build -p csv
    ```
2. Run
   ```bash
   ./target/release/capsule_manager --enable-tls false
   ```

## Contributing

Please check [CONTRIBUTING.md](CONTRIBUTING.md)

## License

This project is licensed under the [Apache License](LICENSE)
