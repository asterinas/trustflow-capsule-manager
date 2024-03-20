#
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
#
set -e

GREEN="\033[32m"
BLUE='\033[1;34m'
NO_COLOR="\033[0m"
NC='\033[0m'

# cd work dir
SCRIPT=$(readlink -f "$0")
SCRIPT_DIR=$(dirname "$SCRIPT")
WORK_SPACE_DIR=$SCRIPT_DIR/..

pushd $WORK_SPACE_DIR
CARGO_TARGET_DIR=target cargo build --features production --release

rm -rf occlum_release
mkdir occlum_release
cd occlum_release
occlum init

# Copy glibc so to image.
cp /opt/occlum/glibc/lib/libdl*.so* image/opt/occlum/glibc/lib/
cp /opt/occlum/glibc/lib/librt*.so* image/opt/occlum/glibc/lib/
#DNS
cp /opt/occlum/glibc/lib/libnss_dns.so.2 \
    /opt/occlum/glibc/lib/libnss_files.so.2 \
    /opt/occlum/glibc/lib/libresolv.so.2 \
    image/opt/occlum/glibc/lib/

cp ../target/release/capsule_manager image/bin/capsule_manager
cp ../deployment/conf/Occlum_sgx2.json Occlum.json
cp ../deployment/conf/config.yaml config.yaml
mkdir -p image/etc/kubetee/
cp ../deployment/conf/unified_attestation.json image/etc/kubetee/unified_attestation.json
cp ../second_party/remote-attestation/c/lib/* image/lib/
cp /usr/lib/x86_64-linux-gnu/libcrypto.so.1.1 image/lib/
cp /usr/lib/x86_64-linux-gnu/libssl.so.1.1 image/lib/
cp ../deployment/bin/gen_mrenclave.sh gen_mrenclave.sh
if [ ! -d "../capsule-manager/resources" ]; then
    mkdir ../capsule-manager/resources
fi
cp -r ../capsule-manager/resources resources

if [ -z $KEY_PATH ]; then
    echo "KEY_PATH not found"
    exit
else
    # absolute path
    if [[ $KEY_PATH == /* ]]; then
        occlum build --sign-key $KEY_PATH
    # relative path
    else
        occlum build --sign-key ../$KEY_PATH
    fi
fi
