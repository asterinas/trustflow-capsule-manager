#!/bin/bash
#
# Copyright 2024 Ant Group Co., Ltd.
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

BLUE='\033[1;34m'
GREEN='\033[1;32m'
LIGHT_CYAN='\033[1;36m'
NC='\033[0m'

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" >/dev/null 2>&1 && pwd)"
workspace_dir="$(realpath "$script_dir/..")"
occlum_instance_dir="$(realpath "$script_dir/occlum_instance")"

echo -e "${GREEN} ===== Build occlum start ==== ${NC}"
echo -e "${LIGHT_CYAN}build script dir:${NC} $script_dir"
echo -e "${LIGHT_CYAN}workspace dir${NC}: $workspace_dir"
echo -e "${LIGHT_CYAN}occlum_instance dir${NC}: $occlum_instance_dir"

echo -e "${GREEN} ===== Initailize occlum workspace start ===== ${NC}"
rm -rf $occlum_instance_dir
pushd $script_dir
occlum new occlum_instance
popd
echo -e "${GREEN} ===== Initailize occlum workspace end ===== ${NC}"

pushd $occlum_instance_dir
mkdir -p image/bin/
cp $workspace_dir/target/release/grpc-as image/bin/capsule_manager

# Copy glibc so to image.
mkdir -p image/opt/occlum/glibc/lib/
pushd image/opt/occlum/glibc/lib/
cp -a /opt/occlum/glibc/lib/libdl*.so* .
cp -a /opt/occlum/glibc/lib/librt*.so* .

#DNS
cp -a /opt/occlum/glibc/lib/libnss_dns.so* \
  /opt/occlum/glibc/lib/libnss_files.so* \
  /opt/occlum/glibc/lib/libresolv.so* \
  .
# dcap and it's deps
cp -an /usr/lib/x86_64-linux-gnu/lib*so* .
popd

# trustedflow attestation lib
mkdir -p image/usr/local/lib
cp /lib/libgeneration.so image/usr/local/lib
cp /lib/libverification.so image/usr/local/lib

chmod +x image/lib64/ld-linux-x86-64.so.2

cp $script_dir/Occlum.json .
cp $script_dir/conf/config.yaml .
popd