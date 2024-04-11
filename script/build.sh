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

show_help() {
    echo "Usage: bash build.sh [OPTION]..."
    echo "  -p"
    echo "       the platform to build with. sim/sgx/tdx/csv."
    echo "  -h"
    echo "       help"
    exit
}

[ $# -eq 0 ] && show_help

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" >/dev/null 2>&1 && pwd)"
cd $SCRIPT_DIR


# 解析短选项的getopts循环
while getopts "p:h" opt; do
  case $opt in
    p)
      PLATFORM="$OPTARG"
      echo "Build platform $PLATFORM"
      ;;
    *|h)
      show_help
      ;;
  esac
done

# 重置getopts处理的位置参数
shift $((OPTIND-1))

GREEN="\033[32m"
NC="\033[0m"

# install attestation lib
bash install_attestation_lib.sh -p $PLATFORM

case "$PLATFORM" in
  sgx)
    /root/.cargo/bin/cargo build -p capsule_manager --release --features production
    bash build_occlum.sh
    ;;
  sim)
    /root/.cargo/bin/cargo build -p capsule_manager --release
    ;;
  tdx|csv)
    /root/.cargo/bin/cargo build -p capsule_manager --release --features production
    ;;
  *)
    echo -e "PLATFORM does not match any of options(sim/sgx/tdx/csv)"
    exit 1
    ;;
esac
