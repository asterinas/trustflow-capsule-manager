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
    echo "Usage: bash install_attestation_lib.sh [OPTION]..."
    echo "  -p"
    echo "       the platform to build with. sim/sgx/tdx/csv."
    echo "  -s"
    echo "       the path to save library."
    echo "  -h"
    echo "       help"
    exit
}

[ $# -eq 0 ] && show_help

# 解析短选项的getopts循环
while getopts "p:s:" opt; do
  case $opt in
    p)
      PLATFORM="$OPTARG"
      ;;
    s)
      SAVE_PATH="$OPTARG"
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

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" >/dev/null 2>&1 && pwd)"
cd $SCRIPT_DIR
rm -rf trustedflow
# OPENSOURCE-CLEANUP GSUB git@code.alipay.com:secretflow/trustedflow.git https://github.com/secretflow/capsule-manager.git
git clone git@code.alipay.com:secretflow/trustedflow.git
cd trustedflow

echo "build trustedflow attestation"
case "$PLATFORM" in
  sim)
    bazel build -c opt //trustedflow/...
    ;;
  sgx)
    bazel build -c opt --define tee_type=sgx2 //trustedflow/...
    ;;
  tdx)
    bazel build -c opt --define tee_type=tdx //trustedflow/...
    ;;
  csv)
    bazel build -c opt --define tee_type=csv //trustedflow/...
    ;;
  *)
    echo -e "PLATFORM does not match any of options(sim/sgx/tdx/csv)"
    exit 1
    ;;
esac
echo "build trustedflow attestation successfully"

if [ -z "$SAVE_PATH" ]; then
  SAVE_PATH="/lib"
fi


cp bazel-bin/trustedflow/attestation/generation/wrapper/libgeneration.so /lib
echo "copy libgeneration.so to $SAVE_PATH successfully"

cp bazel-bin/trustedflow/attestation/verification/wrapper/libverification.so /lib
echo "copy libverication.so to $SAVE_PATH successfully"

cd .. && rm -rf trustedflow
