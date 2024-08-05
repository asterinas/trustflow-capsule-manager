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
    echo "  -v"
    echo "       the version to build with."
    echo "  -l"
    echo "       tag this version as latest."
    echo "  -u"
    echo "       upload to docker registry."
    echo "  -e"
    echo "       docker registry."
    echo "  -h"
    echo "       help"
    exit
}

[ $# -eq 0 ] && show_help

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" >/dev/null 2>&1 && pwd)"
cd $SCRIPT_DIR/..

DOCKER_REG="secretflow"

# 解析短选项的getopts循环
while getopts "p:v:e:luh" opt; do
  case $opt in
    p)
      PLATFORM="$OPTARG"
      echo "build platform $PLATFORM"
      ;;
    v)
      VERSION="$OPTARG"
      echo "docker image version: $VERSION"
      ;;
    e)
      IFS=: read -a DOCKER_REGS <<< "$OPTARG"
      i=1
      for repo in "${DOCKER_REGS[@]}"; do
          echo "docker repo${i}: $repo"
          i=$((i+1))
      done
      ;;
    l)
      LATEST=1
      ;;
    u)
      UPLOAD=1
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

IMAGE_TAG=capsule-manager-$PLATFORM-ubuntu22.04:${VERSION}
LATEST_TAG=capsule-manager-$PLATFORM-ubuntu22.04:latest
echo -e "Building ${GREEN}${IMAGE_TAG}${NO_COLOR}"
case "$PLATFORM" in
  sgx)
    docker build --build-arg PLATFORM=$PLATFORM -f deployment/occlum.Dockerfile -t $IMAGE_TAG .
    ;;
  sim|tdx|csv)
    docker build --build-arg PLATFORM=$PLATFORM -f deployment/Dockerfile -t $IMAGE_TAG .
    ;;
  *)
    echo -e "PLATFORM does not match any of options(sim/sgx/tdx/csv)"
    exit 1
    ;;
esac

for repo in "${DOCKER_REGS[@]}"; do
  docker tag $IMAGE_TAG $repo/$IMAGE_TAG
  if [[ UPLOAD -eq 1 ]]; then
    docker push $repo/$IMAGE_TAG
    if [[ LATEST -eq 1 ]]; then
        echo -e "Tag ${GREEN}${LATEST_TAG}${NO_COLOR} ..."
        docker tag ${IMAGE_TAG} $repo/$LATEST_TAG
        echo -e "Push ${GREEN}${LATEST_TAG}${NO_COLOR} ..."
        docker push $repo/$LATEST_TAG
    fi
  fi
done