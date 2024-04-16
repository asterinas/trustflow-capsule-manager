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

FROM secretflow/trustedflow-dev-ubuntu22.04:latest as builder

ARG PLATFORM

WORKDIR /home/admin/dev

ENV PROTOC /root/.local/bin/protoc

COPY Cargo.toml ./
COPY capsule-manager ./capsule-manager
COPY script ./script

RUN ./script/build.sh -p $PLATFORM

FROM secretflow/trustedflow-release-ubuntu22.04:latest

COPY --from=builder /lib/libverification.so /home/admin/lib/libverification.so
COPY --from=builder /lib/libgeneration.so /home/admin/lib/libgeneration.so
COPY --from=builder /home/admin/dev/target/release/capsule_manager /home/admin/capsule_manager
COPY --from=builder /home/admin/dev/script/conf/config.yaml /home/admin/config.yaml

COPY deployment/entrypoint.sh /home/admin/entrypoint.sh
# Add Tini
ENV TINI_VERSION v0.19.0
ADD https://github.com/krallin/tini/releases/download/${TINI_VERSION}/tini /tini
RUN chmod +x /tini
ENTRYPOINT ["/tini", "--"]

ENV LD_LIBRARY_PATH="$LD_LIBRARY_PATH:/home/admin/lib"

WORKDIR /home/admin

CMD [ "/home/admin/entrypoint.sh" ]
