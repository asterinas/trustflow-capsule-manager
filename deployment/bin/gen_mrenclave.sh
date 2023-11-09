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
sgx_sign dump -enclave build/lib/libocclum-libos.signed.so -dumpfile metadata.txt
printf "\n MRENCLAVE: "
sed -n -e '/enclave_hash.m/,/metadata->enclave_css.body.isv_prod_id/p' ./metadata.txt | head -3 | tail -2 | xargs | sed 's/0x//g' | sed 's/ //g' | tr 'a-z' 'A-Z'
