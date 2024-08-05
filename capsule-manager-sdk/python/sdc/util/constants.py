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

SEPARATOR = b"."

Version = 1
Schema = 1
VersionBytes = 4
SchemaBytes = 4

BlockBytes = 0x2000
PacketCntBytes = 8
BlockLenBytes = 4

IvBytes = 12
MacBytes = 16
ContentKeyBytes = 16
IvFieldBytes = 32
MacFieldBytes = 32
IvLenBytes = 1
MacLenBytes = 1
Padding = 0
