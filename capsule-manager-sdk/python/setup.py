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
from datetime import date
from pathlib import Path

import setuptools

__version__ = "0.2.0.dev$$DATE$$"


def get_version():
    date_str = date.today().strftime("%Y%m%d")
    return __version__.replace("$$DATE$$", date_str)


def read(fname):
    with open(Path(__file__).resolve().parent / Path(fname)) as f:
        return f.read()


if __name__ == "__main__":
    setuptools.setup(
        name="capsule-manager-sdk",
        version=get_version(),
        author="secretflow",
        author_email="secretflow-contact@service.alipay.com",
        description="Secure Data Capsule SDK for python",
        long_description_content_type="text/markdown",
        long_description="Secure Data Capsule SDK for python",
        license="Apache 2.0",
        url="https://github.com/secretflow/capsule-manager-sdk.git",
        packages=setuptools.find_namespace_packages(exclude=("tests", "tests.*")),
        install_requires=read("requirements.txt"),
        entry_points="""
          [console_scripts]
          cms=cli.cms:cms
          cms_util=cli.cms_util:cms_util
          cms_config=cli.cms_config:cms_config
      """,
        classifiers=[
            "Programming Language :: Python :: 3",
            "License :: OSI Approved :: Apache Software License",
            "Operating System :: POSIX :: Linux",
        ],
        options={
            "bdist_wheel": {"plat_name": "manylinux2014_x86_64"},
        },
        include_package_data=True,
    )
