FROM secretflow/occlum:0.29.5-ubuntu20.04

LABEL maintainer="secretflow-contact@service.alipay.com"

USER root:root
ENV TZ=Asia/Shanghai
RUN ln -snf /usr/share/zoneinfo/$TZ /etc/localtime \
		&& echo $TZ > /etc/timezone \
		&& ln -sf /usr/bin/bash /bin/sh

# install rust
RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | bash -s -- -y
RUN rustup install 1.68.2 && rustup default 1.68.2
RUN curl -LsSf https://get.nexte.st/latest/linux | tar zxf - -C ${CARGO_HOME:-~/.cargo}/bin

RUN apt-key adv --keyserver keyserver.ubuntu.com --recv-keys E5C7F0FA1C6C6C3C \
		&& apt-get update && apt-get upgrade -y \
		&& apt-get install -y g++ cmake ninja-build nasm wget protobuf-compiler \
		&& wget https://github.com/bazelbuild/bazelisk/releases/download/v1.18.0/bazelisk-linux-amd64 \
    && chmod 777 bazelisk-linux-amd64 && mv bazelisk-linux-amd64 /usr/local/bin/bazelisk \
		&& apt-get clean


# run as root for now
WORKDIR /home/admin/