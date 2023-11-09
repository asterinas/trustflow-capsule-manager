FROM secretflow/capsule-manager-ci:0.1.0b as builder

WORKDIR /home/admin/dev

COPY Cargo.toml ./
COPY capsule-manager ./capsule-manager
COPY capsule-manager-tonic ./capsule-manager-tonic
COPY second_party ./second_party
COPY deployment ./deployment


RUN bash second_party/remote-attestation/compile.sh \
		&& openssl genrsa -3 -out private_key.pem 3072 \
		&& openssl rsa -in private_key.pem -pubout -out public_key.pem \
		&& KEY_PATH=private_key.pem bash deployment/build.sh

FROM secretflow/capsule-manager-ci:0.1.0b

COPY --from=builder /home/admin/dev/occlum_release /home/admin/occlum_release

WORKDIR /home/admin
