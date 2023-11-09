FROM secretflow/capsule-manager-ci:0.1.0b as builder

WORKDIR /home/admin/dev

COPY Cargo.toml ./
COPY capsule-manager ./capsule-manager
COPY capsule-manager-tonic ./capsule-manager-tonic
COPY second_party ./second_party

RUN cargo build --release

FROM ubuntu:20.04

COPY --from=builder /home/admin/dev/second_party/remote-attestation/c/lib /home/admin/lib
COPY --from=builder /home/admin/dev/target/release/capsule_manager /home/admin/capsule_manager

COPY deployment/entrypoint.sh /home/admin/entrypoint.sh
# Add Tini
ENV TINI_VERSION v0.19.0
ADD https://github.com/krallin/tini/releases/download/${TINI_VERSION}/tini /tini
RUN chmod +x /tini
ENTRYPOINT ["/tini", "--"]

ENV LD_LIBRARY_PATH="$LD_LIBRARY_PATH:/home/admin/lib"

WORKDIR /home/admin

CMD [ "/home/admin/entrypoint.sh" ]
