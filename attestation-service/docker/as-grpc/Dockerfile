# Copyright (c) 2023 by Alibaba.
# Licensed under the Apache License, Version 2.0, see LICENSE for details.
# SPDX-License-Identifier: Apache-2.0

FROM rust:latest as builder
ARG ARCH=x86_64

WORKDIR /usr/src/attestation-service
COPY . .

# Install TPM Build Dependencies
RUN apt-get update && apt-get install -y protobuf-compiler clang libtss2-dev python3-pip

# Install NV Attestation SDK
RUN pip3 install attestation-service/docker/verifier-1.3.0-py3-none-any.whl --break-system-packages
RUN pip3 install attestation-service/docker/nv_attestation_sdk-1.3.0-py3-none-any.whl --break-system-packages

# Install TDX Build Dependencies
RUN if [ "${ARCH}" = "x86_64" ]; then curl -L https://download.01.org/intel-sgx/sgx_repo/ubuntu/intel-sgx-deb.key | tee intel-sgx-deb.key | apt-key add - && \
    echo 'deb [arch=amd64] https://download.01.org/intel-sgx/sgx_repo/ubuntu jammy main' | tee /etc/apt/sources.list.d/intel-sgx.list && \
    apt-get update && apt-get install -y libsgx-dcap-quote-verify-dev; fi

# Build and Install gRPC attestation-service
RUN cargo install --path attestation-service --bin grpc-as --features grpc-bin --locked


FROM ubuntu:22.04
ARG ARCH=x86_64

LABEL org.opencontainers.image.source="https://github.com/confidential-containers/attestation-service"

# Install TDX Runtime Dependencies
RUN apt-get update && apt-get install curl gnupg openssl python3 python3-pip python3.11-dev -y && \
    rm -rf /var/lib/apt/lists/{apt,dpkg,cache,log} /tmp/* /var/tmp/*

# Install NV Attestation SDK
COPY --from=builder /usr/src/attestation-service/attestation-service/docker/verifier-1.3.0-py3-none-any.whl /usr
COPY --from=builder /usr/src/attestation-service/attestation-service/docker/nv_attestation_sdk-1.3.0-py3-none-any.whl /usr
RUN python3.11 -m pip install /usr/verifier-1.3.0-py3-none-any.whl
RUN python3.11 -m pip install /usr/nv_attestation_sdk-1.3.0-py3-none-any.whl

# Install NV Attestation Default Token validation policy
COPY --from=builder /usr/src/attestation-service/deps/verifier/test_data/NVGPULocalPolicyDefault.json /opt/confidential-containers/attestation-service

RUN if [ "${ARCH}" = "x86_64" ]; then curl -L https://download.01.org/intel-sgx/sgx_repo/ubuntu/intel-sgx-deb.key | tee intel-sgx-deb.key | apt-key add - && \
    echo 'deb [arch=amd64] https://download.01.org/intel-sgx/sgx_repo/ubuntu jammy main' | tee /etc/apt/sources.list.d/intel-sgx.list && \
    apt-get update && \
    apt-get install -y libsgx-dcap-default-qpl libsgx-dcap-quote-verify && \
    rm -rf /var/lib/apt/lists/{apt,dpkg,cache,log} /tmp/* /var/tmp/*; fi

# Copy TPM Runtime Dependencies
COPY --from=builder /usr/lib/${ARCH}-linux-gnu/libtss* /usr/lib/${ARCH}-linux-gnu

COPY --from=builder /usr/local/cargo/bin/grpc-as /usr/local/bin/grpc-as

VOLUME /opt/confidential-containers/attestation-service

CMD ["grpc-as", "--socket", "0.0.0.0:50004"]

EXPOSE 50004