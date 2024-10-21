# Copyright (c) 2023 by Alibaba.
# Licensed under the Apache License, Version 2.0, see LICENSE for details.
# SPDX-License-Identifier: Apache-2.0

FROM ubuntu:24.04 as builder
ARG ARCH=x86_64

WORKDIR /usr/src/attestation-service
COPY . .

# Install Rust
RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y

ENV PATH="/root/.cargo/bin:${PATH}"

# Install TPM Build Dependencies
RUN apt-get update && apt-get install -y protobuf-compiler clang libtss2-dev python3.12 python3-pip python3.12-dev

# Install NV Attestation SDK
RUN python3.12 -m pip install attestation-service/docker/verifier-1.3.0-py3-none-any.whl --break-system-packages
RUN python3.12 -m pip install attestation-service/docker/nv_attestation_sdk-1.3.0-py3-none-any.whl --break-system-packages

# Install TDX Build Dependencies
RUN if [ "${ARCH}" = "x86_64" ]; then curl -L https://download.01.org/intel-sgx/sgx_repo/ubuntu/intel-sgx-deb.key | tee intel-sgx-deb.key | apt-key add - && \
    echo 'deb [arch=amd64] https://download.01.org/intel-sgx/sgx_repo/ubuntu jammy main' | tee /etc/apt/sources.list.d/intel-sgx.list && \
    apt-get update && apt-get install -y libsgx-dcap-quote-verify-dev; fi

# Build and Install RESTful attestation-service
RUN cargo install --path attestation-service --bin restful-as --features restful-bin --locked

FROM ubuntu:24.04
ARG ARCH=x86_64

LABEL org.opencontainers.image.source="https://github.com/confidential-containers/attestation-service"

# Install TDX Runtime Dependencies
RUN apt-get update && apt-get install curl gnupg openssl python3.12 python3-pip python3.12-dev -y && \
    rm -rf /var/lib/apt/lists/{apt,dpkg,cache,log} /tmp/* /var/tmp/*

# Install NV Attestation SDK
COPY --from=builder /usr/src/attestation-service/attestation-service/docker/verifier-1.3.0-py3-none-any.whl /usr
COPY --from=builder /usr/src/attestation-service/attestation-service/docker/nv_attestation_sdk-1.3.0-py3-none-any.whl /usr
RUN python3.12 -m pip install /usr/verifier-1.3.0-py3-none-any.whl
RUN python3.12 -m pip install /usr/nv_attestation_sdk-1.3.0-py3-none-any.whl

# Install NV Attestation Default Token validation policy
COPY --from=builder /usr/src/attestation-service/deps/verifier/test_data/NVGPULocalPolicyDefault.json /usr/

RUN if [ "${ARCH}" = "x86_64" ]; then curl -L https://download.01.org/intel-sgx/sgx_repo/ubuntu/intel-sgx-deb.key | tee intel-sgx-deb.key | apt-key add - && \
    echo 'deb [arch=amd64] https://download.01.org/intel-sgx/sgx_repo/ubuntu jammy main' | tee /etc/apt/sources.list.d/intel-sgx.list && \
    apt-get update && \
    apt-get install -y libsgx-dcap-default-qpl libsgx-dcap-quote-verify && \
    rm -rf /var/lib/apt/lists/{apt,dpkg,cache,log} /tmp/* /var/tmp/*; fi

# Copy TPM Runtime Dependencies
COPY --from=builder /usr/lib/${ARCH}-linux-gnu/libtss* /usr/lib/${ARCH}-linux-gnu

COPY --from=builder /usr/local/cargo/bin/restful-as /usr/local/bin/restful-as

COPY ./attestation-service/config.json /etc/config.json

VOLUME /opt/confidential-containers/attestation-service

CMD ["restful-as", "--socket", "0.0.0.0:8080", "--config-file", "/etc/config.json"]

EXPOSE 8080