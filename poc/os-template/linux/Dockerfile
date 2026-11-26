# Builder for the Ubuntu 24.04 offline template build (build-ubuntu-template.sh), used by
# azure-pipelines-os-template-ubuntu.yml. It runs unprivileged (no --privileged, no Docker socket):
# libguestfs starts its own small qemu appliance with the kernel installed here.
#
#   docker build -t ssi-os-template-builder -f poc/os-template/linux/Dockerfile poc/os-template/linux
ARG UBUNTU_IMAGE=ubuntu:24.04
# Official Trivy v0.70.0, the same digest as the canonical scan worker.
ARG TRIVY_IMAGE=ghcr.io/aquasecurity/trivy@sha256:be1190afcb28352bfddc4ddeb71470835d16462af68d310f9f4bca710961a41e

FROM ${TRIVY_IMAGE} AS trivy

FROM ${UBUNTU_IMAGE}
ARG DEBIAN_FRONTEND=noninteractive
# supermin builds the appliance from this kernel; an unprivileged user must be able to read it.
# isc-dhcp-client: the appliance configures its network (virt-customize --network) with dhclient;
# without it the guest's apt sees "Network is unreachable".
RUN apt-get update \
  && apt-get install -y --no-install-recommends \
    libguestfs-tools linux-image-virtual qemu-utils qemu-system-x86 \
    isc-dhcp-client ca-certificates curl gpgv nodejs libxml2-utils \
  && rm -rf /var/lib/apt/lists/* \
  && chmod 0644 /boot/vmlinuz-*
COPY --from=trivy /usr/local/bin/trivy /usr/local/bin/trivy
ENV LIBGUESTFS_BACKEND=direct
