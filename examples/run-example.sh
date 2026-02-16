#!/usr/bin/env bash
set -euo pipefail

if [ "$#" -lt 1 ]; then
  echo "usage: $0 <example-folder> [-- args...]"
  exit 2
fi

EXAMPLE="$1"
shift || true

HOST_REPO="/Users/nhatle/projects/ebpf-beginner"
VM_CMD="cd ${HOST_REPO}/${EXAMPLE} && go build -o /tmp/${EXAMPLE}-bin . && sudo /tmp/${EXAMPLE}-bin $*"

echo "Building and running '${EXAMPLE}' inside lima-k8s-ebpf VM..."
limactl shell lima-k8s-ebpf -- bash -lc "${VM_CMD}"
