#!/bin/bash
set -euo pipefail
os=$(uname -s | tr '[:upper:]' '[:lower:]')
arch=$(uname -m)
ver="v1.33.0"

case "${arch}" in
    x86_x64*)     arch="amd64";;
esac

curl -sSL  "https://github.com/kubernetes-sigs/controller-tools/releases/download/envtest-${ver}/envtest-${ver}-${os}-${arch}.tar.gz" | tar -zvxf -
rm -rf kubebuilder || true
mv controller-tools kubebuilder
mv kubebuilder/envtest kubebuilder/bin
