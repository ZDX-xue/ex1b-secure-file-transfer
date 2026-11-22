#!/bin/bash
set -euo pipefail
cd -- "$(dirname -- "$0")"

go_bin="${EX1B_GO:-}"
if [[ -z "$go_bin" ]]; then
  go_bin="$(command -v go || true)"
fi
go_hint=/private/tmp/ex1b-go-path-verified
if [[ -z "$go_bin" && -f "$go_hint" && -O "$go_hint" && ! -L "$go_hint" ]]; then
  go_bin="$(< "$go_hint")"
fi
if [[ -z "$go_bin" ]] || ! command -v -- "$go_bin" >/dev/null 2>&1; then
  printf '请准备 Go 1.25 或更新版本，或将 EX1B_GO 设为 Go 可执行文件的绝对路径。\n' >&2
  exit 1
fi

workdir="$(mktemp -d "${TMPDIR:-/tmp}/ex1b-verify.XXXXXXXX")"
trap 'rm -rf -- "$workdir"' EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
export GOCACHE="${GOCACHE:-$workdir/go-cache}"
export GOFLAGS='' GOPROXY=off GOTOOLCHAIN=local GOWORK=off

printf '\n[1/3] 编译源码并执行构建产物\n'
"$go_bin" version
"$go_bin" build -trimpath -o "$workdir/ex1b" ./cmd/ex1b
"$workdir/ex1b" version

printf '\n[2/3] 验证双向证书与账号目录隔离\n'
"$go_bin" test -count=1 -timeout=1m -v \
  -run '^(TestMutualTLS|TestAccountIsolationAndPortableNames)$' \
  ./internal/identity ./internal/storage

printf '\n[3/3] 验证真实报文、并发限速、续传、中转授权与连接容量\n'
"$go_bin" test -count=1 -timeout=1m -v \
  -run '^(TestProtocolTraceRecordsTLSAndFileExchanges|TestRealSessionsParallelTransferAndIdentityRate|TestRealUploadAndDownloadResume|TestLiveRelayACLIntegrityAndBilateralRate|TestCapacityAndHeartbeat)$' \
  ./internal/transfer ./internal/service
