#!/bin/bash
set -eu
cd "$(dirname "$0")"
binary=bin/ex1b-web-mac-arm64
if [[ "$(uname -m)" != arm64 || ! -x "$binary" ]]; then
  if ! command -v go >/dev/null; then
    printf '找不到适用的预编译程序。Apple 芯片 Mac 可直接运行。源码构建需 Go 1.25 或以上。\n' >&2
    exit 1
  fi
  mkdir -p bin
  binary=bin/ex1b-web-mac-local
  go build -trimpath -o "$binary" ./cmd/ex1b
fi
"$binary" web --listen 127.0.0.1:44080 --origin http://127.0.0.1:44080 \
  --admin-port 44081 --user-ports 44082,44083,44084 --data web-data &
pid=$!
trap 'kill -TERM "$pid" 2>/dev/null || true; wait "$pid" 2>/dev/null || true' EXIT
trap 'exit 0' INT TERM
for ((i=0; i<30; i++)); do
  if ! kill -0 "$pid" 2>/dev/null; then wait "$pid"; exit 1; fi
  if curl --silent --fail --max-time 1 http://127.0.0.1:44080/healthz >/dev/null; then
    open http://127.0.0.1:44080
    wait "$pid"
    exit
  fi
  sleep 0.25
done
printf 'Web 页启动超时，请检查上面的提示。\n' >&2
exit 1
