#!/bin/bash
set -eu
cd "$(dirname "$0")"
machine=$(uname -m)
if [[ "$machine" == x86_64 ]]; then machine=amd64; fi
binary="bin/ex1b-mac-$machine"
if [[ ! -x "$binary" ]]; then
  if ! command -v go >/dev/null; then
    printf '找不到预编译程序。若从源码启动，请先准备 Go 1.25 或以上。\n' >&2
    exit 1
  fi
  mkdir -p bin
  go build -trimpath -o "$binary" ./cmd/ex1b
fi
if [[ ! -f demo/server.json ]]; then
  "$binary" init --dir demo
fi
jobs_running=()
stop() {
  for job in "${jobs_running[@]}"; do kill -TERM "$job" 2>/dev/null || true; done
  wait 2>/dev/null || true
}
trap stop EXIT
trap 'exit 0' INT TERM
"$binary" server --config demo/server.json &
jobs_running+=("$!")
"$binary" client --config demo/alice.json &
jobs_running+=("$!")
"$binary" client --config demo/vip.json &
jobs_running+=("$!")
sleep 1
for job in "${jobs_running[@]}"; do
  if ! kill -0 "$job" 2>/dev/null; then
    printf '有进程未能启动，请检查上方错误。\n' >&2
    exit 1
  fi
done
printf '演示已运行。按 Ctrl+C 关闭。\n'
open 'http://127.0.0.1:43950' 'http://127.0.0.1:43952' 'http://127.0.0.1:43953'
wait
