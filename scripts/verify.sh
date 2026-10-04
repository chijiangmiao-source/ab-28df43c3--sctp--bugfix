#!/bin/sh
# 一次性验证: 构建检查 → 代码测试 → 对运行中的审计台做 API/HTTP 冒烟。
# 任一环节失败即以非零退出码结束; 全部通过以 0 结束。
set -e

echo "== [1/4] 构建检查: go vet =="
go vet ./...

echo "== [2/4] 构建检查: go build =="
go build -buildvcs=false ./...

echo "== [3/4] 代码测试: go test =="
go test ./...

echo "== [4/4] API/HTTP 冒烟 =="
go run -buildvcs=false ./cmd/smoke -addr "${SMOKE_ADDR:-http://app:8080}"

echo "VERIFY OK"
