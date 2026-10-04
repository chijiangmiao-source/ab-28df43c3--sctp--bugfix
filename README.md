# 星载控制中继 · SCTP 弱链路审计台

星载控制中继在弱链路上接收控制消息。审计员在操作页填写**稳定审计标识**, 按捕获顺序提交
**至多 32 个 Base64 编码的 SCTP 报文**, 系统逐包裁决并**冻结**结论; 之后可用同一标识重新
打开, 逐包裁决与消息列表与首次完全一致。

审查范围: **单关联、单个有序流**中的 **DATA** 与 **FORWARD-TSN**。每个报文校验公共头与
**CRC32C**(Castagnoli, 小端校验和字段), 依据 TSN 与 B/E 标志维护并展示:

- **累计 TSN**(连续确认点)与已观测最大 TSN
- **缓存分片**(TSN / 流序 / B/E 标志 / 长度)及**每包缓存变化**(+/−)
- **跳过范围**(被合法 FORWARD-TSN 跨越的 TSN 区间)
- **已交付消息**(流序、来源 TSN、长度、内容十六进制)

## 裁决规则

| 情形 | 裁决 | 状态变化 |
| --- | --- | --- |
| DATA 补齐完整消息 | `delivered` | 交付消息, 缓存 − |
| DATA 入缓存等待补齐 | `buffered` | 缓存 + |
| 字节完全相同的 DATA 重传 | `duplicate` | 不变(不增加消息数) |
| 被 FORWARD-TSN 跨越的迟到旧片 | `stale` | 不变(不改变结论) |
| 合法 FORWARD-TSN | `accepted` | 累计 TSN 推进、记录跳过范围、残缺消息作废、流序推进 |
| 同一 TSN 不同字节 | `rejected`(冻结) | 不变, 稳定显示**首个原始字节依据** |
| 非法流序(无序 DATA / 非受审流 / 分片交错 / 流序回退等) | `rejected`(冻结) | 不变 |
| 越界跳过(新累计 TSN 超出已观测范围或回退) | `rejected`(冻结) | 不变 |
| 公共头 / CRC32C / 块格式错误 | `rejected`(冻结) | 不变 |

所有裁决一经作出即冻结并持久化(`DATA_DIR`, 默认 `./data`, 容器内 `/data`);
同一审计标识的重复读取(包括服务重启后)结果逐字节一致。重复提交同一捕获批次是幂等的;
若同一捕获位置提交了不同字节, 返回 `409` 并给出已冻结报文的指纹与首个原始字节。

## 快速开始

```bash
# 启动操作页与健康响应(宿主端口可配置, 默认 8080)
APP_HOST_PORT=8080 docker compose up app

# 操作页
open http://localhost:8080/
# 健康响应
curl http://localhost:8080/health
```

## 一键验证(代码测试 + 构建检查 + API/HTTP 冒烟)

```bash
docker compose up --exit-code-from verify --abort-on-container-exit
echo "verify exit=$?"          # 0 = 全部通过, 非 0 = 失败
docker compose down -v          # 清理
```

`verify` 容器在一次运行内依次执行 `go vet`、`go build`、`go test`, 然后对 `app`
服务执行 HTTP 冒烟(覆盖本文件"裁决规则"中的全部验收场景), 完成后退出并以退出码报告结果。

## API

| 方法 | 路径 | 说明 |
| --- | --- | --- |
| `GET` | `/` | 操作页 |
| `GET` | `/health` | 健康响应 `{"status":"ok"}` |
| `GET` | `/api/audits/{id}` | 按标识重新打开: 逐包裁决 + 状态 + 消息列表 |
| `POST` | `/api/audits/{id}/packets` | 提交 `{"packets":["<base64>", ...]}`, 至多 32 个 |

示例(乱序互补的两个分片, 交付一条 `HELLO-WORLD!`):

```bash
curl -X POST http://localhost:8080/api/audits/pass-001/packets \
  -H 'Content-Type: application/json' \
  -d '{"packets":[
        "E4gACQECAwRZOWKtAAEAFgAAA+kABwAKAAAAAFdPUkxEIQAA",
        "E4gACQECAwRyllc1AAIAFgAAA+gABwAKAAAAAEhFTExPLQAA"
      ]}'
curl http://localhost:8080/api/audits/pass-001
```

审计标识: 1–64 位字母、数字、`-`、`_`。

## 环境变量

| 变量 | 默认 | 说明 |
| --- | --- | --- |
| `PORT` | `8080` | 容器内监听端口 |
| `DATA_DIR` | `./data`(容器内 `/data`) | 冻结裁决持久化目录 |
| `APP_HOST_PORT` | `8080` | Compose 暴露的宿主端口 |
| `SMOKE_ADDR` | `http://app:8080` | verify 冒烟目标地址 |

## 本地开发(无需 Docker)

```bash
go test ./...                                   # 代码测试
go run ./cmd/server                             # 启动服务(PORT/DATA_DIR 可配)
go run ./cmd/smoke -addr http://localhost:8080  # 对运行中的服务做冒烟
```

## 结构

```
sctp/     SCTP 公共头 + CRC32C 校验、DATA / FORWARD-TSN 解析与构造
audit/    逐包裁决引擎、冻结存储、HTTP API、操作页
cmd/server  服务入口
cmd/smoke   验收场景冒烟工具
scripts/verify.sh  verify 容器的一次性验证脚本
```
