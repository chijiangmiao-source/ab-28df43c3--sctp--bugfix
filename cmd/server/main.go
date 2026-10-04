// 星载控制中继 SCTP 弱链路审计台服务入口。
package main

import (
	"log"
	"net/http"
	"os"

	"sctpaudit/audit"
)

func getenv(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func main() {
	port := getenv("PORT", "8080")
	dataDir := getenv("DATA_DIR", "./data")
	st, err := audit.NewStore(dataDir)
	if err != nil {
		log.Fatalf("初始化存储失败: %v", err)
	}
	log.Printf("审计台监听 :%s, 数据目录 %s", port, dataDir)
	log.Printf("操作页 http://localhost:%s/ 健康响应 http://localhost:%s/health", port, port)
	log.Fatal(http.ListenAndServe(":"+port, audit.NewHandler(st)))
}
