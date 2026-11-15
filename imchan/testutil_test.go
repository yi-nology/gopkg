package imchan

// 共享测试小助手（契约测试专用；不参与生产构建语义）。

import (
	"testing"
	"time"
)

// waitFor 轮询直到 cond 为真或超时（异步状态断言用；避免 sleep 猜测）。
func waitFor(t *testing.T, d time.Duration, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(d)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatal("条件等待超时")
}
