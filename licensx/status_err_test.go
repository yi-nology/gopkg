package licensx

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// TestLoadStatusErrChain 验收（gopkg#28）：非 Valid 时 Status.Err 携带原始
// 类型化错误链，errors.Is 可判文件缺失/读取失败/解析失败/签名/过期/吊销；
// Valid 时 Err 为 nil。Reason 仍是人读文案，且 JSON 输出不受 error 字段影响。
func TestLoadStatusErrChain(t *testing.T) {
	pub, priv := testKeyPair(t)
	dir := t.TempDir()
	future := baseTime().Add(24 * time.Hour)
	past := baseTime().Add(-time.Hour)
	now := baseTime().Add(time.Hour)

	payload, err := json.Marshal(hostClaims{Customer: "acme"})
	if err != nil {
		t.Fatal(err)
	}
	signed := func(serial string, expiresAt *time.Time) *License {
		l := &License{Serial: serial, IssuedAt: baseTime(), ExpiresAt: expiresAt, Payload: payload}
		if err := Sign(l, priv); err != nil {
			t.Fatal(err)
		}
		return l
	}
	write := func(name string, l *License) string {
		p := filepath.Join(dir, name)
		b, err := json.Marshal(l)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, b, 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}
	badPath := filepath.Join(dir, "bad.json")
	if err := os.WriteFile(badPath, []byte("{not json"), 0o600); err != nil {
		t.Fatal(err)
	}

	cases := []struct {
		name         string
		load         func() Status
		want         error
		reason       string // 固定文案（空则只校验 reasonPrefix / 与 Err 文案一致）
		reasonPrefix string
	}{
		{
			name:   "未配置 → ErrNoFile",
			load:   func() Status { return Load("", pub, now) },
			want:   ErrNoFile,
			reason: "未配置 license 文件（无授权运行）",
		},
		{
			name:   "文件不存在 → ErrNoFile",
			load:   func() Status { return Load(filepath.Join(dir, "nope.json"), pub, now) },
			want:   ErrNoFile,
			reason: "license 文件不存在（无授权运行）",
		},
		{
			name:         "读取失败 → ErrUnreadable",
			load:         func() Status { return Load(dir, pub, now) }, // 目录不是可读文件
			want:         ErrUnreadable,
			reasonPrefix: "license 文件读取失败: ",
		},
		{
			name:         "解析失败 → ErrParseFailed",
			load:         func() Status { return Load(badPath, pub, now) },
			want:         ErrParseFailed,
			reasonPrefix: "license 文件解析失败: ",
		},
		{
			name: "篡改 → ErrSignatureInvalid",
			load: func() Status {
				l := signed("2026-001", &future)
				l.Serial = "tampered"
				return Load(write("tampered.json", l), pub, now)
			},
			want: ErrSignatureInvalid,
		},
		{
			name: "过期 → ErrExpired",
			load: func() Status {
				return Load(write("expired.json", signed("2026-001", &past)), pub, now)
			},
			want: ErrExpired,
		},
		{
			name: "吊销 → ErrRevoked",
			load: func() Status {
				return Load(write("revoked.json", signed("2026-001", &future)), pub, now,
					WithRevokedSerials([]string{"2026-001"}))
			},
			want: ErrRevoked,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			st := tc.load()
			if st.Valid {
				t.Fatalf("st = %+v, want 非 Valid", st)
			}
			if st.Err == nil {
				t.Fatal("非 Valid 必须携带 Err 原始错误链（gopkg#28）")
			}
			if !errors.Is(st.Err, tc.want) {
				t.Fatalf("errors.Is(st.Err, %v) = false, Err = %v", tc.want, st.Err)
			}
			if st.Reason == "" {
				t.Fatal("非 Valid 必须保留 Reason 文案（不静默）")
			}
			if tc.reason != "" && st.Reason != tc.reason {
				t.Fatalf("Reason = %q, want %q（文案零变化）", st.Reason, tc.reason)
			}
			if tc.reasonPrefix != "" && !strings.HasPrefix(st.Reason, tc.reasonPrefix) {
				t.Fatalf("Reason = %q, want 前缀 %q（文案零变化）", st.Reason, tc.reasonPrefix)
			}
			// 校验类分支的 Reason 就是 Validate 返回的原文（Err 链路不改文案）。
			if st.Loaded && st.Reason != st.Err.Error() {
				t.Fatalf("Reason = %q, Err = %q，校验类文案应逐字一致", st.Reason, st.Err)
			}

			// Err 带 json:"-"：Status 仍可直接进诊断 JSON 输出。
			b, err := json.Marshal(st)
			if err != nil {
				t.Fatalf("json.Marshal(Status) 失败: %v", err)
			}
			var obj map[string]json.RawMessage
			if err := json.Unmarshal(b, &obj); err != nil {
				t.Fatalf("Status JSON 非法: %v", err)
			}
			if _, ok := obj["Err"]; ok {
				t.Fatalf("Status JSON 不应包含 Err 字段: %s", b)
			}
			if _, ok := obj["err"]; ok {
				t.Fatalf("Status JSON 不应包含 err 字段: %s", b)
			}
			if _, ok := obj["reason"]; !ok {
				t.Fatalf("Status JSON 应保留 reason: %s", b)
			}
		})
	}

	t.Run("有效 → Err 为 nil", func(t *testing.T) {
		st := Load(write("valid.json", signed("2026-001", &future)), pub, now)
		if !st.Valid || !st.Loaded {
			t.Fatalf("st = %+v, want 有效", st)
		}
		if st.Err != nil {
			t.Fatalf("Valid 时 Err = %v, want nil", st.Err)
		}
		if st.Reason != "" {
			t.Fatalf("Valid 时 Reason = %q, want 空", st.Reason)
		}
		b, err := json.Marshal(st)
		if err != nil {
			t.Fatalf("json.Marshal(Status) 失败: %v", err)
		}
		if strings.Contains(string(b), `"err"`) {
			t.Fatalf("Status JSON 不应包含 err: %s", b)
		}
	})
}
