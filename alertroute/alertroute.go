package alertroute

import (
	"encoding/json"
	"errors"
	"strings"
	"time"
)

// ErrFingerprintRequired fingerprint 缺失（TrimSpace 后为空）。告警源必须给出幂等
// 锚点；调用方按 400 拒绝，不得生成默认指纹。
var ErrFingerprintRequired = errors.New("alertroute: fingerprint 必填（幂等锚点）")

// RouteLabelsMatch 判定路由行 labels（JSON map 字符串）是否命中入站标签。
//
// 契约：空白 raw = 全匹配；坏 JSON / 非 string→string 对象 = 不命中；规则内每个
// 键值都命中才算匹配（入站多余标签不影响）；缺失标签按空串参与比较。实现与
// 告警接入热路径同源，纯函数零 IO。
func RouteLabelsMatch(raw string, in map[string]string) bool {
	if strings.TrimSpace(raw) == "" {
		return true
	}
	var m map[string]string
	if err := json.Unmarshal([]byte(raw), &m); err != nil {
		return false
	}
	for k, v := range m {
		if in[k] != v {
			return false
		}
	}
	return true
}

// NormalizeFingerprint 规范化告警源给出的 fingerprint：去首尾空白，空值拒绝。
// 不做哈希/截断/大小写变换——源侧重投必须逐字复刻同一值才能命中幂等。
func NormalizeFingerprint(fingerprint string) (string, error) {
	fp := strings.TrimSpace(fingerprint)
	if fp == "" {
		return "", ErrFingerprintRequired
	}
	return fp, nil
}

// NormalizeStartsAt 规范化告警发生时刻：去首尾空白；空值由服务端补 now 的 UTC
// RFC3339 形态。非空值原样保留（不解析、不换时区）——它是精确比对的幂等锚点，
// 任何重格式化都会让发送侧的重投值对不上库内既有行。
//
// now 由调用方注入（生产传 time.Now()；测试传固定时刻）。
func NormalizeStartsAt(startsAt string, now time.Time) string {
	if s := strings.TrimSpace(startsAt); s != "" {
		return s
	}
	return now.UTC().Format(time.RFC3339)
}

// DedupeKey 受理幂等键：(fingerprint, starts_at) 精确对。结构可比较，可直接作
// map 键；落库唯一索引与查询条件必须使用同一对值。
type DedupeKey struct {
	Fingerprint string
	StartsAt    string
}

// NewDedupeKey 构造幂等键：fingerprint 必填（去空白），starts_at 空值补 now 的
// UTC RFC3339。同一输入 + 同一 now（或非空 starts_at）得到相同键——构造是幂等
// 的；starts_at 为空且 now 不同则视为不同事件（空值无锚点，重投会新开）。
func NewDedupeKey(fingerprint, startsAt string, now time.Time) (DedupeKey, error) {
	fp, err := NormalizeFingerprint(fingerprint)
	if err != nil {
		return DedupeKey{}, err
	}
	return DedupeKey{Fingerprint: fp, StartsAt: NormalizeStartsAt(startsAt, now)}, nil
}

// Matches 判定两个键是否指向同一次受理：两字段都逐字相等才为 true。starts_at
// 不同即新一轮告警（恢复后重发/再次触发），fingerprint 相同也不得去重。
func (k DedupeKey) Matches(other DedupeKey) bool {
	return k == other
}
