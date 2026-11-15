package eventsrc

import (
	"errors"
	"net/http"
)

// 留痕拒绝原因词表（Event.Reason；管理面按此聚合与展示）。
const (
	ReasonUnknownSource = "unknown_source" // 源不存在
	ReasonDisabled      = "disabled"       // 源已停用
	ReasonBadToken      = "bad_token"      // Bearer/X-Webhook-Token 不匹配
	ReasonBadSignature  = "bad_signature"  // HMAC 验签失败
	ReasonRateLimited   = "rate_limited"   // 超出每源滑动窗口
	ReasonBadPayload    = "bad_payload"    // 非 JSON 对象/超出体量
	ReasonFiltered      = "filtered"       // 过滤未命中（送达成功、平台选择不响应）
	ReasonError         = "error"          // 投递回调失败等内部错误
)

// 留痕状态（Event.Status）。
const (
	StatusAccepted = "accepted"
	StatusRejected = "rejected"
)

// RejectError 管道硬拒绝（未知源/停用/鉴权/限频/坏载荷/投递失败）。
// Reason 是留痕原因码；Status 是给 HTTP handler 的建议状态码。
//
// [RejectError.Is] 按 Reason 比较，因此调用方可用 errors.Is(err, ErrBadToken)
// 判定类别，同时拿到带上下文的 Message。
type RejectError struct {
	Reason  string
	Status  int
	Message string
}

func (e *RejectError) Error() string {
	if e == nil {
		return "<nil>"
	}
	return e.Message
}

// Is 同类拒绝按 Reason 相等判定（动态 Message 不影响 errors.Is）。
func (e *RejectError) Is(target error) bool {
	t, ok := target.(*RejectError)
	return ok && e != nil && t != nil && e.Reason == t.Reason
}

// 管道拒绝哨兵：Ingest 返回这些值（或带动态文案的同 Reason 实例）。
var (
	ErrUnknownSource = &RejectError{Reason: ReasonUnknownSource, Status: http.StatusNotFound, Message: "事件源不存在"}
	ErrDisabled      = &RejectError{Reason: ReasonDisabled, Status: http.StatusForbidden, Message: "事件源已停用"}
	ErrBadToken      = &RejectError{Reason: ReasonBadToken, Status: http.StatusUnauthorized, Message: "鉴权失败（Authorization: Bearer <secret> 或 X-Webhook-Token）"}
	ErrBadSignature  = &RejectError{Reason: ReasonBadSignature, Status: http.StatusUnauthorized, Message: "签名校验失败（X-Webhook-Signature: sha256=<hex>）"}
	ErrRateLimited   = &RejectError{Reason: ReasonRateLimited, Status: http.StatusTooManyRequests, Message: "事件源触发超限"}
	ErrBadPayload    = &RejectError{Reason: ReasonBadPayload, Status: http.StatusBadRequest, Message: "载荷必须是 JSON 对象"}
	ErrSink          = &RejectError{Reason: ReasonError, Status: http.StatusInternalServerError, Message: "事件投递失败"}
)

// 管理面错误（源 CRUD/存储装配；与管道拒绝分开，便于 handler 映射）。
var (
	ErrInvalidSource    = errors.New("eventsrc: 源配置非法")
	ErrSourceNotFound   = errors.New("eventsrc: 事件源不存在")
	ErrSourceExists     = errors.New("eventsrc: 事件源已存在")
	ErrStoreUnavailable = errors.New("eventsrc: 存储未装配")
)

// ReasonOf 提取错误对应的留痕原因码；非拒绝错误返回空串。
func ReasonOf(err error) string {
	var re *RejectError
	if errors.As(err, &re) {
		return re.Reason
	}
	return ""
}

// HTTPStatus 映射建议 HTTP 状态码（非 RejectError 一律 500）。
func HTTPStatus(err error) int {
	var re *RejectError
	if errors.As(err, &re) && re.Status > 0 {
		return re.Status
	}
	return http.StatusInternalServerError
}
