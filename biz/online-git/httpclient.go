package onlinegit

import (
	"net/http"
	"time"

	"github.com/oekit/httpx"
)

// APITimeout 是 git 平台 API 调用的超时口径（拨号与读取各以它为上限，
// 外层再用 http.Client.Timeout 兜一个总时长顶）。
//
// 三家 provider 此前都用裸 &http.Client{}——**完全没有超时**：对端挂起时
// 调用方 goroutine 永久阻塞，且 gitlab/gitea 连 Transport 都是零值（连
// 连接池参数都不可控）。现在三家共用这一份口径，漂移无处可藏。
const APITimeout = 30 * time.Second

// APIRoundTripper 返回受 httpx 治理的 git 平台 API RoundTripper。
//
// component 按平台给（如 "online-git/github"），让指标与链路能按平台分面；
// TLS 策略经 WithTLSSkipVerify 收进同一构造，不再各 provider 手搓
// http.Transport。
//
// 返回值属于进程生命周期（与 provider 同寿命），调用方无需也不应 Close。
// 构造失败显式返回 error——NewProvider 本就返回 error，不走 panic。
func APIRoundTripper(component string, insecureSkipTLS bool) (http.RoundTripper, error) {
	opts := []httpx.ClientOption{httpx.WithTimeout(APITimeout)}
	if insecureSkipTLS {
		opts = append(opts, httpx.WithTLSSkipVerify())
	}
	return httpx.NewRoundTripperE(component, opts...)
}

// APIHTTPClient 是 APIRoundTripper 的 *http.Client 形态，给直接收
// *http.Client 的 SDK（go-gitlab、gitea sdk）用。
//
// client.Timeout 是**整个请求**的总预算（含读完 body），与 httpx 的
// 拨号/读取分项上限是两层不同语义的保险——只靠分项上限时，一个慢慢
// 滴 body 的对端仍能把请求拖很久。
func APIHTTPClient(component string, insecureSkipTLS bool) (*http.Client, error) {
	rt, err := APIRoundTripper(component, insecureSkipTLS)
	if err != nil {
		return nil, err
	}
	return &http.Client{Transport: rt, Timeout: APITimeout}, nil
}
