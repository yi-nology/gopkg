// Package git 提供本地 git 仓库的分支/标签读写与打 tag 推送。
package git

import (
	"context"

	"github.com/go-git/go-git/v5/plumbing"
	"github.com/go-git/go-git/v5/plumbing/object"
)

// Git 是分支/标签操作面。
//
// 日志不再作为方法参数传递——那是 common 时代的形状：调用方每次调用都要
// 递一个 logger 进来，而 logger 本就属于包（见 git.go 的包级 Delegating），
// 传参只是把包的责任转嫁给每个调用点。
type Git interface {
	// Branches 列出全部分支（先 fetch 同步远端）。
	Branches() ([]*plumbing.Reference, error)
	// Tags 列出全部标签。
	Tags() ([]*plumbing.Reference, error)
	// CreateTag 在 pl 指向的提交上打 version 标签并推送远端。
	CreateTag(ctx context.Context, pl plumbing.Reference, version string, sign *object.Signature) error
	// DeleteTag 删除 version 标签并推送远端。
	DeleteTag(ctx context.Context, version string) error
}
