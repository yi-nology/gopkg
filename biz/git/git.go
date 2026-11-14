package git

import (
	"context"

	"github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/config"
	"github.com/go-git/go-git/v5/plumbing"
	"github.com/go-git/go-git/v5/plumbing/object"
	"github.com/oekit/logx"
)

// log 是包级懒解析 logger：gopkg 是库，service name 属于消费方，包归属
// 用 component 属性标识（oekit 红线：SDK/基础包包级 logger 必须
// Delegating，禁 Default()/WithService——后者会把消费方的服务名写死）。
var log = logx.Delegating("git")

// Branches 列出全部分支。
//
// 此前实现遍历分支时只 fmt.Println(ref.Name()) 而从不 append，branchesResult
// 恒为 nil——调用方拿到的永远是空列表，且往 stdout 打印对库而言是污染。
// 现在真正收集，并把 ForEach 的错误上抛（原实现直接丢弃）。
func (i *Info) Branches() ([]*plumbing.Reference, error) {
	if err := i.project.Fetch(&git.FetchOptions{Auth: i.publicKey}); err != nil && err != git.NoErrAlreadyUpToDate {
		log.Error("fetch branches failed", logx.ErrKey, err)
		return nil, err
	}

	branches, err := i.project.Branches()
	if err != nil {
		log.Error("list branches failed", logx.ErrKey, err)
		return nil, err
	}

	var out []*plumbing.Reference
	if err := branches.ForEach(func(ref *plumbing.Reference) error {
		out = append(out, ref)
		return nil
	}); err != nil {
		log.Error("iterate branches failed", logx.ErrKey, err)
		return nil, err
	}
	return out, nil
}

// Tags 列出全部标签。
func (i *Info) Tags() ([]*plumbing.Reference, error) {
	tags, err := i.project.Tags()
	if err != nil {
		log.Error("list tags failed", logx.ErrKey, err)
		return nil, err
	}
	var out []*plumbing.Reference
	if err := tags.ForEach(func(ref *plumbing.Reference) error {
		if ref != nil {
			out = append(out, ref)
		}
		return nil
	}); err != nil {
		log.Error("iterate tags failed", logx.ErrKey, err)
		return nil, err
	}
	return out, nil
}

// CreateTag 打标签并推送远端。
func (i *Info) CreateTag(ctx context.Context, pl plumbing.Reference, version string, sign *object.Signature) error {
	if _, err := i.project.CreateTag(version, pl.Hash(), &git.CreateTagOptions{
		Tagger:  sign,
		Message: "this is my tag",
	}); err != nil {
		log.Error("create tag failed", "version", version, logx.ErrKey, err)
		return err
	}
	return i.push(ctx)
}

// DeleteTag 删除标签并推送远端。
func (i *Info) DeleteTag(ctx context.Context, version string) error {
	if err := i.project.DeleteTag(version); err != nil {
		log.Error("delete tag failed", "version", version, logx.ErrKey, err)
		return err
	}
	return i.push(ctx)
}

// push 把标签变更推到远端。Progress 不再写 os.Stdout——库不占用进程标准
// 输出，需要进度的调用方自己在远端层面观测。
func (i *Info) push(ctx context.Context) error {
	if err := i.project.PushContext(ctx, &git.PushOptions{
		RemoteName: i.url,
		RefSpecs: []config.RefSpec{
			"+refs/tags/*:refs/tags/*",
		},
		Auth: i.publicKey,
	}); err != nil {
		log.Error("push tags failed", logx.ErrKey, err)
		return err
	}
	return nil
}
