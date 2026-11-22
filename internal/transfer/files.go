package transfer

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"ex1b/internal/storage"
	"ex1b/internal/ui"
	"ex1b/internal/wire"
)

func hashFile(r io.Reader) (string, int64, error) {
	h := sha256.New()
	size, err := io.Copy(h, io.LimitReader(r, wire.MaxFile+1))
	return hex.EncodeToString(h.Sum(nil)), size, err
}

func (e *Engine) Upload(ctx context.Context, name, sourcePath string, notify func(ui.Progress)) error {
	if err := storage.ValidateName(name); err != nil {
		return err
	}
	if _, exists := e.files.LoadOrStore("up:"+name, true); exists {
		return errors.New("此文件已有上传任务")
	}
	defer e.files.Delete("up:" + name)
	source, err := os.Open(sourcePath)
	if err != nil {
		return err
	}
	defer source.Close()
	stat, err := source.Stat()
	if err != nil || !stat.Mode().IsRegular() || stat.Size() > wire.MaxFile {
		return errors.New("只支持 128 MiB 以内的普通文件")
	}
	digest, size, err := hashFile(source)
	if err != nil || size != stat.Size() {
		return errors.New("无法读取文件，或文件在读取期间发生变化")
	}
	base := wire.Header{Kind: "put_begin", Name: name, SHA256: digest, Size: size}
	var resumedAt int64
	return retry(ctx, func() error {
		link, err := e.ensure(ctx)
		if err != nil {
			return err
		}
		begin, err := link.call(ctx, wire.Frame{Header: base})
		if err != nil {
			return err
		}
		offset := begin.Offset
		if offset < 0 || offset > size || begin.Done && offset != size {
			return errors.New("服务端上传偏移无效")
		}
		if offset > 0 && !begin.Done {
			resumedAt = offset
		}
		report(notify, offset, size, resumedAt, digest)
		if begin.Done {
			return nil
		}
		part := base
		part.Kind = "put_chunk"
		buffer := make([]byte, wire.ChunkSize)
		for offset < size {
			requested := min(size-offset, int64(len(buffer)))
			n, err := source.ReadAt(buffer[:requested], offset)
			if err != nil || int64(n) != requested {
				return errors.New("源文件已改变或无法继续读取")
			}
			part.Offset = offset
			ack, err := link.call(ctx, wire.Frame{Header: part, Body: buffer[:n]})
			if err != nil {
				return err
			}
			if ack.Offset != offset+int64(n) {
				return errors.New("服务端确认的上传偏移不一致")
			}
			offset = ack.Offset
			report(notify, offset, size, resumedAt, digest)
		}
		finish := base
		finish.Kind = "put_finish"
		reply, err := link.call(ctx, wire.Frame{Header: finish})
		if err == nil && !reply.Done {
			return errors.New("服务端未确认上传校验")
		}
		return err
	})
}

func (e *Engine) Download(ctx context.Context, name, dir string, notify func(ui.Progress)) (string, error) {
	if err := storage.ValidateName(name); err != nil {
		return "", err
	}
	if _, exists := e.files.LoadOrStore("down:"+name, true); exists {
		return "", errors.New("此文件已有下载任务")
	}
	defer e.files.Delete("down:" + name)
	root, err := os.OpenRoot(dir)
	if err != nil {
		return "", err
	}
	defer root.Close()
	var meta wire.Frame
	err = retry(ctx, func() error {
		var err error
		meta, err = e.call(ctx, wire.Header{Kind: "get_begin", Name: name}, nil)
		return err
	})
	if err != nil {
		return "", err
	}
	decoded, parseErr := hex.DecodeString(meta.SHA256)
	if meta.Size < 0 || meta.Size > wire.MaxFile || parseErr != nil || len(decoded) != sha256.Size {
		return "", errors.New("服务端文件元数据无效")
	}
	result := filepath.Join(dir, name)
	exists, err := checkDownloaded(root, name, meta.SHA256, meta.Size)
	if err != nil {
		return "", err
	}
	if exists {
		report(notify, meta.Size, meta.Size, 0, meta.SHA256)
		return result, nil
	}
	if err := root.MkdirAll(".ex1b-partial", 0700); err != nil {
		return "", err
	}
	key := sha256.Sum256([]byte(name + "\x00" + meta.SHA256))
	partialName := fmt.Sprintf(".ex1b-partial/%x.part", key)
	partial, err := root.OpenFile(partialName, os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return "", err
	}
	defer partial.Close()
	stat, err := partial.Stat()
	if err != nil || !stat.Mode().IsRegular() || stat.Size() > meta.Size {
		return "", errors.New("本地续传文件状态无效")
	}
	offset := stat.Size()
	resumedAt := offset
	started := false
	err = retry(ctx, func() error {
		link, err := e.ensure(ctx)
		if err != nil {
			return err
		}
		if started && offset > 0 {
			resumedAt = offset
		}
		started = true
		report(notify, offset, meta.Size, resumedAt, meta.SHA256)
		for offset < meta.Size {
			limit := int(min(meta.Size-offset, wire.ChunkSize))
			r, err := link.call(ctx, wire.Frame{Header: wire.Header{
				Kind: "get_chunk", Name: name, SHA256: meta.SHA256, Offset: offset, Limit: limit,
			}})
			if err != nil {
				return err
			}
			if len(r.Body) != limit || r.Offset != offset+int64(limit) {
				return errors.New("下载分块长度或偏移不一致")
			}
			if _, err := partial.WriteAt(r.Body, offset); err != nil {
				_ = partial.Truncate(offset)
				return err
			}
			offset = r.Offset
			report(notify, offset, meta.Size, resumedAt, meta.SHA256)
		}
		return nil
	})
	if err != nil {
		return "", err
	}
	digest, size, err := hashFile(partial)
	if err != nil || size != meta.Size || digest != meta.SHA256 {
		_ = partial.Close()
		_ = root.Remove(partialName)
		return "", errors.New("下载完整性校验失败，请重新传输")
	}
	if err := partial.Sync(); err != nil {
		return "", err
	}
	if err := partial.Close(); err != nil {
		return "", err
	}
	err = retry(ctx, func() error {
		finish, err := e.call(ctx, wire.Header{Kind: "get_finish", Name: name, SHA256: digest, Size: size}, nil)
		if err == nil && !finish.Done {
			return errors.New("服务端未确认下载回执")
		}
		return err
	})
	if err != nil {
		return "", err
	}
	// A same-volume hard link publishes only a verified complete file and fails
	// atomically if another task or the user already created the destination.
	if err := root.Link(partialName, name); err != nil {
		return "", fmt.Errorf("无法将校验通过的文件保存为 %s: %w", name, err)
	}
	_ = root.Remove(partialName)
	return result, nil
}

func checkDownloaded(root *os.Root, name, expected string, size int64) (bool, error) {
	f, err := root.Open(name)
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	defer f.Close()
	stat, err := f.Stat()
	if err != nil || !stat.Mode().IsRegular() || stat.Size() != size {
		return false, errors.New("下载目录已有同名文件")
	}
	digest, _, err := hashFile(f)
	if err != nil || digest != expected {
		return false, errors.New("下载目录已有同名异内容文件")
	}
	return true, nil
}

func report(notify func(ui.Progress), done, total, resumed int64, digest string) {
	if notify != nil {
		notify(ui.Progress{Done: done, Total: total, ResumedAt: resumed, SHA256: digest})
	}
}
