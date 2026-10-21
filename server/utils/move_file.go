package utils

import (
	"io"
	"os"
	"path/filepath"
	"strings"
)

func MoveFile(src, dst string) error {
	if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
		return err
	}
	err := os.Rename(src, dst)
	if err != nil {
		if strings.Contains(err.Error(), "invalid cross-device link") {
			return MoveFileCrossFS(src, dst)
		}
		return err
	}
	return nil
}

func MoveFileCrossFS(src, dst string) error {
	tmp := dst + ".tmp"
	srcFile, err := os.Open(src)
	if err != nil {
		return err
	}

	tmpFile, err := os.Create(tmp)
	if err != nil {
		_ = srcFile.Close()
		return err
	}
	_, err = io.Copy(tmpFile, srcFile)
	if err != nil {
		_ = srcFile.Close()
		_ = tmpFile.Close()
		return err
	}
	_ = srcFile.Close()
	_ = tmpFile.Close()
	fi, err := os.Stat(src)
	if err != nil {
		return err
	}
	err = os.Chmod(tmp, fi.Mode())
	if err != nil {
		return err
	}
	_ = os.Remove(src)
	err = os.Rename(tmp, dst)
	if err != nil {
		return err
	}
	return nil
}

func MoveFilesRecursively(src, dst string) error {
	return filepath.Walk(src, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		fileName := strings.Replace(path, src, "", 1)
		dstName := dst + fileName
		fileInfo, err := os.Stat(path)
		if err != nil {
			return err
		}

		if fileInfo.IsDir() {
			return os.MkdirAll(dstName, fileInfo.Mode())
		}
		return MoveFile(path, dstName)
	})
}

// CopyFile copies src over dst through a temporary file next to dst, so a
// reader of dst never sees it half written.
func CopyFile(src, dst string) error {
	if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
		return err
	}
	srcFile, err := os.Open(src)
	if err != nil {
		return err
	}
	defer func() { _ = srcFile.Close() }()

	tmp := dst + ".tmp"
	tmpFile, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o644)
	if err != nil {
		return err
	}
	if _, err = io.Copy(tmpFile, srcFile); err != nil {
		_ = tmpFile.Close()
		_ = os.Remove(tmp)
		return err
	}
	if err = tmpFile.Close(); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	return os.Rename(tmp, dst)
}
