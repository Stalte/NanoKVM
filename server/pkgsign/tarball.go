package pkgsign

import (
	"archive/tar"
	"compress/gzip"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"regexp"
	"strings"
	"time"
)

var tarballNamePattern = regexp.MustCompile(`^nanokvm_([0-9]+\.[0-9]+\.[0-9]+)\.tar\.gz$`)

// VersionFromTarballName returns the version a package file name declares,
// which is the version the device will require the package to contain.
func VersionFromTarballName(name string) (string, error) {
	m := tarballNamePattern.FindStringSubmatch(path.Base(name))
	if m == nil {
		return "", fmt.Errorf("%q is not named nanokvm_<major>.<minor>.<patch>.tar.gz", name)
	}
	return m[1], nil
}

// SignTarball writes a signed copy of the package at inPath to outPath. Every
// original entry is copied unchanged and in order; any existing signature is
// dropped and the new one is appended at the end. It returns the manifest that
// was signed.
func SignTarball(inPath, outPath string, key ed25519.PrivateKey) ([]byte, error) {
	version, err := VersionFromTarballName(inPath)
	if err != nil {
		return nil, err
	}
	root := "nanokvm_" + version

	hashes, versionFile, modTime, err := hashTarball(inPath, root)
	if err != nil {
		return nil, err
	}
	if strings.TrimSpace(versionFile) != version {
		return nil, fmt.Errorf("package version file says %q, file name says %q", strings.TrimSpace(versionFile), version)
	}
	manifest, err := BuildManifest(version, hashes)
	if err != nil {
		return nil, err
	}
	sig := Sign(key, manifest)

	if err := rewriteTarball(inPath, outPath, root, modTime, manifest, sig); err != nil {
		return nil, err
	}
	return manifest, nil
}

type tarEntry struct {
	header *tar.Header
	body   io.Reader
}

func walkTarball(p, root string, fn func(name string, e tarEntry) error) error {
	f, err := os.Open(p)
	if err != nil {
		return err
	}
	defer f.Close()
	gz, err := gzip.NewReader(f)
	if err != nil {
		return fmt.Errorf("open gzip archive: %w", err)
	}
	defer gz.Close()
	tr := tar.NewReader(gz)
	for {
		h, err := tr.Next()
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			return fmt.Errorf("read tar archive: %w", err)
		}
		name := strings.TrimSuffix(path.Clean(strings.TrimPrefix(h.Name, "./")), "/")
		if name != root && !strings.HasPrefix(name, root+"/") {
			return fmt.Errorf("entry %q is outside %s/", h.Name, root)
		}
		switch h.Typeflag {
		case tar.TypeReg, tar.TypeDir:
		default:
			return fmt.Errorf("entry %q is not a regular file or directory", h.Name)
		}
		if err := fn(name, tarEntry{header: h, body: tr}); err != nil {
			return err
		}
	}
}

func isSignatureEntry(name, root string) bool {
	return name == root+"/"+Dir || strings.HasPrefix(name, root+"/"+Dir+"/")
}

func hashTarball(p, root string) (map[string]string, string, int64, error) {
	hashes := make(map[string]string)
	var versionFile string
	var modTime int64
	err := walkTarball(p, root, func(name string, e tarEntry) error {
		if name == root {
			modTime = e.header.ModTime.Unix()
		}
		if isSignatureEntry(name, root) || e.header.Typeflag != tar.TypeReg {
			return nil
		}
		rel := strings.TrimPrefix(name, root+"/")
		if _, dup := hashes[rel]; dup {
			return fmt.Errorf("duplicate entry %q", name)
		}
		h := sha256.New()
		var body io.Reader = e.body
		if rel == "version" {
			data, err := io.ReadAll(io.LimitReader(e.body, 256))
			if err != nil {
				return err
			}
			versionFile = string(data)
			body = strings.NewReader(versionFile)
		}
		if _, err := io.Copy(h, body); err != nil {
			return err
		}
		hashes[rel] = hex.EncodeToString(h.Sum(nil))
		return nil
	})
	return hashes, versionFile, modTime, err
}

func rewriteTarball(inPath, outPath, root string, modTime int64, manifest, sig []byte) error {
	out, err := os.OpenFile(outPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o644)
	if err != nil {
		return err
	}
	ok := false
	defer func() {
		_ = out.Close()
		if !ok {
			_ = os.Remove(outPath)
		}
	}()

	gz, err := gzip.NewWriterLevel(out, gzip.BestCompression)
	if err != nil {
		return err
	}
	tw := tar.NewWriter(gz)

	err = walkTarball(inPath, root, func(name string, e tarEntry) error {
		if isSignatureEntry(name, root) {
			return nil
		}
		h := *e.header
		if err := tw.WriteHeader(&h); err != nil {
			return err
		}
		_, err := io.Copy(tw, e.body)
		return err
	})
	if err != nil {
		return err
	}

	base := tar.Header{Uid: 0, Gid: 0, Format: tar.FormatGNU}
	base.ModTime = time.Unix(modTime, 0).UTC()
	dir := base
	dir.Typeflag, dir.Name, dir.Mode = tar.TypeDir, root+"/"+Dir+"/", 0o755
	if err := tw.WriteHeader(&dir); err != nil {
		return err
	}
	for _, f := range []struct {
		name string
		data []byte
	}{{ManifestFile, manifest}, {SigFile, sig}} {
		h := base
		h.Typeflag, h.Name, h.Mode, h.Size = tar.TypeReg, root+"/"+Dir+"/"+f.name, 0o644, int64(len(f.data))
		if err := tw.WriteHeader(&h); err != nil {
			return err
		}
		if _, err := tw.Write(f.data); err != nil {
			return err
		}
	}

	if err := tw.Close(); err != nil {
		return err
	}
	if err := gz.Close(); err != nil {
		return err
	}
	if err := out.Close(); err != nil {
		return err
	}
	ok = true
	return nil
}
