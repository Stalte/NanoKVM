package pkgsign

import (
	"archive/tar"
	"compress/gzip"
	"crypto/ed25519"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func writeTarball(t *testing.T, dir, version string, files map[string]string) string {
	t.Helper()
	p := filepath.Join(dir, "nanokvm_"+version+".tar.gz")
	f, err := os.Create(p)
	if err != nil {
		t.Fatal(err)
	}
	gz := gzip.NewWriter(f)
	tw := tar.NewWriter(gz)
	root := "nanokvm_" + version
	mtime := time.Unix(1700000000, 0)
	if err := tw.WriteHeader(&tar.Header{Typeflag: tar.TypeDir, Name: root + "/", Mode: 0o755, ModTime: mtime}); err != nil {
		t.Fatal(err)
	}
	files["version"] = version + "\n"
	for name, body := range files {
		if strings.Contains(name, "/") {
			d := root + "/" + filepath.Dir(name) + "/"
			_ = tw.WriteHeader(&tar.Header{Typeflag: tar.TypeDir, Name: d, Mode: 0o755, ModTime: mtime})
		}
		h := &tar.Header{Typeflag: tar.TypeReg, Name: root + "/" + name, Mode: 0o755, Size: int64(len(body)), ModTime: mtime}
		if err := tw.WriteHeader(h); err != nil {
			t.Fatal(err)
		}
		if _, err := io.WriteString(tw, body); err != nil {
			t.Fatal(err)
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	return p
}

func extract(t *testing.T, tarball, dest string) string {
	t.Helper()
	f, err := os.Open(tarball)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	gz, err := gzip.NewReader(f)
	if err != nil {
		t.Fatal(err)
	}
	tr := tar.NewReader(gz)
	var root string
	for {
		h, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		target := filepath.Join(dest, h.Name)
		if root == "" {
			root = filepath.Join(dest, strings.SplitN(h.Name, "/", 2)[0])
		}
		if h.Typeflag == tar.TypeDir {
			_ = os.MkdirAll(target, 0o755)
			continue
		}
		_ = os.MkdirAll(filepath.Dir(target), 0o755)
		data, _ := io.ReadAll(tr)
		if err := os.WriteFile(target, data, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return root
}

func keyPair(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	pubFile, privFile, err := GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	pub, err := ParsePublicKey(pubFile)
	if err != nil {
		t.Fatal(err)
	}
	priv, err := ParsePrivateKey(privFile)
	if err != nil {
		t.Fatal(err)
	}
	return pub, priv
}

func signedPackage(t *testing.T, priv ed25519.PrivateKey) string {
	t.Helper()
	dir := t.TempDir()
	in := writeTarball(t, filepath.Join(dir), "2.5.901", map[string]string{
		"server/NanoKVM-Server": "binary",
		"system/init.d/S95":     "#!/bin/sh\n",
	})
	outDir := filepath.Join(dir, "signed")
	_ = os.MkdirAll(outDir, 0o755)
	out := filepath.Join(outDir, filepath.Base(in))
	if _, err := SignTarball(in, out, priv); err != nil {
		t.Fatal(err)
	}
	return extract(t, out, filepath.Join(dir, "x"))
}

func TestSignAndVerify(t *testing.T) {
	pub, priv := keyPair(t)
	root := signedPackage(t, priv)
	if err := VerifyDir(root, "2.5.901", []ed25519.PublicKey{pub}); err != nil {
		t.Fatalf("verify: %v", err)
	}
}

func TestVerifyRejects(t *testing.T) {
	pub, priv := keyPair(t)
	other, _ := keyPair(t)

	cases := map[string]struct {
		mutate  func(root string)
		version string
		keys    []ed25519.PublicKey
		want    error
	}{
		"changed file": {
			mutate: func(root string) {
				_ = os.WriteFile(filepath.Join(root, "server/NanoKVM-Server"), []byte("evil"), 0o644)
			},
			want: ErrTampered,
		},
		"added file": {
			mutate: func(root string) {
				_ = os.WriteFile(filepath.Join(root, "server/extra"), []byte("x"), 0o644)
			},
			want: ErrTampered,
		},
		"removed file": {
			mutate: func(root string) { _ = os.Remove(filepath.Join(root, "system/init.d/S95")) },
			want:   ErrTampered,
		},
		"wrong key":        {keys: []ed25519.PublicKey{other}, want: ErrBadSignature},
		"version mismatch": {version: "2.5.902", want: ErrTampered},
		"unsigned": {
			mutate: func(root string) { _ = os.RemoveAll(filepath.Join(root, Dir)) },
			want:   ErrUnsigned,
		},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			root := signedPackage(t, priv)
			if tc.mutate != nil {
				tc.mutate(root)
			}
			version := tc.version
			if version == "" {
				version = "2.5.901"
			}
			keys := tc.keys
			if keys == nil {
				keys = []ed25519.PublicKey{pub}
			}
			if err := VerifyDir(root, version, keys); !errors.Is(err, tc.want) {
				t.Fatalf("got %v, want %v", err, tc.want)
			}
		})
	}
}

func TestResignReplacesSignature(t *testing.T) {
	pub, priv := keyPair(t)
	dir := t.TempDir()
	in := writeTarball(t, dir, "2.5.901", map[string]string{"a": "1"})
	once := filepath.Join(dir, "once")
	twice := filepath.Join(dir, "twice")
	_ = os.MkdirAll(once, 0o755)
	_ = os.MkdirAll(twice, 0o755)
	if _, err := SignTarball(in, filepath.Join(once, filepath.Base(in)), priv); err != nil {
		t.Fatal(err)
	}
	if _, err := SignTarball(filepath.Join(once, filepath.Base(in)), filepath.Join(twice, filepath.Base(in)), priv); err != nil {
		t.Fatal(err)
	}
	root := extract(t, filepath.Join(twice, filepath.Base(in)), filepath.Join(dir, "x"))
	if err := VerifyDir(root, "2.5.901", []ed25519.PublicKey{pub}); err != nil {
		t.Fatal(err)
	}
}

func TestEmbeddedKeysParse(t *testing.T) {
	if _, err := TrustedKeys(); err != nil {
		t.Fatal(err)
	}
}
