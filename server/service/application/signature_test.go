package application

import (
	"archive/tar"
	"compress/gzip"
	"crypto/ed25519"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"NanoKVM-Server/pkgsign"
)

// A package signed by nanokvm-sign must pass the device's own archive checks
// unchanged, and its signature must survive the device's extraction.
func TestSignedPackagePassesOfflineUpdatePipeline(t *testing.T) {
	const version = "2.5.901"
	root := "nanokvm_" + version
	dir := t.TempDir()
	unsigned := filepath.Join(dir, root+".tar.gz")

	f, err := os.Create(unsigned)
	if err != nil {
		t.Fatal(err)
	}
	gz := gzip.NewWriter(f)
	tw := tar.NewWriter(gz)
	mtime := time.Unix(1700000000, 0)
	for _, d := range []string{"", "server", "kvm_system", "system", "system/init.d"} {
		name := root + "/"
		if d != "" {
			name = root + "/" + d + "/"
		}
		if err := tw.WriteHeader(&tar.Header{Typeflag: tar.TypeDir, Name: name, Mode: 0o755, ModTime: mtime}); err != nil {
			t.Fatal(err)
		}
	}
	for name, body := range map[string]string{
		"version":                  version + "\n",
		"server/NanoKVM-Server":    "server",
		"kvm_system/kvm_system":    "kvm_system",
		"system/init.d/S95nanokvm": "#!/bin/sh\n",
	} {
		if err := tw.WriteHeader(&tar.Header{Typeflag: tar.TypeReg, Name: root + "/" + name, Mode: 0o755, Size: int64(len(body)), ModTime: mtime}); err != nil {
			t.Fatal(err)
		}
		if _, err := tw.Write([]byte(body)); err != nil {
			t.Fatal(err)
		}
	}
	_ = tw.Close()
	_ = gz.Close()
	_ = f.Close()

	pubFile, privFile, err := pkgsign.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	pub, _ := pkgsign.ParsePublicKey(pubFile)
	priv, _ := pkgsign.ParsePrivateKey(privFile)
	signedDir := filepath.Join(dir, "signed")
	_ = os.MkdirAll(signedDir, 0o755)
	signed := filepath.Join(signedDir, root+".tar.gz")
	if _, err := pkgsign.SignTarball(unsigned, signed, priv); err != nil {
		t.Fatal(err)
	}

	if _, err := inspectUpdateArchive(signed, root); err != nil {
		t.Fatalf("inspect: %v", err)
	}
	workspace := filepath.Join(dir, "work")
	_ = os.MkdirAll(workspace, 0o755)
	sourceDir, err := extractUpdateArchive(signed, workspace, root)
	if err != nil {
		t.Fatalf("extract: %v", err)
	}
	if err := validateExtractedPackage(sourceDir, version); err != nil {
		t.Fatalf("validate: %v", err)
	}
	if err := pkgsign.VerifyDir(sourceDir, version, []ed25519.PublicKey{pub}); err != nil {
		t.Fatalf("verify: %v", err)
	}

	// The same pipeline on the unsigned original reports it as unsigned.
	workspace2 := filepath.Join(dir, "work2")
	_ = os.MkdirAll(workspace2, 0o755)
	sourceDir2, err := extractUpdateArchive(unsigned, workspace2, root)
	if err != nil {
		t.Fatal(err)
	}
	if err := pkgsign.VerifyDir(sourceDir2, version, []ed25519.PublicKey{pub}); !errors.Is(err, pkgsign.ErrUnsigned) {
		t.Fatalf("unsigned package: got %v", err)
	}
}
