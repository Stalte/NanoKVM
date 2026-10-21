// nanokvm-sign generates update signing keys and signs NanoKVM application
// packages for the hardened build. Run it on your own machine: the private key
// never needs to leave it.
//
//	nanokvm-sign keygen -out ~/.nanokvm/update
//	nanokvm-sign sign -key ~/.nanokvm/update.key [-o signed] nanokvm_2.5.901.tar.gz
//	nanokvm-sign verify -pub server/pkgsign/keys/owner.pub signed/nanokvm_2.5.901.tar.gz
package main

import (
	"archive/tar"
	"compress/gzip"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"strings"

	"NanoKVM-Server/pkgsign"
)

func main() {
	if len(os.Args) < 2 {
		usage()
	}
	var err error
	switch os.Args[1] {
	case "keygen":
		err = keygen(os.Args[2:])
	case "sign":
		err = sign(os.Args[2:])
	case "verify":
		err = verify(os.Args[2:])
	default:
		usage()
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, `usage:
  nanokvm-sign keygen -out <path-prefix>
  nanokvm-sign sign -key <private.key> [-o <dir>] <nanokvm_X.Y.Z.tar.gz>
  nanokvm-sign verify -pub <public.pub> <nanokvm_X.Y.Z.tar.gz>`)
	os.Exit(2)
}

func keygen(args []string) error {
	fs := flag.NewFlagSet("keygen", flag.ExitOnError)
	out := fs.String("out", "", "path prefix; writes <prefix>.key and <prefix>.pub")
	_ = fs.Parse(args)
	if *out == "" {
		return errors.New("-out is required")
	}
	keyPath, pubPath := *out+".key", *out+".pub"
	for _, p := range []string{keyPath, pubPath} {
		if _, err := os.Stat(p); err == nil {
			return fmt.Errorf("%s already exists; refusing to overwrite a key", p)
		}
	}
	pub, priv, err := pkgsign.GenerateKey()
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(keyPath), 0o700); err != nil {
		return err
	}
	if err := os.WriteFile(keyPath, priv, 0o600); err != nil {
		return err
	}
	if err := os.WriteFile(pubPath, pub, 0o644); err != nil {
		return err
	}
	fmt.Printf("private key: %s (keep this secret and backed up)\npublic key:  %s\n", keyPath, pubPath)
	fmt.Println("commit the public key as server/pkgsign/keys/<name>.pub and rebuild")
	return nil
}

func sign(args []string) error {
	fs := flag.NewFlagSet("sign", flag.ExitOnError)
	keyPath := fs.String("key", "", "private key file from keygen")
	outDir := fs.String("o", "signed", "output directory")
	_ = fs.Parse(args)
	if *keyPath == "" || fs.NArg() != 1 {
		return errors.New("usage: sign -key <private.key> [-o dir] <package>")
	}
	in := fs.Arg(0)

	keyData, err := os.ReadFile(*keyPath)
	if err != nil {
		return err
	}
	key, err := pkgsign.ParsePrivateKey(keyData)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(*outDir, 0o755); err != nil {
		return err
	}
	out := filepath.Join(*outDir, filepath.Base(in))
	if abs(out) == abs(in) {
		return errors.New("output would overwrite the input; choose another -o")
	}
	if _, err := pkgsign.SignTarball(in, out, key); err != nil {
		return err
	}
	sum, err := fileSHA256(out)
	if err != nil {
		return err
	}
	pub := key.Public().(ed25519.PublicKey)
	fmt.Printf("signed:  %s\nsha256:  %s\nkey:     %x\n", out, sum, pub[:8])
	fmt.Println("upload it under Settings > Update > Offline update, with the sha256 above")
	return nil
}

func verify(args []string) error {
	fs := flag.NewFlagSet("verify", flag.ExitOnError)
	pubPath := fs.String("pub", "", "public key file")
	_ = fs.Parse(args)
	if *pubPath == "" || fs.NArg() != 1 {
		return errors.New("usage: verify -pub <public.pub> <package>")
	}
	pubData, err := os.ReadFile(*pubPath)
	if err != nil {
		return err
	}
	pub, err := pkgsign.ParsePublicKey(pubData)
	if err != nil {
		return err
	}
	in := fs.Arg(0)
	version, err := pkgsign.VersionFromTarballName(in)
	if err != nil {
		return err
	}
	tmp, err := os.MkdirTemp("", "nanokvm-verify-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(tmp)
	root := "nanokvm_" + version
	if err := extract(in, tmp, root); err != nil {
		return err
	}
	if err := pkgsign.VerifyDir(filepath.Join(tmp, root), version, []ed25519.PublicKey{pub}); err != nil {
		return err
	}
	fmt.Printf("OK: %s is signed by %s\n", in, *pubPath)
	return nil
}

// extract unpacks only directories and regular files that stay under root,
// the same entries the device's updater accepts.
func extract(tarball, dest, root string) error {
	f, err := os.Open(tarball)
	if err != nil {
		return err
	}
	defer f.Close()
	gz, err := gzip.NewReader(f)
	if err != nil {
		return err
	}
	tr := tar.NewReader(gz)
	for {
		h, err := tr.Next()
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			return err
		}
		name := strings.TrimSuffix(path.Clean(strings.TrimPrefix(h.Name, "./")), "/")
		if name != root && !strings.HasPrefix(name, root+"/") {
			return fmt.Errorf("entry %q is outside %s/", h.Name, root)
		}
		target := filepath.Join(dest, filepath.FromSlash(name))
		switch h.Typeflag {
		case tar.TypeDir:
			if err := os.MkdirAll(target, 0o755); err != nil {
				return err
			}
		case tar.TypeReg:
			if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
				return err
			}
			w, err := os.OpenFile(target, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o644)
			if err != nil {
				return err
			}
			_, err = io.Copy(w, tr)
			_ = w.Close()
			if err != nil {
				return err
			}
		default:
			return fmt.Errorf("entry %q is not a regular file or directory", h.Name)
		}
	}
}

func fileSHA256(p string) (string, error) {
	f, err := os.Open(p)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

func abs(p string) string {
	a, err := filepath.Abs(p)
	if err != nil {
		return p
	}
	return a
}
