// Package pkgsign signs and verifies NanoKVM application packages.
//
// A signed package is an ordinary nanokvm_<version>.tar.gz whose root
// directory also carries .signature/manifest and .signature/manifest.sig. The
// manifest lists the SHA-256 of every regular file in the package except the
// .signature directory itself, and manifest.sig is an ed25519 signature over
// the manifest bytes. Keeping the signature inside the archive means the
// stock offline-update page can upload a signed package unchanged.
//
// The device rebuilds the manifest from what it actually extracted and
// requires it to match the signed one byte for byte, so a file that was
// added, removed or changed after signing fails verification.
package pkgsign

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"embed"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"
)

const (
	// Dir is the directory, relative to the package root, that holds the
	// signature files.
	Dir          = ".signature"
	ManifestFile = "manifest"
	SigFile      = "manifest.sig"

	manifestHeader = "nanokvm-package-manifest v1"

	publicKeyPrefix  = "nanokvm-ed25519 "
	privateKeyPrefix = "nanokvm-ed25519-private "
)

var (
	ErrUnsigned     = errors.New("package is not signed")
	ErrBadSignature = errors.New("package signature does not match any trusted key")
	ErrTampered     = errors.New("package contents do not match the signed manifest")
)

//go:embed keys
var embeddedKeys embed.FS

// TrustedKeys returns the public keys compiled into this build from
// pkgsign/keys/*.pub. An empty result means the build was made without a
// signing key.
func TrustedKeys() ([]ed25519.PublicKey, error) {
	entries, err := fs.ReadDir(embeddedKeys, "keys")
	if err != nil {
		return nil, err
	}
	var keys []ed25519.PublicKey
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".pub") {
			continue
		}
		data, err := embeddedKeys.ReadFile("keys/" + entry.Name())
		if err != nil {
			return nil, err
		}
		key, err := ParsePublicKey(data)
		if err != nil {
			return nil, fmt.Errorf("keys/%s: %w", entry.Name(), err)
		}
		keys = append(keys, key)
	}
	return keys, nil
}

// GenerateKey returns a new key pair encoded as the public and private key
// files the signing tool reads and writes.
func GenerateKey() (publicFile, privateFile []byte, err error) {
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		return nil, nil, err
	}
	publicFile = []byte(publicKeyPrefix + base64.StdEncoding.EncodeToString(pub) + "\n")
	privateFile = []byte(privateKeyPrefix + base64.StdEncoding.EncodeToString(priv.Seed()) + "\n")
	return publicFile, privateFile, nil
}

func ParsePublicKey(data []byte) (ed25519.PublicKey, error) {
	raw, err := decodeKeyLine(data, publicKeyPrefix, ed25519.PublicKeySize)
	if err != nil {
		return nil, err
	}
	return ed25519.PublicKey(raw), nil
}

func ParsePrivateKey(data []byte) (ed25519.PrivateKey, error) {
	raw, err := decodeKeyLine(data, privateKeyPrefix, ed25519.SeedSize)
	if err != nil {
		return nil, err
	}
	return ed25519.NewKeyFromSeed(raw), nil
}

func decodeKeyLine(data []byte, prefix string, size int) ([]byte, error) {
	line := strings.TrimSpace(string(data))
	if !strings.HasPrefix(line, prefix) {
		return nil, fmt.Errorf("not a %q key", strings.TrimSpace(prefix))
	}
	raw, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(line, prefix))
	if err != nil {
		return nil, fmt.Errorf("decode key: %w", err)
	}
	if len(raw) != size {
		return nil, fmt.Errorf("key has %d bytes, want %d", len(raw), size)
	}
	return raw, nil
}

// BuildManifest renders the manifest for a package version and the SHA-256
// (hex) of each file, keyed by its slash-separated path relative to the
// package root. Paths inside Dir must not be passed in.
func BuildManifest(version string, hashes map[string]string) ([]byte, error) {
	if version == "" || strings.ContainsAny(version, " \n") {
		return nil, fmt.Errorf("invalid version %q", version)
	}
	names := make([]string, 0, len(hashes))
	for name := range hashes {
		if name == "" || strings.ContainsAny(name, "\n") || path.Clean(name) != name ||
			strings.HasPrefix(name, "../") || strings.HasPrefix(name, "/") {
			return nil, fmt.Errorf("invalid manifest path %q", name)
		}
		if name == Dir || strings.HasPrefix(name, Dir+"/") {
			return nil, fmt.Errorf("manifest must not list %q", name)
		}
		names = append(names, name)
	}
	sort.Strings(names)

	var buf bytes.Buffer
	fmt.Fprintf(&buf, "%s\nversion %s\n", manifestHeader, version)
	for _, name := range names {
		fmt.Fprintf(&buf, "%s  %s\n", hashes[name], name)
	}
	return buf.Bytes(), nil
}

// Sign returns the base64 signature file contents for a manifest.
func Sign(key ed25519.PrivateKey, manifest []byte) []byte {
	sig := ed25519.Sign(key, manifest)
	return []byte(base64.StdEncoding.EncodeToString(sig) + "\n")
}

// HashDir hashes every regular file under root except the signature
// directory. Anything that is neither a directory nor a regular file is an
// error: the updater never installs links or device nodes.
func HashDir(root string) (map[string]string, error) {
	hashes := make(map[string]string)
	err := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(root, p)
		if err != nil {
			return err
		}
		rel = filepath.ToSlash(rel)
		if rel == "." {
			return nil
		}
		if rel == Dir {
			if !d.IsDir() {
				return fmt.Errorf("%s is not a directory", Dir)
			}
			return filepath.SkipDir
		}
		if d.IsDir() {
			return nil
		}
		if !d.Type().IsRegular() {
			return fmt.Errorf("%s is not a regular file", rel)
		}
		sum, err := hashFile(p)
		if err != nil {
			return err
		}
		hashes[rel] = sum
		return nil
	})
	return hashes, err
}

func hashFile(p string) (string, error) {
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

// VerifyDir checks an extracted package root against its signature and the
// trusted keys. It returns ErrUnsigned when the signature files are absent.
func VerifyDir(root, expectedVersion string, keys []ed25519.PublicKey) error {
	if len(keys) == 0 {
		return errors.New("no trusted signing keys")
	}
	manifest, err := os.ReadFile(filepath.Join(root, Dir, ManifestFile))
	if errors.Is(err, fs.ErrNotExist) {
		return ErrUnsigned
	}
	if err != nil {
		return err
	}
	sigFile, err := os.ReadFile(filepath.Join(root, Dir, SigFile))
	if errors.Is(err, fs.ErrNotExist) {
		return ErrUnsigned
	}
	if err != nil {
		return err
	}
	if err := VerifyManifest(manifest, sigFile, keys); err != nil {
		return err
	}

	hashes, err := HashDir(root)
	if err != nil {
		return err
	}
	actual, err := BuildManifest(expectedVersion, hashes)
	if err != nil {
		return err
	}
	if !bytes.Equal(actual, manifest) {
		return ErrTampered
	}
	return nil
}

// VerifyManifest checks a manifest's signature against the trusted keys.
func VerifyManifest(manifest, sigFile []byte, keys []ed25519.PublicKey) error {
	sig, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(sigFile)))
	if err != nil || len(sig) != ed25519.SignatureSize {
		return ErrBadSignature
	}
	for _, key := range keys {
		if ed25519.Verify(key, manifest, sig) {
			return nil
		}
	}
	return ErrBadSignature
}
