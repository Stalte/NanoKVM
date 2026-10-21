// nanokvm-guard is the small privileged helper behind the hardened build's
// boot scripts. It is a static binary so it runs on the stock BusyBox image.
//
//	nanokvm-guard run-as <user> -- <command> [args...]
//	    Drop to <user> (its uid, gid and no supplementary groups), forbid
//	    regaining privileges, and exec <command>. This is how tailscaled runs
//	    as the one unprivileged user the firewall lets reach the internet.
//
//	nanokvm-guard timesync [-as <user>] [-url <https url>] [-min-skew 2s]
//	    Set the system clock from the Date header of an HTTPS response. The
//	    request is made by a child running as <user>, so it leaves through the
//	    same firewall exception as Tailscale itself and nothing else; the root
//	    parent only sets the clock. A device without a battery-backed clock
//	    boots with a stale date, and TLS to Tailscale fails until it is fixed.
//
// The clock cannot be trusted to check the certificate, so timesync checks it
// against the date the server reports instead: the chain must verify for the
// requested host at that date. An attacker without a valid certificate for the
// host cannot feed the device a date.
package main

import (
	"crypto/tls"
	"crypto/x509"
	_ "embed"
	"errors"
	"flag"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"os/user"
	"strconv"
	"strings"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

//go:embed isrg-root-x1.pem
var isrgRootX1 []byte

//go:embed isrg-root-x2.pem
var isrgRootX2 []byte

func main() {
	if len(os.Args) < 2 {
		usage()
	}
	var err error
	switch os.Args[1] {
	case "run-as":
		err = runAs(os.Args[2:])
	case "timesync":
		err = timesync(os.Args[2:])
	case "timesync-fetch":
		err = timesyncFetch(os.Args[2:])
	default:
		usage()
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "nanokvm-guard:", err)
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, `usage:
  nanokvm-guard run-as <user> -- <command> [args...]
  nanokvm-guard timesync [-as <user>] [-url <https url>] [-min-skew 2s]`)
	os.Exit(2)
}

func lookup(name string) (uid, gid int, home string, err error) {
	u, err := user.Lookup(name)
	if err != nil {
		return 0, 0, "", err
	}
	uid, err = strconv.Atoi(u.Uid)
	if err != nil {
		return 0, 0, "", err
	}
	gid, err = strconv.Atoi(u.Gid)
	if err != nil {
		return 0, 0, "", err
	}
	if uid == 0 || gid == 0 {
		return 0, 0, "", fmt.Errorf("refusing to run as %s: it is root", name)
	}
	return uid, gid, u.HomeDir, nil
}

// dropTo changes the whole process to uid/gid. Since Go 1.16 the syscall
// package applies these to every thread, so no thread keeps root.
func dropTo(uid, gid int) error {
	if err := syscall.Setgroups([]int{}); err != nil {
		return fmt.Errorf("setgroups: %w", err)
	}
	if err := syscall.Setgid(gid); err != nil {
		return fmt.Errorf("setgid: %w", err)
	}
	if err := syscall.Setuid(uid); err != nil {
		return fmt.Errorf("setuid: %w", err)
	}
	if err := unix.Prctl(unix.PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0); err != nil {
		return fmt.Errorf("no_new_privs: %w", err)
	}
	if syscall.Getuid() != uid || syscall.Geteuid() != uid {
		return errors.New("still privileged after setuid")
	}
	return nil
}

func runAs(args []string) error {
	if len(args) < 3 || args[1] != "--" {
		usage()
	}
	uid, gid, home, err := lookup(args[0])
	if err != nil {
		return err
	}
	bin, err := exec.LookPath(args[2])
	if err != nil {
		return err
	}
	if err := dropTo(uid, gid); err != nil {
		return err
	}
	env := []string{
		"PATH=/usr/sbin:/usr/bin:/sbin:/bin",
		"HOME=" + home,
		"USER=" + args[0],
	}
	for _, kv := range os.Environ() {
		if strings.HasPrefix(kv, "GOMEMLIMIT=") || strings.HasPrefix(kv, "TS_") {
			env = append(env, kv)
		}
	}
	return syscall.Exec(bin, args[2:], env)
}

func timesync(args []string) error {
	fs := flag.NewFlagSet("timesync", flag.ExitOnError)
	as := fs.String("as", "tailscale", "unprivileged user that makes the request")
	rawURL := fs.String("url", "https://controlplane.tailscale.com/", "HTTPS URL whose Date header is trusted")
	minSkew := fs.Duration("min-skew", 2*time.Second, "leave the clock alone if it is closer than this")
	_ = fs.Parse(args)

	self, err := os.Executable()
	if err != nil {
		return err
	}
	// The child drops privileges before it opens a socket; the parent never
	// touches the network.
	cmd := exec.Command(self, "run-as", *as, "--", self, "timesync-fetch", *rawURL)
	cmd.Stderr = os.Stderr
	out, err := cmd.Output()
	if err != nil {
		return fmt.Errorf("fetch time: %w", err)
	}
	sec, err := strconv.ParseInt(strings.TrimSpace(string(out)), 10, 64)
	if err != nil {
		return fmt.Errorf("bad time from fetcher: %q", out)
	}
	remote := time.Unix(sec, 0)
	skew := time.Since(remote)
	if skew < 0 {
		skew = -skew
	}
	if skew < *minSkew {
		fmt.Printf("clock ok (skew %s)\n", skew.Round(time.Millisecond))
		return nil
	}
	tv := syscall.NsecToTimeval(remote.UnixNano())
	if err := syscall.Settimeofday(&tv); err != nil {
		return fmt.Errorf("settimeofday: %w", err)
	}
	fmt.Printf("clock set to %s (was off by %s)\n", remote.UTC().Format(time.RFC3339), skew.Round(time.Second))
	return nil
}

func timesyncFetch(args []string) error {
	if len(args) != 1 {
		usage()
	}
	if syscall.Geteuid() == 0 {
		return errors.New("timesync-fetch must not run as root")
	}
	u, err := url.Parse(args[0])
	if err != nil || u.Scheme != "https" || u.Hostname() == "" {
		return fmt.Errorf("need an https URL, got %q", args[0])
	}
	roots, err := x509.SystemCertPool()
	if err != nil || roots == nil {
		roots = x509.NewCertPool()
	}
	roots.AppendCertsFromPEM(isrgRootX1)
	roots.AppendCertsFromPEM(isrgRootX2)

	var peer []*x509.Certificate
	client := &http.Client{
		Timeout: 20 * time.Second,
		Transport: &http.Transport{
			Proxy: nil,
			TLSClientConfig: &tls.Config{
				ServerName: u.Hostname(),
				// The local clock is the thing being fixed, so the handshake
				// cannot check validity dates. The chain is verified below,
				// at the date the server itself reports.
				InsecureSkipVerify: true,
				VerifyConnection: func(cs tls.ConnectionState) error {
					peer = cs.PeerCertificates
					return nil
				},
			},
		},
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	resp, err := client.Head(u.String())
	if err != nil {
		return err
	}
	_ = resp.Body.Close()

	date, err := http.ParseTime(resp.Header.Get("Date"))
	if err != nil {
		return fmt.Errorf("no usable Date header: %w", err)
	}
	if len(peer) == 0 {
		return errors.New("server sent no certificate")
	}
	inter := x509.NewCertPool()
	for _, c := range peer[1:] {
		inter.AddCert(c)
	}
	if _, err := peer[0].Verify(x509.VerifyOptions{
		DNSName:       u.Hostname(),
		Roots:         roots,
		Intermediates: inter,
		CurrentTime:   date,
	}); err != nil {
		return fmt.Errorf("certificate for %s does not verify at %s: %w", u.Hostname(), date.UTC().Format(time.RFC3339), err)
	}
	fmt.Println(date.Unix())
	return nil
}
