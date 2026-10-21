package tailscale

import (
	"NanoKVM-Server/hardened"
	"NanoKVM-Server/utils"
	"fmt"
	"io"
	"net/http"
	"os"

	log "github.com/sirupsen/logrus"
)

const (
	OriginalURL = "https://pkgs.tailscale.com/stable/tailscale_latest_riscv64.tgz"
	Workspace   = "/root/.tailscale"

	// BundledDir holds the pinned, checksum-verified Tailscale binaries the
	// hardened package ships (see scripts/fetch-tailscale.sh).
	BundledDir = "/kvmapp/tailscale"
)

func isInstalled() bool {
	_, err1 := os.Stat(TailscalePath)
	_, err2 := os.Stat(TailscaledPath)

	return err1 == nil && err2 == nil
}

func install() error {
	if hardened.Enabled {
		return installBundled()
	}

	_ = os.MkdirAll(Workspace, 0o755)
	defer func() {
		_ = os.RemoveAll(Workspace)
	}()

	tarFile := fmt.Sprintf("%s/tailscale_riscv64.tgz", Workspace)

	// download
	if err := download(tarFile); err != nil {
		log.Errorf("failed to download tailscale: %s", err)
		return err
	}

	// decompress
	dir, err := utils.UnTarGz(tarFile, Workspace)
	if err != nil {
		log.Errorf("failed to decompress tailscale: %s", err)
		return err
	}

	// move
	tailscalePath := fmt.Sprintf("%s/tailscale", dir)
	err = utils.MoveFile(tailscalePath, TailscalePath)
	if err != nil {
		log.Errorf("failed to move tailscale: %s", err)
		return err
	}

	tailscaledPath := fmt.Sprintf("%s/tailscaled", dir)
	err = utils.MoveFile(tailscaledPath, TailscaledPath)
	if err != nil {
		log.Errorf("failed to move tailscaled: %s", err)
		return err
	}

	log.Debugf("install tailscale successfully")
	return nil
}

func download(target string) error {
	url, err := getDownloadURL()
	if err != nil {
		log.Errorf("failed to get Tailscale download url: %s", err)
		return err
	}

	resp, err := http.Get(url)
	if err != nil {
		log.Errorf("failed to download Tailscale: %s", err)
		return err
	}
	defer func() {
		_ = resp.Body.Close()
	}()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}

	out, err := os.Create(target)
	if err != nil {
		log.Errorf("failed to create file: %s", err)
		return err
	}
	defer func() {
		_ = out.Close()
	}()

	_, err = io.Copy(out, resp.Body)
	if err != nil {
		log.Errorf("failed to copy response body to file: %s", err)
		return err
	}

	log.Debugf("download Tailscale successfully")
	return nil
}

func getDownloadURL() (string, error) {
	resp, err := (&http.Client{}).Get(OriginalURL)
	if err != nil {
		return "", err
	}
	defer func() {
		_ = resp.Body.Close()
	}()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusFound {
		return "", fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}

	return resp.Request.URL.String(), nil
}

// installBundled copies the binaries shipped inside the package into place
// instead of downloading whatever pkgs.tailscale.com calls "latest".
func installBundled() error {
	for _, pair := range [][2]string{
		{BundledDir + "/tailscale", TailscalePath},
		{BundledDir + "/tailscaled", TailscaledPath},
	} {
		if err := utils.CopyFile(pair[0], pair[1]); err != nil {
			log.Errorf("failed to install bundled %s: %s", pair[0], err)
			return err
		}
		if err := os.Chmod(pair[1], 0o755); err != nil {
			return err
		}
	}

	log.Debugf("install bundled tailscale successfully")
	return nil
}
