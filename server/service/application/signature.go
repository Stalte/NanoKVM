package application

import (
	"fmt"

	"NanoKVM-Server/hardened"
	"NanoKVM-Server/pkgsign"

	log "github.com/sirupsen/logrus"
)

// verifyPackageSignature requires an extracted package to be signed by one of
// the keys compiled into this build. A hardened build made without any key
// accepts unsigned packages, so that it can still be replaced, and says so.
func verifyPackageSignature(sourceDir, expectedVersion string) error {
	if !hardened.Enabled {
		return nil
	}
	keys, err := pkgsign.TrustedKeys()
	if err != nil {
		return fmt.Errorf("load trusted signing keys: %w", err)
	}
	if len(keys) == 0 {
		log.Warn("no update signing key is built in; installing an unsigned package")
		return nil
	}
	if err := pkgsign.VerifyDir(sourceDir, expectedVersion, keys); err != nil {
		return fmt.Errorf("update package signature: %w", err)
	}
	return nil
}
