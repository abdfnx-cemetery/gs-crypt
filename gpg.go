package gscrypt

import "os/exec"

type GPGVersion int

const (
	GPGv2 GPGVersion = iota
	GPGv1
	GPGVersionUndetermined
)

type GPGClient interface {
	ReadGPGPubRingFile() ([]byte, error)
	GetGPGPrivateKey(keyid uint64, passphrase string) ([]byte, error)
	GetSecretKeyDetails(keyid uint64) ([]byte, bool, error)
	GetKeyDetails(keyid uint64) ([]byte, bool, error)
	ResolveRecipients([]string) []string
}

type gpgClient struct {
	gpgHomeDir string
}

// gpgv2Client is a gpg2 client
type gpgv2Client struct {
	gpgClient
}

// gpgv1Client is a gpg client
type gpgv1Client struct {
	gpgClient
}

func GuessGPGVersion() GPGVersion {
	if err := exec.Command("gpg2", "--version").Run(); err == nil {
		return GPGv2
	} else if err := exec.Command("gpg", "--version").Run(); err == nil {
		return GPGv1
	} else {
		return GPGVersionUndetermined
	}
}
