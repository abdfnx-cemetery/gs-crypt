package gscrypt

import (
	"fmt"
	"os/exec"
)

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

func NewGPGClient(gpgVersion, gpgHomeDir string) (GPGClient, error) {
	v := new(GPGVersion)
	switch gpgVersion {
		case "v1":
			*v = GPGv1

		case "v2":
			*v = GPGv2

		default:
			v = nil
	}

	return newGPGClient(v, gpgHomeDir)
}

func newGPGClient(version *GPGVersion, homedir string) (GPGClient, error) {
	var gpgVersion GPGVersion
	if version != nil {
		gpgVersion = *version
	} else {
		gpgVersion = GuessGPGVersion()
	}

	switch gpgVersion {
		case GPGv1:
			return &gpgv1Client{
				gpgClient: gpgClient{gpgHomeDir: homedir},
			}, nil

		case GPGv2:
			return &gpgv2Client{
				gpgClient: gpgClient{gpgHomeDir: homedir},
			}, nil

		case GPGVersionUndetermined:
			return nil, fmt.Errorf("unable to determine GPG version")

		default:
			return nil, fmt.Errorf("unhandled case: NewGPGClient")
	}
}
