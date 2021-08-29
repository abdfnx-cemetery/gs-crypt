package gscrypt

import (
	"fmt"
	"os/exec"
	"io/ioutil"
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

func (gc *gpgv2Client) GetGPGPrivateKey(keyid uint64, passphrase string) ([]byte, error) {
	var args []string

	if gc.gpgHomeDir != "" {
		args = append(args, []string{"--homedir", gc.gpgHomeDir}...)
	}

	rfile, wfile, err := os.Pipe()
	if err != nil {
		return nil, errors.Wrapf(err, "could not create pipe")
	}
	defer func() {
		rfile.Close()
		wfile.Close()
	}()
	// fill pipe in background
	go func(passphrase string) {
		_, _ = wfile.Write([]byte(passphrase))
		wfile.Close()
	}(passphrase)

	args = append(args, []string{"--pinentry-mode", "loopback", "--batch", "--passphrase-fd", fmt.Sprintf("%d", 3), "--export-secret-key", fmt.Sprintf("0x%x", keyid)}...)

	cmd := exec.Command("gpg2", args...)
	cmd.ExtraFiles = []*os.File{rfile}

	return runGPGGetOutput(cmd)
}

// ReadGPGPubRingFile reads the GPG public key ring file
func (gc *gpgv2Client) ReadGPGPubRingFile() ([]byte, error) {
	var args []string

	if gc.gpgHomeDir != "" {
		args = append(args, []string{"--homedir", gc.gpgHomeDir}...)
	}
	args = append(args, []string{"--batch", "--export"}...)

	cmd := exec.Command("gpg2", args...)

	return runGPGGetOutput(cmd)
}

func runGPGGetOutput(cmd *exec.Cmd) ([]byte, error) {
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, err
	}

	stderr, err := cmd.StderrPipe()
	if err != nil {
		return nil, err
	}

	if err := cmd.Start(); err != nil {
		return nil, err
	}

	stdoutstr, err2 := ioutil.ReadAll(stdout)
	stderrstr, _ := ioutil.ReadAll(stderr)

	if err := cmd.Wait(); err != nil {
		return nil, fmt.Errorf("error from %s: %s", cmd.Path, string(stderrstr))
	}

	return stdoutstr, err2
}
