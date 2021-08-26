package gscrypt

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
