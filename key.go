package trustee

import (
	"io/ioutil"

	"golang.org/x/crypto/ssh"
)

type Keypair struct {
	Path string

	publicKey ssh.PublicKey
	signer    ssh.Signer
}

func NewKeypairFromDisk(publicKeyPath, privateKeyPath string) (*Keypair, error) {
	publicKeyData, err := ioutil.ReadFile(publicKeyPath)
	if err != nil {
		return nil, err
	}

	publicKey, _, _, _, err := ssh.ParseAuthorizedKey(publicKeyData)
	if err != nil {
		return nil, err
	}

	privateKeyData, err := ioutil.ReadFile(privateKeyPath)
	if err != nil {
		return nil, err
	}

	signer, err := ssh.ParsePrivateKey(privateKeyData)
	if err != nil {
		return nil, err
	}

	return &Keypair{
		Path:      privateKeyPath,
		publicKey: publicKey,
		signer:    signer,
	}, nil
}
