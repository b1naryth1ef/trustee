package trustee

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"log"
	"net"
	"os"

	"github.com/spf13/viper"
	"golang.org/x/crypto/ed25519"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

var NotImplErr = errors.New("Not Built Yet Yo")

type Server struct {
	locked   bool
	listener net.Listener
}

func NewServer() (*Server, error) {
	ln, err := net.Listen("unix", "/tmp/trustee.sock")
	if err != nil {
		return nil, err
	}

	return &Server{false, ln}, nil
}

func (s *Server) Close() {
	s.listener.Close()
	os.Remove("/tmp/trustee.sock")
}

func (s *Server) Run() {
	for {
		fd, err := s.listener.Accept()
		if err != nil {
			log.Fatal("Accept error: ", err)
		}

		go func() {
			log.Printf("serving agent for new connection %v", fd.RemoteAddr())
			err := agent.ServeAgent(s, fd)
			if err != nil {
				log.Printf("error = %v", err)
			}
		}()
	}
}

func (s *Server) List() ([]*agent.Key, error) {
	var keys []*agent.Key

	publicKey := viper.GetString("key.public")

	data, err := base64.RawStdEncoding.DecodeString(publicKey)
	if err != nil {
		panic(err)
	}

	keys = append(keys, &agent.Key{
		Format:  "ssh-ed25519",
		Blob:    data,
		Comment: "andrei",
	})

	log.Printf("List() %v", keys)
	return keys, nil
}

func (s *Server) Sign(key ssh.PublicKey, data []byte) (*ssh.Signature, error) {
	if s.locked {
		return nil, errors.New("agent is locked, pls ssh-add -X")
	}

	privateKey := viper.GetString("key.private")

	keyData, err := ssh.ParseRawPrivateKey([]byte(privateKey))
	if err != nil {
		panic(err)
	}

	keySigner := keyData.(*ed25519.PrivateKey)

	signer, err := ssh.NewSignerFromSigner(keySigner)
	if err != nil {
		panic(err)
	}

	signature, err := signer.Sign(rand.Reader, data)
	if err != nil {
		panic(err)
	}
	log.Printf("Sign()")

	return signature, nil
}

func (s *Server) Add(key agent.AddedKey) error {
	log.Printf("Add()")
	return NotImplErr
}

func (s *Server) Remove(key ssh.PublicKey) error {
	log.Printf("Remove()")
	return NotImplErr
}

func (s *Server) RemoveAll() error {
	log.Printf("RemoveAll()")
	return NotImplErr
}

func (s *Server) Lock(passphrase []byte) error {
	s.locked = true
	return nil
}

func (s *Server) Unlock(passphrase []byte) error {
	s.locked = false
	return nil
}

func (s *Server) Signers() ([]ssh.Signer, error) {
	log.Printf("Signers()")
	return nil, NotImplErr
}
