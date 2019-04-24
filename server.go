package trustee

import (
	"bytes"
	"crypto/rand"
	"errors"
	"log"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/fsnotify/fsnotify"
	"github.com/spf13/viper"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

var supportedKeyAlgos []string = []string{
	ssh.KeyAlgoED25519,
	ssh.KeyAlgoRSA,
}

var ErrNoKeyFound = errors.New("No key matching path found")
var NotImplErr = errors.New("Not Built Yet Yo")

type Server struct {
	socketPath string
	locked     bool
	listener   net.Listener

	keysLock sync.Mutex
	keys     map[*Keypair]bool
}

func NewServer() (*Server, error) {
	socketPath := viper.GetString("socket_path")

	ln, err := net.Listen("unix", socketPath)
	if err != nil {
		return nil, err
	}

	return &Server{
		socketPath: socketPath,
		locked:     false,
		listener:   ln,
		keys:       make(map[*Keypair]bool),
	}, nil
}

func (s *Server) Run() {
	go s.watchKeys()

	for {
		fd, err := s.listener.Accept()
		if err != nil {
			log.Fatal("Accept error: ", err)
		}

		go s.handleConnection(fd)
	}
}

func (s *Server) Close() {
	s.listener.Close()
	os.Remove(s.socketPath)
}

func (s *Server) handleConnection(fd net.Conn) {
	creds, err := getCredentials(fd.(*net.UnixConn))
	if err != nil {
		panic(err)
	}

	log.Printf("serving agent for new connection %v, %v, %v", creds.Pid, creds.Uid, creds.Gid)
	err = agent.ServeAgent(s, fd)
	if err != nil {
		log.Printf("error = %v", err)
	}
}

func (s *Server) scanInKeys(path string) error {
	pubkeys := make([]string, 0)

	err := filepath.Walk(path, func(walkFilePath string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		if info.IsDir() {
			return nil
		}

		if strings.HasSuffix(info.Name(), ".pub") {
			pubkeys = append(pubkeys, walkFilePath)
		}

		return nil
	})

	for _, pubKeyPath := range pubkeys {
		err = s.upsertLocalkey(pubKeyPath)
		if err != nil {
			log.Printf("Failed to load key `%v`: %v", pubKeyPath, err)
		}
	}

	return nil
}

func (s *Server) watchKeys() {
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		log.Fatal("Failed to create fsnotify watcher to observe keyfile changes: %v", err)
	}

	for _, keyPath := range viper.GetStringSlice("key_paths") {
		expandedKeyPath, err := expandPath(keyPath)
		if err != nil {
			log.Printf("Failed to expand path %v: %v", keyPath, err)
			continue
		}

		err = watcher.Add(expandedKeyPath)
		if err != nil {
			log.Printf("Failed to add key path %v: %v", expandedKeyPath, err)
			continue
		}

		err = s.scanInKeys(expandedKeyPath)
		if err != nil {
			log.Printf("Failed to perform initial key scan on path %v: %v", expandedKeyPath, err)
		}
	}

	for {
		select {
		case event, ok := <-watcher.Events:
			if !ok {
				return
			}

			if event.Op&fsnotify.Remove == fsnotify.Remove {
				err = s.removeLocalKey(event.Name)
			} else {
				err = s.upsertLocalkey(event.Name)
			}

			if err != nil {
				log.Printf("Failed to handle fsnotify event: %v", err)
			}
		case err, ok := <-watcher.Errors:
			if !ok {
				return
			}

			log.Fatal("fsnotify watcher error: %v", err)
		}
	}
}

func (s *Server) upsertLocalkey(path string) error {
	var privateKeyPath string
	var publicKeyPath string

	if strings.HasSuffix(path, ".pub") {
		publicKeyPath = path
		privateKeyPath = publicKeyPath[0 : len(publicKeyPath)-4]
		if _, err := os.Stat(privateKeyPath); os.IsNotExist(err) {
			return err
		}
	} else {
		privateKeyPath = path
		publicKeyPath = privateKeyPath + ".pub"
		if _, err := os.Stat(publicKeyPath); os.IsNotExist(err) {
			return err
		}
	}

	key, err := NewKeypairFromDisk(publicKeyPath, privateKeyPath)
	if err != nil {
		return err
	}

	s.keysLock.Lock()
	s.keys[key] = true
	s.keysLock.Unlock()

	log.Printf("Loaded new key from disk: %v", privateKeyPath)

	return nil
}

func (s *Server) removeLocalKey(path string) error {
	if strings.HasSuffix(path, ".pub") {
		path = path[0 : len(path)-4]
	}

	s.keysLock.Lock()
	defer s.keysLock.Unlock()

	var matchingKey *Keypair
	for key := range s.keys {
		if key.Path == path {
			matchingKey = key
			break
		}
	}

	if matchingKey != nil {
		delete(s.keys, matchingKey)
	} else {
		return ErrNoKeyFound
	}

	return nil
}

func (s *Server) List() ([]*agent.Key, error) {
	var keys []*agent.Key

	s.keysLock.Lock()
	defer s.keysLock.Unlock()
	for key := range s.keys {
		keys = append(keys, &agent.Key{
			Format:  key.publicKey.Type(),
			Blob:    key.publicKey.Marshal(),
			Comment: "",
		})
	}

	return keys, nil
	// publicKey := viper.GetString("key.public")
	//
	// data, err := base64.RawStdEncoding.DecodeString(publicKey)
	// if err != nil {
	// 	panic(err)
	// }
	//
	// keys = append(keys, &agent.Key{
	// 	Format:  "ssh-ed25519",
	// 	Blob:    data,
	// 	Comment: "andrei",
	// })
	//
	// log.Printf("List() %v", keys)
	// return keys, nil
}

func (s *Server) Sign(key ssh.PublicKey, data []byte) (*ssh.Signature, error) {
	if s.locked {
		return nil, errors.New("agent is locked, pls ssh-add -X")
	}

	for keypair := range s.keys {
		if keypair.publicKey.Type() != key.Type() {
			continue
		}

		if bytes.Compare(keypair.publicKey.Marshal(), key.Marshal()) != 0 {
			continue
		}

		signature, err := keypair.signer.Sign(rand.Reader, data)
		return signature, err
	}

	return nil, ErrNoKeyFound
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
