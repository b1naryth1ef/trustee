package trustee

import (
	"net"
	"os"
	"path/filepath"
	"syscall"
)

// Retrives unix credentials for the given unix socket connection
func getCredentials(conn *net.UnixConn) (*syscall.Ucred, error) {
	f, err := conn.File()
	if err != nil {
		return nil, err
	}
	defer f.Close()

	return syscall.GetsockoptUcred(int(f.Fd()), syscall.SOL_SOCKET, syscall.SO_PEERCRED)
}

// Expands a path that contains a leading `~`
func expandPath(path string) (string, error) {
	if path[0] != '~' {
		return path, nil
	}

	homeDirPath, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}

	return filepath.Join(homeDirPath, path[1:]), nil
}
