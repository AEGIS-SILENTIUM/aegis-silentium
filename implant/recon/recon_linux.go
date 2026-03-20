//go:build linux

package recon

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// getProcessList reads process info from /proc.
func getProcessList() ([]ProcInfo, error) {
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return nil, err
	}

	var procs []ProcInfo
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		pid, err := strconv.Atoi(e.Name())
		if err != nil {
			continue
		}

		proc := ProcInfo{PID: pid}

		// Name from /proc/<pid>/comm
		if b, err := os.ReadFile(fmt.Sprintf("/proc/%d/comm", pid)); err == nil {
			proc.Name = strings.TrimSpace(string(b))
		}

		// PPID from /proc/<pid>/status
		if b, err := os.ReadFile(fmt.Sprintf("/proc/%d/status", pid)); err == nil {
			for _, line := range strings.Split(string(b), "\n") {
				if strings.HasPrefix(line, "PPid:") {
					parts := strings.Fields(line)
					if len(parts) >= 2 {
						proc.PPID, _ = strconv.Atoi(parts[1])
					}
				}
				if strings.HasPrefix(line, "Uid:") {
					parts := strings.Fields(line)
					if len(parts) >= 2 {
						proc.User = parts[1]
					}
				}
			}
		}

		// Cmdline from /proc/<pid>/cmdline
		if b, err := os.ReadFile(fmt.Sprintf("/proc/%d/cmdline", pid)); err == nil {
			cmdline := strings.ReplaceAll(string(b), "\x00", " ")
			if len(cmdline) > 256 {
				cmdline = cmdline[:256]
			}
			proc.Cmdline = strings.TrimSpace(cmdline)
		}

		procs = append(procs, proc)
	}
	return procs, nil
}

// getNetworkConnections parses /proc/net/tcp and /proc/net/udp.
func getNetworkConnections() ([]NetConn, error) {
	var conns []NetConn

	for _, proto := range []string{"tcp", "tcp6", "udp", "udp6"} {
		path := filepath.Join("/proc/net", proto)
		f, err := os.Open(path)
		if err != nil {
			continue
		}

		scanner := bufio.NewScanner(f)
		scanner.Scan() // skip header
		for scanner.Scan() {
			line := scanner.Text()
			fields := strings.Fields(line)
			if len(fields) < 5 {
				continue
			}
			local := hexToAddr(fields[1])
			remote := hexToAddr(fields[2])
			state := tcpState(fields[3])

			conns = append(conns, NetConn{
				Proto:      proto,
				LocalAddr:  local,
				RemoteAddr: remote,
				State:      state,
			})
		}
		f.Close()
	}
	return conns, nil
}

// hexToAddr converts a /proc/net/tcp hex address "0100007F:0050" to "127.0.0.1:80".
func hexToAddr(hex string) string {
	parts := strings.SplitN(hex, ":", 2)
	if len(parts) != 2 {
		return hex
	}
	addrHex, portHex := parts[0], parts[1]

	port, _ := strconv.ParseUint(portHex, 16, 16)

	if len(addrHex) == 8 {
		// IPv4 little-endian
		var b [4]byte
		v, _ := strconv.ParseUint(addrHex, 16, 32)
		b[0] = byte(v)
		b[1] = byte(v >> 8)
		b[2] = byte(v >> 16)
		b[3] = byte(v >> 24)
		return fmt.Sprintf("%d.%d.%d.%d:%d", b[0], b[1], b[2], b[3], port)
	}
	// IPv6 — return raw for brevity
	return fmt.Sprintf("[%s]:%d", addrHex, port)
}

var tcpStates = map[string]string{
	"01": "ESTABLISHED", "02": "SYN_SENT", "03": "SYN_RECV",
	"04": "FIN_WAIT1", "05": "FIN_WAIT2", "06": "TIME_WAIT",
	"07": "CLOSE", "08": "CLOSE_WAIT", "09": "LAST_ACK",
	"0A": "LISTEN", "0B": "CLOSING",
}

func tcpState(hex string) string {
	hex = strings.ToUpper(hex)
	if s, ok := tcpStates[hex]; ok {
		return s
	}
	return hex
}
