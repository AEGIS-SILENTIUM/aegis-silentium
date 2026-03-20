//go:build !linux && !windows

package recon

func getProcessList() ([]ProcInfo, error)       { return nil, nil }
func getNetworkConnections() ([]NetConn, error) { return nil, nil }
