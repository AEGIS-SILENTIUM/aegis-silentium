//go:build windows

package recon

import (
	"encoding/binary"
	"fmt"
	"net"
	"syscall"
	"unsafe"
)

var (
	kernel32             = syscall.NewLazyDLL("kernel32.dll")
	iphlpapi             = syscall.NewLazyDLL("iphlpapi.dll")
	procCreateToolhelp32 = kernel32.NewProc("CreateToolhelp32Snapshot")
	procProcess32First   = kernel32.NewProc("Process32FirstW")
	procProcess32Next    = kernel32.NewProc("Process32NextW")
	procGetExtTcpTable   = iphlpapi.NewProc("GetExtendedTcpTable")
	procGetExtUdpTable   = iphlpapi.NewProc("GetExtendedUdpTable")
)

const (
	th32csSnapProcess = 0x00000002
	invalidHandle     = ^uintptr(0)

	// TCP_TABLE_OWNER_PID_ALL: PID + local/remote addr for all connections
	tcpTableOwnerPidAll = 5
	udpTableOwnerPid    = 1
	afInet              = 2 // AF_INET (IPv4)
)

type processEntry32 struct {
	DwSize              uint32
	CntUsage            uint32
	Th32ProcessID       uint32
	Th32DefaultHeapID   uintptr
	Th32ModuleID        uint32
	CntThreads          uint32
	Th32ParentProcessID uint32
	PcPriClassBase      int32
	DwFlags             uint32
	SzExeFile           [260]uint16
}

// MIB_TCPROW_OWNER_PID is the Win32 struct for one TCP connection row.
// Layout matches Windows SDK definition exactly.
type mibTcpRowOwnerPid struct {
	State      uint32
	LocalAddr  uint32
	LocalPort  uint32
	RemoteAddr uint32
	RemotePort uint32
	OwningPid  uint32
}

// MIB_UDPROW_OWNER_PID
type mibUdpRowOwnerPid struct {
	LocalAddr uint32
	LocalPort uint32
	OwningPid uint32
}

// tcpStateNames maps Windows MIB TCP state values to human-readable strings.
var tcpStateNames = map[uint32]string{
	1: "CLOSED", 2: "LISTEN", 3: "SYN_SENT", 4: "SYN_RECEIVED",
	5: "ESTABLISHED", 6: "FIN_WAIT_1", 7: "FIN_WAIT_2",
	8: "CLOSE_WAIT", 9: "CLOSING", 10: "LAST_ACK", 11: "TIME_WAIT", 12: "DELETE_TCB",
}

// getProcessList uses Toolhelp32 snapshot to enumerate processes.
func getProcessList() ([]ProcInfo, error) {
	snap, _, _ := procCreateToolhelp32.Call(th32csSnapProcess, 0)
	if snap == invalidHandle {
		return nil, fmt.Errorf("CreateToolhelp32Snapshot failed")
	}
	defer syscall.CloseHandle(syscall.Handle(snap))

	var entry processEntry32
	entry.DwSize = uint32(unsafe.Sizeof(entry))

	var procs []ProcInfo
	ret, _, _ := procProcess32First.Call(snap, uintptr(unsafe.Pointer(&entry)))
	for ret != 0 {
		name := syscall.UTF16ToString(entry.SzExeFile[:])
		procs = append(procs, ProcInfo{
			PID:  int(entry.Th32ProcessID),
			PPID: int(entry.Th32ParentProcessID),
			Name: name,
		})
		entry.DwSize = uint32(unsafe.Sizeof(entry))
		ret, _, _ = procProcess32Next.Call(snap, uintptr(unsafe.Pointer(&entry)))
	}
	return procs, nil
}

// getNetworkConnections enumerates TCP and UDP connections using
// GetExtendedTcpTable / GetExtendedUdpTable from iphlpapi.dll.
// This is a full Win32 implementation — no stubs.
func getNetworkConnections() ([]NetConn, error) {
	var conns []NetConn

	tcpConns, err := getTcpConnections()
	if err == nil {
		conns = append(conns, tcpConns...)
	}

	udpConns, err := getUdpConnections()
	if err == nil {
		conns = append(conns, udpConns...)
	}

	if len(conns) == 0 && err != nil {
		return nil, err
	}
	return conns, nil
}

// getTcpConnections calls GetExtendedTcpTable with TCP_TABLE_OWNER_PID_ALL.
func getTcpConnections() ([]NetConn, error) {
	// First call: get required buffer size
	var size uint32
	procGetExtTcpTable.Call(
		0, uintptr(unsafe.Pointer(&size)),
		1, // bOrder=TRUE (sort by local address)
		afInet,
		tcpTableOwnerPidAll,
		0,
	)
	if size == 0 {
		size = 65536
	}

	buf := make([]byte, size)
	ret, _, _ := procGetExtTcpTable.Call(
		uintptr(unsafe.Pointer(&buf[0])),
		uintptr(unsafe.Pointer(&size)),
		1,
		afInet,
		tcpTableOwnerPidAll,
		0,
	)
	if ret != 0 {
		return nil, fmt.Errorf("GetExtendedTcpTable: error %d", ret)
	}

	// First 4 bytes = number of rows
	numEntries := binary.LittleEndian.Uint32(buf[0:4])
	rowSize := uint32(unsafe.Sizeof(mibTcpRowOwnerPid{}))
	offset := uint32(4)

	var conns []NetConn
	for i := uint32(0); i < numEntries; i++ {
		if offset+rowSize > uint32(len(buf)) {
			break
		}
		row := (*mibTcpRowOwnerPid)(unsafe.Pointer(&buf[offset]))
		offset += rowSize

		state := tcpStateNames[row.State]
		if state == "" {
			state = fmt.Sprintf("UNKNOWN(%d)", row.State)
		}

		conns = append(conns, NetConn{
			Proto:      "tcp",
			LocalAddr:  ipPort(row.LocalAddr, row.LocalPort),
			RemoteAddr: ipPort(row.RemoteAddr, row.RemotePort),
			State:      state,
			PID:        int(row.OwningPid),
		})
	}
	return conns, nil
}

// getUdpConnections calls GetExtendedUdpTable with UDP_TABLE_OWNER_PID.
func getUdpConnections() ([]NetConn, error) {
	var size uint32
	procGetExtUdpTable.Call(0, uintptr(unsafe.Pointer(&size)), 1, afInet, udpTableOwnerPid, 0)
	if size == 0 {
		size = 65536
	}

	buf := make([]byte, size)
	ret, _, _ := procGetExtUdpTable.Call(
		uintptr(unsafe.Pointer(&buf[0])),
		uintptr(unsafe.Pointer(&size)),
		1,
		afInet,
		udpTableOwnerPid,
		0,
	)
	if ret != 0 {
		return nil, fmt.Errorf("GetExtendedUdpTable: error %d", ret)
	}

	numEntries := binary.LittleEndian.Uint32(buf[0:4])
	rowSize := uint32(unsafe.Sizeof(mibUdpRowOwnerPid{}))
	offset := uint32(4)

	var conns []NetConn
	for i := uint32(0); i < numEntries; i++ {
		if offset+rowSize > uint32(len(buf)) {
			break
		}
		row := (*mibUdpRowOwnerPid)(unsafe.Pointer(&buf[offset]))
		offset += rowSize

		conns = append(conns, NetConn{
			Proto:     "udp",
			LocalAddr: ipPort(row.LocalAddr, row.LocalPort),
			State:     "LISTEN",
			PID:       int(row.OwningPid),
		})
	}
	return conns, nil
}

// ipPort converts a Windows network-order IPv4 address + port to "ip:port".
// Windows stores IPs in host byte order for local, network order for remote —
// GetExtendedTcpTable returns them in network order, so we use big-endian.
func ipPort(addr, port uint32) string {
	ip := make(net.IP, 4)
	binary.BigEndian.PutUint32(ip, addr)
	// Port in Windows structs is stored in network byte order (big-endian)
	// but the high/low bytes are swapped — use htons equivalent
	p := (port&0xFF)<<8 | (port>>8)&0xFF
	return fmt.Sprintf("%s:%d", ip.String(), p)
}
