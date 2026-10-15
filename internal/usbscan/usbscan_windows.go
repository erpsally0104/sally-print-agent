//go:build windows

package usbscan

import (
	"errors"
	"fmt"
	"strings"
	"sync"
	"syscall"
	"time"
	"unsafe"

	"github.com/sallyerp/sally-print-agent/internal/escl"
)

// Everything here goes through package syscall: no cgo and no
// golang.org/x/sys. cfgmgr32.dll is loaded from System32 only.
var (
	kernel32                = syscall.NewLazyDLL("kernel32.dll")
	procCreateEventW        = kernel32.NewProc("CreateEventW")
	procGetOverlappedResult = kernel32.NewProc("GetOverlappedResult")
	procCancelIoEx          = kernel32.NewProc("CancelIoEx")
	procLoadLibraryExW      = kernel32.NewProc("LoadLibraryExW")
)

const (
	genericRead       = 0x80000000
	genericWrite      = 0x40000000
	fileShareRead     = 0x1
	fileShareWrite    = 0x2
	openExisting      = 3
	fileFlagOverlaped = 0x40000000

	errorOperationAborted = syscall.Errno(995)
	errorHandleEOF        = syscall.Errno(38)

	waitObject0 = 0
	waitTimeout = 258

	loadLibrarySearchSystem32 = 0x800

	// CONFIGRET values.
	crSuccess     = 0
	crBufferSmall = 0x1A
	crNoSuchValue = 0x25

	// CM_LOCATE_DEVNODE_PHANTOM: also a device that is not present.
	cmLocateDevnodePhantom = 1
)

type guid struct {
	Data1 uint32
	Data2 uint16
	Data3 uint16
	Data4 [8]byte
}

// ippUSB is {f2f40381-f46d-4e51-bce7-62de6cf2d098}.
var ippUSB = guid{0xf2f40381, 0xf46d, 0x4e51, [8]byte{0xbc, 0xe7, 0x62, 0xde, 0x6c, 0xf2, 0xd0, 0x98}}

// devpropKey mirrors DEVPROPKEY.
type devpropKey struct {
	fmtid guid
	pid   uint32
}

var (
	// DEVPKEY_Device_InstanceId {78c34fc8-104a-4aca-9ea4-524d52996e57} 256.
	keyInstanceID = devpropKey{guid{0x78c34fc8, 0x104a, 0x4aca, [8]byte{0x9e, 0xa4, 0x52, 0x4d, 0x52, 0x99, 0x6e, 0x57}}, 256}
	// DEVPKEY_Device_CompatibleIds {a45c254e-df1c-4efd-8020-67d146a850e0} 4.
	keyCompatibleIDs = devpropKey{guid{0xa45c254e, 0xdf1c, 0x4efd, [8]byte{0x80, 0x20, 0x67, 0xd1, 0x46, 0xa8, 0x50, 0xe0}}, 4}
	// DEVPKEY_Device_BusReportedDeviceDesc {540b947e-8b40-45bc-a8a2-6a0b894cbda2} 4.
	keyBusReportedDeviceDesc = devpropKey{guid{0x540b947e, 0x8b40, 0x45bc, [8]byte{0xa8, 0xa2, 0x6a, 0x0b, 0x89, 0x4c, 0xbd, 0xa2}}, 4}
)

// cfgmgr holds the configuration manager calls, each found once.
type cfgmgr struct {
	listSize, list, ifaceProp, locate, nodeProp, parent, status *syscall.Proc
}

var (
	cfgOnce sync.Once
	cfg     *cfgmgr
	cfgErr  error
)

// loadCfgmgr loads cfgmgr32.dll from System32 and finds its calls. A
// missing call is an error, never a panic.
func loadCfgmgr() (*cfgmgr, error) {
	cfgOnce.Do(func() {
		if err := procLoadLibraryExW.Find(); err != nil {
			cfgErr = err
			return
		}
		name, err := syscall.UTF16PtrFromString("cfgmgr32.dll")
		if err != nil {
			cfgErr = err
			return
		}
		h, _, e := procLoadLibraryExW.Call(uintptr(unsafe.Pointer(name)), 0, loadLibrarySearchSystem32)
		if h == 0 {
			cfgErr = fmt.Errorf("usbscan: loading cfgmgr32.dll: %v", e)
			return
		}
		d := &syscall.DLL{Name: "cfgmgr32.dll", Handle: syscall.Handle(h)}
		c := &cfgmgr{}
		for _, p := range []struct {
			to   **syscall.Proc
			name string
		}{
			{&c.listSize, "CM_Get_Device_Interface_List_SizeW"},
			{&c.list, "CM_Get_Device_Interface_ListW"},
			{&c.ifaceProp, "CM_Get_Device_Interface_PropertyW"},
			{&c.locate, "CM_Locate_DevNodeW"},
			{&c.nodeProp, "CM_Get_DevNode_PropertyW"},
			{&c.parent, "CM_Get_Parent"},
			{&c.status, "CM_Get_DevNode_Status"},
		} {
			proc, err := d.FindProc(p.name)
			if err != nil {
				cfgErr = err
				return
			}
			*p.to = proc
		}
		cfg = c
	})
	return cfg, cfgErr
}

// crError is a CONFIGRET other than success.
type crError struct {
	op   string
	code uintptr
}

func (e *crError) Error() string { return fmt.Sprintf("usbscan: %s: CONFIGRET 0x%X", e.op, e.code) }

// FindAll lists the IPP-over-USB interfaces present now, sorted by path,
// each named after its USB device.
func FindAll() ([]Path, error) {
	paths, err := presentInterfaces(&ippUSB)
	if err != nil {
		return nil, err
	}
	return pickIPPUSB(paths, describe), nil
}

// presentInterfaces lists the present interfaces of class g. The list can
// grow between the size and the read; that is tried 3 times.
func presentInterfaces(g *guid) ([]string, error) {
	c, err := loadCfgmgr()
	if err != nil {
		return nil, err
	}
	for try := 0; try < 3; try++ {
		var n uint32
		// Flags 0: CM_GET_DEVICE_INTERFACE_LIST_PRESENT. n counts UTF-16
		// units, 1 for an empty list.
		r, _, _ := c.listSize.Call(uintptr(unsafe.Pointer(&n)), uintptr(unsafe.Pointer(g)), 0, 0)
		if r != crSuccess {
			return nil, &crError{"CM_Get_Device_Interface_List_SizeW", r}
		}
		if n == 0 {
			n = 1
		}
		buf := make([]uint16, n)
		r, _, _ = c.list.Call(uintptr(unsafe.Pointer(g)), 0, uintptr(unsafe.Pointer(&buf[0])), uintptr(n), 0)
		switch r {
		case crSuccess:
			return splitMultiSz(buf), nil
		case crBufferSmall:
			continue
		default:
			return nil, &crError{"CM_Get_Device_Interface_ListW", r}
		}
	}
	return nil, &crError{"CM_Get_Device_Interface_ListW", crBufferSmall}
}

// readProp reads one property by two calls: the size, then the value. call
// makes one call with the given pointers (buf nil for the size). A missing
// property is nil, not an error.
func readProp(op string, call func(typ *uint32, buf *uint16, size *uint32) uintptr) ([]string, error) {
	var typ, size uint32
	r := call(&typ, nil, &size)
	switch {
	case r == crNoSuchValue:
		return nil, nil
	case r == crSuccess || (r == crBufferSmall && size == 0):
		return nil, nil
	case r != crBufferSmall:
		return nil, &crError{op, r}
	}
	buf := make([]uint16, (size+1)/2)
	r = call(&typ, &buf[0], &size)
	if r == crNoSuchValue {
		return nil, nil
	}
	if r != crSuccess {
		return nil, &crError{op, r}
	}
	return splitMultiSz(buf), nil
}

func (c *cfgmgr) interfaceProp(path *uint16, key *devpropKey) ([]string, error) {
	return readProp("CM_Get_Device_Interface_PropertyW", func(typ *uint32, buf *uint16, size *uint32) uintptr {
		r, _, _ := c.ifaceProp.Call(uintptr(unsafe.Pointer(path)), uintptr(unsafe.Pointer(key)),
			uintptr(unsafe.Pointer(typ)), uintptr(unsafe.Pointer(buf)), uintptr(unsafe.Pointer(size)), 0)
		return r
	})
}

func (c *cfgmgr) devNodeProp(dn uint32, key *devpropKey) ([]string, error) {
	return readProp("CM_Get_DevNode_PropertyW", func(typ *uint32, buf *uint16, size *uint32) uintptr {
		r, _, _ := c.nodeProp.Call(uintptr(dn), uintptr(unsafe.Pointer(key)),
			uintptr(unsafe.Pointer(typ)), uintptr(unsafe.Pointer(buf)), uintptr(unsafe.Pointer(size)), 0)
		return r
	})
}

func (c *cfgmgr) locateNode(inst string, flags uintptr) (uint32, error) {
	p, err := syscall.UTF16PtrFromString(inst)
	if err != nil {
		return 0, err
	}
	var dn uint32
	r, _, _ := c.locate.Call(uintptr(unsafe.Pointer(&dn)), uintptr(unsafe.Pointer(p)), flags)
	if r != crSuccess {
		return 0, &crError{"CM_Locate_DevNodeW", r}
	}
	return dn, nil
}

func (c *cfgmgr) parentOf(dn uint32) (uint32, error) {
	var p uint32
	r, _, _ := c.parent.Call(uintptr(unsafe.Pointer(&p)), uintptr(dn), 0)
	if r != crSuccess {
		return 0, &crError{"CM_Get_Parent", r}
	}
	return p, nil
}

func first(s []string, err error) string {
	if err != nil || len(s) == 0 {
		return ""
	}
	return strings.TrimSpace(s[0])
}

// describe reads an interface's device instance id, its compatible ids and
// its name: the parent device's for one function of a composite device
// (its own may be a label like "Printer"), else or if that is blank its
// own.
func describe(path string) (inst string, compat []string, name string, err error) {
	c, err := loadCfgmgr()
	if err != nil {
		return "", nil, "", err
	}
	p, err := syscall.UTF16PtrFromString(path)
	if err != nil {
		return "", nil, "", err
	}
	ids, err := c.interfaceProp(p, &keyInstanceID)
	if err != nil {
		return "", nil, "", err
	}
	if len(ids) == 0 || ids[0] == "" {
		return "", nil, "", errors.New("usbscan: the interface has no device instance id")
	}
	inst = ids[0]
	dn, err := c.locateNode(inst, 0)
	if err != nil {
		return inst, nil, "", err
	}
	compat, err = c.devNodeProp(dn, &keyCompatibleIDs)
	if err != nil {
		return inst, nil, "", err
	}
	if isChild(inst) {
		if pdn, perr := c.parentOf(dn); perr == nil {
			name = first(c.devNodeProp(pdn, &keyBusReportedDeviceDesc))
		}
	}
	if name == "" {
		name = first(c.devNodeProp(dn, &keyBusReportedDeviceDesc))
	}
	return inst, compat, name, nil
}

// Attached reports that the USB device of path is plugged in, even when
// the interface itself is not present (the device switched to its maker's
// mode: the PI_ function is a phantom, its parent present).
func Attached(path string) bool {
	parts := strings.Split(path, "#")
	if len(parts) < 4 {
		return false
	}
	head := parts[0]
	if len(head) > 4 && (head[:4] == `\\?\` || head[:4] == `\\.\`) {
		head = head[4:]
	}
	inst := head + `\` + parts[1] + `\` + parts[2]
	c, err := loadCfgmgr()
	if err != nil {
		return false
	}
	dn, err := c.locateNode(inst, cmLocateDevnodePhantom)
	if err != nil {
		return false
	}
	if isChild(inst) {
		if dn, err = c.parentOf(dn); err != nil {
			return false
		}
		if !parentIsUSB(first(c.devNodeProp(dn, &keyInstanceID))) {
			return false
		}
	}
	var st, prob uint32
	r, _, _ := c.status.Call(uintptr(unsafe.Pointer(&st)), uintptr(unsafe.Pointer(&prob)), uintptr(dn), 0)
	return r == crSuccess
}

func refusedErrno(err error) bool {
	var e syscall.Errno
	// ERROR_SHARING_VIOLATION, ERROR_BUSY.
	return errors.As(err, &e) && (e == 32 || e == 170)
}

func goneErrno(err error) bool {
	var e syscall.Errno
	// ERROR_DEV_NOT_EXIST, ERROR_NO_SUCH_DEVICE, ERROR_DEVICE_NOT_CONNECTED,
	// ERROR_DEVICE_REMOVED.
	return errors.As(err, &e) && (e == 55 || e == 433 || e == 1167 || e == 1617)
}

// port is an open IPP-over-USB channel.
type port struct {
	mu   sync.Mutex
	h    syscall.Handle
	rov  *syscall.Overlapped
	wov  *syscall.Overlapped
	rbuf []byte
	wbuf []byte
}

// Open opens a device path for overlapped I/O.
func Open(path string) (escl.Port, error) {
	p, err := syscall.UTF16PtrFromString(path)
	if err != nil {
		return nil, err
	}
	h, err := syscall.CreateFile(p, genericRead|genericWrite, fileShareRead|fileShareWrite, nil, openExisting, fileFlagOverlaped, 0)
	if err != nil {
		return nil, fmt.Errorf("usbscan: opening the scanner: %w", err)
	}
	rev, err := createEvent()
	if err != nil {
		syscall.CloseHandle(h)
		return nil, err
	}
	wev, err := createEvent()
	if err != nil {
		syscall.CloseHandle(rev)
		syscall.CloseHandle(h)
		return nil, err
	}
	// The OVERLAPPED structs and buffers live on the heap, owned by the
	// port, so they stay put while the kernel holds pointers to them.
	return &port{
		h:    h,
		rov:  &syscall.Overlapped{HEvent: rev},
		wov:  &syscall.Overlapped{HEvent: wev},
		rbuf: make([]byte, 64<<10),
	}, nil
}

func createEvent() (syscall.Handle, error) {
	// Manual reset, initially not signalled.
	h, _, err := procCreateEventW.Call(0, 1, 0, 0)
	if h == 0 {
		return 0, err
	}
	return syscall.Handle(h), nil
}

// writeWait bounds a write; a scanner that will not take 4 KB of request in
// this long is gone.
const writeWait = 30 * time.Second

// Write sends p in one WriteFile and waits until the device has taken it.
// Never buffered: a small buffered write only leaves when the handle closes.
func (p *port) Write(b []byte) (int, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.h == syscall.InvalidHandle {
		return 0, errors.New("usbscan: closed")
	}
	p.wbuf = append(p.wbuf[:0], b...)
	resetOverlapped(p.wov)
	var done uint32
	err := syscall.WriteFile(p.h, p.wbuf, &done, p.wov)
	if err != nil && !errors.Is(err, syscall.ERROR_IO_PENDING) {
		return 0, fmt.Errorf("usbscan: write: %w", err)
	}
	n, err := p.wait(p.wov, writeWait)
	if err != nil {
		if errors.Is(err, escl.ErrTimeout) {
			return n, fmt.Errorf("usbscan: the scanner did not take the request")
		}
		return n, err
	}
	return n, nil
}

// ReadTimeout reads what the device sends, waiting at most d. Reads that
// complete empty (a zero-length packet) are retried until d runs out.
func (p *port) ReadTimeout(b []byte, d time.Duration) (int, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.h == syscall.InvalidHandle {
		return 0, errors.New("usbscan: closed")
	}
	deadline := time.Now().Add(d)
	for {
		want := len(b)
		if want > len(p.rbuf) {
			want = len(p.rbuf)
		}
		resetOverlapped(p.rov)
		var done uint32
		err := syscall.ReadFile(p.h, p.rbuf[:want], &done, p.rov)
		if err != nil && !errors.Is(err, syscall.ERROR_IO_PENDING) && !errors.Is(err, errorHandleEOF) {
			return 0, fmt.Errorf("usbscan: read: %w", err)
		}
		left := time.Until(deadline)
		if left <= 0 {
			left = time.Millisecond
		}
		var n int
		if errors.Is(err, errorHandleEOF) {
			n, err = 0, nil
		} else {
			n, err = p.wait(p.rov, left)
		}
		if n > 0 {
			copy(b, p.rbuf[:n])
			return n, nil
		}
		if err != nil && !errors.Is(err, errorHandleEOF) {
			return 0, err
		}
		if !time.Now().Before(deadline) {
			return 0, escl.ErrTimeout
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// wait waits for an overlapped operation. On timeout it cancels the
// operation and waits for the cancellation to land, so the buffer and the
// OVERLAPPED are free again before returning. Bytes that arrived in the race
// are returned, not lost.
func (p *port) wait(ov *syscall.Overlapped, d time.Duration) (int, error) {
	ms := uint32(d / time.Millisecond)
	if ms == 0 {
		ms = 1
	}
	ev, werr := syscall.WaitForSingleObject(ov.HEvent, ms)
	if ev != waitObject0 {
		procCancelIoEx.Call(uintptr(p.h), uintptr(unsafe.Pointer(ov)))
		n, _ := p.result(ov)
		if n > 0 {
			return n, nil
		}
		if ev == waitTimeout {
			return 0, escl.ErrTimeout
		}
		return 0, fmt.Errorf("usbscan: wait failed: %v", werr)
	}
	n, err := p.result(ov)
	if err != nil {
		if errors.Is(err, errorOperationAborted) {
			return n, escl.ErrTimeout
		}
		return n, err
	}
	return n, nil
}

// result is GetOverlappedResult with bWait = TRUE.
func (p *port) result(ov *syscall.Overlapped) (int, error) {
	var n uint32
	r, _, err := procGetOverlappedResult.Call(uintptr(p.h), uintptr(unsafe.Pointer(ov)), uintptr(unsafe.Pointer(&n)), 1)
	if r == 0 {
		return int(n), err
	}
	return int(n), nil
}

func resetOverlapped(ov *syscall.Overlapped) {
	ov.Internal, ov.InternalHigh, ov.Offset, ov.OffsetHigh = 0, 0, 0, 0
}

// Close cancels anything pending and closes the handle and events.
func (p *port) Close() error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.h == syscall.InvalidHandle {
		return nil
	}
	procCancelIoEx.Call(uintptr(p.h), 0)
	err := syscall.CloseHandle(p.h)
	p.h = syscall.InvalidHandle
	syscall.CloseHandle(p.rov.HEvent)
	syscall.CloseHandle(p.wov.HEvent)
	return err
}
