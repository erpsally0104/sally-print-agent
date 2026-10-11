//go:build windows

package usbscan

import (
	"errors"
	"fmt"
	"sync"
	"syscall"
	"time"
	"unsafe"

	"github.com/sallyerp/sally-print-agent/internal/escl"
)

// Everything here goes through package syscall and lazily loaded DLLs: no
// cgo and no golang.org/x/sys.
var (
	kernel32                = syscall.NewLazyDLL("kernel32.dll")
	procCreateEventW        = kernel32.NewProc("CreateEventW")
	procGetOverlappedResult = kernel32.NewProc("GetOverlappedResult")
	procCancelIoEx          = kernel32.NewProc("CancelIoEx")

	setupapi                             = syscall.NewLazyDLL("setupapi.dll")
	procSetupDiGetClassDevsW             = setupapi.NewProc("SetupDiGetClassDevsW")
	procSetupDiEnumDeviceInterfaces      = setupapi.NewProc("SetupDiEnumDeviceInterfaces")
	procSetupDiGetDeviceInterfaceDetailW = setupapi.NewProc("SetupDiGetDeviceInterfaceDetailW")
	procSetupDiDestroyDeviceInfoList     = setupapi.NewProc("SetupDiDestroyDeviceInfoList")
)

const (
	genericRead       = 0x80000000
	genericWrite      = 0x40000000
	fileShareRead     = 0x1
	fileShareWrite    = 0x2
	openExisting      = 3
	fileFlagOverlaped = 0x40000000

	keyRead = 0x20019

	digcfPresent         = 0x2
	digcfDeviceInterface = 0x10

	errorNoMoreItems        = syscall.Errno(259)
	errorInsufficientBuffer = syscall.Errno(122)
	errorOperationAborted   = syscall.Errno(995)
	errorHandleEOF          = syscall.Errno(38)

	waitObject0 = 0
	waitTimeout = 258
)

type guid struct {
	Data1 uint32
	Data2 uint16
	Data3 uint16
	Data4 [8]byte
}

// ippUSB is {f2f40381-f46d-4e51-bce7-62de6cf2d098}.
var ippUSB = guid{0xf2f40381, 0xf46d, 0x4e51, [8]byte{0xbc, 0xe7, 0x62, 0xde, 0x6c, 0xf2, 0xd0, 0x98}}

// Find lists candidate device paths, best first.
func Find() ([]string, error) {
	present, _ := setupAPIPaths()
	linked, other, regErr := registryPaths()
	out := order(present, linked, other)
	if len(out) == 0 && regErr != nil {
		return nil, regErr
	}
	return out, nil
}

// spDeviceInterfaceData mirrors SP_DEVICE_INTERFACE_DATA.
type spDeviceInterfaceData struct {
	cbSize   uint32
	guid     guid
	flags    uint32
	reserved uintptr
}

// setupAPIPaths asks SetupAPI for present IPP-over-USB interfaces. On the
// machine this was built against it found nothing; the registry is the
// fallback that did.
func setupAPIPaths() ([]string, error) {
	if err := procSetupDiGetClassDevsW.Find(); err != nil {
		return nil, err
	}
	devs, _, err := procSetupDiGetClassDevsW.Call(uintptr(unsafe.Pointer(&ippUSB)), 0, 0, digcfPresent|digcfDeviceInterface)
	if devs == 0 || devs == ^uintptr(0) {
		return nil, err
	}
	defer procSetupDiDestroyDeviceInfoList.Call(devs)

	// SP_DEVICE_INTERFACE_DETAIL_DATA_W.cbSize: 8 on 64-bit, 6 on 32-bit.
	detailCb := uint32(6)
	if unsafe.Sizeof(uintptr(0)) == 8 {
		detailCb = 8
	}
	var out []string
	for i := uint32(0); i < 64; i++ {
		data := &spDeviceInterfaceData{}
		data.cbSize = uint32(unsafe.Sizeof(*data))
		r, _, _ := procSetupDiEnumDeviceInterfaces.Call(devs, 0, uintptr(unsafe.Pointer(&ippUSB)), uintptr(i), uintptr(unsafe.Pointer(data)))
		if r == 0 {
			break
		}
		var need uint32
		procSetupDiGetDeviceInterfaceDetailW.Call(devs, uintptr(unsafe.Pointer(data)), 0, 0, uintptr(unsafe.Pointer(&need)), 0)
		if need < 8 || need > 64<<10 {
			continue
		}
		// []uint64 for alignment of the DWORD at the front.
		buf := make([]uint64, (need+7)/8)
		*(*uint32)(unsafe.Pointer(&buf[0])) = detailCb
		r, _, _ = procSetupDiGetDeviceInterfaceDetailW.Call(devs, uintptr(unsafe.Pointer(data)), uintptr(unsafe.Pointer(&buf[0])), uintptr(need), 0, 0)
		if r == 0 {
			continue
		}
		chars := unsafe.Slice((*uint16)(unsafe.Add(unsafe.Pointer(&buf[0]), 4)), (need-4)/2)
		if p := syscall.UTF16ToString(chars); p != "" {
			out = append(out, p)
		}
	}
	return out, nil
}

// registryPaths reads DeviceClasses\{f2f40381-…}. linked are interfaces with
// "#\Control" Linked = 1; other are the rest (possibly a scanner unplugged).
func registryPaths() (linked, other []string, err error) {
	keyPath, _ := syscall.UTF16PtrFromString(`SYSTEM\CurrentControlSet\Control\DeviceClasses\` + InterfaceGUID)
	var h syscall.Handle
	if err := syscall.RegOpenKeyEx(syscall.HKEY_LOCAL_MACHINE, keyPath, 0, keyRead, &h); err != nil {
		return nil, nil, fmt.Errorf("usbscan: no IPP-over-USB interfaces registered: %w", err)
	}
	defer syscall.RegCloseKey(h)

	for i := uint32(0); i < 256; i++ {
		buf := make([]uint16, 512)
		n := uint32(len(buf))
		err := syscall.RegEnumKeyEx(h, i, &buf[0], &n, nil, nil, nil, nil)
		if err != nil {
			if !errors.Is(err, errorNoMoreItems) {
				return linked, other, err
			}
			break
		}
		name := syscall.UTF16ToString(buf[:n])
		path, ok := pathFromKey(name)
		if !ok {
			continue
		}
		if isLinked(h, name+`\#\Control`) {
			linked = append(linked, path)
		} else {
			other = append(other, path)
		}
	}
	return linked, other, nil
}

func isLinked(parent syscall.Handle, sub string) bool {
	p, _ := syscall.UTF16PtrFromString(sub)
	var k syscall.Handle
	if syscall.RegOpenKeyEx(parent, p, 0, keyRead, &k) != nil {
		return false
	}
	defer syscall.RegCloseKey(k)
	name, _ := syscall.UTF16PtrFromString("Linked")
	var typ, val uint32
	size := uint32(4)
	if syscall.RegQueryValueEx(k, name, nil, &typ, (*byte)(unsafe.Pointer(&val)), &size) != nil {
		return false
	}
	return val == 1
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
