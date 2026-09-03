//go:build windows

package main

import (
	"fmt"
	"strings"
	"syscall"
	"unsafe"
)

/*
Windows autostart: a per-user Run key.

  HKCU\Software\Microsoft\Windows\CurrentVersion\Run
      SallyPrintAgent = "C:\path\to\sally-print-agent.exe"

Written through advapi32 directly rather than by shelling out to reg.exe. The
value is a path that will contain spaces on most machines, and handing a quoted
Windows path through a command line to be re-parsed is exactly where that goes
wrong. It also keeps the promise in go.mod: no third-party packages, not even
x/sys.
*/

const (
	runKeyPath   = `Software\Microsoft\Windows\CurrentVersion\Run`
	runValueName = "SallyPrintAgent"

	keyQueryValue = 0x0001
	keySetValue   = 0x0002
	regSZ         = 1
)

var (
	advapi32           = syscall.NewLazyDLL("advapi32.dll")
	procRegCreateKeyEx = advapi32.NewProc("RegCreateKeyExW")
	procRegSetValueEx  = advapi32.NewProc("RegSetValueExW")
	procRegDeleteValue = advapi32.NewProc("RegDeleteValueW")
)

func autostartLocation() string {
	return `HKCU\` + runKeyPath + `\` + runValueName
}

// autostartState reads the Run key without creating it.
func autostartState() (AutostartState, error) {
	state := AutostartState{Supported: true, Location: autostartLocation()}

	keyPath, err := syscall.UTF16PtrFromString(runKeyPath)
	if err != nil {
		return state, err
	}
	var h syscall.Handle
	if err := syscall.RegOpenKeyEx(syscall.HKEY_CURRENT_USER, keyPath, 0, keyQueryValue, &h); err != nil {
		// No Run key at all is a normal state, not a failure.
		return state, nil
	}
	defer syscall.RegCloseKey(h)

	name, err := syscall.UTF16PtrFromString(runValueName)
	if err != nil {
		return state, err
	}
	var typ uint32
	var size uint32 = 1024
	buf := make([]uint16, size/2)
	err = syscall.RegQueryValueEx(h, name, nil, &typ, (*byte)(unsafe.Pointer(&buf[0])), &size)
	if err != nil {
		// Value absent → simply not enabled.
		return state, nil
	}

	state.Enabled = true
	// The stored value is quoted; compare against the unquoted path.
	state.RegisteredPath = strings.Trim(syscall.UTF16ToString(buf), `"`)
	return state, nil
}

// enableAutostart writes the Run value, creating the key if the profile has
// never had one.
func enableAutostart() error {
	exe, err := currentExecutable()
	if err != nil {
		return err
	}

	keyPath, err := syscall.UTF16PtrFromString(runKeyPath)
	if err != nil {
		return err
	}
	var h syscall.Handle
	var disposition uint32
	r, _, _ := procRegCreateKeyEx.Call(
		uintptr(syscall.HKEY_CURRENT_USER),
		uintptr(unsafe.Pointer(keyPath)),
		0, 0, 0,
		uintptr(keySetValue|keyQueryValue),
		0,
		uintptr(unsafe.Pointer(&h)),
		uintptr(unsafe.Pointer(&disposition)),
	)
	if r != 0 {
		return fmt.Errorf("opening %s: error %d", autostartLocation(), r)
	}
	defer syscall.RegCloseKey(h)

	// Quoted so a path with spaces launches as one argument.
	value, err := syscall.UTF16FromString(`"` + exe + `"`)
	if err != nil {
		return err
	}
	name, err := syscall.UTF16PtrFromString(runValueName)
	if err != nil {
		return err
	}
	r, _, _ = procRegSetValueEx.Call(
		uintptr(h),
		uintptr(unsafe.Pointer(name)),
		0,
		uintptr(regSZ),
		uintptr(unsafe.Pointer(&value[0])),
		// Byte length including the terminating NUL.
		uintptr(len(value)*2),
	)
	if r != 0 {
		return fmt.Errorf("writing %s: error %d", autostartLocation(), r)
	}
	return nil
}

// disableAutostart removes the value. A value that was never there is success:
// the caller asked for "not registered", and it is not registered.
func disableAutostart() error {
	keyPath, err := syscall.UTF16PtrFromString(runKeyPath)
	if err != nil {
		return err
	}
	var h syscall.Handle
	if err := syscall.RegOpenKeyEx(syscall.HKEY_CURRENT_USER, keyPath, 0, keySetValue, &h); err != nil {
		return nil
	}
	defer syscall.RegCloseKey(h)

	name, err := syscall.UTF16PtrFromString(runValueName)
	if err != nil {
		return err
	}
	r, _, _ := procRegDeleteValue.Call(uintptr(h), uintptr(unsafe.Pointer(name)))
	// 2 == ERROR_FILE_NOT_FOUND.
	if r != 0 && r != 2 {
		return fmt.Errorf("removing %s: error %d", autostartLocation(), r)
	}
	return nil
}

// autostartLaunchesIt reports whether enableAutostart also started the agent.
// Writing a Run key does not: Windows reads it at the next login and no
// sooner, so -install has to go on and serve the current session itself.
func autostartLaunchesIt() bool { return false }
