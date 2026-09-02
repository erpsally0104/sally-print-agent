// Command sally-print-agent lets Sally print a document to a chosen printer
// without going through the browser's print dialog.
//
// It is a small HTTP service bound to loopback. Sally probes it on page load;
// when it answers, the print dialog shows a real printer list and jobs go
// straight to the spooler. When it is absent — not installed, not running,
// stopped by the user — Sally silently falls back to its browser print path.
// The agent is an enhancement and never a dependency; nothing in Sally breaks
// when it is missing.
//
// Read security.go before changing how requests are accepted. A service on
// loopback is reachable by every website the user visits, and the controls
// there are what stops a hostile page spooling a ream to their printer.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"
)

// version is a var, not a const, so a release build can stamp it:
//
//	go build -ldflags "-X main.version=1.2.3"
var version = "1.0.0-dev"

// candidatePorts is a small fixed range rather than an ephemeral port: the page
// has to find the agent without being told where it is, and it cannot read a
// port file. Sally probes these in order.
var candidatePorts = []int{17777, 17778, 17779, 17780}

func main() {
	var (
		portFlag  = flag.Int("port", 0, "bind to this port instead of the default range")
		showVer   = flag.Bool("version", false, "print the version and exit")
		install   = flag.Bool("install", false, "start the agent automatically at login, then run")
		uninstall = flag.Bool("uninstall", false, "stop starting at login, then exit")
		status    = flag.Bool("status", false, "report whether the agent starts at login, then exit")
	)
	flag.Parse()

	if *showVer {
		fmt.Printf("sally-print-agent %s\n", version)
		return
	}

	// The autostart flags run before anything binds a port: they are
	// administrative, and -uninstall in particular has to work while another
	// copy of the agent is already running and holding that port.
	if *status {
		if err := reportAutostart(); err != nil {
			fmt.Fprintf(os.Stderr, "sally-print-agent: %v\n", err)
			os.Exit(1)
		}
		return
	}
	if *uninstall {
		if err := disableAutostart(); err != nil {
			fmt.Fprintf(os.Stderr, "sally-print-agent: %v\n", err)
			os.Exit(1)
		}
		fmt.Println("The agent will no longer start at login.")
		fmt.Println("Any running copy keeps going until you quit it.")
		return
	}
	if *install {
		if err := enableAutostart(); err != nil {
			fmt.Fprintf(os.Stderr, "sally-print-agent: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("The agent will start automatically at login (%s).\n", autostartLocation())
		// Deliberately falls through into serving: someone who has just run
		// -install wants printing working now, not after the next reboot.
	}

	cfg, configPath, err := loadOrCreateConfig()
	if err != nil {
		fmt.Fprintf(os.Stderr, "sally-print-agent: %v\n", err)
		os.Exit(1)
	}

	logger, logPath, closeLog := openLogger()
	defer closeLog()

	ports := candidatePorts
	if *portFlag != 0 {
		ports = []int{*portFlag}
	}
	ln, port, err := listenLoopback(ports)
	if err != nil {
		logger.Printf("could not bind a port: %v", err)
		fmt.Fprintf(os.Stderr, "sally-print-agent: %v\n", err)
		os.Exit(1)
	}

	srv := newServer(cfg, version, logger)
	srv.port = port
	srv.configPath = configPath
	srv.logPath = logPath

	httpSrv := &http.Server{
		Handler: srv.routes(),
		// A print job can be a few megabytes over loopback; the rest is quick.
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       60 * time.Second,
		WriteTimeout:      90 * time.Second,
		IdleTimeout:       120 * time.Second,
		ErrorLog:          logger,
	}

	// Both the Quit button and Ctrl+C land here.
	shutdown := make(chan struct{})
	var stopOnce = make(chan struct{}, 1)
	srv.stop = func() {
		select {
		case stopOnce <- struct{}{}:
			close(shutdown)
		default:
		}
	}

	signals := make(chan os.Signal, 1)
	signal.Notify(signals, os.Interrupt, syscall.SIGTERM)
	go func() {
		select {
		case sig := <-signals:
			logger.Printf("received %s", sig)
			srv.stop()
		case <-shutdown:
		}
	}()

	logger.Printf("sally-print-agent %s listening on %s", version, srv.selfOrigin())
	fmt.Printf("Sally Print Agent %s is running.\nStatus and controls: %s\n", version, srv.selfOrigin())

	go func() {
		if err := httpSrv.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
			logger.Printf("server stopped: %v", err)
			srv.stop()
		}
	}()

	<-shutdown

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := httpSrv.Shutdown(ctx); err != nil {
		logger.Printf("shutdown was not clean: %v", err)
	}
	logger.Printf("stopped")
}

// reportAutostart prints the registration state for -status, including the
// "you moved the binary" case. That one is otherwise invisible until the
// machine is next restarted and printing has quietly stopped working.
func reportAutostart() error {
	state, err := autostartState()
	if err != nil {
		return err
	}
	if !state.Supported {
		fmt.Println("Start at login: not supported on this platform.")
		return nil
	}
	if !state.Enabled {
		fmt.Println("Start at login: no.")
		fmt.Println("Enable it with:  sally-print-agent -install")
		return nil
	}
	fmt.Printf("Start at login: yes (%s)\n", state.Location)
	fmt.Printf("  registered:   %s\n", state.RegisteredPath)

	exe, err := currentExecutable()
	if err == nil && state.Stale(exe) {
		fmt.Printf("  running:      %s\n", exe)
		fmt.Println()
		fmt.Println("These differ: the agent has moved since it was registered, so the copy")
		fmt.Println("that starts at login is not this one. Re-run -install from here.")
	}
	return nil
}

// listenLoopback binds the first free candidate port.
//
// The address is 127.0.0.1 and never 0.0.0.0: the agent must be unreachable
// from the network, so a machine on the same shop LAN cannot enumerate or use
// this user's printers.
func listenLoopback(ports []int) (net.Listener, int, error) {
	var lastErr error
	for _, p := range ports {
		ln, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", p))
		if err == nil {
			return ln, p, nil
		}
		lastErr = err
	}
	return nil, 0, fmt.Errorf("every port in %v is in use (last error: %w)", ports, lastErr)
}

// openLogger writes to a rolling-by-hand log beside the config plus stderr, so
// a support call can ask for one file and a developer running it in a terminal
// still sees output.
func openLogger() (*log.Logger, string, func()) {
	dir, err := configDir()
	if err != nil {
		return log.New(os.Stderr, "", log.LstdFlags), "", func() {}
	}
	path := filepath.Join(dir, "agent.log")

	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return log.New(os.Stderr, "", log.LstdFlags), "", func() {}
	}
	// Keep the log from growing without bound on a machine that never restarts.
	if st, serr := f.Stat(); serr == nil && st.Size() > 2<<20 {
		f.Close()
		_ = os.Rename(path, path+".1")
		if f, err = os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600); err != nil {
			return log.New(os.Stderr, "", log.LstdFlags), "", func() {}
		}
	}

	logger := log.New(io.MultiWriter(os.Stderr, f), "", log.LstdFlags|log.LUTC)
	return logger, path, func() { _ = f.Close() }
}
