package main

import (
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

// termSize is the client's terminal size, in characters.
type termSize struct {
	rows, cols uint16
}

// ptyDrain is how long output may keep arriving after the command exits.
const ptyDrain = 2 * time.Second

// openPTY returns a new pseudo-terminal pair with the given size.
func openPTY(size termSize) (master, slave *os.File, err error) {
	master, err = os.OpenFile("/dev/ptmx", os.O_RDWR|syscall.O_NOCTTY|syscall.O_CLOEXEC, 0)
	if err != nil {
		return nil, nil, err
	}
	// Fd() would make the master blocking, and Close could then not stop a pending read.
	conn, err := master.SyscallConn()
	if err != nil {
		master.Close()
		return nil, nil, err
	}
	var n int
	var ioctlErr error
	if err := conn.Control(func(fd uintptr) {
		if ioctlErr = unix.IoctlSetPointerInt(int(fd), unix.TIOCSPTLCK, 0); ioctlErr == nil {
			n, ioctlErr = unix.IoctlGetInt(int(fd), unix.TIOCGPTN)
		}
	}); err != nil || ioctlErr != nil {
		master.Close()
		return nil, nil, fmt.Errorf("unlock pty: %w", errors.Join(err, ioctlErr))
	}
	slave, err = os.OpenFile(fmt.Sprintf("/dev/pts/%d", n), os.O_RDWR|syscall.O_NOCTTY|syscall.O_CLOEXEC, 0)
	if err != nil {
		master.Close()
		return nil, nil, err
	}
	ws := &unix.Winsize{Row: size.rows, Col: size.cols}
	if err := unix.IoctlSetWinsize(int(slave.Fd()), unix.TIOCSWINSZ, ws); err != nil {
		master.Close()
		slave.Close()
		return nil, nil, fmt.Errorf("set pty size: %w", err)
	}
	return master, slave, nil
}

// runInPTY runs cmd on a new terminal of the given size and copies its output to w.
func runInPTY(cmd *exec.Cmd, w io.Writer, size termSize) int {
	master, slave, err := openPTY(size)
	if err != nil {
		fmt.Fprintf(w, "broker: cannot open a terminal: %v\n", err)
		return 1
	}
	defer master.Close()

	cmd.Stdin, cmd.Stdout, cmd.Stderr = slave, slave, slave
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true, Setctty: true}
	startErr := cmd.Start()
	slave.Close()
	if startErr != nil {
		fmt.Fprintf(w, "broker: cannot run docker: %v\n", startErr)
		return 1
	}

	// Reading the master ends with EIO once every copy of the slave is closed.
	copied := make(chan struct{})
	go func() {
		_, _ = io.Copy(w, master)
		close(copied)
	}()
	err = cmd.Wait()
	select {
	case <-copied:
	case <-time.After(ptyDrain):
		// A leftover process still holds the terminal; stop reading.
		master.Close()
		<-copied
	}

	if exit, ok := errors.AsType[*exec.ExitError](err); ok {
		return exit.ExitCode()
	}
	if err != nil {
		fmt.Fprintf(w, "broker: cannot run docker: %v\n", err)
		return 1
	}
	return 0
}
