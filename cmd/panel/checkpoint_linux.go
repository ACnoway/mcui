package main

import (
	"crypto/tls"
	"fmt"
	"os"

	"github.com/ACnoway/mcui/internal/checkpoint"
	"github.com/ACnoway/mcui/internal/checkpointhttp"
	"github.com/ACnoway/mcui/internal/checkpointjournal"
	"golang.org/x/sys/unix"
)

func (c taskCheckpointConfig) open() (*checkpoint.Machine, func(), error) {
	ca, err := os.ReadFile(c.ca)
	if err != nil {
		return nil, nil, err
	}
	cert, err := os.ReadFile(c.cert)
	if err != nil {
		return nil, nil, err
	}
	key, err := readPrivateKey(c.key)
	if err != nil {
		return nil, nil, err
	}
	identity, err := tls.X509KeyPair(cert, key)
	if err != nil {
		return nil, nil, err
	}
	authority, err := checkpointhttp.NewClient(c.origin, ca, identity)
	if err != nil {
		return nil, nil, err
	}

	// Hold a process-lifetime lock in addition to SQLite's transaction locks.
	fd, err := unix.Open(c.journal, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0)
	if err != nil {
		return nil, nil, fmt.Errorf("open checkpoint journal lock: %w", err)
	}
	if err := unix.Flock(fd, unix.LOCK_EX|unix.LOCK_NB); err != nil {
		_ = unix.Close(fd)
		return nil, nil, fmt.Errorf("lock checkpoint journal: %w", err)
	}
	journal, err := checkpointjournal.Open(c.journal)
	if err != nil {
		_ = unix.Close(fd)
		return nil, nil, err
	}
	return &checkpoint.Machine{Journal: journal, Authority: authority}, func() {
		_ = journal.Close()
		_ = unix.Close(fd)
	}, nil
}
