package core

import (
	"bufio"
	"io"
	"sync"
)

type RingLog struct {
	mu    sync.Mutex
	lines []string
	max   int
}

func NewRingLog(maxLines int) *RingLog {
	if maxLines <= 0 {
		maxLines = 400
	}
	return &RingLog{
		lines: make([]string, 0, maxLines),
		max:   maxLines,
	}
}

func (r *RingLog) Append(line string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if len(r.lines) >= r.max {
		copy(r.lines, r.lines[1:])
		r.lines[len(r.lines)-1] = line
		return
	}
	r.lines = append(r.lines, line)
}

func (r *RingLog) Capture(rd io.Reader) {
	sc := bufio.NewScanner(rd)
	buf := make([]byte, 0, 64*1024)
	sc.Buffer(buf, 512*1024)
	for sc.Scan() {
		r.Append(sc.Text())
	}
}

func (r *RingLog) Tail(n int) []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	if n <= 0 || n > len(r.lines) {
		n = len(r.lines)
	}
	start := len(r.lines) - n
	out := make([]string, n)
	copy(out, r.lines[start:])
	return out
}
