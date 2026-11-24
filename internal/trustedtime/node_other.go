//go:build !linux

package trustedtime

import "time"

func NodeNow() func() (time.Time, error) {
	return NewChrony(DefaultNTSSource).Now
}
