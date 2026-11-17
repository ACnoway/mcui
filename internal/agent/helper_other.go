//go:build !linux

package agent

import "errors"

func NewUnixStatusExecutor(string) (StatusExecutor, error) {
	return nil, errors.New("the privileged Helper socket is available only on Linux")
}
