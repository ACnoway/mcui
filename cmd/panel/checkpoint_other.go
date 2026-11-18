//go:build !linux

package main

import (
	"errors"

	"github.com/ACnoway/mcui/internal/checkpoint"
)

func (c taskCheckpointConfig) open() (*checkpoint.Machine, func(), error) {
	return nil, nil, errors.New("checkpoint-enabled Master requires Linux")
}
