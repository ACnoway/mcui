package main

import (
	"errors"
	"flag"
	"os"
)

type taskCheckpointConfig struct {
	origin, journal, ca, cert, key string
}

func registerTaskCheckpointFlags() *taskCheckpointConfig {
	config := &taskCheckpointConfig{}
	flag.StringVar(&config.origin, "task-checkpoint-url", os.Getenv("MCUI_TASK_CHECKPOINT_URL"), "independent checkpoint HTTPS origin")
	flag.StringVar(&config.journal, "task-checkpoint-journal", os.Getenv("MCUI_TASK_CHECKPOINT_JOURNAL"), "pre-enrolled local checkpoint journal")
	flag.StringVar(&config.ca, "task-checkpoint-ca", os.Getenv("MCUI_TASK_CHECKPOINT_CA"), "checkpoint server CA PEM")
	flag.StringVar(&config.cert, "task-checkpoint-client-cert", os.Getenv("MCUI_TASK_CHECKPOINT_CLIENT_CERT"), "checkpoint client certificate PEM")
	flag.StringVar(&config.key, "task-checkpoint-client-key", os.Getenv("MCUI_TASK_CHECKPOINT_CLIENT_KEY"), "checkpoint client private key PEM")
	return config
}

func (c taskCheckpointConfig) enabled() bool {
	return c != (taskCheckpointConfig{})
}

func (c taskCheckpointConfig) validate() error {
	if c.origin == "" || c.journal == "" || c.ca == "" || c.cert == "" || c.key == "" {
		return errors.New("task checkpoint requires URL, journal, CA, client certificate and client key")
	}
	return nil
}
