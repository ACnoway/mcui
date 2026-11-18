package main

import (
	"context"
	"errors"
	"flag"
	"fmt"

	"github.com/ACnoway/mcui/internal/checkpoint"
	"github.com/ACnoway/mcui/internal/checkpointjournal"
	"github.com/ACnoway/mcui/internal/master"
	"github.com/ACnoway/mcui/internal/security"
	"github.com/ACnoway/mcui/internal/store"
	"github.com/ACnoway/mcui/internal/taskdispatch"
)

func initializeMasterJournal(args []string) error {
	flags := flag.NewFlagSet("init-master-journal", flag.ContinueOnError)
	db := flags.String("db", "", "existing panel database path")
	taskDB := flags.String("task-db", "", "existing task database path")
	journalPath := flags.String("journal", "", "new local journal path")
	node := flags.String("node", "", "Master checkpoint identity")
	epoch := flags.Uint64("epoch", 0, "Master checkpoint epoch")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 || *db == "" || *taskDB == "" || *journalPath == "" || !security.ValidNodeID(*node) || *epoch == 0 {
		return errors.New("init-master-journal requires -db, -task-db, -journal, -node and -epoch")
	}
	panel, err := store.OpenExisting(*db)
	if err != nil {
		return err
	}
	defer panel.Close()
	tasks, err := taskdispatch.Open(*taskDB)
	if err != nil {
		return err
	}
	defer tasks.Close()
	digest, err := master.TaskCheckpointDigest(context.Background(), panel, tasks)
	if err != nil {
		return err
	}
	journal, err := checkpointjournal.Create(*journalPath, checkpoint.Record{Node: *node, Epoch: *epoch, Digest: digest})
	if err != nil {
		return err
	}
	if err = journal.Close(); err != nil {
		return err
	}
	fmt.Printf("%x\n", digest)
	return nil
}
