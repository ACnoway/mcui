//go:build linux

package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/ACnoway/mcui/internal/artifacttrust"
	"github.com/ACnoway/mcui/internal/trustedtime"
	"github.com/ACnoway/mcui/internal/xrayruntime"
	"golang.org/x/sys/unix"
)

func main() {
	log.SetFlags(0)
	if err := run(); err != nil {
		log.Fatal(err)
	}
}

func run() error {
	if len(os.Args) < 2 {
		return errors.New("usage: mcui-xray initialize|initialize-panel-inbounds|status|recover|install|upgrade|downgrade|start|stop|uninstall")
	}
	command := os.Args[1]
	flags := flag.NewFlagSet(command, flag.ContinueOnError)
	var release xrayruntime.Release
	var metadataURL string
	var releaseKeyPath string
	var manifestVersion int64
	action := xrayruntime.Action(command)
	switch action {
	case xrayruntime.Install, xrayruntime.Upgrade, xrayruntime.Downgrade:
		flags.StringVar(&metadataURL, "metadata-url", "", "legacy: explicitly use this TUF HTTPS metadata origin")
		flags.StringVar(&releaseKeyPath, "release-public-key", "", "locally provisioned release public key (default /etc/mcui-xray/release.pub)")
		flags.Int64Var(&manifestVersion, "manifest-version", 0, "require this exact release manifest version")
		fallthrough
	case xrayruntime.Start, xrayruntime.Stop, xrayruntime.Uninstall:
		flags.StringVar(&release.Version, "version", "", "exact Xray release version")
		flags.StringVar(&release.SHA256, "sha256", "", "exact Xray archive SHA-256")
	case "initialize", "initialize-panel-inbounds", "recover", "status":
	default:
		return fmt.Errorf("unknown Xray command %q", command)
	}
	if err := flags.Parse(os.Args[2:]); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return nil
		}
		return err
	}
	if flags.NArg() != 0 {
		return errors.New("unexpected positional argument")
	}
	manifestRequested := false
	flags.Visit(func(opt *flag.Flag) { manifestRequested = manifestRequested || opt.Name == "manifest-version" })
	if manifestRequested && manifestVersion <= 0 {
		return errors.New("-manifest-version must be positive")
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	ctx, cancel := context.WithTimeout(ctx, 20*time.Minute)
	defer cancel()
	runtime, err := xrayruntime.Open(command == "initialize")
	if err != nil {
		return err
	}
	defer runtime.Close()
	switch action {
	case "initialize", "status":
	case "initialize-panel-inbounds":
		err = runtime.InitializePanelInbounds()
	case "recover":
		err = runtime.Recover(ctx)
	case xrayruntime.Install, xrayruntime.Upgrade, xrayruntime.Downgrade:
		var client *artifacttrust.Client
		switch {
		case metadataURL != "" && releaseKeyPath != "":
			return errors.New("configure only one artifact trust source")
		case metadataURL != "":
			client, err = openLegacyTrust(metadataURL)
		default:
			if releaseKeyPath == "" {
				releaseKeyPath = "/etc/mcui-xray/release.pub"
			}
			clock := trustedtime.NewChronyUnix(trustedtime.DefaultNTSSource)
			client, err = artifacttrust.OpenSignedCore(releaseKeyPath, filepath.Join(xrayruntime.StateDir, "control", "xray-manifest"), clock.Now)
		}
		if err == nil && manifestRequested {
			err = runtime.ApplyWithManifest(ctx, action, release, client, manifestVersion)
		} else if err == nil {
			err = runtime.Apply(ctx, action, release, client)
		}
	default:
		err = runtime.Control(ctx, action, release)
	}
	if err != nil {
		return err
	}
	state, err := runtime.Status()
	if err != nil {
		return err
	}
	return json.NewEncoder(os.Stdout).Encode(state)
}

func openLegacyTrust(url string) (*artifacttrust.Client, error) {
	if url == "" {
		return nil, errors.New("-metadata-url is required")
	}
	const trustedRoot = "/etc/mcui-xray/root.json"
	const maxRootBytes = 512 << 10
	fd, err := unix.Open(trustedRoot, unix.O_CLOEXEC|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_RDONLY, 0)
	if err != nil {
		return nil, fmt.Errorf("open provisioned offline Xray TUF root: %w", err)
	}
	file := os.NewFile(uintptr(fd), trustedRoot)
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || info.Mode().Perm()&0022 != 0 || info.Sys().(*syscall.Stat_t).Uid != 0 || info.Size() > maxRootBytes {
		return nil, errors.New("Xray TUF root must be a bounded, root-owned regular file")
	}
	root, err := io.ReadAll(io.LimitReader(file, maxRootBytes+1))
	if err != nil {
		return nil, err
	}
	dir := filepath.Join(xrayruntime.StateDir, "control")
	clock := trustedtime.NewChronyUnix(trustedtime.DefaultNTSSource)
	return artifacttrust.New(artifacttrust.Config{
		MetadataURL:     url,
		TrustedRoot:     root,
		MetadataDir:     filepath.Join(dir, "tuf-metadata"),
		RootHistoryDir:  filepath.Join(dir, "tuf-roots"),
		TargetCacheDir:  filepath.Join(dir, "artifact-cache"),
		RequireCoreRole: true,
		TrustedTimeHealthy: func() error {
			_, err := clock.Now()
			return err
		},
	})
}
