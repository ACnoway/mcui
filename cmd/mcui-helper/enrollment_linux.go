package main

import (
	"bytes"
	"errors"
	"fmt"
	"os"

	"github.com/ACnoway/mcui/internal/security"
)

func checkEnrollmentTrust(keyPath, expectedKeyPath, caPath, expectedCAPath string) error {
	actualRaw, err := os.ReadFile(keyPath)
	if err != nil {
		return fmt.Errorf("read task public key: %w", err)
	}
	actualKey, err := security.ParseEd25519PublicKey(actualRaw)
	if err != nil {
		return err
	}
	expectedRaw, err := os.ReadFile(expectedKeyPath)
	if err != nil {
		return fmt.Errorf("read expected task public key: %w", err)
	}
	expectedKey, err := security.ParseEd25519PublicKey(expectedRaw)
	if err != nil {
		return err
	}
	if !bytes.Equal(actualKey, expectedKey) {
		return errors.New("task key differs from the installed trust; use the local trust rotation workflow")
	}
	if expectedCAPath == "" {
		return nil
	}
	actualCA, err := security.ReadEnrollmentCA(caPath)
	if err != nil {
		return fmt.Errorf("read installed or staged Master CA: %w", err)
	}
	expectedCA, err := security.ReadEnrollmentCA(expectedCAPath)
	if err != nil {
		return fmt.Errorf("read expected Master CA: %w", err)
	}
	if !bytes.Equal(actualCA, expectedCA) {
		return errors.New("Master CA differs from the installed trust; use the local trust rotation workflow")
	}
	return nil
}
