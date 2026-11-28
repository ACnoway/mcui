package db

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/ACnoway/mcui/internal/master/model"
	"github.com/glebarez/sqlite"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

func Open(dbPath string) (*gorm.DB, error) {
	if err := os.MkdirAll(filepath.Dir(dbPath), 0o755); err != nil {
		return nil, fmt.Errorf("create db dir: %w", err)
	}
	dsn := fmt.Sprintf("%s?_pragma=busy_timeout(5000)&_pragma=journal_mode(WAL)&_pragma=foreign_keys(1)", dbPath)
	gdb, err := gorm.Open(sqlite.Open(dsn), &gorm.Config{
		Logger: logger.Default.LogMode(logger.Silent),
	})
	if err != nil {
		return nil, fmt.Errorf("open sqlite: %w", err)
	}

	if err := gdb.AutoMigrate(
		&model.User{},
		&model.Node{},
		&model.NodeCore{},
		&model.Inbound{},
		&model.Client{},
		&model.ClientInbound{},
		&model.Setting{},
	); err != nil {
		return nil, fmt.Errorf("migrate sqlite: %w", err)
	}

	if err := seedDefaultAdmin(gdb); err != nil {
		return nil, err
	}
	return gdb, nil
}

func seedDefaultAdmin(gdb *gorm.DB) error {
	var count int64
	if err := gdb.Model(&model.User{}).Count(&count).Error; err != nil {
		return err
	}
	if count > 0 {
		return nil
	}
	initialUser := os.Getenv("MCUI_ADMIN_USER")
	if initialUser == "" {
		initialUser = "admin"
	}
	initialPass := os.Getenv("MCUI_ADMIN_PASS")
	if initialPass == "" {
		initialPass = "admin"
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(initialPass), bcrypt.DefaultCost)
	if err != nil {
		return err
	}
	return gdb.Create(&model.User{
		Username:     initialUser,
		PasswordHash: string(hash),
		SessionEpoch: 1,
	}).Error
}
