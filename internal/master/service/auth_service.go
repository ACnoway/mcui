package service

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/ACnoway/mcui/internal/master/model"
	"github.com/ACnoway/mcui/pkg/crypto"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/gorm"
)

const sessionSecretSettingKey = "session_hmac_secret"

type AuthService struct {
	db     *gorm.DB
	secret []byte
}

func NewAuthService(gdb *gorm.DB) (*AuthService, error) {
	var row model.Setting
	err := gdb.Where("key = ?", sessionSecretSettingKey).First(&row).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		sec, gerr := crypto.RandomHex(32)
		if gerr != nil {
			return nil, gerr
		}
		row = model.Setting{Key: sessionSecretSettingKey, Value: sec}
		if cerr := gdb.Create(&row).Error; cerr != nil {
			return nil, cerr
		}
	} else if err != nil {
		return nil, err
	}
	return &AuthService{db: gdb, secret: []byte(row.Value)}, nil
}

func (s *AuthService) Login(username, password string) (string, *model.User, error) {
	var u model.User
	if err := s.db.Where("username = ?", strings.TrimSpace(username)).First(&u).Error; err != nil {
		return "", nil, errors.New("invalid username or password")
	}
	if err := bcrypt.CompareHashAndPassword([]byte(u.PasswordHash), []byte(password)); err != nil {
		return "", nil, errors.New("invalid username or password")
	}
	tok := s.issueToken(u.ID, u.SessionEpoch, time.Now().Add(7*24*time.Hour))
	return tok, &u, nil
}

func (s *AuthService) VerifySession(token string) (*model.User, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 2 {
		return nil, errors.New("malformed session token")
	}
	payloadBytes, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return nil, errors.New("malformed session payload")
	}
	expectedSig := s.sign(payloadBytes)
	if !hmac.Equal([]byte(parts[1]), []byte(expectedSig)) {
		return nil, errors.New("invalid session signature")
	}

	fields := strings.Split(string(payloadBytes), ":")
	if len(fields) != 3 {
		return nil, errors.New("invalid session fields")
	}
	uid, err1 := strconv.ParseUint(fields[0], 10, 32)
	epoch, err2 := strconv.ParseInt(fields[1], 10, 64)
	expUnix, err3 := strconv.ParseInt(fields[2], 10, 64)
	if err1 != nil || err2 != nil || err3 != nil {
		return nil, errors.New("corrupt session claims")
	}
	if time.Now().Unix() > expUnix {
		return nil, errors.New("session expired")
	}

	var u model.User
	if err := s.db.First(&u, uint(uid)).Error; err != nil {
		return nil, errors.New("user not found")
	}
	if u.SessionEpoch != epoch {
		return nil, errors.New("session revoked")
	}
	return &u, nil
}

func (s *AuthService) ChangeCredentials(userID uint, currentPassword, newUsername, newPassword string) error {
	var u model.User
	if err := s.db.First(&u, userID).Error; err != nil {
		return err
	}
	if err := bcrypt.CompareHashAndPassword([]byte(u.PasswordHash), []byte(currentPassword)); err != nil {
		return errors.New("current password is incorrect")
	}
	if trimmedUser := strings.TrimSpace(newUsername); trimmedUser != "" {
		u.Username = trimmedUser
	}
	if len(newPassword) < 6 {
		return errors.New("new password must be at least 6 characters")
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(newPassword), bcrypt.DefaultCost)
	if err != nil {
		return err
	}
	u.PasswordHash = string(hash)
	u.SessionEpoch++
	return s.db.Save(&u).Error
}

func (s *AuthService) issueToken(uid uint, epoch int64, exp time.Time) string {
	payload := fmt.Sprintf("%d:%d:%d", uid, epoch, exp.Unix())
	encoded := base64.RawURLEncoding.EncodeToString([]byte(payload))
	sig := s.sign([]byte(payload))
	return encoded + "." + sig
}

func (s *AuthService) sign(payload []byte) string {
	mac := hmac.New(sha256.New, s.secret)
	mac.Write(payload)
	return hex.EncodeToString(mac.Sum(nil))
}
