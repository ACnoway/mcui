package master

import (
	"crypto/subtle"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/ACnoway/mcui/internal/store"
)

var errAdminAlreadyInitialized = errors.New("administrator already initialized")

// PrepareSingleAdmin returns credentials only for a new installation or an
// explicit recovery of a pending account, after the database commit succeeds.
func PrepareSingleAdmin(db *store.Store, recoverPending bool) (username, password string, err error) {
	newPassword, err := randomToken(32)
	if err != nil {
		return "", "", err
	}
	id, err := randomToken(16)
	if err != nil {
		return "", "", err
	}
	err = db.Update(func(st *store.State) error {
		var account store.Admin
		for _, existing := range st.Admins {
			if existing.Disabled {
				continue
			}
			if account.ID != "" || existing.Role != "security_admin" || !existing.AllNodes {
				return errors.New("single-admin mode requires one enabled global security administrator")
			}
			account = existing
		}
		if recoverPending && !account.SetupPending {
			return errors.New("no pending administrator to recover")
		}
		if !recoverPending && len(st.Admins) != 0 {
			if account.ID == "" {
				return errors.New("existing database has no enabled administrator")
			}
			return errAdminAlreadyInitialized
		}
		if !recoverPending {
			account = store.Admin{ID: id, Username: "admin_" + id, Role: "security_admin", AllNodes: true, SetupPending: true}
		}
		account.PasswordHash, err = newPasswordHash(newPassword)
		if err != nil {
			return err
		}
		st.Admins[account.ID] = account
		action := "bootstrap.admin.create"
		if recoverPending {
			action = "bootstrap.admin.recover"
		}
		st.Audits = append(st.Audits, store.Audit{At: time.Now().Unix(), Actor: "local", Action: action, ResourceType: "admin", Resource: account.ID, Outcome: "success"})
		username, password = account.Username, newPassword
		return nil
	})
	if err == errAdminAlreadyInitialized {
		return "", "", nil
	}
	if err != nil {
		return "", "", err
	}
	return username, password, nil
}

func (s *Server) EnableSingleAdmin() {
	s.singleAdmin = true
	s.bootstrapToken = ""
}

func (s *Server) setupMode(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]bool{"manual_bootstrap": s.bootstrapToken != ""})
}

func (s *Server) completeAdminSetup(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Username        string `json:"username"`
		InitialPassword string `json:"initial_password"`
		NewPassword     string `json:"new_password"`
		TOTPSecret      string `json:"totp_secret"`
		Code            string `json:"code"`
	}
	if !sameOriginRequest(r) || readJSON(r, &in) != nil || !validLoginFields(in.Username, in.InitialPassword) ||
		len(in.NewPassword) < 12 || len(in.NewPassword) > 1024 || in.NewPassword == in.InitialPassword || len(in.TOTPSecret) != 32 {
		http.Error(w, "invalid setup request", http.StatusBadRequest)
		return
	}
	if !s.allowLoginAttempt(r, in.Username) {
		http.Error(w, "too many attempts", http.StatusTooManyRequests)
		return
	}
	account, passwordOK := s.verifyAdminPassword(in.Username, in.InitialPassword)
	if !passwordOK || !account.SetupPending || !validTOTP(in.TOTPSecret, in.Code, time.Now()) {
		_ = s.recordAudit("anonymous", "bootstrap.admin.complete", "admin", in.Username, "denied")
		http.Error(w, "invalid initial credentials or MFA code", http.StatusUnauthorized)
		return
	}
	newHash, err := newPasswordHash(in.NewPassword)
	if err != nil {
		http.Error(w, "administrator setup unavailable", http.StatusInternalServerError)
		return
	}
	err = s.store.Update(func(st *store.State) error {
		current := st.Admins[account.ID]
		if current.Disabled || !current.SetupPending || current.PasswordHash != account.PasswordHash {
			return store.ErrNotFound
		}
		current.PasswordHash = newHash
		current.TOTPSecret = in.TOTPSecret
		current.SetupPending = false
		st.Admins[account.ID] = current
		s.appendAudit(st, store.Audit{At: time.Now().Unix(), Actor: account.ID, Action: "bootstrap.admin.complete", ResourceType: "admin", Resource: account.ID, Outcome: "success"})
		return nil
	})
	if err != nil {
		http.Error(w, "administrator setup unavailable", http.StatusConflict)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func validLoginFields(username, password string) bool {
	return usernamePattern.MatchString(username) && len(password) > 0 && len(password) <= 1024
}

func (s *Server) allowLoginAttempt(r *http.Request, username string) bool {
	return s.allowAttempt("login-ip:"+clientAddress(r)) && s.allowAttempt("login-user:"+hash(strings.ToLower(username)))
}

func (s *Server) verifyAdminPassword(username, password string) (store.Admin, bool) {
	var account store.Admin
	err := s.store.View(func(st store.State) error {
		for _, candidate := range st.Admins {
			if candidate.Username == username {
				account = candidate
				break
			}
		}
		return nil
	})
	parts := strings.SplitN(account.PasswordHash, ":", 2)
	if len(parts) != 2 {
		// Keep the unknown-user path close to the real password-verification cost.
		_ = passwordHash(password, "AAECAwQFBgcICQoLDA0ODw")
		return account, false
	}
	matches := subtle.ConstantTimeCompare([]byte(parts[1]), []byte(passwordHash(password, parts[0]))) == 1
	return account, err == nil && matches && !account.Disabled && (!s.singleAdmin || (account.Role == "security_admin" && account.AllNodes))
}
