package master

import (
	"encoding/base32"
	"testing"
	"time"
)

func TestValidTOTPMatchesRFC6238StyleCode(t *testing.T) {
	secret := base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString([]byte("12345678901234567890"))
	if !validTOTP(secret, fmtCode(totpAt([]byte("12345678901234567890"), 59/30)), time.Unix(59, 0)) {
		t.Fatal("valid TOTP rejected")
	}
	if validTOTP(secret, "000000", time.Unix(59, 0)) {
		t.Fatal("invalid TOTP accepted")
	}
}
func totpAt(key []byte, step int64) uint32 {
	msg := make([]byte, 8)
	v := uint64(step)
	for i := 7; i >= 0; i-- {
		msg[i] = byte(v)
		v >>= 8
	}
	mac := hmacSHA1(key, msg)
	off := mac[len(mac)-1] & 15
	n := ((uint32(mac[off]) & 127) << 24) | (uint32(mac[off+1]) << 16) | (uint32(mac[off+2]) << 8) | uint32(mac[off+3])
	return n % 1000000
}
