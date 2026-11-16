package master

import (
	"crypto/hmac"
	"crypto/sha1"
	"encoding/base32"
	"fmt"
	"time"
)

func base32Decode(s string) ([]byte, error) {
	return base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(s)
}
func hmacSHA1(key, msg []byte) []byte {
	m := hmac.New(sha1.New, key)
	_, _ = m.Write(msg)
	return m.Sum(nil)
}
func fmtCode(n uint32) string { return fmt.Sprintf("%06d", n) }
func validTOTP(secret, code string, now time.Time) bool {
	if len(code) != 6 {
		return false
	}
	key, err := base32Decode(secret)
	if err != nil {
		return false
	}
	step := now.Unix() / 30
	for d := int64(-1); d <= 1; d++ {
		msg := make([]byte, 8)
		v := uint64(step + d)
		for i := 7; i >= 0; i-- {
			msg[i] = byte(v)
			v >>= 8
		}
		mac := hmacSHA1(key, msg)
		off := mac[len(mac)-1] & 15
		n := ((uint32(mac[off]) & 127) << 24) | (uint32(mac[off+1]) << 16) | (uint32(mac[off+2]) << 8) | uint32(mac[off+3])
		if fmtCode(n%1000000) == code {
			return true
		}
	}
	return false
}
