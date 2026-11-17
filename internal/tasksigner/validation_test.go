package tasksigner

import (
	"crypto/ed25519"
	"strings"
	"testing"
)

func TestNewKeyIDGrammar(t *testing.T) {
	key := ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize))
	for _, tc := range []struct {
		name, id string
		valid    bool
	}{
		{"empty", "", false},
		{"one", "a", true},
		{"allowed", "Az09._:-", true},
		{"maximum", strings.Repeat("a", 128), true},
		{"too long", strings.Repeat("a", 129), false},
		{"space", "bad key", false},
		{"newline", "bad\n", false},
		{"unicode", "kéy", false},
		{"slash", "a/b", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s, err := New(tc.id, key)
			if (err == nil) != tc.valid || (s != nil) != tc.valid {
				t.Fatalf("New(%q): signer %v, error %v; valid %v", tc.id, s != nil, err, tc.valid)
			}
		})
	}
}
