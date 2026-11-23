package tls

import (
	"testing"

	utls "github.com/refraction-networking/utls"
)

// TestRandomFingerprintSatisfiesMLKEM verifies that:
//  1. "random" resolves to one of the three browser auto fingerprints chosen in init().
//  2. Every candidate carries an X25519MLKEM768 key_share before X25519, which is
//     required by the upstream REALITY server.
func TestRandomFingerprintSatisfiesMLKEM(t *testing.T) {
	candidates := map[string]*utls.ClientHelloID{
		"chrome":  &utls.HelloChrome_Auto,
		"firefox": &utls.HelloFirefox_Auto,
		"safari":  &utls.HelloSafari_Auto,
	}

	// (1) random must resolve to one of the three auto fingerprints.
	got := GetFingerprint("random")
	if got == nil {
		t.Fatal("GetFingerprint(\"random\") returned nil")
	}
	matched := ""
	for name, c := range candidates {
		if got.Str() == c.Str() {
			matched = name
			break
		}
	}
	if matched == "" {
		t.Fatalf("random resolved to %s, not one of chrome/firefox/safari auto", got.Str())
	}
	t.Logf("random resolved to: %s (%s)", got.Str(), matched)

	// (2) every candidate must have MLKEM key_share (4588) before X25519 (29).
	for name, id := range candidates {
		spec, err := utls.UTLSIdToSpec(*id)
		if err != nil {
			t.Fatalf("%s: UTLSIdToSpec: %v", name, err)
		}
		var groups []int
		for _, e := range spec.Extensions {
			if ks, ok := e.(*utls.KeyShareExtension); ok {
				for _, k := range ks.KeyShares {
					groups = append(groups, int(k.Group))
				}
			}
		}
		const MLKEM = 4588
		const X25519 = 29
		mlkemOK := false
		for _, g := range groups {
			if g == MLKEM {
				mlkemOK = true
				break
			}
			if g == X25519 {
				break
			}
		}
		if !mlkemOK {
			t.Errorf("%s (%s) lacks MLKEM before X25519: key_shares=%v", name, id.Str(), groups)
		} else {
			t.Logf("%s (%s) OK, key_shares=%v", name, id.Str(), groups)
		}
	}
}
