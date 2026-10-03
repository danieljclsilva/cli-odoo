package lock

import (
	"bytes"
	"strings"
	"testing"
)

func TestSealOpenRoundtrip(t *testing.T) {
	plain := []byte(`{"version":1,"instance":"prod"}`)
	p, err := Seal(plain, "correct horse battery staple")
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	if p.FormatVersion != FormatVersion {
		t.Fatalf("FormatVersion = %d, want %d", p.FormatVersion, FormatVersion)
	}
	if p.KDF != KDFID {
		t.Fatalf("KDF = %q, want %q", p.KDF, KDFID)
	}
	if len(p.Salt) != SaltLen || len(p.Nonce) != NonceLen || len(p.Ciphertext) == 0 || len(p.Verifier) == 0 {
		t.Fatalf("incomplete envelope: salt=%d nonce=%d ct=%d verifier=%d",
			len(p.Salt), len(p.Nonce), len(p.Ciphertext), len(p.Verifier))
	}
	out, err := p.Open("correct horse battery staple")
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if !bytes.Equal(out, plain) {
		t.Fatalf("roundtrip mismatch: %q", out)
	}
}

func TestOpenWrongPasswordFailsClosed(t *testing.T) {
	p, err := Seal([]byte(`{"version":1}`), "right-password")
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	out, err := p.Open("wrong-password")
	if err == nil {
		t.Fatal("Open with wrong password succeeded")
	}
	if len(out) != 0 {
		t.Fatalf("wrong-password Open leaked %d bytes", len(out))
	}
}

func TestSealRandomizesEnvelopes(t *testing.T) {
	a, err := Seal([]byte(`{"v":1}`), "same-password")
	if err != nil {
		t.Fatalf("Seal a: %v", err)
	}
	b, err := Seal([]byte(`{"v":1}`), "same-password")
	if err != nil {
		t.Fatalf("Seal b: %v", err)
	}
	if bytes.Equal(a.Salt, b.Salt) || bytes.Equal(a.Nonce, b.Nonce) || bytes.Equal(a.Ciphertext, b.Ciphertext) {
		t.Fatal("two seals of the same input are identical (no randomness)")
	}
}

func TestOpenRejectsEnvelope(t *testing.T) {
	p, err := Seal([]byte(`{"v":1}`), "pw")
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	bad := p
	bad.FormatVersion = 999
	if _, err := bad.Open("pw"); err == nil {
		t.Fatal("bad version accepted")
	}
	bad = p
	bad.KDF = "scrypt"
	if _, err := bad.Open("pw"); err == nil {
		t.Fatal("bad kdf accepted")
	}
	bad = p
	bad.Ciphertext = append([]byte(nil), p.Ciphertext...)
	bad.Ciphertext[0] ^= 0xff
	if _, err := bad.Open("pw"); err == nil {
		t.Fatal("tampered ciphertext accepted")
	}
	if _, err := p.Open(""); err == nil {
		t.Fatal("empty password accepted")
	}
	if _, err := Seal(nil, "pw"); err == nil {
		t.Fatal("empty policy sealed")
	}
}

func TestReadPasswordLineTrims(t *testing.T) {
	got, err := readPasswordLine(strings.NewReader("  secret \n"))
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if got != "secret" {
		t.Fatalf("got %q", got)
	}
	if _, err := readPasswordLine(strings.NewReader("\n")); err == nil {
		t.Fatal("blank password accepted")
	}
}

func TestOpenRejectsBadSizesWithoutPanic(t *testing.T) {
	p, err := Seal([]byte(`{"v":1}`), "pw")
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	cases := map[string]func() Profile{
		"1-byte nonce": func() Profile {
			bad := p
			bad.Nonce = []byte{0x01}
			return bad
		},
		"truncated salt": func() Profile {
			bad := p
			bad.Salt = p.Salt[:7]
			return bad
		},
		"truncated verifier": func() Profile {
			bad := p
			bad.Verifier = p.Verifier[:16]
			return bad
		},
		"empty ciphertext": func() Profile {
			bad := p
			bad.Ciphertext = nil
			return bad
		},
		"oversize ciphertext": func() Profile {
			bad := p
			bad.Ciphertext = make([]byte, 4<<20)
			return bad
		},
	}
	for name, mk := range cases {
		func() {
			defer func() {
				if r := recover(); r != nil {
					t.Fatalf("%s panicked: %v", name, r)
				}
			}()
			if _, err := mk().Open("pw"); err == nil {
				t.Fatalf("%s accepted", name)
			}
		}()
	}
}

func TestSealBoundsInputs(t *testing.T) {
	if _, err := Seal([]byte(`{"v":1}`), ""); err == nil {
		t.Fatal("empty password sealed")
	}
	if _, err := Seal(make([]byte, 4<<20), "pw"); err == nil {
		t.Fatal("oversize payload sealed")
	}
	bad, err := Seal([]byte(`{"v":1}`), "pw")
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	if _, err := bad.Open("nope"); err == nil {
		t.Fatal("wrong password opened")
	}
}

func TestReadPasswordLineKeepsSecondLine(t *testing.T) {
	// One shared reader, two sequential line reads: the first read must
	// not swallow the second line (the old per-call bufio.Reader did).
	r := strings.NewReader("first-pw\nsecond-pw\n")
	first, err := readPasswordLine(r)
	if err != nil {
		t.Fatalf("first: %v", err)
	}
	second, err := readPasswordLine(r)
	if err != nil {
		t.Fatalf("second: %v", err)
	}
	if first != "first-pw" || second != "second-pw" {
		t.Fatalf("got %q, %q", first, second)
	}
}
