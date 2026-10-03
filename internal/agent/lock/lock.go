// Package lock seals the human-built agent policy into an encrypted profile.
//
// A human runs `agent setup` once on their own machine: the policy JSON is
// sealed with Seal under an admin password (PBKDF2-SHA256 600k via stdlib
// crypto/pbkdf2, AES-GCM) and written to disk. `agent serve` re-opens it
// with Open after an interactive password prompt. A wrong password fails
// closed (constant-time verifier check first) and returns no partial data.
package lock

import (
	"bufio"
	"crypto/aes"
	"crypto/cipher"
	"crypto/pbkdf2"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	"golang.org/x/term"
)

// Profile envelope constants.
const (
	// FormatVersion is the only profile version this code reads or writes.
	FormatVersion = 1
	// KDFID identifies the key derivation: PBKDF2-SHA256, 600k iterations.
	KDFID = "pbkdf2-sha256-600k"
	// Iterations is the PBKDF2 work factor.
	Iterations = 600_000
	// KeyLen is the AES-256 key length in bytes.
	KeyLen = 32
	// SaltLen is the random salt length in bytes.
	SaltLen = 32
	// NonceLen is the AES-GCM nonce length in bytes.
	NonceLen = 12
)

// verifierDomain separates the password-check block from the encryption key:
// the verifier authenticates the password without exposing the key.
var verifierDomain = []byte("cli-odoo profile verifier v1|")

// Profile is the sealed on-disk envelope. Salt, Nonce, Ciphertext, and
// Verifier marshal as base64 in JSON. Instance is informational only (the
// sealed policy JSON is authoritative); Seal leaves it empty for the caller
// (setup) to fill in before writing the file.
type Profile struct {
	FormatVersion int    `json:"format_version"`
	Instance      string `json:"instance"`
	KDF           string `json:"kdf"`
	Salt          []byte `json:"salt"`
	Nonce         []byte `json:"nonce"`
	Ciphertext    []byte `json:"ciphertext"`
	Verifier      []byte `json:"verifier"`
}

// derive returns the AES-256 key for password+salt, or an error on empty input.
func derive(password string, salt []byte) ([]byte, error) {
	if password == "" {
		return nil, errors.New("lock: empty admin password")
	}
	if len(salt) == 0 {
		return nil, errors.New("lock: empty salt")
	}
	key, err := pbkdf2.Key(sha256.New, password, salt, Iterations, KeyLen)
	if err != nil {
		return nil, fmt.Errorf("lock: derive key: %w", err)
	}
	return key, nil
}

// verifierFor binds key to the verifier domain so Open can reject a wrong
// password before attempting decryption.
func verifierFor(key []byte) []byte {
	h := sha256.New()
	h.Write(verifierDomain)
	h.Write(key)
	return h.Sum(nil)
}

// Seal encrypts policyJSON under adminPassword and returns the envelope.
// Salt and nonce are drawn from crypto/rand.
func Seal(policyJSON []byte, adminPassword string) (Profile, error) {
	if len(policyJSON) == 0 {
		return Profile{}, errors.New("lock: nothing to seal")
	}
	var salt [SaltLen]byte
	if _, err := rand.Read(salt[:]); err != nil {
		return Profile{}, fmt.Errorf("lock: salt: %w", err)
	}
	key, err := derive(adminPassword, salt[:])
	if err != nil {
		return Profile{}, err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return Profile{}, fmt.Errorf("lock: cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return Profile{}, fmt.Errorf("lock: gcm: %w", err)
	}
	var nonce [NonceLen]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return Profile{}, fmt.Errorf("lock: nonce: %w", err)
	}
	return Profile{
		FormatVersion: FormatVersion,
		KDF:           KDFID,
		Salt:          append([]byte(nil), salt[:]...),
		Nonce:         append([]byte(nil), nonce[:]...),
		Ciphertext:    gcm.Seal(nil, nonce[:], policyJSON, nil),
		Verifier:      verifierFor(key),
	}, nil
}

// Open decrypts the profile under adminPassword. A wrong password (or a
// corrupt envelope) returns an error and no partial data.
func (p Profile) Open(adminPassword string) ([]byte, error) {
	if p.FormatVersion != FormatVersion {
		return nil, fmt.Errorf("lock: unsupported profile version %d", p.FormatVersion)
	}
	if p.KDF != KDFID {
		return nil, fmt.Errorf("lock: unsupported kdf %q", p.KDF)
	}
	if len(p.Salt) == 0 || len(p.Nonce) == 0 || len(p.Ciphertext) == 0 || len(p.Verifier) == 0 {
		return nil, errors.New("lock: incomplete profile envelope")
	}
	key, err := derive(adminPassword, p.Salt)
	if err != nil {
		return nil, err
	}
	if subtle.ConstantTimeCompare(verifierFor(key), p.Verifier) != 1 {
		return nil, errors.New("lock: wrong admin password")
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("lock: cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("lock: gcm: %w", err)
	}
	plain, err := gcm.Open(nil, p.Nonce, p.Ciphertext, nil)
	if err != nil {
		return nil, errors.New("lock: profile decrypt failed (corrupt profile)")
	}
	return plain, nil
}

// PromptAdminPassword reads a password without echo when stdin is a TTY
// (via golang.org/x/term), falling back to a line read so piped stdin keeps
// working. The password never comes from args or env.
func PromptAdminPassword(prompt string) (string, error) {
	fmt.Fprint(os.Stderr, prompt)
	fd := int(os.Stdin.Fd())
	if term.IsTerminal(fd) {
		b, err := term.ReadPassword(fd)
		fmt.Fprintln(os.Stderr)
		if err != nil {
			return "", fmt.Errorf("lock: read password: %w", err)
		}
		if strings.TrimSpace(string(b)) == "" {
			return "", errors.New("lock: empty admin password")
		}
		return strings.TrimSpace(string(b)), nil
	}
	return readPasswordLine(os.Stdin)
}

// ReadAdminPasswordStdin reads the admin password from stdin for the
// --admin-password-stdin flag only. It never consults args or env.
func ReadAdminPasswordStdin() (string, error) {
	return readPasswordLine(os.Stdin)
}

// readPasswordLine reads one line (piped-stdin fallback) and trims it.
func readPasswordLine(r io.Reader) (string, error) {
	line, err := bufio.NewReader(r).ReadString('\n')
	if err != nil && err != io.EOF {
		return "", fmt.Errorf("lock: read password: %w", err)
	}
	if strings.TrimSpace(line) == "" {
		return "", errors.New("lock: empty admin password")
	}
	return strings.TrimSpace(line), nil
}
