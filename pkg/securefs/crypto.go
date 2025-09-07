package securefs

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
)

func RandomBytes(n int) []byte {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return b
}

// deriveKey acts like HKDF-Expand over a PRK derived from password and salt.
// This is for demo only.
func deriveKey(password, salt, info []byte, length int) []byte {
	prkMac := hmac.New(sha256.New, password)
	prkMac.Write(salt)
	prk := prkMac.Sum(nil)

	var out []byte
	var ctr uint32 = 1
	for len(out) < length {
		var ctrB [4]byte
		binary.BigEndian.PutUint32(ctrB[:], ctr)
		m := hmac.New(sha256.New, prk)
		m.Write(info)
		m.Write(ctrB[:])
		out = append(out, m.Sum(nil)...)
		ctr++
	}
	return out[:length]
}

func symEnc(key, plaintext []byte) []byte {
	// prepend random 12-byte nonce
	nonce := RandomBytes(12)
	block, _ := aes.NewCipher(key)
	aead, _ := cipher.NewGCM(block)
	ct := aead.Seal(nil, nonce, plaintext, nil)
	return append(nonce, ct...)
}

func symDec(key, ciphertext []byte) ([]byte, error) {
	if len(ciphertext) < 12 {
		return nil, errors.New("ciphertext too short")
	}
	nonce := ciphertext[:12]
	ct := ciphertext[12:]
	block, _ := aes.NewCipher(key)
	aead, _ := cipher.NewGCM(block)
	return aead.Open(nil, nonce, ct, nil)
}

func hmacSHA256(key, msg []byte) []byte {
	m := hmac.New(sha256.New, key)
	m.Write(msg)
	return m.Sum(nil)
}
