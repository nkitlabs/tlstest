package tlstest

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
)

// NewKey generates random 2048 private and publick key
func NewKey() (*rsa.PrivateKey, error) {
	return rsa.GenerateKey(rand.Reader, 2048)
}

// Encrypt encrypts the given text with given public key
func Encrypt(text []byte, key *rsa.PublicKey) ([]byte, error) {
	return rsa.EncryptPKCS1v15(rand.Reader, key, text)
}

// Decrypt decrypts the given cipher text with given public key
func Decrypt(cText []byte, key *rsa.PrivateKey) ([]byte, error) {
	return rsa.DecryptPKCS1v15(rand.Reader, key, cText)
}

// Sign creates signature from the given text with private key
func Sign(text []byte, key *rsa.PrivateKey) ([]byte, error) {
	hash := sha256.Sum256(text)
	return rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, hash[:])
}

// Verify returns whether the signature matches the given text or not
func Verify(text, sig []byte, key *rsa.PublicKey) error {
	hash := sha256.Sum256(text)
	return rsa.VerifyPKCS1v15(key, crypto.SHA256, hash[:], sig)
}
