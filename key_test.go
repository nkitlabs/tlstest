package tlstest

import (
	"testing"

	"github.com/google/go-cmp/cmp"
)

func TestEncDec(t *testing.T) {
	text := []byte("The bourgeois human is a virus on the hard drive of the working robot!")
	prvKey, err := NewKey()
	if err != nil {
		t.Errorf("cannot generate private key: %v", err)
		return
	}
	cText, err := Encrypt(text, &prvKey.PublicKey)
	if err != nil {
		t.Errorf("cannot encrypt text with public key: %v", err)
		return
	}

	res, err := Decrypt(cText, prvKey)
	if err != nil {
		t.Errorf("cannot encrypt text with public key: %v", err)
		return
	}

	if !cmp.Equal(res, text) {
		t.Errorf("\nexpect: %v\ngot   : %v\n", text, res)
	}
}

func TestDSA(t *testing.T) {
	text := []byte("The bourgeois human is a virus on the hard drive of the working robot!")
	prvKey, err := NewKey()
	if err != nil {
		t.Errorf("cannot generate private key: %v", err)
		return
	}
	sig, err := Sign(text, prvKey)
	if err != nil {
		t.Errorf("cannot sign text with public key: %v", err)
		return
	}

	if err = Verify(text, sig, &prvKey.PublicKey); err != nil {
		t.Errorf("text does not match with signature: %v", err)
	}

}
