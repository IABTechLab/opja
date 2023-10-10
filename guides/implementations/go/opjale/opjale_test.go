package opjale

import (
	"bytes"
	"crypto/rand"
	"fmt"
	"testing"
)

func setupAeadTest() (Sealer, Opener, error) {
	suite := NewLESuite()
	_, _, aeadID := suite.l.Params()
	key := make([]byte, aeadID.KeySize())
	if n, err := rand.Read(key); err != nil {
		return Sealer{}, Opener{}, err
	} else if n != len(key) {
		return Sealer{}, Opener{}, fmt.Errorf("unexpected key size: got %d; want %d", n, len(key))
	}

	aead, err := aeadID.New(key)
	if err != nil {
		return Sealer{}, Opener{}, err
	}

	Nn := aeadID.NonceSize()
	baseNonce := make([]byte, Nn)
	if n, err := rand.Read(baseNonce); err != nil {
		return Sealer{}, Opener{}, err
	} else if n != len(baseNonce) {
		return Sealer{}, Opener{}, fmt.Errorf("unexpected base nonce size: got %d; want %d", n, len(baseNonce))
	}

	sealer := Sealer{
		aead, baseNonce, make([]byte, Nn), make([]byte, Nn),
	}
	opener := Opener{
		aead,
	}
	return sealer, opener, nil
}

func TestAeadNonceUpdate(t *testing.T) {
	sealer, opener, err := setupAeadTest()
	if err != nil {
		t.Errorf("setup failed")
	}
	aad := "aad"

	numAttempts := 2
	var prevCt string
	for i := 0; i < numAttempts; i++ {
		ct, err := sealer.SealOne(aad)
		if err != nil {
			t.Fatalf("encryption failed: %s", err)
		}

		if prevCt != "" && ct == prevCt {
			t.Error("ciphertext matches the previous (nonce not updated)")
		}

		_, err = opener.Open(ct, aad)
		if err != nil {
			t.Errorf("decryption failed: %s", err)
		}

		prevCt = ct
	}
}

func TestMultipleOpen(t *testing.T) {
	sealer, opener, err := setupAeadTest()
	if err != nil {
		t.Errorf("setup failed")
	}
	aad := "aad"

	ct, err := sealer.SealZero(aad)
	if err != nil {
		t.Fatalf("encryption failed: %s", err)
	}

	pt, err := opener.Open(ct, aad)
	if err != nil {
		t.Fatalf("decryption failed: %s", err)
	}

	if !bytes.Equal(pt, []byte{labelZero}) {
		t.Fatal("plaintext mismatch")
	}

	pt, err = opener.Open(ct, aad)
	if err != nil {
		t.Fatal("decryption failed when it should have succeeded")
	}

	if !bytes.Equal(pt, []byte{labelZero}) {
		t.Fatal("plaintext mismatch")
	}
}

func TestOutOfOrderOpen(t *testing.T) {
	sealer, opener, err := setupAeadTest()
	if err != nil {
		t.Errorf("setup failed")
	}
	aad := "aad"

	ct0, err := sealer.SealZero(aad)
	if err != nil {
		t.Fatalf("encryption failed: %s", err)
	}

	ct1, err := sealer.SealOne(aad)
	if err != nil {
		t.Fatalf("encryption failed: %s", err)
	}

	pt1, err := opener.Open(ct1, aad)
	if err != nil {
		t.Fatal("decryption failed when it should have succeeded")
	}

	if !bytes.Equal(pt1, []byte{labelOne}) {
		t.Fatal("plaintext mismatch")
	}

	pt0, err := opener.Open(ct0, aad)
	if err != nil {
		t.Fatal("decryption failed when it should have succeeded")
	}

	if !bytes.Equal(pt0, []byte{labelZero}) {
		t.Fatal("plaintext mismatch")
	}
}

func TestInvalidLabelDecryption(t *testing.T) {
	sealer, opener, err := setupAeadTest()
	if err != nil {
		t.Errorf("setup failed")
	}
	aad := "aad"
	pt := []byte{0xEF}

	ct, err := sealer.seal(pt, []byte(aad))
	if err != nil {
		t.Fatalf("encryption failed: %s", err)
	}

	_, err = opener.Open(ct, aad)
	if err == nil {
		t.Fatal("decryption succeeded when it should have failed")
	}

	_, err = opener.Open(ct, "aad1")
	if err == nil {
		t.Fatal("decryption succeeded when it should have failed")
	}
}

func TestAeadSeqOverflow(t *testing.T) {
	sealer, opener, err := setupAeadTest()
	if err != nil {
		t.Errorf("setup failed")
	}

	Nn := len(sealer.baseNonce)
	aad := "aad"

	// Sets sequence number to 256 before its max value = 0xFF...FF.
	for i := 0; i < Nn-1; i++ {
		sealer.sequenceNumber[i] = 0xFF
	}
	sealer.sequenceNumber[Nn-1] = 0x00

	numAttempts := 260
	wantCorrect := 2 * 255
	wantIncorrect := 2*numAttempts - wantCorrect
	gotCorrect := 0
	gotIncorrect := 0

	for i := 0; i < numAttempts; i++ {
		ct, err := sealer.SealZero(aad)
		switch {
		case ct != "" && err == nil:
			gotCorrect++
		case ct == "" && err != nil:
			gotIncorrect++
		default:
			t.FailNow()
		}

		pt, err := opener.Open(ct, aad)
		switch {
		case pt != nil && err == nil:
			gotCorrect++
		case pt == nil && err != nil:
			gotIncorrect++
		default:
			t.FailNow()
		}
	}

	if gotCorrect != wantCorrect {
		t.Errorf("Expected correct attemps: %d\nNo. of correct attempts: %d", wantCorrect, gotCorrect)
	}
	if gotIncorrect != wantIncorrect {
		t.Errorf("Expected incorrect attemps: %d\nNo. of incorrect attempts: %d", wantIncorrect, gotIncorrect)
	}
}
