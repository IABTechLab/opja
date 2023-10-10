package opjale

import (
	"bytes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"github.com/cloudflare/circl/hpke"
	"io"
)

const (
	labelZero = 0x00
	labelOne  = 0xFF
)

// label encryption cipher suite
type LESuite struct {
	l hpke.Suite
}

// returns a label encryption suite with the specified KEM, KDF, and AEAD algorithms
func NewLESuite() LESuite {
	return LESuite{l: hpke.NewSuite(hpke.KEM_X25519_HKDF_SHA256, hpke.KDF_HKDF_SHA256, hpke.AEAD_AES128GCM)}
}

// wrapper for HPKE KEM GenerateKeyPair()
func (suite LESuite) GenerateKeyPair() ([]byte, []byte, error) {
	kemID, _, _ := suite.l.Params()
	pk, sk, err := kemID.Scheme().GenerateKeyPair()
	if err != nil {
		return nil, nil, err
	}

	skBytes, err := sk.MarshalBinary()
	if err != nil {
		return nil, nil, err
	}

	pkBytes, err := pk.MarshalBinary()
	if err != nil {
		return nil, nil, err
	}

	return pkBytes, skBytes, nil
}

// returns the encapsulated key and a Sealer (defined below) object for the specified aead algorithm
func (suite LESuite) NewSender(sSKBytes, rPKBytes, info []byte) ([]byte, Sealer, error) {
	kemID, _, aeadID := suite.l.Params()
	rPK, err := kemID.Scheme().UnmarshalBinaryPublicKey(rPKBytes)
	if err != nil {
		return nil, Sealer{}, err
	}

	sSK, err := kemID.Scheme().UnmarshalBinaryPrivateKey(sSKBytes)
	if err != nil {
		return nil, Sealer{}, err
	}

	sender, err := suite.l.NewSender(rPK, info)
	if err != nil {
		return nil, Sealer{}, err
	}

	encapKey, sealer, err := sender.SetupAuth(rand.Reader, sSK)
	if err != nil {
		return nil, Sealer{}, err
	}

	key := sealer.Export(info, aeadID.KeySize())
	aead, err := aeadID.New(key)
	if err != nil {
		return nil, Sealer{}, err
	}

	Nn := aead.NonceSize()
	baseNonce := make([]byte, Nn)
	if _, err := io.ReadFull(rand.Reader, baseNonce); err != nil {
		return nil, Sealer{}, err
	}

	return encapKey,
		Sealer{
			aead,
			baseNonce,
			make([]byte, Nn),
			make([]byte, Nn),
		}, nil
}

// returns an Opener (defined below) object for the specified aead algorithm
func (suite LESuite) NewReceiver(sPKBytes, rSKBytes, info, encapKey []byte) (Opener, error) {
	kemID, _, aeadID := suite.l.Params()
	sPK, err := kemID.Scheme().UnmarshalBinaryPublicKey(sPKBytes)
	if err != nil {
		return Opener{}, err
	}

	rSK, err := kemID.Scheme().UnmarshalBinaryPrivateKey(rSKBytes)
	if err != nil {
		return Opener{}, err
	}

	receiver, err := suite.l.NewReceiver(rSK, info)
	if err != nil {
		return Opener{}, err
	}

	opener, err := receiver.SetupAuth(encapKey, sPK)
	if err != nil {
		return Opener{}, err
	}

	Nk := aeadID.KeySize()
	key := opener.Export(info, Nk)
	aead, err := aeadID.New(key)
	if err != nil {
		return Opener{}, err
	}

	return Opener{
		aead,
	}, nil
}

// sealer encrypts a plaintext using the specified AEAD encryption algorithm
type Sealer struct {
	cipher.AEAD
	baseNonce      []byte
	sequenceNumber []byte
	nonce          []byte
}

// calculates nonce by XORing the base nonce with the sequence number
func (s Sealer) calcNonce() []byte {
	for i := range s.baseNonce {
		s.nonce[i] = s.baseNonce[i] ^ s.sequenceNumber[i]
	}
	return s.nonce
}

// increments sequence number
func (s Sealer) increment() error {
	allOnes := byte(0xFF)
	for i := range s.sequenceNumber {
		allOnes &= s.sequenceNumber[i]
	}
	if allOnes == byte(0xFF) {
		return hpke.ErrAEADSeqOverflows
	}

	carry := uint(1)
	for i := len(s.sequenceNumber) - 1; i >= 0; i-- {
		sum := uint(s.sequenceNumber[i]) + carry
		carry = sum >> 8
		s.sequenceNumber[i] = byte(sum & 0xFF)
	}
	if carry != 0 {
		return hpke.ErrAEADSeqOverflows
	}
	return nil
}

// takes plaintext and associated data to produce a ciphertext. The nonce is incremented after each call.
func (s Sealer) seal(pt, aad []byte) (string, error) {
	nonce := s.calcNonce()
	ct := s.AEAD.Seal(nil, nonce, pt, aad)
	err := s.increment()
	if err != nil {
		for i := range ct {
			ct[i] = 0
		}
		return "", err
	}
	ct = append(nonce, ct...)
	return base64.StdEncoding.EncodeToString(ct), nil
}

// takes associated data and encrypts "0xFF" to produce the corresponding encrypted label. The nonce is incremented after each call.
func (s Sealer) SealOne(aad string) (string, error) {
	return s.seal([]byte{labelOne}, []byte(aad))
}

// takes associated data and encrypts "0x00" to produce the corresponding encrypted label. The nonce is incremented after each call.
func (s Sealer) SealZero(aad string) (string, error) {
	return s.seal([]byte{labelZero}, []byte(aad))
}

// opener decrypts a ciphertext using the specified AEAD encryption algorithm
type Opener struct {
	cipher.AEAD
}

// takes a ciphertext and associated data to recover the plaintext. The nonce is extracted from the ciphertext.
func (o Opener) Open(ct, aad string) ([]byte, error) {
	ctBytes, err := base64.StdEncoding.DecodeString(ct)
	if err != nil {
		return nil, err
	}
	Nn := o.AEAD.NonceSize()
	if len(ct) < Nn {
		return nil, errors.New("ciphertext length less than nonce length")
	}
	pt, err := o.AEAD.Open(nil, ctBytes[0:Nn], ctBytes[Nn:], []byte(aad))
	if err != nil {
		return nil, err
	}

	if !bytes.Equal(pt, []byte{labelOne}) && !bytes.Equal(pt, []byte{labelZero}) {
		return nil, errors.New("invalid label")
	}
	return pt, nil
}
