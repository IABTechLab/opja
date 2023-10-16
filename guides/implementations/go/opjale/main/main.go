package main

import (
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"github.com/Optable/docs/opja/dsp/opjale"
	"log"
)

func main() {
	// create a new OPJA label encryption cipher suite
	suite := opjale.NewLESuite()

	// generate matching system key pair
	msPK, msSK, err := suite.GenerateKeyPair()
	logErr(err)
	fmt.Println("Matching System Private Key: " + hex.EncodeToString(msSK))
	fmt.Println("Matching System Public Key: " + hex.EncodeToString(msPK))
	fmt.Println("Matching System Public Key Base64url: " + base64.RawURLEncoding.EncodeToString(msPK))

	// generate DSP key pair
	dspPK, dspSK, err := suite.GenerateKeyPair()
	logErr(err)
	fmt.Println("DSP Private Key: " + hex.EncodeToString(dspSK))
	fmt.Println("DSP Public Key: " + hex.EncodeToString(dspPK))
	fmt.Println("DSP Public Key Base64url: " + base64.RawURLEncoding.EncodeToString(dspPK))

	info := []byte("match-system-operator.com") // sender identity information (e.g., domain name)
	// creates a new matching system object with knowledge of the DSP's public key. Returns the Sealer and corresponding encapsulated key.
	encapKey, sealer, err := suite.NewSender(msSK, dspPK, info)
	logErr(err)
	fmt.Println("Encapsulated Key: " + hex.EncodeToString(encapKey))

	id := "2VwhmTY9MecgWsu6" // dummy match transaction id
	fmt.Println("Match Transaction Id: ", id)

	// encrypt a "zero" label
	encLabel0, err := sealer.SealZero(id)
	logErr(err)
	fmt.Println("Encrypted Label0 Base64: ", encLabel0)

	// encrypt a "one" label
	encLabel1, err := sealer.SealOne(id)
	logErr(err)
	fmt.Println("Encrypted Label1 Base64: ", encLabel1)

	// creates a new DSP object with knowledge of the matching system's public key and the encapsulated key. Returns the Opener.
	opener, err := suite.NewReceiver(msPK, dspSK, info, encapKey)
	logErr(err)

	// decrypt "zero" label
	label0, err := opener.Open(encLabel0, id)
	logErr(err)
	fmt.Println("Decrypted Label0: " + hex.EncodeToString(label0))

	// decrypt "one" label
	label1, err := opener.Open(encLabel1, id)
	logErr(err)
	fmt.Println("Decrypted Label1: " + hex.EncodeToString(label1))
}

// print error and exit
func logErr(err error) {
	if err != nil {
		log.Fatal(err)
	}
}
