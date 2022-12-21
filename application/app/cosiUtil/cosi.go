package cosiUtil

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"go.dedis.ch/cothority/v3/blscosi"
	"go.dedis.ch/cothority/v3/blscosi/blscosi/check"
	"go.dedis.ch/onet/v3/app"
	"log"
	"os"
)

type sigHex struct {
	Hash      string
	Signature string
}

// Sign takes a stream and a toml file defining the servers
func Sign(msg []byte, tomlFileName string) (*blscosi.SignatureResponse, error) {
	log.Println("Starting signature")
	f, err := os.Open(tomlFileName)
	if err != nil {
		return nil, err
	}
	g, err := app.ReadGroupDescToml(f)
	if err != nil {
		return nil, err
	}
	if len(g.Roster.List) <= 0 {
		return nil, fmt.Errorf("Empty or invalid blscosi group file: %s", tomlFileName)
	}

	log.Println("Sending signature to", g.Roster)
	return check.SignStatement(msg, g.Roster)
}

// writeSigAsJSON - writes the JSON out to a file
func WriteSigAsJSON(res *blscosi.SignatureResponse) (string, error) {
	b, err := json.Marshal(sigHex{
		Hash:      hex.EncodeToString(res.Hash),
		Signature: hex.EncodeToString(res.Signature)},
	)

	if err != nil {
		return "", fmt.Errorf("Couldn't encode signature: %s", err.Error())
	}

	return string(b), nil
}

// verify takes a group-definition, calls the signature
// verification and prints the result. If sigFileName is empty it
// assumes to find the standard signature in fileName.sig
func verify(msg string, sigStr string, groupToml string) error {

	sigBytes := []byte(sigStr)
	sigHex := &sigHex{}
	err := json.Unmarshal(sigBytes, sigHex)
	if err != nil {
		return err
	}

	sig := &blscosi.SignatureResponse{}
	sig.Hash, err = hex.DecodeString(sigHex.Hash)
	if err != nil {
		return err
	}
	sig.Signature, err = hex.DecodeString(sigHex.Signature)
	if err != nil {
		return err
	}
	fGroup, err := os.Open(groupToml)
	if err != nil {
		return err
	}

	log.Println("Reading group definition")
	g, err := app.ReadGroupDescToml(fGroup)
	if err != nil {
		return err
	}

	log.Println("Verifying signature %x %x", msg, sig.Signature)
	return check.VerifySignatureHash([]byte(msg), sig, g.Roster)
}
