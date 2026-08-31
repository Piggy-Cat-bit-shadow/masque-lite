package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"fmt"
)

func keygen() {
	k, e := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if e != nil {
		panic(e)
	}
	raw := make([]byte, 32)
	k.D.FillBytes(raw)
	pub := elliptic.Marshal(elliptic.P256(), k.PublicKey.X, k.PublicKey.Y)
	fmt.Printf("private-key: %s\npublic-key: %s\n", base64.StdEncoding.EncodeToString(raw), base64.StdEncoding.EncodeToString(pub))
}
