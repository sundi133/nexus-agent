//go:build ignore

// sign-update produces the signature the agent verifies before installing a
// self-update: base64(ed25519.Sign(priv, sha256(binary))).
//
//	go run scripts/sign-update.go keygen                 # prints private + public key
//	go run scripts/sign-update.go sign <privkey-b64> <binary>
//
// Keep the private key in your release pipeline's KMS/HSM, never in the repo.
// Put the public key in the agent config as update_public_key.
package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"os"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: sign-update keygen | sign <privkey-b64> <file>")
		os.Exit(2)
	}
	switch os.Args[1] {
	case "keygen":
		pub, priv, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			panic(err)
		}
		fmt.Println("private:", base64.StdEncoding.EncodeToString(priv))
		fmt.Println("public: ", base64.StdEncoding.EncodeToString(pub))
	case "sign":
		if len(os.Args) != 4 {
			fmt.Fprintln(os.Stderr, "usage: sign-update sign <privkey-b64> <file>")
			os.Exit(2)
		}
		key, err := base64.StdEncoding.DecodeString(os.Args[2])
		if err != nil || len(key) != ed25519.PrivateKeySize {
			fmt.Fprintln(os.Stderr, "invalid private key")
			os.Exit(1)
		}
		b, err := os.ReadFile(os.Args[3])
		if err != nil {
			panic(err)
		}
		sum := sha256.Sum256(b)
		fmt.Println("sha256:   ", hex.EncodeToString(sum[:]))
		fmt.Println("signature:", base64.StdEncoding.EncodeToString(ed25519.Sign(ed25519.PrivateKey(key), sum[:])))
	}
}
