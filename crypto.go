package watchstander

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"io"
	"math/big"

	"golang.org/x/crypto/nacl/box"
)

// Primitives - https://github.com/gtank/cryptopasta/blob/master/sign.go

func NewSigningKey() (*ecdsa.PrivateKey, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	return key, err
}

// Sign signs arbitrary data using ECDSA.
func Sign(data []byte, privkey *ecdsa.PrivateKey) ([]byte, error) {
	// hash message
	digest := sha256.Sum256(data)

	// sign the hash
	r, s, err := ecdsa.Sign(rand.Reader, privkey, digest[:])
	if err != nil {
		return nil, err
	}

	// encode the signature {R, S}
	// big.Int.Bytes() will need padding in the case of leading zero bytes
	params := privkey.Curve.Params()
	curveOrderByteSize := params.P.BitLen() / 8
	rBytes, sBytes := r.Bytes(), s.Bytes()
	signature := make([]byte, curveOrderByteSize*2)
	copy(signature[curveOrderByteSize-len(rBytes):], rBytes)
	copy(signature[curveOrderByteSize*2-len(sBytes):], sBytes)

	return signature, nil
}

// Verify checks a raw ECDSA signature.
// Returns true if it's valid and false if not.
func Verify(data, signature []byte, pubkey *ecdsa.PublicKey) bool {
	digest := sha256.Sum256(data)

	curveOrderByteSize := pubkey.Curve.Params().P.BitLen() / 8

	r, s := new(big.Int), new(big.Int)
	r.SetBytes(signature[:curveOrderByteSize])
	s.SetBytes(signature[curveOrderByteSize:])

	return ecdsa.Verify(pubkey, digest[:], r, s)
}

func NewEncryptionKeyPair() (*[32]byte, *[32]byte) {
	publicKey, privateKey, err := box.GenerateKey(rand.Reader)
	if err != nil {
		panic(err)
	}
	return publicKey, privateKey
}

func Encrypt(message []byte, recipientPublicKey, senderPrivateKey *[32]byte) []byte {
	var nonce [24]byte
	if _, err := io.ReadFull(rand.Reader, nonce[:]); err != nil {
		panic(err)
	}

	return box.Seal(nonce[:], message, &nonce, recipientPublicKey, senderPrivateKey)
}

func Decrypt(encrypted []byte, senderPublicKey, recipientPrivateKey *[32]byte) ([]byte, error) {
	var decryptNonce [24]byte
	copy(decryptNonce[:], encrypted[:24])
	decrypted, ok := box.Open(nil, encrypted[24:], &decryptNonce, senderPublicKey, recipientPrivateKey)
	if !ok {
		return nil, fmt.Errorf("unable to decrypt")
	}
	return decrypted, nil
}
