package watchstander

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"math/big"
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

// Policy Doc definitions
type PolicyDoc struct {
	Predicates                [][]byte
	PredicateSignatures       [][]byte
	VerificationKeySignatures [][]byte
	Signature                 []byte
	VerificationKeys          []*ecdsa.PublicKey
	ExtensionKey              *ecdsa.PrivateKey
}

// NewPolicyDoc creates a new doc from an initial predicate and a root key
func NewPolicyDoc(identifier string, initialKey *ecdsa.PrivateKey) (*PolicyDoc, error) {
	initialSignature, err := Sign([]byte(identifier), initialKey)
	if err != nil {
		return nil, err
	}

	extensionKey, err := NewSigningKey()
	if err != nil {
		return nil, err
	}

	encodedExtensionPub, err := x509.MarshalPKIXPublicKey(extensionKey.Public())
	if err != nil {
		return nil, err
	}

	initialPubKeySignature, err := Sign(encodedExtensionPub, initialKey)
	if err != nil {
		return nil, err
	}

	return &PolicyDoc{
		Predicates:                [][]byte{[]byte(identifier)},
		PredicateSignatures:       [][]byte{initialSignature},
		VerificationKeySignatures: [][]byte{initialPubKeySignature},
		Signature:                 initialSignature,
		VerificationKeys:          []*ecdsa.PublicKey{&initialKey.PublicKey},
		ExtensionKey:              extensionKey,
	}, nil
}

// RemoveExtensionKey turns a doc into an inextensible one
func (d *PolicyDoc) RemoveExtensionKey() {
	d.ExtensionKey = nil
}

// VerifySignatures verifies the integrity of a doc given a root public key
// It does not verify the contents of the predicates
func (d *PolicyDoc) VerifySignatures(verificationKey *ecdsa.PublicKey) bool {
	// Verify verification keys
	for i, v := range d.VerificationKeys {
		if i == 0 {
			if v != verificationKey {
				fmt.Println("initial key doesn't match")
				return false
			}
		} else {
			encodedPub, err := x509.MarshalPKIXPublicKey(v)
			if err != nil {
				fmt.Printf("unable to encode key: %v\n", err)
			}
			if !Verify(encodedPub, d.VerificationKeySignatures[i-1], d.VerificationKeys[i-1]) {
				fmt.Printf("couldn't verify key %v\n", hex.EncodeToString(encodedPub))
				return false
			}
		}
	}

	// Verify predicate signatures
	for i, p := range d.Predicates {
		if !Verify(p, d.PredicateSignatures[i], d.VerificationKeys[i]) {
			fmt.Printf("couldn't verify predicate: %s\n", string(p))
			return false
		}
	}

	// Verify signature
	return Verify(d.Predicates[0], d.Signature, d.VerificationKeys[len(d.VerificationKeys)-1])
}

func (d PolicyDoc) String() string {
	var desc string
	desc += "Predicates: \n"
	for _, p := range d.Predicates {
		desc += "  " + string(p) + "\n"
	}
	desc += "\nPredicateSignatures: \n"
	for _, p := range d.PredicateSignatures {
		desc += "  " + hex.EncodeToString(p) + "\n"
	}
	return desc
}

// Extend creates a new policy doc, extended with the predicate added
func Extend(d *PolicyDoc, predicate string) (*PolicyDoc, error) {
	if d.ExtensionKey == nil {
		return nil, fmt.Errorf("No extension key, cannot extend.")
	}

	// Add the predicate to the list
	predicates := append(d.Predicates, []byte(predicate))

	// Sign the predicate with the current extension key
	predicateSignature, err := Sign([]byte(predicate), d.ExtensionKey)
	if err != nil {
		return nil, err
	}
	predicateSignatures := append(d.PredicateSignatures, predicateSignature)

	// Generate the next extension key
	extensionKey, err := NewSigningKey()
	if err != nil {
		return nil, err
	}
	encodedExtensionPub, err := x509.MarshalPKIXPublicKey(extensionKey.Public())
	if err != nil {
		return nil, err
	}

	// Sign the next extension key with the current extension key
	pubKeySignature, err := Sign(encodedExtensionPub, d.ExtensionKey)
	if err != nil {
		return nil, err
	}
	verificationKeySignatures := append(d.VerificationKeySignatures, pubKeySignature)

	// Sign the original identifier with the current extension key
	signature, err := Sign(d.Predicates[0], d.ExtensionKey)
	if err != nil {
		return nil, err
	}

	// Add the current extension public key as a verification key
	verificationKeys := append(d.VerificationKeys, &d.ExtensionKey.PublicKey)

	return &PolicyDoc{
		Predicates:                predicates,
		PredicateSignatures:       predicateSignatures,
		VerificationKeySignatures: verificationKeySignatures,
		Signature:                 signature,
		VerificationKeys:          verificationKeys,
		ExtensionKey:              extensionKey,
	}, nil
}
