package watchstander

import (
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"crypto/elliptic"
)

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
func NewPolicyDoc(identifier Predicate, initialKey *ecdsa.PrivateKey) (*PolicyDoc, error) {
	initialSignature, err := Sign([]byte(identifier.String()), initialKey)
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
		Predicates:                [][]byte{[]byte(identifier.String())},
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
	// Quick hack to deal with gob encoding - force P256
	verificationKey.Curve = elliptic.P256()

	encodedVerificationKey, err := x509.MarshalPKIXPublicKey(verificationKey)
	if err != nil {
		fmt.Printf("unable to encode verification key: %v\n", err)
	}

	// Verify verification keys
	for i, v := range d.VerificationKeys {
		encodedPub, err := x509.MarshalPKIXPublicKey(v)
		if err != nil {
			fmt.Printf("unable to encode key: %v\n", err)
		}
		if i == 0 {
			if string(encodedPub) != string(encodedVerificationKey) {
				return false
			}
		} else {
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
func Extend(d *PolicyDoc, predicate Predicate) (*PolicyDoc, error) {
	if d.ExtensionKey == nil {
		return nil, fmt.Errorf("No extension key, cannot extend.")
	}

	// Add the predicate to the list
	predicates := append(d.Predicates, []byte(predicate.String()))

	// Sign the predicate with the current extension key
	predicateSignature, err := Sign([]byte(predicate.String()), d.ExtensionKey)
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
