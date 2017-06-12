package watchstander

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/x509"
	"encoding/base64"
	"encoding/gob"
	"fmt"
	"io"
	"strings"
)

const REMOTE_PREFIX = "com.default.rp"

type Predicate interface {
	String() string
}

// LocalPredicate is just a string
type LocalPredicate string

func (p LocalPredicate) String() string {
	return string(p)
}

// RemotePredicate encodes the public key of another policy doc that can "discharge" the predicate
// Can also include additional local predicates
type RemotePredicate struct {
	Location              string
	VerificationKey       *ecdsa.PublicKey
	Predicates            []LocalPredicate
	EmbeddingPublicKey    *[32]byte // Optional
	EncryptedDischargeKey *[]byte   // Optional
}

func DecodeRemotePredicate(encoded string) (*RemotePredicate, error) {
	var predicate RemotePredicate

	split := strings.Split(encoded, ":")
	if len(split) > 1 {
		if split[0] != REMOTE_PREFIX {
			return nil, fmt.Errorf("tried to decode remote predicate with wrong prefix: %s", split[0])
		}
		encoded = split[1]
	}

	base64decoded, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return nil, err
	}

	dec := gob.NewDecoder(bytes.NewReader(base64decoded))

	if err := dec.Decode(&predicate); err != nil {
		if err != io.EOF {
			return nil, err
		}
	}
	return &predicate, nil
}

func (p RemotePredicate) String() string {
	var buffer bytes.Buffer
	gob.Register(elliptic.P256())
	enc := gob.NewEncoder(&buffer)
	err := enc.Encode(p)
	if err != nil {
		fmt.Println(err)
	}
	return REMOTE_PREFIX + ":" + base64.StdEncoding.EncodeToString(buffer.Bytes())
}

// NewRemotePredicateFromDischargeRoot creates a remote predicate from an existing ecdsa key, the root of the
// discharge document. This requires the discharger to communicate the public key to the extender ahead of time.
func NewRemotePredicateFromDischargeRoot(location string, dischargeVerificationKey *ecdsa.PublicKey, predicates []LocalPredicate) *RemotePredicate {
	return &RemotePredicate{
		Location:        location,
		VerificationKey: dischargeVerificationKey,
		Predicates:      predicates,
	}
}

// NewRemotePredicateWithRoot creates a remote predicate and outputs the keypair the discharger should use to
// initialize the discharge document. This requires the extender to communicate the discharge key to the discharger
// out of band.
func NewRemotePredicateWithRoot(location string, predicates []LocalPredicate) (*RemotePredicate, *ecdsa.PrivateKey, error) {
	dischargeKey, err := NewSigningKey()
	if err != nil {
		return nil, nil, err
	}
	return NewRemotePredicateFromDischargeRoot(location, &dischargeKey.PublicKey, predicates), dischargeKey, nil
}

// NewRemotePredicateWithEncryptedRoot generates a root keypair for a discharger and encrypts it with a public key
// from the discharger. This requires the extender to communicate the encrypted discharge key to the discharger
// out of band.
func NewRemotePredicateWithEncryptedRoot(location string, dischargerPublicKey *[32]byte, predicates []LocalPredicate) (*RemotePredicate, []byte, error) {
	predicate, dischargeRootKey, err := NewRemotePredicateWithRoot(location, predicates)
	if err != nil {
		return nil, nil, err
	}
	senderPublicKey, senderPrivateKey := NewEncryptionKeyPair()

	encodedDischargeRootKey, err := x509.MarshalECPrivateKey(dischargeRootKey)
	if err != nil {
		return nil, nil, err
	}
	encryptedDischargeRootKey := Encrypt(encodedDischargeRootKey, dischargerPublicKey, senderPrivateKey)
	predicate.EmbeddingPublicKey = senderPublicKey
	return predicate, encryptedDischargeRootKey, nil
}

// NewRemotePredicateWithEncryptedRoot generates a root keypair for a discharger and encrypts it with a public key
// from the discharger. The encrypted root keypair is embedded in the predicate so that the key doesn't need to be
// communicated out of band. This requires that the original policy document be communicated to the discharger.
func NewRemotePredicateWithEmbeddedEncryptedRoot(location string, dischargerPublicKey *[32]byte, predicates []LocalPredicate) (*RemotePredicate, error) {
	predicate, encryptedDischargeKey, err := NewRemotePredicateWithEncryptedRoot(location, dischargerPublicKey, predicates)
	if err != nil {
		return nil, err
	}
	predicate.EncryptedDischargeKey = &encryptedDischargeKey
	return predicate, nil
}

// VerifyRemotePredicateWithKey verifies a predicate given a discharging PolicyDoc
// Currently doesn't deal with embedded LocalPredicates
func DischargeRemotePredicate(p *RemotePredicate, d *PolicyDoc) bool {
	return d.VerifySignatures(p.VerificationKey)
}
