package watchstander

import (
	"bytes"
	"testing"
)

func MockPredicateVerifier(t *testing.T, doc *PolicyDoc, discharges map[string]*PolicyDoc) bool {
	// Set up verifiers
	localVerifier := func(p []byte) bool {
		return true
	}

	// Discharging doc should satisfy the remote predicate
	for _, p := range doc.Predicates {
		if bytes.HasPrefix(p, []byte(REMOTE_PREFIX)) {
			remote, err := DecodeRemotePredicate(string(p))
			if err != nil {
				t.Fatalf("failed to parse remote predicate: %v", err)
			}
			discharge, ok := discharges[remote.Location]
			if !ok {
				t.Fatalf("couldn't find discharge for predicate")
			}
			if !DischargeRemotePredicate(remote, discharge) {
				return false
			}
		} else {
			if !localVerifier(p) {
				return false
			}
		}
	}
	return true
}

func TestSerialization(t *testing.T) {
	dischargerPublic, _ := NewEncryptionKeyPair()
	predicate, _, err := NewRemotePredicateWithEncryptedRoot("test", dischargerPublic, []LocalPredicate{LocalPredicate("Test")})
	if err != nil {
		t.Fatalf("couldn't create predicate")
	}
	encoded := predicate.String()

	decoded, err := DecodeRemotePredicate(encoded)
	if err != nil {
		t.Fatalf("couldn't decode predicate: %s", err)
	}

	if encoded != decoded.String() {
		t.Fatalf("decoded didn't match encoded")
	}
}

func TestPolicyWithRemotePredicate(t *testing.T) {
	initialKey, err := NewSigningKey()
	doc, err := NewPolicyDoc(LocalPredicate("id"), initialKey)
	if err != nil {
		t.Fatalf("failed to initialize doc: %v", err)
	}

	// Add a local predicate
	doc, err = Extend(doc, LocalPredicate("predicate1"))
	if err != nil {
		t.Fatalf("failed to extend doc: %v", err)
	}

	// Add a remote predicate
	remotePredicate, dischargeKey, err := NewRemotePredicateWithRoot("my.discharge.svc.local", []LocalPredicate{LocalPredicate("discharger-will-verify")})
	doc, err = Extend(doc, remotePredicate)
	if err != nil {
		t.Fatalf("failed to extend doc: %v", err)
	}

	// Doc should be valid
	if !doc.VerifySignatures(&initialKey.PublicKey) {
		t.Fatal("initialized doc is invalid")
	}

	// Create a discharging policy document for the remote predicate
	dischargeDoc, err := NewPolicyDoc(LocalPredicate("my.discharge.svc.local"), dischargeKey)
	if err != nil {
		t.Fatalf("failed to initialize doc: %v", err)
	}

	if dischargeKey.Public() != remotePredicate.VerificationKey {
		t.Fatalf("public key not encoded")
	}

	if !MockPredicateVerifier(t, doc, map[string]*PolicyDoc{"my.discharge.svc.local": dischargeDoc}) {
		t.Fatalf("Document should be valid")
	}
}
