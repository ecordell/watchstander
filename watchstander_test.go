package watchstander

import "testing"

func TestBasicPolicyDoc(t *testing.T) {
	initialKey, err := NewSigningKey()
	doc, err := NewPolicyDoc(LocalPredicate("id"), initialKey)
	if err != nil {
		t.Fatalf("failed to initialize doc: %v", err)
	}
	if !doc.VerifySignatures(&initialKey.PublicKey) {
		t.Fatal("initialized doc is invalid")
	}
}

func TestExtendedPolicyDoc(t *testing.T) {
	initialKey, err := NewSigningKey()
	doc, err := NewPolicyDoc(LocalPredicate("id"), initialKey)
	if err != nil {
		t.Fatalf("failed to initialize doc: %v", err)
	}

	doc, err = Extend(doc, LocalPredicate("predicate1"))
	if err != nil {
		t.Fatalf("failed to extend doc: %v", err)
	}
	doc, err = Extend(doc, LocalPredicate("predicate2"))
	if err != nil {
		t.Fatalf("failed to extend doc: %v", err)
	}
	if !doc.VerifySignatures(&initialKey.PublicKey) {
		t.Fatal("initialized doc is invalid")
	}
}

func TestPolicyDocVerificationFailureModes(t *testing.T) {
	initialKey, err := NewSigningKey()
	doc, err := NewPolicyDoc(LocalPredicate("id"), initialKey)
	if err != nil {
		t.Fatalf("failed to initialize doc: %v", err)
	}
	doc1, err := Extend(doc, LocalPredicate("predicate1"))
	if err != nil {
		t.Fatalf("failed to extend doc: %v", err)
	}
	doc2, err := Extend(doc1, LocalPredicate("predicate2"))
	if err != nil {
		t.Fatalf("failed to extend doc: %v", err)
	}

	extraKey, err := NewSigningKey()
	if err != nil {
		t.Fatalf("failed to create key for testing: %v", err)
	}

	// try to verify with wrong root key
	if doc2.VerifySignatures(&extraKey.PublicKey) {
		t.Fatal("doc shouldn't verify")
	}

	// try to modify a predicate
	modifiedPredicate := []byte("modified")
	doc2.Predicates[1] = modifiedPredicate
	if doc2.VerifySignatures(&initialKey.PublicKey) {
		t.Fatal("doc shouldn't verify")
	}

	// try to modify the signature too
	modifiedSignature, err := Sign(modifiedPredicate, extraKey)
	if err != nil {
		t.Fatalf("failed to sign: %v", err)
	}
	doc2.PredicateSignatures[1] = modifiedSignature
	if doc2.VerifySignatures(&initialKey.PublicKey) {
		t.Fatal("doc shouldn't verify")
	}

	// try to swap out the verification key too
	doc2.VerificationKeys[1] = &extraKey.PublicKey
	if doc2.VerifySignatures(&initialKey.PublicKey) {
		t.Fatal("doc shouldn't verify")
	}

	// try to add a predicate without the correct extension key
	doc1.ExtensionKey = extraKey
	evilDoc, err := Extend(doc1, LocalPredicate("evil_predicate"))
	if err != nil {
		t.Fatalf("failed to extend doc: %v", err)
	}
	if evilDoc.VerifySignatures(&initialKey.PublicKey) {
		t.Fatal("doc shouldn't verify")
	}

	// try to extend a doc without an extension key
	doc.ExtensionKey = nil
	_, err = Extend(doc, LocalPredicate("nope"))
	if err == nil {
		t.Fatalf("extend should have failed")
	}
}
