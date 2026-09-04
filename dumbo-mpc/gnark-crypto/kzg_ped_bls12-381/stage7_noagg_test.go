package main

import (
	"math/big"
	"testing"

	curve "github.com/consensys/gnark-crypto/ecc/bls12-381"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
)

func TestNoAggCombinedPedersenMatchesSplitHonestVerification(t *testing.T) {
	fixture := makeIPAKZGFixture(t, 3)
	relation := fixture.left
	witnesses := make([]curve.G1Affine, len(relation.openings))
	splitProofs := make([]OpeningProofPub, len(relation.openings))
	for index, opening := range relation.openings {
		value, err := parseCanonicalFieldScalar(
			opening.ClaimedValue, "test value",
		)
		if err != nil {
			t.Fatal(err)
		}
		valueAux, err := parseCanonicalFieldScalar(
			opening.ClaimedValueAux, "test auxiliary value",
		)
		if err != nil {
			t.Fatal(err)
		}
		var valueBig, valueAuxBig big.Int
		value.BigInt(&valueBig)
		valueAux.BigInt(&valueAuxBig)
		var shareG, shareH curve.G1Affine
		shareG.ScalarMultiplication(
			&fixture.parameters.VerifyingKey.G1_g, &valueBig,
		)
		shareH.ScalarMultiplication(
			&fixture.parameters.VerifyingKey.G1_h, &valueAuxBig,
		)
		witnesses[index] = opening.H
		splitProofs[index] = OpeningProofPub{
			H: opening.H, GClaim: shareG, HClaim: shareH,
		}
	}

	var point fr.Element
	point.SetInt64(int64(relation.point))
	if !BatchVerifyPub(
		relation.commitments, splitProofs, point,
		fixture.parameters.VerifyingKey,
	) {
		t.Fatal("split G/H honest verification failed")
	}
	valid, err := BatchVerifyPubCombined(
		relation.commitments, witnesses, relation.pedersen, point,
		fixture.parameters.VerifyingKey,
	)
	if err != nil || !valid {
		t.Fatalf("combined-Ped honest verification failed: %v", err)
	}
	valid, err = BatchVerifyPubCombinedUnbatched(
		relation.commitments, witnesses, relation.pedersen, point,
		fixture.parameters.VerifyingKey,
	)
	if err != nil || !valid {
		t.Fatalf("unbatched combined-Ped honest verification failed: %v", err)
	}
}
