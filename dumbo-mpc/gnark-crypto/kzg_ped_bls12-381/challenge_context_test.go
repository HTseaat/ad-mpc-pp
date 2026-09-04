package main

import (
	"encoding/json"
	"math/big"
	"testing"

	curve "github.com/consensys/gnark-crypto/ecc/bls12-381"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr/kzg_ped"
)

func challengeTestSRS(t *testing.T, alpha int64) *kzg_ped.SRS {
	t.Helper()
	srs, err := kzg_ped.NewSRS(8, big.NewInt(alpha))
	if err != nil {
		t.Fatal(err)
	}
	delta := big.NewInt(7)
	for index := range srs.Pk.G1_h {
		srs.Pk.G1_h[index].ScalarMultiplication(&srs.Pk.G1_g[index], delta)
	}
	srs.Vk.G1_h.ScalarMultiplication(&srs.Vk.G1_g, delta)
	return srs
}

func mustChallengeJSON(t *testing.T, value interface{}) []byte {
	t.Helper()
	encoded, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return encoded
}

func mustPrettyJSON(t *testing.T, input []byte) []byte {
	t.Helper()
	var presentation map[string]interface{}
	if err := json.Unmarshal(input, &presentation); err != nil {
		t.Fatal(err)
	}
	encoded, err := json.MarshalIndent(presentation, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	return encoded
}

func cloneAggEvalContext(context AggEvalChallengeContext) AggEvalChallengeContext {
	cloned := context
	cloned.OldCommitments = append([]kzg_ped.Digest(nil), context.OldCommitments...)
	cloned.NewCommitments = append([]kzg_ped.Digest(nil), context.NewCommitments...)
	return cloned
}

func cloneIPAKZGContext(context IPAKZGChallengeContext) IPAKZGChallengeContext {
	cloned := context
	cloned.LeftCommitments = append([]kzg_ped.Digest(nil), context.LeftCommitments...)
	cloned.RightCommitments = append([]kzg_ped.Digest(nil), context.RightCommitments...)
	cloned.OutputCommitments = append([]kzg_ped.Digest(nil), context.OutputCommitments...)
	cloned.LeftPedersen = append([]curve.G1Affine(nil), context.LeftPedersen...)
	cloned.RightPedersen = append([]curve.G1Affine(nil), context.RightPedersen...)
	cloned.OutputPedersen = append([]curve.G1Affine(nil), context.OutputPedersen...)
	return cloned
}

func assertChallengeChanged(t *testing.T, baseline, changed fr.Element, label string) {
	t.Helper()
	if baseline.Equal(&changed) {
		t.Fatalf("%s did not change the challenge", label)
	}
}

func TestLegacyChallengeCharacterization(t *testing.T) {
	srs := challengeTestSRS(t, 42)
	commitments := []kzg_ped.Digest{srs.Pk.G1_g[0], srs.Pk.G1_g[1]}
	challenge, err := deriveLegacyChallenge(mustChallengeJSON(t, commitments))
	if err != nil {
		t.Fatal(err)
	}
	const expected = "2392097786975479467205329552135548081814733436074882278258736819889816564658"
	if challenge.String() != expected {
		t.Fatalf("legacy challenge changed: got %s, want %s", challenge.String(), expected)
	}
}

func TestAggEvalChallengeCanonicalAndBinding(t *testing.T) {
	srs := challengeTestSRS(t, 42)
	pkJSON := mustChallengeJSON(t, &srs.Pk)
	vkJSON := mustChallengeJSON(t, &srs.Vk)
	context := AggEvalChallengeContext{
		Version:        challengeContextVersion,
		Domain:         aggEvalDomain,
		OldPoint:       "1", // dealer_local_id=0 -> Shamir evaluation point 1
		FreshPoint:     "0",
		OldCommitments: []kzg_ped.Digest{srs.Pk.G1_g[0], srs.Pk.G1_g[1], srs.Pk.G1_g[2]},
		NewCommitments: []kzg_ped.Digest{srs.Pk.G1_h[0], srs.Pk.G1_h[1], srs.Pk.G1_h[2]},
	}
	contextJSON := mustChallengeJSON(t, context)
	baseline, err := deriveAggEvalChallenge(pkJSON, vkJSON, contextJSON)
	if err != nil {
		t.Fatal(err)
	}
	repeated, err := deriveAggEvalChallenge(pkJSON, vkJSON, contextJSON)
	if err != nil || !baseline.Equal(&repeated) {
		t.Fatalf("same AggEval context was not reproducible: %v", err)
	}
	presentedDifferently, err := deriveAggEvalChallenge(
		mustPrettyJSON(t, pkJSON), mustPrettyJSON(t, vkJSON), mustPrettyJSON(t, contextJSON),
	)
	if err != nil || !baseline.Equal(&presentedDifferently) {
		t.Fatalf("JSON presentation changed AggEval challenge: %v", err)
	}

	mutations := []struct {
		name   string
		mutate func(*AggEvalChallengeContext)
	}{
		{"old point", func(value *AggEvalChallengeContext) { value.OldPoint = "2" }},
		{"fresh point", func(value *AggEvalChallengeContext) { value.FreshPoint = "3" }},
		{"old commitment", func(value *AggEvalChallengeContext) { value.OldCommitments[0] = srs.Pk.G1_g[4] }},
		{"new commitment", func(value *AggEvalChallengeContext) { value.NewCommitments[0] = srs.Pk.G1_h[4] }},
		{"old vector order", func(value *AggEvalChallengeContext) {
			value.OldCommitments[0], value.OldCommitments[1] = value.OldCommitments[1], value.OldCommitments[0]
		}},
		{"batch length", func(value *AggEvalChallengeContext) {
			value.OldCommitments = value.OldCommitments[:2]
			value.NewCommitments = value.NewCommitments[:2]
		}},
	}
	for _, mutation := range mutations {
		t.Run(mutation.name, func(t *testing.T) {
			changedContext := cloneAggEvalContext(context)
			mutation.mutate(&changedContext)
			changed, err := deriveAggEvalChallenge(pkJSON, vkJSON, mustChallengeJSON(t, changedContext))
			if err != nil {
				t.Fatal(err)
			}
			assertChallengeChanged(t, baseline, changed, mutation.name)
		})
	}

	otherSRS := challengeTestSRS(t, 43)
	changedSP, err := deriveAggEvalChallenge(
		mustChallengeJSON(t, &otherSRS.Pk), mustChallengeJSON(t, &otherSRS.Vk), contextJSON,
	)
	if err != nil {
		t.Fatal(err)
	}
	assertChallengeChanged(t, baseline, changedSP, "public parameters")

	invalidDomain := cloneAggEvalContext(context)
	invalidDomain.Domain = ipaKZGDomain
	if _, err := deriveAggEvalChallenge(pkJSON, vkJSON, mustChallengeJSON(t, invalidDomain)); err == nil {
		t.Fatal("AggEval API accepted a cross-protocol domain")
	}
	invalidVersion := cloneAggEvalContext(context)
	invalidVersion.Version++
	if _, err := deriveAggEvalChallenge(pkJSON, vkJSON, mustChallengeJSON(t, invalidVersion)); err == nil {
		t.Fatal("AggEval API accepted an unsupported version")
	}
	mismatched := cloneAggEvalContext(context)
	mismatched.NewCommitments = mismatched.NewCommitments[:2]
	if _, err := deriveAggEvalChallenge(pkJSON, vkJSON, mustChallengeJSON(t, mismatched)); err == nil {
		t.Fatal("AggEval API accepted mismatched vector lengths")
	}
}

func TestIPAKZGChallengeCanonicalAndBinding(t *testing.T) {
	srs := challengeTestSRS(t, 42)
	pkJSON := mustChallengeJSON(t, &srs.Pk)
	vkJSON := mustChallengeJSON(t, &srs.Vk)
	context := IPAKZGChallengeContext{
		Version:           challengeContextVersion,
		Domain:            ipaKZGDomain,
		LeftPoint:         "4", // dealer_local_id=3 -> Shamir evaluation point 4
		RightPoint:        "4",
		OutputPoint:       "0",
		LeftCommitments:   []kzg_ped.Digest{srs.Pk.G1_g[0], srs.Pk.G1_g[1], srs.Pk.G1_g[2]},
		RightCommitments:  []kzg_ped.Digest{srs.Pk.G1_g[1], srs.Pk.G1_g[2], srs.Pk.G1_g[3]},
		OutputCommitments: []kzg_ped.Digest{srs.Pk.G1_g[2], srs.Pk.G1_g[3], srs.Pk.G1_g[4]},
		LeftPedersen:      []curve.G1Affine{srs.Pk.G1_h[0], srs.Pk.G1_h[1], srs.Pk.G1_h[2]},
		RightPedersen:     []curve.G1Affine{srs.Pk.G1_h[1], srs.Pk.G1_h[2], srs.Pk.G1_h[3]},
		OutputPedersen:    []curve.G1Affine{srs.Pk.G1_h[2], srs.Pk.G1_h[3], srs.Pk.G1_h[4]},
	}
	contextJSON := mustChallengeJSON(t, context)
	baseline, err := deriveIPAKZGChallenge(pkJSON, vkJSON, contextJSON)
	if err != nil {
		t.Fatal(err)
	}
	repeated, err := deriveIPAKZGChallenge(pkJSON, vkJSON, contextJSON)
	if err != nil || !baseline.Equal(&repeated) {
		t.Fatalf("same IPAKZG context was not reproducible: %v", err)
	}
	presentedDifferently, err := deriveIPAKZGChallenge(
		mustPrettyJSON(t, pkJSON), mustPrettyJSON(t, vkJSON), mustPrettyJSON(t, contextJSON),
	)
	if err != nil || !baseline.Equal(&presentedDifferently) {
		t.Fatalf("JSON presentation changed IPAKZG challenge: %v", err)
	}

	mutations := []struct {
		name   string
		mutate func(*IPAKZGChallengeContext)
	}{
		{"left point", func(value *IPAKZGChallengeContext) { value.LeftPoint = "5" }},
		{"right point", func(value *IPAKZGChallengeContext) { value.RightPoint = "5" }},
		{"output point", func(value *IPAKZGChallengeContext) { value.OutputPoint = "1" }},
		{"left commitment", func(value *IPAKZGChallengeContext) { value.LeftCommitments[0] = srs.Pk.G1_g[5] }},
		{"right commitment", func(value *IPAKZGChallengeContext) { value.RightCommitments[0] = srs.Pk.G1_g[5] }},
		{"output commitment", func(value *IPAKZGChallengeContext) { value.OutputCommitments[0] = srs.Pk.G1_g[5] }},
		{"left Pedersen", func(value *IPAKZGChallengeContext) { value.LeftPedersen[0] = srs.Pk.G1_h[5] }},
		{"right Pedersen", func(value *IPAKZGChallengeContext) { value.RightPedersen[0] = srs.Pk.G1_h[5] }},
		{"output Pedersen", func(value *IPAKZGChallengeContext) { value.OutputPedersen[0] = srs.Pk.G1_h[5] }},
		{"vector order", func(value *IPAKZGChallengeContext) {
			value.LeftCommitments[0], value.LeftCommitments[1] = value.LeftCommitments[1], value.LeftCommitments[0]
		}},
		{"batch length", func(value *IPAKZGChallengeContext) {
			value.LeftCommitments = value.LeftCommitments[:2]
			value.RightCommitments = value.RightCommitments[:2]
			value.OutputCommitments = value.OutputCommitments[:2]
			value.LeftPedersen = value.LeftPedersen[:2]
			value.RightPedersen = value.RightPedersen[:2]
			value.OutputPedersen = value.OutputPedersen[:2]
		}},
	}
	for _, mutation := range mutations {
		t.Run(mutation.name, func(t *testing.T) {
			changedContext := cloneIPAKZGContext(context)
			mutation.mutate(&changedContext)
			changed, err := deriveIPAKZGChallenge(pkJSON, vkJSON, mustChallengeJSON(t, changedContext))
			if err != nil {
				t.Fatal(err)
			}
			assertChallengeChanged(t, baseline, changed, mutation.name)
		})
	}

	otherSRS := challengeTestSRS(t, 43)
	changedSP, err := deriveIPAKZGChallenge(
		mustChallengeJSON(t, &otherSRS.Pk), mustChallengeJSON(t, &otherSRS.Vk), contextJSON,
	)
	if err != nil {
		t.Fatal(err)
	}
	assertChallengeChanged(t, baseline, changedSP, "public parameters")

	invalidDomain := cloneIPAKZGContext(context)
	invalidDomain.Domain = aggEvalDomain
	if _, err := deriveIPAKZGChallenge(pkJSON, vkJSON, mustChallengeJSON(t, invalidDomain)); err == nil {
		t.Fatal("IPAKZG API accepted a cross-protocol domain")
	}
	mismatched := cloneIPAKZGContext(context)
	mismatched.OutputPedersen = mismatched.OutputPedersen[:2]
	if _, err := deriveIPAKZGChallenge(pkJSON, vkJSON, mustChallengeJSON(t, mismatched)); err == nil {
		t.Fatal("IPAKZG API accepted mismatched vector lengths")
	}
}

func TestChallengeContextRejectsUnknownFields(t *testing.T) {
	srs := challengeTestSRS(t, 42)
	context := AggEvalChallengeContext{
		Version: challengeContextVersion, Domain: aggEvalDomain,
		OldPoint: "1", FreshPoint: "0",
		OldCommitments: []kzg_ped.Digest{srs.Pk.G1_g[0], srs.Pk.G1_g[1]},
		NewCommitments: []kzg_ped.Digest{srs.Pk.G1_h[0], srs.Pk.G1_h[1]},
	}
	var withUnknown map[string]interface{}
	if err := json.Unmarshal(mustChallengeJSON(t, context), &withUnknown); err != nil {
		t.Fatal(err)
	}
	withUnknown["dealer_id"] = 0
	if _, err := deriveAggEvalChallenge(
		mustChallengeJSON(t, &srs.Pk), mustChallengeJSON(t, &srs.Vk), mustChallengeJSON(t, withUnknown),
	); err == nil {
		t.Fatal("typed context accepted an unknown field")
	}
}
