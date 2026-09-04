package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"strconv"
	"testing"

	curve "github.com/consensys/gnark-crypto/ecc/bls12-381"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr/kzg_ped"
)

type aggEvalFixture struct {
	parameters  parsedPublicParameters
	context     AggEvalChallengeContext
	contextJSON []byte
	oldCom      []curve.G1Affine
	newCom      []curve.G1Affine
	oldOpenings []aggOpeningWire
	newOpenings []aggOpeningWire
}

type ipaRelationFixture struct {
	commitments []curve.G1Affine
	pedersen    []curve.G1Affine
	openings    []aggOpeningWire
	point       int
}

type ipaKZGFixture struct {
	parameters  parsedPublicParameters
	context     IPAKZGChallengeContext
	contextJSON []byte
	left        ipaRelationFixture
	right       ipaRelationFixture
	output      ipaRelationFixture
}

type failingRandomReader struct{}

func (failingRandomReader) Read([]byte) (int, error) {
	return 0, errors.New("injected randomness failure")
}

func testScalar(value int64) fr.Element {
	var result fr.Element
	result.SetInt64(value)
	return result
}

func testParameters(t *testing.T, srs *kzg_ped.SRS) parsedPublicParameters {
	t.Helper()
	parameters, err := parsePublicParameters(
		mustChallengeJSON(t, &srs.Pk), mustChallengeJSON(t, &srs.Vk),
	)
	if err != nil {
		t.Fatal(err)
	}
	return parameters
}

func openingToWire(proof kzg_ped.OpeningProof) aggOpeningWire {
	return aggOpeningWire{
		H:               proof.H,
		ClaimedValue:    canonicalFieldString(&proof.ClaimedValue),
		ClaimedValueAux: canonicalFieldString(&proof.ClaimedValueAux),
	}
}

func nonzeroTestRandomness() *bytes.Reader {
	// crypto/rand.Int consumes 32 big-endian bytes for this scalar field.  Each
	// block below encodes a small, non-zero integer and is always below Fr's
	// modulus, so the test is deterministic without exercising rejection.
	blockOne := make([]byte, 32)
	blockOne[31] = 1
	blockTwo := make([]byte, 32)
	blockTwo[31] = 2
	return bytes.NewReader(append(blockOne, blockTwo...))
}

func makeAggEvalFixture(t *testing.T, batchSize int) aggEvalFixture {
	t.Helper()
	srs := challengeTestSRS(t, 42)
	fixture := aggEvalFixture{
		parameters:  testParameters(t, srs),
		oldCom:      make([]curve.G1Affine, batchSize),
		newCom:      make([]curve.G1Affine, batchSize),
		oldOpenings: make([]aggOpeningWire, batchSize),
		newOpenings: make([]aggOpeningWire, batchSize),
	}
	oldPoint := testScalar(1)
	newPoint := testScalar(0)
	for index := 0; index < batchSize; index++ {
		value := testScalar(int64(10 + index))
		valueAux := testScalar(int64(30 + index))
		oldSlope := testScalar(int64(3 + index))
		oldSlopeAux := testScalar(int64(5 + index))
		newSlope := testScalar(int64(7 + index))
		newSlopeAux := testScalar(int64(11 + index))
		var oldConstant, oldConstantAux fr.Element
		oldConstant.Sub(&value, &oldSlope)
		oldConstantAux.Sub(&valueAux, &oldSlopeAux)
		oldPolynomial := []fr.Element{oldConstant, oldSlope}
		oldPolynomialAux := []fr.Element{oldConstantAux, oldSlopeAux}
		newPolynomial := []fr.Element{value, newSlope}
		newPolynomialAux := []fr.Element{valueAux, newSlopeAux}

		oldCommitment, err := kzg_ped.Commit(oldPolynomial, oldPolynomialAux, srs.Pk)
		if err != nil {
			t.Fatal(err)
		}
		newCommitment, err := kzg_ped.Commit(newPolynomial, newPolynomialAux, srs.Pk)
		if err != nil {
			t.Fatal(err)
		}
		oldProof, err := kzg_ped.Open(oldPolynomial, oldPolynomialAux, oldPoint, srs.Pk)
		if err != nil {
			t.Fatal(err)
		}
		newProof, err := kzg_ped.Open(newPolynomial, newPolynomialAux, newPoint, srs.Pk)
		if err != nil {
			t.Fatal(err)
		}
		fixture.oldCom[index] = oldCommitment
		fixture.newCom[index] = newCommitment
		fixture.oldOpenings[index] = openingToWire(oldProof)
		fixture.newOpenings[index] = openingToWire(newProof)
	}
	fixture.context = AggEvalChallengeContext{
		Version:        challengeContextVersion,
		Domain:         aggEvalDomain,
		OldPoint:       "1",
		FreshPoint:     "0",
		OldCommitments: fixture.oldCom,
		NewCommitments: fixture.newCom,
	}
	fixture.contextJSON = mustChallengeJSON(t, fixture.context)
	return fixture
}

func makeIPARelation(
	t *testing.T,
	srs *kzg_ped.SRS,
	batchSize int,
	point int,
	valueOffset int64,
) ipaRelationFixture {
	t.Helper()
	relation := ipaRelationFixture{
		commitments: make([]curve.G1Affine, batchSize),
		pedersen:    make([]curve.G1Affine, batchSize),
		openings:    make([]aggOpeningWire, batchSize),
		point:       point,
	}
	fieldPoint := testScalar(int64(point))
	for index := 0; index < batchSize; index++ {
		value := testScalar(valueOffset + int64(index))
		valueAux := testScalar(valueOffset + 20 + int64(index))
		slope := testScalar(valueOffset + 3 + int64(index))
		slopeAux := testScalar(valueOffset + 7 + int64(index))
		var pointSlope, pointSlopeAux, constant, constantAux fr.Element
		pointSlope.Mul(&fieldPoint, &slope)
		pointSlopeAux.Mul(&fieldPoint, &slopeAux)
		constant.Sub(&value, &pointSlope)
		constantAux.Sub(&valueAux, &pointSlopeAux)
		polynomial := []fr.Element{constant, slope}
		polynomialAux := []fr.Element{constantAux, slopeAux}
		commitment, err := kzg_ped.Commit(polynomial, polynomialAux, srs.Pk)
		if err != nil {
			t.Fatal(err)
		}
		proof, err := kzg_ped.Open(polynomial, polynomialAux, fieldPoint, srs.Pk)
		if err != nil {
			t.Fatal(err)
		}
		pedersen, err := pedersenCommitment(
			&srs.Vk.G1_g, &srs.Vk.G1_h, &proof.ClaimedValue, &proof.ClaimedValueAux,
		)
		if err != nil {
			t.Fatal(err)
		}
		relation.commitments[index] = commitment
		relation.pedersen[index] = pedersen
		relation.openings[index] = openingToWire(proof)
	}
	return relation
}

func makeIPAKZGFixture(t *testing.T, batchSize int) ipaKZGFixture {
	t.Helper()
	srs := challengeTestSRS(t, 42)
	fixture := ipaKZGFixture{
		parameters: testParameters(t, srs),
		left:       makeIPARelation(t, srs, batchSize, 4, 10),
		right:      makeIPARelation(t, srs, batchSize, 4, 50),
		output:     makeIPARelation(t, srs, batchSize, 0, 90),
	}
	fixture.context = IPAKZGChallengeContext{
		Version:           challengeContextVersion,
		Domain:            ipaKZGDomain,
		LeftPoint:         "4",
		RightPoint:        "4",
		OutputPoint:       "0",
		LeftCommitments:   fixture.left.commitments,
		RightCommitments:  fixture.right.commitments,
		OutputCommitments: fixture.output.commitments,
		LeftPedersen:      fixture.left.pedersen,
		RightPedersen:     fixture.right.pedersen,
		OutputPedersen:    fixture.output.pedersen,
	}
	fixture.contextJSON = mustChallengeJSON(t, fixture.context)
	return fixture
}

func aggregateRelationWitness(
	t *testing.T,
	relation ipaRelationFixture,
	challenge fr.Element,
) curve.G1Affine {
	t.Helper()
	witness, _, _, err := aggregateOpeningVector(relation.openings, challenge)
	if err != nil {
		t.Fatal(err)
	}
	return witness
}

func mutateG1(point curve.G1Affine, generator curve.G1Affine) curve.G1Affine {
	var mutated curve.G1Affine
	mutated.Add(&point, &generator)
	return mutated
}

func TestPokPedCompletenessAndBinding(t *testing.T) {
	fixture := makeAggEvalFixture(t, 3)
	context, err := parseAggEvalContext(fixture.parameters.Digest, fixture.contextJSON)
	if err != nil {
		t.Fatal(err)
	}
	challenge := hashCanonicalChallenge(bytes.NewBuffer(context.Canonical))
	_, value, valueAux, err := aggregateOpeningVector(fixture.oldOpenings, challenge)
	if err != nil {
		t.Fatal(err)
	}
	statement, err := pedersenCommitment(
		&fixture.parameters.VerifyingKey.G1_g, &fixture.parameters.VerifyingKey.G1_h,
		&value, &valueAux,
	)
	if err != nil {
		t.Fatal(err)
	}
	proof, err := pokPedProveWithReader(
		fixture.parameters, context, statement, value, valueAux, nonzeroTestRandomness(),
	)
	if err != nil {
		t.Fatal(err)
	}
	if !pokPedVerify(fixture.parameters, context, statement, proof) {
		t.Fatal("honest pokPed proof was rejected")
	}
	announcementBytes := proof.A.Bytes()
	zBytes := proof.Z.Bytes()
	zHatBytes := proof.ZHat.Bytes()
	if size := len(announcementBytes) + len(zBytes) + len(zHatBytes); size != 112 {
		t.Fatalf("unexpected compressed pokPed size: got %d, want 112", size)
	}

	generator := fixture.parameters.VerifyingKey.G1_g
	mutatedStatement := mutateG1(statement, generator)
	if pokPedVerify(fixture.parameters, context, mutatedStatement, proof) {
		t.Fatal("pokPed accepted a mutated T")
	}
	mutatedA := proof
	mutatedA.A = mutateG1(mutatedA.A, generator)
	if pokPedVerify(fixture.parameters, context, statement, mutatedA) {
		t.Fatal("pokPed accepted a mutated A")
	}
	mutatedZ := proof
	mutatedZ.Z.Add(&mutatedZ.Z, &testScalarOne)
	if pokPedVerify(fixture.parameters, context, statement, mutatedZ) {
		t.Fatal("pokPed accepted a mutated z")
	}
	mutatedZHat := proof
	mutatedZHat.ZHat.Add(&mutatedZHat.ZHat, &testScalarOne)
	if pokPedVerify(fixture.parameters, context, statement, mutatedZHat) {
		t.Fatal("pokPed accepted a mutated z_hat")
	}

	changedContextValue := cloneAggEvalContext(fixture.context)
	changedContextValue.FreshPoint = "2"
	changedContext, err := parseAggEvalContext(
		fixture.parameters.Digest, mustChallengeJSON(t, changedContextValue),
	)
	if err != nil {
		t.Fatal(err)
	}
	if pokPedVerify(fixture.parameters, changedContext, statement, proof) {
		t.Fatal("pokPed replay succeeded under a different context")
	}

	otherParameters := testParameters(t, challengeTestSRS(t, 43))
	otherContext, err := parseAggEvalContext(otherParameters.Digest, fixture.contextJSON)
	if err != nil {
		t.Fatal(err)
	}
	if pokPedVerify(otherParameters, otherContext, statement, proof) {
		t.Fatal("pokPed accepted a proof under different public parameters")
	}

	if _, err := pokPedProveWithReader(
		fixture.parameters, context, statement, value, valueAux, failingRandomReader{},
	); err == nil {
		t.Fatal("pokPed ignored a randomness-source failure")
	}
	badValue := value
	badValue.Add(&badValue, &testScalarOne)
	if _, err := pokPedProveWithReader(
		fixture.parameters, context, statement, badValue, valueAux, nonzeroTestRandomness(),
	); err == nil {
		t.Fatal("pokPed prover accepted a witness that does not open T")
	}
}

var testScalarOne = testScalar(1)

func TestAggPubEvalOldAndFreshRelations(t *testing.T) {
	for _, batchSize := range []int{1, 3} {
		t.Run("batch_"+strconv.Itoa(batchSize), func(t *testing.T) {
			fixture := makeAggEvalFixture(t, batchSize)
			oldProof, err := aggPubProEvalWithReader(
				fixture.parameters, fixture.contextJSON, fixture.oldCom,
				fixture.oldOpenings, 1, nonzeroTestRandomness(),
			)
			if err != nil {
				t.Fatal(err)
			}
			if !aggPubVerEval(
				fixture.parameters, fixture.contextJSON, fixture.oldCom, 1,
				oldProof.T, oldProof.W, oldProof.PokPed,
			) {
				t.Fatal("AggPubVerEval rejected the honest old-anchor relation")
			}
			newProof, err := aggPubProEvalWithReader(
				fixture.parameters, fixture.contextJSON, fixture.newCom,
				fixture.newOpenings, 0, nonzeroTestRandomness(),
			)
			if err != nil {
				t.Fatal(err)
			}
			if !oldProof.T.Equal(&newProof.T) {
				t.Fatal("old and fresh relations produced different combined claims")
			}
			// AggTrans sends one T and one pokPed.  The same pair must bind the
			// old and fresh KZG relations, while each relation keeps its own W.
			if !aggPubVerEval(
				fixture.parameters, fixture.contextJSON, fixture.newCom, 0,
				oldProof.T, newProof.W, oldProof.PokPed,
			) {
				t.Fatal("same T/context/pokPed did not verify the fresh-zero relation")
			}

			context, err := parseAggEvalContext(fixture.parameters.Digest, fixture.contextJSON)
			if err != nil {
				t.Fatal(err)
			}
			gamma := hashCanonicalChallenge(bytes.NewBuffer(context.Canonical))
			if !PubAggVerifyEvalCombined(
				fixture.parameters.VerifyingKey, fixture.oldCom, 1,
				oldProof.T, oldProof.W, gamma,
			) {
				t.Fatal("new AggPub verifier disagreed with the low-level pairing relation")
			}
		})
	}
}

func TestAggPubEvalBatch2CompletenessAndIndependentResults(t *testing.T) {
	fixture := makeAggEvalFixture(t, 3)
	proof, err := aggPubProEvalBatch2WithReader(
		fixture.parameters, fixture.contextJSON,
		fixture.oldOpenings, fixture.newOpenings, nonzeroTestRandomness(),
	)
	if err != nil {
		t.Fatal(err)
	}
	result, err := aggPubVerEvalBatch2(
		fixture.parameters, fixture.contextJSON, proof.T,
		proof.WOld, proof.WNew, proof.PokPed,
	)
	if err != nil || result != aggTransPokPedValidMask|aggTransFreshValidMask|aggTransOldValidMask {
		t.Fatalf("batched AggPub verifier rejected honest proof: mask=%d err=%v", result, err)
	}

	mutatedOld := mutateG1(proof.WOld, fixture.parameters.VerifyingKey.G1_g)
	result, err = aggPubVerEvalBatch2(
		fixture.parameters, fixture.contextJSON, proof.T,
		mutatedOld, proof.WNew, proof.PokPed,
	)
	if err != nil || result != aggTransPokPedValidMask|aggTransFreshValidMask {
		t.Fatalf("old-witness mutation changed unrelated results: mask=%d err=%v", result, err)
	}

	mutatedPok := proof.PokPed
	mutatedPok.Z.Add(&mutatedPok.Z, &testScalarOne)
	result, err = aggPubVerEvalBatch2(
		fixture.parameters, fixture.contextJSON, proof.T,
		proof.WOld, proof.WNew, mutatedPok,
	)
	if err != nil || result != aggTransFreshValidMask|aggTransOldValidMask {
		t.Fatalf("pokPed mutation changed KZG results: mask=%d err=%v", result, err)
	}
}

func TestAggPubEvalRejectsTamperingAndMalformedInputs(t *testing.T) {
	fixture := makeAggEvalFixture(t, 3)
	proof, err := aggPubProEvalWithReader(
		fixture.parameters, fixture.contextJSON, fixture.oldCom,
		fixture.oldOpenings, 1, nonzeroTestRandomness(),
	)
	if err != nil {
		t.Fatal(err)
	}
	generator := fixture.parameters.VerifyingKey.G1_g
	mutatedT := mutateG1(proof.T, generator)
	if aggPubVerEval(fixture.parameters, fixture.contextJSON, fixture.oldCom, 1, mutatedT, proof.W, proof.PokPed) {
		t.Fatal("AggPubVerEval accepted a mutated T")
	}
	mutatedW := mutateG1(proof.W, generator)
	if aggPubVerEval(fixture.parameters, fixture.contextJSON, fixture.oldCom, 1, proof.T, mutatedW, proof.PokPed) {
		t.Fatal("AggPubVerEval accepted a mutated W")
	}
	mutatedPok := proof.PokPed
	mutatedPok.Z.Add(&mutatedPok.Z, &testScalarOne)
	if aggPubVerEval(fixture.parameters, fixture.contextJSON, fixture.oldCom, 1, proof.T, proof.W, mutatedPok) {
		t.Fatal("AggPubVerEval accepted a mutated pokPed")
	}
	mutatedCommitments := append([]curve.G1Affine(nil), fixture.oldCom...)
	mutatedCommitments[0] = mutateG1(mutatedCommitments[0], generator)
	if aggPubVerEval(fixture.parameters, fixture.contextJSON, mutatedCommitments, 1, proof.T, proof.W, proof.PokPed) {
		t.Fatal("AggPubVerEval accepted commitments outside the context")
	}
	if aggPubVerEval(fixture.parameters, fixture.contextJSON, fixture.oldCom, 2, proof.T, proof.W, proof.PokPed) {
		t.Fatal("AggPubVerEval accepted an evaluation point outside the context")
	}
	changedContext := cloneAggEvalContext(fixture.context)
	changedContext.FreshPoint = "2"
	if aggPubVerEval(
		fixture.parameters, mustChallengeJSON(t, changedContext), fixture.oldCom, 1,
		proof.T, proof.W, proof.PokPed,
	) {
		t.Fatal("AggPubVerEval accepted replay under a changed context")
	}
	if _, err := aggPubProEvalWithReader(
		fixture.parameters, fixture.contextJSON, nil, nil, 1, nonzeroTestRandomness(),
	); err == nil {
		t.Fatal("AggPubProEval accepted empty vectors")
	}
	if _, err := aggPubProEvalWithReader(
		fixture.parameters, fixture.contextJSON, fixture.oldCom[:2],
		fixture.oldOpenings, 1, nonzeroTestRandomness(),
	); err == nil {
		t.Fatal("AggPubProEval accepted mismatched vectors")
	}
	nonCanonical := append([]aggOpeningWire(nil), fixture.oldOpenings...)
	nonCanonical[0].ClaimedValue = "01"
	if _, err := aggPubProEvalWithReader(
		fixture.parameters, fixture.contextJSON, fixture.oldCom,
		nonCanonical, 1, nonzeroTestRandomness(),
	); err == nil {
		t.Fatal("AggPubProEval accepted a non-canonical scalar")
	}
	unknownFieldContext := append(fixture.contextJSON[:len(fixture.contextJSON)-1], []byte(`,"unknown":1}`)...)
	if aggPubVerEval(
		fixture.parameters, unknownFieldContext, fixture.oldCom, 1,
		proof.T, proof.W, proof.PokPed,
	) {
		t.Fatal("AggPubVerEval accepted an unknown context field")
	}
}

func TestAggPedVerEvalAllRelationsAndLowLevelEquivalence(t *testing.T) {
	for _, batchSize := range []int{1, 3} {
		t.Run("batch_"+strconv.Itoa(batchSize), func(t *testing.T) {
			fixture := makeIPAKZGFixture(t, batchSize)
			context, err := parseIPAKZGContext(fixture.parameters.Digest, fixture.contextJSON)
			if err != nil {
				t.Fatal(err)
			}
			gamma := hashCanonicalChallenge(bytes.NewBuffer(context.Canonical))
			for name, relation := range map[string]ipaRelationFixture{
				"left": fixture.left, "right": fixture.right, "output": fixture.output,
			} {
				t.Run(name, func(t *testing.T) {
					witness := aggregateRelationWitness(t, relation, gamma)
					valid, err := aggPedVerEval(
						fixture.parameters, fixture.contextJSON, relation.commitments,
						relation.pedersen, relation.point, witness,
					)
					if err != nil || !valid {
						t.Fatalf("AggPedVerEval rejected honest %s relation: %v", name, err)
					}
					coefficients, err := challengePowers(gamma, batchSize)
					if err != nil {
						t.Fatal(err)
					}
					statement, err := aggregateG1(relation.pedersen, coefficients, "test Pedersen")
					if err != nil {
						t.Fatal(err)
					}
					if !PubAggVerifyEvalCombined(
						fixture.parameters.VerifyingKey, relation.commitments, relation.point,
						statement, witness, gamma,
					) {
						t.Fatal("AggPedVerEval disagreed with the low-level pairing relation")
					}
				})
			}
		})
	}
}

func TestAggPedVerEvalBatch3CompletenessAndIndependentResults(t *testing.T) {
	fixture := makeIPAKZGFixture(t, 3)
	context, err := parseIPAKZGContext(fixture.parameters.Digest, fixture.contextJSON)
	if err != nil {
		t.Fatal(err)
	}
	challenge := hashCanonicalChallenge(bytes.NewBuffer(context.Canonical))
	leftWitness := aggregateRelationWitness(t, fixture.left, challenge)
	rightWitness := aggregateRelationWitness(t, fixture.right, challenge)
	outputWitness := aggregateRelationWitness(t, fixture.output, challenge)
	result, err := aggPedVerEvalBatch3(
		fixture.parameters, fixture.contextJSON,
		leftWitness, rightWitness, outputWitness,
	)
	if err != nil || result != ipaKZGLeftValidMask|ipaKZGRightValidMask|ipaKZGOutputValidMask {
		t.Fatalf("batched AggPed verifier rejected honest proof: mask=%d err=%v", result, err)
	}

	mutatedLeft := mutateG1(leftWitness, fixture.parameters.VerifyingKey.G1_g)
	result, err = aggPedVerEvalBatch3(
		fixture.parameters, fixture.contextJSON,
		mutatedLeft, rightWitness, outputWitness,
	)
	if err != nil || result != ipaKZGRightValidMask|ipaKZGOutputValidMask {
		t.Fatalf("left-witness mutation changed unrelated results: mask=%d err=%v", result, err)
	}

	changedContext := cloneIPAKZGContext(fixture.context)
	changedContext.RightPoint = "5"
	result, err = aggPedVerEvalBatch3(
		fixture.parameters, mustChallengeJSON(t, changedContext),
		leftWitness, rightWitness, outputWitness,
	)
	if err != nil || result != 0 {
		t.Fatalf("batched AggPed verifier accepted replay under changed ctx: mask=%d err=%v", result, err)
	}
}

func TestAggPedVerEvalRejectsTamperingAndMalformedInputs(t *testing.T) {
	fixture := makeIPAKZGFixture(t, 3)
	context, err := parseIPAKZGContext(fixture.parameters.Digest, fixture.contextJSON)
	if err != nil {
		t.Fatal(err)
	}
	gamma := hashCanonicalChallenge(bytes.NewBuffer(context.Canonical))
	witness := aggregateRelationWitness(t, fixture.left, gamma)
	generator := fixture.parameters.VerifyingKey.G1_g

	mutatedCommitments := append([]curve.G1Affine(nil), fixture.left.commitments...)
	mutatedCommitments[0] = mutateG1(mutatedCommitments[0], generator)
	valid, err := aggPedVerEval(
		fixture.parameters, fixture.contextJSON, mutatedCommitments,
		fixture.left.pedersen, fixture.left.point, witness,
	)
	if err != nil || valid {
		t.Fatalf("AggPedVerEval accepted commitments outside the context: %v", err)
	}
	mutatedPedersen := append([]curve.G1Affine(nil), fixture.left.pedersen...)
	mutatedPedersen[0] = mutateG1(mutatedPedersen[0], generator)
	valid, err = aggPedVerEval(
		fixture.parameters, fixture.contextJSON, fixture.left.commitments,
		mutatedPedersen, fixture.left.point, witness,
	)
	if err != nil || valid {
		t.Fatalf("AggPedVerEval accepted Pedersen commitments outside the context: %v", err)
	}
	mutatedWitness := mutateG1(witness, generator)
	valid, err = aggPedVerEval(
		fixture.parameters, fixture.contextJSON, fixture.left.commitments,
		fixture.left.pedersen, fixture.left.point, mutatedWitness,
	)
	if err != nil || valid {
		t.Fatalf("AggPedVerEval accepted a mutated witness: %v", err)
	}
	changedContext := cloneIPAKZGContext(fixture.context)
	changedContext.RightPoint = "5"
	valid, err = aggPedVerEval(
		fixture.parameters, mustChallengeJSON(t, changedContext), fixture.left.commitments,
		fixture.left.pedersen, fixture.left.point, witness,
	)
	if err != nil || valid {
		t.Fatalf("AggPedVerEval accepted replay under a changed context: %v", err)
	}
	if _, err := aggPedVerEval(
		fixture.parameters, fixture.contextJSON, nil, nil, fixture.left.point, witness,
	); err == nil {
		t.Fatal("AggPedVerEval accepted empty vectors")
	}
	if _, err := aggPedVerEval(
		fixture.parameters, fixture.contextJSON, fixture.left.commitments[:2],
		fixture.left.pedersen, fixture.left.point, witness,
	); err == nil {
		t.Fatal("AggPedVerEval accepted mismatched vectors")
	}
}

func TestStageThreeWireDecodersRejectMalformedValues(t *testing.T) {
	fixture := makeAggEvalFixture(t, 1)
	encodedOpenings := mustChallengeJSON(t, fixture.oldOpenings)
	decoded, err := decodeOpeningVector(encodedOpenings)
	if err != nil || len(decoded) != 1 {
		t.Fatalf("valid opening vector failed to decode: %v", err)
	}

	var presentation []map[string]interface{}
	if err := json.Unmarshal(encodedOpenings, &presentation); err != nil {
		t.Fatal(err)
	}
	presentation[0]["ClaimedValue"] = "-1"
	if _, err := decodeOpeningVector(mustChallengeJSON(t, presentation)); err == nil {
		t.Fatal("opening decoder accepted a negative scalar")
	}
	presentation[0]["ClaimedValue"] = fr.Modulus().String()
	if _, err := decodeOpeningVector(mustChallengeJSON(t, presentation)); err == nil {
		t.Fatal("opening decoder accepted a scalar equal to the modulus")
	}
	presentation[0]["ClaimedValue"] = fixture.oldOpenings[0].ClaimedValue
	presentation[0]["extra"] = true
	if _, err := decodeOpeningVector(mustChallengeJSON(t, presentation)); err == nil {
		t.Fatal("opening decoder accepted an unknown field")
	}
	if _, err := decodeOpeningVector([]byte(`[]`)); err == nil {
		t.Fatal("opening decoder accepted an empty vector")
	}
}
