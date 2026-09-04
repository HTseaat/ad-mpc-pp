// Standalone stage-8 compatibility test for Continuum's actual kzg_ped package.
// Run through trusted_setup.kzg_smoke so the Python side first validates the
// canonical stage-6 digest.
package main

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"

	curve "github.com/consensys/gnark-crypto/ecc/bls12-381"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr/kzg_ped"
)

type serializedSRS struct {
	Format          string   `json:"format"`
	Curve           string   `json:"curve"`
	N               int      `json:"n"`
	T               int      `json:"t"`
	RequestedPowers int      `json:"requested_powers"`
	EffectivePowers int      `json:"effective_powers"`
	RunID           string   `json:"run_id"`
	G1G             []string `json:"g1_g"`
	G1H             []string `json:"g1_h"`
	G2              string   `json:"g2"`
	AlphaG2         string   `json:"alpha_g2"`
	Digest          string   `json:"digest"`
}

type smokeResult struct {
	Package                  string `json:"package"`
	CommitOpenVerify         bool   `json:"commit_open_verify"`
	TamperedValueRejected    bool   `json:"tampered_value_rejected"`
	TamperedProofRejected    bool   `json:"tampered_proof_rejected"`
	TamperedCRSRejected      bool   `json:"tampered_crs_rejected"`
	RequestedPowers          int    `json:"requested_powers"`
	PolynomialCoefficientNum int    `json:"polynomial_coefficient_count"`
	OK                       bool   `json:"ok"`
}

func fatalf(format string, args ...interface{}) {
	fmt.Fprintf(os.Stderr, format+"\n", args...)
	os.Exit(1)
}

func decodeBytes(value string, expected int, label string) []byte {
	decoded, err := base64.StdEncoding.DecodeString(value)
	if err != nil || len(decoded) != expected {
		fatalf("invalid %s encoding", label)
	}
	return decoded
}

func decodeG1(value string, label string) curve.G1Affine {
	var point curve.G1Affine
	decoded := decodeBytes(value, curve.SizeOfG1AffineCompressed, label)
	consumed, err := point.SetBytes(decoded)
	if err != nil || consumed != len(decoded) {
		fatalf("invalid or non-subgroup %s point: %v", label, err)
	}
	return point
}

func decodeG2(value string, label string) curve.G2Affine {
	var point curve.G2Affine
	decoded := decodeBytes(value, curve.SizeOfG2AffineCompressed, label)
	consumed, err := point.SetBytes(decoded)
	if err != nil || consumed != len(decoded) {
		fatalf("invalid or non-subgroup %s point: %v", label, err)
	}
	return point
}

func main() {
	if len(os.Args) != 3 || os.Args[1] != "--srs" {
		fatalf("usage: continuum_kzg_smoke --srs PATH")
	}
	srsPath := os.Args[2]

	input, err := os.Open(srsPath)
	if err != nil {
		fatalf("open SRS: %v", err)
	}
	defer input.Close()
	decoder := json.NewDecoder(input)
	decoder.DisallowUnknownFields()
	var encoded serializedSRS
	if err := decoder.Decode(&encoded); err != nil {
		fatalf("decode SRS: %v", err)
	}
	if encoded.Format != "continuum-kzg-srs-v1" || encoded.Curve != "BLS12-381" {
		fatalf("unsupported SRS format or curve")
	}
	if encoded.RequestedPowers < encoded.T+1 || len(encoded.G1G) != encoded.RequestedPowers || len(encoded.G1H) != encoded.RequestedPowers {
		fatalf("invalid SRS chain length")
	}

	var srs kzg_ped.SRS
	srs.Pk.G1_g = make([]curve.G1Affine, encoded.RequestedPowers)
	srs.Pk.G1_h = make([]curve.G1Affine, encoded.RequestedPowers)
	for i := 0; i < encoded.RequestedPowers; i++ {
		srs.Pk.G1_g[i] = decodeG1(encoded.G1G[i], fmt.Sprintf("g1_g[%d]", i))
		srs.Pk.G1_h[i] = decodeG1(encoded.G1H[i], fmt.Sprintf("g1_h[%d]", i))
	}
	srs.Vk.G1_g = srs.Pk.G1_g[0]
	srs.Vk.G1_h = srs.Pk.G1_h[0]
	srs.Vk.G2[0] = decodeG2(encoded.G2, "g2")
	srs.Vk.G2[1] = decodeG2(encoded.AlphaG2, "alpha_g2")

	coefficientCount := encoded.T + 1
	p := make([]fr.Element, coefficientCount)
	pAux := make([]fr.Element, coefficientCount)
	for i := 0; i < coefficientCount; i++ {
		p[i].SetUint64(uint64(i + 2))
		pAux[i].SetUint64(uint64(3*i + 5))
	}
	var point fr.Element
	point.SetUint64(17)
	commitment, err := kzg_ped.Commit(p, pAux, srs.Pk)
	if err != nil {
		fatalf("Continuum kzg_ped.Commit failed: %v", err)
	}
	proof, err := kzg_ped.Open(p, pAux, point, srs.Pk)
	if err != nil {
		fatalf("Continuum kzg_ped.Open failed: %v", err)
	}
	honestOK := kzg_ped.Verify(&commitment, &proof, point, srs.Vk)

	badValue := proof
	var one fr.Element
	one.SetUint64(1)
	badValue.ClaimedValue.Add(&badValue.ClaimedValue, &one)
	valueRejected := !kzg_ped.Verify(&commitment, &badValue, point, srs.Vk)

	badProof := proof
	badProof.H.Add(&proof.H, &srs.Pk.G1_g[0])
	proofRejected := !kzg_ped.Verify(&commitment, &badProof, point, srs.Vk)

	badVK := srs.Vk
	badVK.G2[1].Add(&srs.Vk.G2[1], &srs.Vk.G2[0])
	crsRejected := !kzg_ped.Verify(&commitment, &proof, point, badVK)

	result := smokeResult{
		Package:                  "github.com/consensys/gnark-crypto/ecc/bls12-381/fr/kzg_ped",
		CommitOpenVerify:         honestOK,
		TamperedValueRejected:    valueRejected,
		TamperedProofRejected:    proofRejected,
		TamperedCRSRejected:      crsRejected,
		RequestedPowers:          encoded.RequestedPowers,
		PolynomialCoefficientNum: coefficientCount,
		OK:                       honestOK && valueRejected && proofRejected && crsRejected,
	}
	output, err := json.Marshal(result)
	if err != nil {
		fatalf("encode result: %v", err)
	}
	fmt.Println(string(output))
	if !result.OK {
		os.Exit(1)
	}
}
