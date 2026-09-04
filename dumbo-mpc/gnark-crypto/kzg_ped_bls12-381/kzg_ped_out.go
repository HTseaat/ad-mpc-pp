package main

import (
	"C"
	"bytes"
	cryptorand "crypto/rand"
	"encoding/binary"
	"encoding/json"
	"io"
	"math/big"
	"sort"

	"crypto/sha256"

	"github.com/consensys/gnark-crypto/ecc"
	curve "github.com/consensys/gnark-crypto/ecc/bls12-381"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
)
import (
	"encoding/base64"
	"fmt"
	"log"
	"os"
	"runtime"
	"sync"
	"time"

	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr/kzg_ped"
)

// OpeningProofPub represents a public KZG evaluation proof where the
// scalars f(i), f̂(i) have been hidden by exponentiating on g / h.
type OpeningProofPub struct {
	H      curve.G1Affine `json:"H"`      // witness w_i
	GClaim curve.G1Affine `json:"GClaim"` // g^{f(i)}
	HClaim curve.G1Affine `json:"HClaim"` // h^{f̂(i)}
}

// openingWitnessWire is the compact wire representation used by the NoAgg
// protocol. The evaluation claims are carried by the combined Pedersen
// commitments, so each opening only needs its KZG witness.
type openingWitnessWire struct {
	H curve.G1Affine `json:"H"`
}

var testSRS *kzg_ped.SRS
var forcedN int

//export pySetN
func pySetN(n int) {
	forcedN = n
}

func resolveN(t int) int {
	if forcedN > 0 {
		return forcedN
	}
	return 3*t + 1
}

//export pyNewSRS
func pyNewSRS(srsSize int) *C.char {
	// testSRS, _ = kzg_ped.NewSRS(ecc.NextPowerOfTwo(uint64(srsSize+1)), new(big.Int).SetInt64(42))
	// outest, _ := json.Marshal(testSRS)
	// return C.CString(string(outest))

	size := ecc.NextPowerOfTwo(uint64(srsSize + 1))
	// first seed → g‑chain
	srsG, _ := kzg_ped.NewSRS(size, new(big.Int).SetInt64(42))

	// derive h_i = δ · g_i （δ 取任意≠0, ≠1 的常数，这里用 7）
	delta := new(big.Int).SetInt64(7)
	for i := range srsG.Pk.G1_h {
		srsG.Pk.G1_h[i].ScalarMultiplication(&srsG.Pk.G1_g[i], delta)
	}
	// Vk 链首保持同样关系
	srsG.Vk.G1_h.ScalarMultiplication(&srsG.Vk.G1_g, delta)

	// // second seed → independent chain for h
	// srsH, _ := kzg_ped.NewSRS(size, new(big.Int).SetInt64(137))

	// // overwrite G1_h with the β‑chain shifted by 1
	// // note: G1_g[0] == generator^0, identical for any seed,
	// // so copy from index 1 to guarantee h ≠ g
	// for i := range srsG.Pk.G1_h {
	//     idx := (i + 1) % len(srsH.Pk.G1_g)
	//     srsG.Pk.G1_h[i].Set(&srsH.Pk.G1_g[idx])
	// }
	// // Vk part: just take β‑chain[1] to avoid clash
	// // srsG.Vk.G1_h.Set(&srsH.Vk.G1_g)

	// // use β‑chain[1] so that Vk’s h matches Pk.G1_h[0]
	// srsG.Vk.G1_h.Set(&srsH.Pk.G1_g[1])

	// Debug: show g and h to verify they differ
	fmt.Println("pyNewSRS g =", srsG.Pk.G1_g[0])
	fmt.Println("pyNewSRS Pk.G1_h =", srsG.Pk.G1_h[0])
	fmt.Println("pyNewSRS Vk.G1_h =", srsG.Vk.G1_h)
	fmt.Println("pyNewSRS g and h Equal?", srsG.Pk.G1_g[0].Equal(&srsG.Pk.G1_h[0]))
	fmt.Println("pyNewSRS Pk.G1_h and Vk.G1_h Equal?", srsG.Pk.G1_h[0].Equal(&srsG.Vk.G1_h))

	// cache for self‑test if needed
	testSRS = srsG

	out, _ := json.Marshal(srsG)
	return C.CString(string(out))
}

func KeyGenPerparty(g curve.G1Affine, n int) ([]curve.G1Affine, []byte) {

	// Generate `n` secret keys and their corresponding public keys
	secretKeys := make([]fr.Element, n)       // Array to store the secret keys
	serializedSecretKeys := make([][]byte, n) // Array to store the serialized secret keys

	// Generate random secret keys and serialize them
	for i := 0; i < n; i++ {
		secretKeys[i].SetRandom()                                // Generate a random secret key
		serializedSecretKeys[i], _ = secretKeys[i].MarshalJSON() // Serialize the secret key
	}

	// Compute the corresponding public keys using batch scalar multiplication
	publicKeys := curve.BatchScalarMultiplicationG1(&g, secretKeys) // Batch multiply to get public keys

	// Create a JSON object that maps each secret key to a base64-encoded string
	secretKeyjsonstr := make(map[string]string)
	for i, secretKey := range serializedSecretKeys {
		// Encode each serialized secret key to base64 and add to the map with its index as the key
		secretKeyjsonstr[fmt.Sprintf("%d", i)] = base64.StdEncoding.EncodeToString(secretKey)
	}

	// Convert the map to a JSON byte array
	jsonsecretKey, err := json.Marshal(secretKeyjsonstr)
	if err != nil {
		fmt.Println("Error marshaling JSON:", err)
	}

	// Return the public keys and serialized secret keys
	return publicKeys, jsonsecretKey
}

func KeyGeneration(g curve.G1Affine, n int) ([][]curve.G1Affine, [][]byte) {
	publickeys_per_party := make([][]curve.G1Affine, n)
	secretkeys_per_party := make([][]byte, n)
	for i := 0; i < n; i++ {
		publickeys_per_party[i], secretkeys_per_party[i] = KeyGenPerparty(g, n)
	}

	publickeys_per_dealer := make([][]curve.G1Affine, n)
	for dealer := 0; dealer < n; dealer++ {
		publickeys_per_dealer[dealer] = make([]curve.G1Affine, n)
		for idx := 0; idx < n; idx++ {
			publickeys_per_dealer[dealer][idx].Set(&publickeys_per_party[idx][dealer])
		}
	}
	return publickeys_per_dealer, secretkeys_per_party
}

//export pyKeyGeneration
func pyKeyGeneration(json_SRS *C.char, n int) *C.char {
	// Deserialize the SRS from JSON
	var SRS *kzg_ped.SRS
	_ = json.Unmarshal([]byte(C.GoString(json_SRS)), &SRS)
	g := SRS.Pk.G1_g[0] // Base point for key generation
	publickeys_per_dealer, secretkeys_per_party := KeyGeneration(g, n)
	// Serialize public and secret keys to JSON
	jsonpublickeys, _ := json.Marshal(publickeys_per_dealer)

	result := make(map[string]interface{})
	result["publickeys"] = string(jsonpublickeys)

	for i, secretKey := range secretkeys_per_party {
		result[fmt.Sprintf("sk_%d", i)] = string(secretKey)
	}

	jsonResult, _ := json.Marshal(result)
	// jsonsecretkeys, _ := json.Marshal(secretkeys_per_party)

	return C.CString(string(jsonResult))
}

func KeyEphemeralGen(g curve.G1Affine) ([]curve.G1Affine, []byte) {
	// Generate an ephemeral secret key
	var ephemeralsecretkey fr.Element
	ephemeralsecretkey.SetRandom()                                       // Generate a random secret key
	serialized_ephemeralsecretkey, _ := ephemeralsecretkey.MarshalJSON() // Serialize the secret key

	// Compute the corresponding ephemeral public key
	var ephemeralsecretkeyBigInt big.Int
	ephemeralsecretkey.BigInt(&ephemeralsecretkeyBigInt) // Convert to BigInt
	ephemeralpublickey := make([]curve.G1Affine, 1)
	ephemeralpublickey[0].ScalarMultiplication(&g, &ephemeralsecretkeyBigInt)

	return ephemeralpublickey, serialized_ephemeralsecretkey
}

//export pyKeyEphemeralGen
func pyKeyEphemeralGen(json_SRS_pk *C.char) *C.char {
	// Deserialize the proving key from JSON
	var Pk *kzg_ped.ProvingKey
	_ = json.Unmarshal([]byte(C.GoString(json_SRS_pk)), &Pk)
	g := Pk.G1_g[0] // Base point for ephemeral key generation
	ephemeralpublickey, serialized_ephemeralsecretkey := KeyEphemeralGen(g)
	// Serialize ephemeral public and secret keys to JSON
	jsonephemeralsecretkey, _ := json.Marshal(serialized_ephemeralsecretkey)
	jsonephemeralpublickey, _ := json.Marshal(ephemeralpublickey)
	var jsonephemeralpublicsecretsharedkey = "{\"ephemeralpublickey\":" + string(jsonephemeralpublickey) + ",\"ephemeralsecretkey\":" + string(jsonephemeralsecretkey) + "}"

	return C.CString(jsonephemeralpublicsecretsharedkey)
}

func SharedKeysGen_sender(ephemeralsecretkey fr.Element, publickey_sender curve.G1Affine) curve.G1Affine {
	// Compute the shared key (sender's perspective)
	var ephemeralsecretkeyBigInt big.Int
	ephemeralsecretkey.BigInt(&ephemeralsecretkeyBigInt) // Convert to BigInt
	var sharedkey_sender curve.G1Affine
	sharedkey_sender.ScalarMultiplication(&publickey_sender, &ephemeralsecretkeyBigInt) // Shared key computation
	return sharedkey_sender
}

//export pySharedKeysGen_sender
func pySharedKeysGen_sender(json_publickey *C.char, json_ephemeralsecretkey *C.char) *C.char {
	// Deserialize the recipient's public key from JSON
	var publickey curve.G1Affine
	_ = json.Unmarshal([]byte(C.GoString(json_publickey)), &publickey)

	// Deserialize the ephemeral secret key from JSON
	var ephemeralsecretkey fr.Element
	var ephemeralsecretkeybyte []byte
	_ = json.Unmarshal([]byte(C.GoString(json_ephemeralsecretkey)), &ephemeralsecretkeybyte)
	ephemeralsecretkey.UnmarshalJSON(ephemeralsecretkeybyte) // Restore the secret key from JSON
	sharedkey_sender := SharedKeysGen_sender(ephemeralsecretkey, publickey)

	// Serialize the shared key to JSON
	jsonsharedkey_sender, _ := json.Marshal(sharedkey_sender)
	return C.CString(string(jsonsharedkey_sender))
}

func SharedKeysGen_recv(sk fr.Element, ephemeralpublickey []curve.G1Affine) curve.G1Affine {
	// Compute the shared key using scalar multiplication
	var secretkeyBigInt big.Int
	sk.BigInt(&secretkeyBigInt)

	var sharedkey curve.G1Affine
	sharedkey.ScalarMultiplication(&ephemeralpublickey[0], &secretkeyBigInt)
	return sharedkey
}

//export pySharedKeysGen_recv
func pySharedKeysGen_recv(json_ephemeralpublickey *C.char, json_secretkey *C.char) *C.char {
	// Deserialize the ephemeral public key from JSON
	var ephemeralpublickey []curve.G1Affine
	_ = json.Unmarshal([]byte(C.GoString(json_ephemeralpublickey)), &ephemeralpublickey)

	// Deserialize the secret key from JSON
	var sk fr.Element
	var skbyte []byte
	_ = json.Unmarshal([]byte(C.GoString(json_secretkey)), &skbyte)
	sk.UnmarshalJSON(skbyte)
	sharedkey := SharedKeysGen_recv(sk, ephemeralpublickey)

	// Serialize the shared key to JSON and return
	jsonsharedkey, _ := json.Marshal(sharedkey)
	return C.CString(string(jsonsharedkey))
}

//export pySampleSecret
func pySampleSecret(batchsize int) *C.char {
	// Generate a batch of random secrets
	secret := make([]fr.Element, batchsize)
	for i := 0; i < batchsize; i++ {
		secret[i].SetRandom()
	}

	// Serialize the secrets to JSON and return
	json_secret, _ := json.Marshal(secret)
	return C.CString(string(json_secret))
}

func samplepolynomial(secret []fr.Element, batch_size int, t int) ([][]fr.Element, [][]fr.Element) {
	// Generate random polynomials and auxiliary polynomials
	polynomialList := make([][]fr.Element, 0)
	polynomialList_aux := make([][]fr.Element, 0)

	for i := 0; i < batch_size; i++ {
		f_poly := make([]fr.Element, t+1)
		f_poly_aux := make([]fr.Element, t+1)
		for j := 0; j < t+1; j++ {
			if j == 0 {
				f_poly[j].Set(&secret[i]) // Set the constant term to the secret
				f_poly_aux[j].SetRandom() // Randomize the auxiliary polynomial
			} else {
				f_poly[j].SetRandom()
				f_poly_aux[j].SetRandom()
			}
		}
		polynomialList = append(polynomialList, f_poly)
		polynomialList_aux = append(polynomialList_aux, f_poly_aux)
	}
	return polynomialList, polynomialList_aux
}

//export pyCommit
func pyCommit(json_SRS_Pk *C.char, json_secret *C.char, t int) *C.char {
	// Deserialize the proving key and secrets from JSON
	var Pk kzg_ped.ProvingKey
	_ = json.Unmarshal([]byte(C.GoString(json_SRS_Pk)), &Pk)

	var secret []fr.Element
	_ = json.Unmarshal([]byte(C.GoString(json_secret)), &secret)

	batch_size := len(secret)

	// Generate polynomials and auxiliary polynomials
	polynomialList, polynomialList_aux := samplepolynomial(secret, batch_size, t)

	// Compute commitments for each polynomial
	commitmentList := make([]kzg_ped.Digest, batch_size)

	var wg sync.WaitGroup
	for i := 0; i < batch_size; i++ {
		wg.Add(1)
		go func(index int) {
			defer wg.Done()
			commitmentList[index], _ = kzg_ped.Commit(polynomialList[index], polynomialList_aux[index], Pk)
		}(i)
	}
	wg.Wait()

	// Compute opening proofs for each polynomial
	n := resolveN(t)
	batchproofsofallparties := Batchopen(polynomialList, polynomialList_aux, n, Pk)

	// Create a result struct for commitments and proofs
	type comlistandprooflist struct {
		CommitmentList []kzg_ped.Digest         `json:"commitmentList"`
		ProofList      [][]kzg_ped.OpeningProof `json:"batchproofsofallparties"`
	}

	result := comlistandprooflist{
		CommitmentList: commitmentList,
		ProofList:      batchproofsofallparties,
	}

	// Serialize the result to JSON and return
	jsonResult, _ := json.Marshal(result)
	return C.CString(string(jsonResult))
}

func samplePolyPair(secret_f []fr.Element, secret_aux []fr.Element, batch_size int, t int) ([][]fr.Element, [][]fr.Element) {
	// Generate random polynomials and auxiliary polynomials
	polynomialList := make([][]fr.Element, 0)
	polynomialList_aux := make([][]fr.Element, 0)

	for i := 0; i < batch_size; i++ {
		f_poly := make([]fr.Element, t+1)
		f_poly_aux := make([]fr.Element, t+1)
		for j := 0; j < t+1; j++ {
			if j == 0 {
				f_poly[j].Set(&secret_f[i])       // Set constant term of main polynomial
				f_poly_aux[j].Set(&secret_aux[i]) // Set constant term of auxiliary polynomial
			} else {
				f_poly[j].SetRandom()
				f_poly_aux[j].SetRandom()
			}
		}
		polynomialList = append(polynomialList, f_poly)
		polynomialList_aux = append(polynomialList_aux, f_poly_aux)
	}
	return polynomialList, polynomialList_aux
}

//export pyPedersenCommit
func pyPedersenCommit(json_SRS_Pk *C.char, json_p *C.char, json_r *C.char) *C.char {
	// Deserialize the proving key and secrets from JSON
	var Pk kzg_ped.ProvingKey
	_ = json.Unmarshal([]byte(C.GoString(json_SRS_Pk)), &Pk)
	g := Pk.G1_g[0]
	h := Pk.G1_h[0]

	var p []fr.Element
	_ = json.Unmarshal([]byte(C.GoString(json_p)), &p)

	var r []fr.Element
	_ = json.Unmarshal([]byte(C.GoString(json_r)), &r)

	commitmentList := make([]curve.G1Affine, len(p))
	for i := 0; i < len(p); i++ {
		var gp, hr, commit curve.G1Affine
		var pBig, rBig big.Int
		p[i].BigInt(&pBig)
		r[i].BigInt(&rBig)

		gp.ScalarMultiplication(&g, &pBig)
		hr.ScalarMultiplication(&h, &rBig)
		commit.Add(&gp, &hr)
		commitmentList[i] = commit
	}
	result, _ := json.Marshal(commitmentList)
	return C.CString(string(result))
}

//export pyPedersenCombine
func pyPedersenCombine(json_gp *C.char, json_hr *C.char) *C.char {
	var gp_list, hr_list []curve.G1Affine
	if err := json.Unmarshal([]byte(C.GoString(json_gp)), &gp_list); err != nil {
		return C.CString(`{"error": "invalid gp list"}`)
	}
	if err := json.Unmarshal([]byte(C.GoString(json_hr)), &hr_list); err != nil {
		return C.CString(`{"error": "invalid hr list"}`)
	}

	if len(gp_list) != len(hr_list) {
		return C.CString(`{"error": "length mismatch"}`)
	}

	commitmentList := make([]curve.G1Affine, len(gp_list))
	for i := 0; i < len(gp_list); i++ {
		var commit curve.G1Affine
		commit.Add(&gp_list[i], &hr_list[i])
		commitmentList[i] = commit
	}

	result, _ := json.Marshal(commitmentList)
	return C.CString(string(result))
}

//export pyCircuitAdd
func pyCircuitAdd(jsonLeft *C.char, jsonRight *C.char) *C.char {
	// Define input structure matching Python add_inputs format
	type proofElem struct {
		H               curve.G1Affine `json:"H"`
		ClaimedValue    string         `json:"ClaimedValue"`
		ClaimedValueAux string         `json:"ClaimedValueAux"`
	}
	type addInputs struct {
		Commitment []curve.G1Affine `json:"commitment"`
		Proof      []proofElem      `json:"proof"`
	}

	// Unmarshal left and right JSON into Go structs
	var left addInputs
	if err := json.Unmarshal([]byte(C.GoString(jsonLeft)), &left); err != nil {
		return C.CString(`{"error":"invalid left inputs"}`)
	}
	var right addInputs
	if err := json.Unmarshal([]byte(C.GoString(jsonRight)), &right); err != nil {
		return C.CString(`{"error":"invalid right inputs"}`)
	}
	// Validate lengths
	if len(left.Commitment) != len(right.Commitment) || len(left.Proof) != len(right.Proof) {
		return C.CString(`{"error":"length mismatch"}`)
	}

	// Prepare result struct
	var result addInputs
	n := len(left.Commitment)
	result.Commitment = make([]curve.G1Affine, n)
	result.Proof = make([]proofElem, n)

	// Combine commitments and proof elements
	for i := 0; i < n; i++ {
		// Add commitments
		var sumCommit curve.G1Affine
		sumCommit.Add(&left.Commitment[i], &right.Commitment[i])
		result.Commitment[i] = sumCommit

		// Add proof.H (witness)
		var sumH curve.G1Affine
		sumH.Add(&left.Proof[i].H, &right.Proof[i].H)
		// Parse and add ClaimedValue
		a, ok := new(big.Int).SetString(left.Proof[i].ClaimedValue, 10)
		if !ok {
			return C.CString(`{"error":"invalid left ClaimedValue"}`)
		}
		b, ok := new(big.Int).SetString(right.Proof[i].ClaimedValue, 10)
		if !ok {
			return C.CString(`{"error":"invalid right ClaimedValue"}`)
		}
		sumA := new(big.Int).Add(a, b)
		// Parse and add ClaimedValueAux
		aAux, ok := new(big.Int).SetString(left.Proof[i].ClaimedValueAux, 10)
		if !ok {
			return C.CString(`{"error":"invalid left ClaimedValueAux"}`)
		}
		bAux, ok := new(big.Int).SetString(right.Proof[i].ClaimedValueAux, 10)
		if !ok {
			return C.CString(`{"error":"invalid right ClaimedValueAux"}`)
		}
		sumAux := new(big.Int).Add(aAux, bAux)

		result.Proof[i] = proofElem{
			H:               sumH,
			ClaimedValue:    sumA.String(),
			ClaimedValueAux: sumAux.String(),
		}
	}

	// Marshal result to JSON and return
	outBytes, err := json.Marshal(result)
	if err != nil {
		return C.CString(`{"error":"marshal failure"}`)
	}
	return C.CString(string(outBytes))
}

//export pyCircuitLinearComb
func pyCircuitLinearComb(jsonInputs *C.char, jsonCoeffs *C.char) *C.char {
	type proofElem struct {
		H               curve.G1Affine `json:"H"`
		ClaimedValue    string         `json:"ClaimedValue"`
		ClaimedValueAux string         `json:"ClaimedValueAux"`
	}
	type circuitValues struct {
		Commitment []curve.G1Affine `json:"commitment"`
		Proof      []proofElem      `json:"proof"`
	}
	type linearInputs struct {
		Terms []circuitValues `json:"terms"`
	}

	var inputs linearInputs
	if err := json.Unmarshal([]byte(C.GoString(jsonInputs)), &inputs); err != nil {
		return C.CString(`{"error":"invalid linear-combination inputs"}`)
	}

	var coeffStrings []string
	if err := json.Unmarshal([]byte(C.GoString(jsonCoeffs)), &coeffStrings); err != nil {
		return C.CString(`{"error":"invalid linear-combination coeffs"}`)
	}

	if len(inputs.Terms) == 0 {
		return C.CString(`{"error":"empty linear-combination terms"}`)
	}
	if len(inputs.Terms) != len(coeffStrings) {
		return C.CString(`{"error":"terms/coeffs length mismatch"}`)
	}

	width := len(inputs.Terms[0].Commitment)
	if width != len(inputs.Terms[0].Proof) {
		return C.CString(`{"error":"commitment/proof length mismatch"}`)
	}
	for i := 1; i < len(inputs.Terms); i++ {
		if len(inputs.Terms[i].Commitment) != width || len(inputs.Terms[i].Proof) != width {
			return C.CString(`{"error":"term width mismatch"}`)
		}
	}

	modulus := fr.Modulus()
	coeffs := make([]big.Int, len(coeffStrings))
	for i, coeffString := range coeffStrings {
		coeff, ok := new(big.Int).SetString(coeffString, 10)
		if !ok {
			return C.CString(`{"error":"invalid coefficient"}`)
		}
		coeff.Mod(coeff, modulus)
		if coeff.Sign() < 0 {
			coeff.Add(coeff, modulus)
		}
		coeffs[i].Set(coeff)
	}

	var result circuitValues
	result.Commitment = make([]curve.G1Affine, width)
	result.Proof = make([]proofElem, width)

	for j := 0; j < width; j++ {
		var commitSum curve.G1Affine
		var hSum curve.G1Affine
		valueSum := new(big.Int).SetInt64(0)
		auxSum := new(big.Int).SetInt64(0)

		for i, term := range inputs.Terms {
			var scaledCommit curve.G1Affine
			scaledCommit.ScalarMultiplication(&term.Commitment[j], &coeffs[i])
			commitSum.Add(&commitSum, &scaledCommit)

			var scaledH curve.G1Affine
			scaledH.ScalarMultiplication(&term.Proof[j].H, &coeffs[i])
			hSum.Add(&hSum, &scaledH)

			value, ok := new(big.Int).SetString(term.Proof[j].ClaimedValue, 10)
			if !ok {
				return C.CString(`{"error":"invalid ClaimedValue"}`)
			}
			aux, ok := new(big.Int).SetString(term.Proof[j].ClaimedValueAux, 10)
			if !ok {
				return C.CString(`{"error":"invalid ClaimedValueAux"}`)
			}

			value.Mod(value, modulus)
			aux.Mod(aux, modulus)

			scaledValue := new(big.Int).Mul(value, &coeffs[i])
			scaledValue.Mod(scaledValue, modulus)
			valueSum.Add(valueSum, scaledValue)
			valueSum.Mod(valueSum, modulus)

			scaledAux := new(big.Int).Mul(aux, &coeffs[i])
			scaledAux.Mod(scaledAux, modulus)
			auxSum.Add(auxSum, scaledAux)
			auxSum.Mod(auxSum, modulus)
		}

		result.Commitment[j] = commitSum
		result.Proof[j] = proofElem{
			H:               hSum,
			ClaimedValue:    valueSum.String(),
			ClaimedValueAux: auxSum.String(),
		}
	}

	outBytes, err := json.Marshal(result)
	if err != nil {
		return C.CString(`{"error":"marshal failure"}`)
	}
	return C.CString(string(outBytes))
}

//export pyCommitWithZeroFull
func pyCommitWithZeroFull(json_SRS_Pk *C.char, json_secret *C.char, json_secret_aux *C.char, t int) *C.char {
	// Deserialize the proving key and secrets from JSON
	var Pk kzg_ped.ProvingKey
	_ = json.Unmarshal([]byte(C.GoString(json_SRS_Pk)), &Pk)

	// var secret []fr.Element
	// _ = json.Unmarshal([]byte(C.GoString(json_secret)), &secret)

	var secret_f []fr.Element
	_ = json.Unmarshal([]byte(C.GoString(json_secret)), &secret_f)

	var secret_aux []fr.Element
	_ = json.Unmarshal([]byte(C.GoString(json_secret_aux)), &secret_aux)

	batch_size := len(secret_f)

	// Generate polynomials and auxiliary polynomials
	// polynomialList, polynomialList_aux := samplepolynomial(secret, batch_size, t)
	polynomialList, polynomialList_aux := samplePolyPair(secret_f, secret_aux, batch_size, t)

	// Commit each polynomial
	commitmentList := make([]kzg_ped.Digest, batch_size)
	for i := 0; i < batch_size; i++ {
		commitmentList[i], _ = kzg_ped.Commit(polynomialList[i], polynomialList_aux[i], Pk)
	}

	// Generate batch opening proofs at x = 1, ..., n
	n := resolveN(t)
	proofList := Batchopen(polynomialList, polynomialList_aux, n, Pk)

	// Generate evaluation proofs at x = 0
	proofAtZero := make([]kzg_ped.OpeningProof, batch_size)
	var point fr.Element
	point.SetInt64(0)
	for i := 0; i < batch_size; i++ {
		proofAtZero[i], _ = kzg_ped.Open(polynomialList[i], polynomialList_aux[i], point, Pk)
	}

	// Compute g^{f(0)} and h^{f_aux(0)}
	shares_g := make([]curve.G1Affine, batch_size)
	shares_h := make([]curve.G1Affine, batch_size)
	g := Pk.G1_g[0]
	h := Pk.G1_h[0]
	fmt.Println("g =", g)
	fmt.Println("h =", h)
	fmt.Println("Equal?", g.Equal(&h))
	for i := 0; i < batch_size; i++ {
		var f0_big, f0aux_big big.Int
		polynomialList[i][0].BigInt(&f0_big)
		polynomialList_aux[i][0].BigInt(&f0aux_big)
		shares_g[i].ScalarMultiplication(&g, &f0_big)
		shares_h[i].ScalarMultiplication(&h, &f0aux_big)
	}

	// // Test: verify shares_g == g^{f(0)}
	// for i := 0; i < batch_size; i++ {
	// 	var expectedG curve.G1Affine
	// 	var f0big big.Int
	// 	polynomialList[i][0].BigInt(&f0big)
	// 	expectedG.ScalarMultiplication(&g, &f0big)
	// 	fmt.Printf("shares_g[%d] == g^{f(0)}? %v\n", i, shares_g[i].Equal(&expectedG))
	// }

	// // Test: verify shares_h == h^{f_aux(0)}
	// for i := 0; i < batch_size; i++ {
	// 	var expectedH curve.G1Affine
	// 	var f0auxbig big.Int
	// 	polynomialList_aux[i][0].BigInt(&f0auxbig)
	// 	expectedH.ScalarMultiplication(&h, &f0auxbig)
	// 	fmt.Printf("shares_h[%d] == h^{f_aux(0)}? %v\n", i, shares_h[i].Equal(&expectedH))
	// }

	// Construct result JSON
	type resultWithZeroFull struct {
		CommitmentList []kzg_ped.Digest         `json:"commitmentList"`
		ProofList      [][]kzg_ped.OpeningProof `json:"proofList"`
		ProofAtZero    []kzg_ped.OpeningProof   `json:"proofAtZero"`
		ShareG         []curve.G1Affine         `json:"shareG"`
		ShareH         []curve.G1Affine         `json:"shareH"`
	}

	result := resultWithZeroFull{
		CommitmentList: commitmentList,
		ProofList:      proofList,
		ProofAtZero:    proofAtZero,
		ShareG:         shares_g,
		ShareH:         shares_h,
	}

	jsonResult, _ := json.Marshal(result)
	return C.CString(string(jsonResult))
}

//export pyComputeShareGH
func pyComputeShareGH(json_SRS_Pk *C.char, json_prooflist_left *C.char, json_prooflist_right *C.char) *C.char {
	var Pk kzg_ped.ProvingKey
	if err := json.Unmarshal([]byte(C.GoString(json_SRS_Pk)), &Pk); err != nil {
		return C.CString(`{"error": "invalid SRS Pk"}`)
	}

	var prooflist_left, prooflist_right []kzg_ped.OpeningProof
	if err := json.Unmarshal([]byte(C.GoString(json_prooflist_left)), &prooflist_left); err != nil {
		return C.CString(`{"error": "invalid prooflist_left"}`)
	}
	if err := json.Unmarshal([]byte(C.GoString(json_prooflist_right)), &prooflist_right); err != nil {
		return C.CString(`{"error": "invalid prooflist_right"}`)
	}

	if len(prooflist_left) != len(prooflist_right) {
		return C.CString(`{"error": "length mismatch"}`)
	}

	batchsize := len(prooflist_left)
	g := Pk.G1_g[0]
	h := Pk.G1_h[0]

	shareG_left := make([]curve.G1Affine, batchsize)
	shareG_right := make([]curve.G1Affine, batchsize)
	shareH_left := make([]curve.G1Affine, batchsize)
	shareH_right := make([]curve.G1Affine, batchsize)

	for i := 0; i < batchsize; i++ {
		var a, b, a_aux, b_aux big.Int
		prooflist_left[i].ClaimedValue.BigInt(&a)
		prooflist_right[i].ClaimedValue.BigInt(&b)
		prooflist_left[i].ClaimedValueAux.BigInt(&a_aux)
		prooflist_right[i].ClaimedValueAux.BigInt(&b_aux)

		shareG_left[i].ScalarMultiplication(&g, &a)
		shareG_right[i].ScalarMultiplication(&g, &b)
		shareH_left[i].ScalarMultiplication(&h, &a_aux)
		shareH_right[i].ScalarMultiplication(&h, &b_aux)
	}

	result := struct {
		ShareGLeft  []curve.G1Affine `json:"shareG_left"`
		ShareGRight []curve.G1Affine `json:"shareG_right"`
		ShareHLeft  []curve.G1Affine `json:"shareH_left"`
		ShareHRight []curve.G1Affine `json:"shareH_right"`
	}{
		ShareGLeft:  shareG_left,
		ShareGRight: shareG_right,
		ShareHLeft:  shareH_left,
		ShareHRight: shareH_right,
	}

	jsonResult, _ := json.Marshal(result)
	return C.CString(string(jsonResult))
}

// func Batchopen(f [][]fr.Element, f_aux [][]fr.Element, n int, pk kzg_ped.ProvingKey) [][]kzg_ped.OpeningProof {
// 	// Compute batch opening proofs for the polynomials
// 	res := make([][]kzg_ped.OpeningProof, n)
// 	var wg sync.WaitGroup

// 	if n == 4 {
// 		for j := 0; j < n; j++ {
// 			if j == 0 {
// 				res[j] = make([]kzg_ped.OpeningProof, len(f))
// 				var point fr.Element
// 				point.SetInt64(int64(j + 1)) // Evaluation point
// 				for idx := 0; idx < len(f); idx++ {
// 					res[j][idx], _ = kzg_ped.Open(f[idx], f_aux[idx], point, pk)
// 				}
// 			} else {
// 				var point fr.Element
// 				point.SetInt64(int64(j + 1)) // Evaluation point
// 				res[j] = make([]kzg_ped.OpeningProof, len(f))
// 				for idx := 0; idx < len(f); idx++ {
// 					res[j][idx].H.Set(&res[0][idx].H)
// 					res[j][idx].ClaimedValue, res[j][idx].ClaimedValueAux = kzg_ped.Eval(f[idx], f_aux[idx], point)
// 				}
// 			}
// 		}
// 	} else {
// 		for j := 0; j < n; j++ {
// 			wg.Add(1)
// 			go func(j int) {
// 				defer wg.Done()
// 				res[j] = make([]kzg_ped.OpeningProof, len(f))
// 				var point fr.Element
// 				point.SetInt64(int64(j + 1)) // Evaluation point

// 				for i := 0; i < len(f); i++ {
// 					res[j][i], _ = kzg_ped.Open(f[i], f_aux[i], point, pk)
// 				}
// 			}(j)
// 		}
// 		wg.Wait()
// 	}

// 	return res
// }

// new version of Batchopen
func Batchopen(f [][]fr.Element, f_aux [][]fr.Element, n int, pk kzg_ped.ProvingKey) [][]kzg_ped.OpeningProof {
	// 始终为每个 (j, idx) 组合重新生成完整的 opening proof，无特殊分支
	res := make([][]kzg_ped.OpeningProof, n)
	var wg sync.WaitGroup

	for j := 0; j < n; j++ {
		wg.Add(1)
		go func(j int) {
			defer wg.Done()
			res[j] = make([]kzg_ped.OpeningProof, len(f))
			var point fr.Element
			point.SetInt64(int64(j + 1)) // 评估点 x = j+1

			for idx := 0; idx < len(f); idx++ {
				// 对多项式 f[idx] 和辅助 f_aux[idx] 在 point 处做 KZG 开证明
				res[j][idx], _ = kzg_ped.Open(f[idx], f_aux[idx], point, pk)
			}
		}(j)
	}
	wg.Wait()
	return res
}

//export pyBatchVerify
func pyBatchVerify(json_SRS_Vk *C.char, json_commitmentlist *C.char, json_prooflist *C.char, i int) bool {
	// Deserialize the verifying key, commitment list, and proof list from JSON
	var Vk kzg_ped.VerifyingKey
	_ = json.Unmarshal([]byte(C.GoString(json_SRS_Vk)), &Vk)

	var commitmentList []kzg_ped.Digest
	_ = json.Unmarshal([]byte(C.GoString(json_commitmentlist)), &commitmentList)

	var prooflist []kzg_ped.OpeningProof
	_ = json.Unmarshal([]byte(C.GoString(json_prooflist)), &prooflist)

	// Set the evaluation point
	var point fr.Element
	point.SetInt64(int64(i + 1))

	// Private proofs always use RLC batch verification regardless of DISABLE_RLC.
	// DISABLE_RLC only controls the public-proof path (pyBatchVerifyPub).
	return BatchVerify(commitmentList, prooflist, point, Vk)
}

//export pyBatchVerifyUnbatched
func pyBatchVerifyUnbatched(json_SRS_Vk *C.char, json_commitmentlist *C.char, json_prooflist *C.char, i int) bool {
	var Vk kzg_ped.VerifyingKey
	_ = json.Unmarshal([]byte(C.GoString(json_SRS_Vk)), &Vk)

	var commitmentList []kzg_ped.Digest
	_ = json.Unmarshal([]byte(C.GoString(json_commitmentlist)), &commitmentList)

	var prooflist []kzg_ped.OpeningProof
	_ = json.Unmarshal([]byte(C.GoString(json_prooflist)), &prooflist)

	var point fr.Element
	point.SetInt64(int64(i + 1))

	return BatchVerifyTest(commitmentList, prooflist, point, Vk)
}

// ------------------------------------------------------------
// Pub‑Verify variant (uses group elements g^f(i), h^f̂(i) that
// are implicitly reconstructed from the scalar ClaimedValue /
// ClaimedValueAux contained in the proof).  Interface is kept
// identical to pyBatchVerify so that existing JSON payloads
// can be reused.
//
// //export pyBatchVerifyPub
// func pyBatchVerifyPub(json_SRS_Vk *C.char,
//                       json_commitmentlist *C.char,
//                       json_prooflist *C.char,
//                       i int) bool {

// 	// 1) Verifying key
// 	var Vk kzg_ped.VerifyingKey
// 	_ = json.Unmarshal([]byte(C.GoString(json_SRS_Vk)), &Vk)

// 	// 2) Commitments
// 	var comList []kzg_ped.Digest
// 	_ = json.Unmarshal([]byte(C.GoString(json_commitmentlist)), &comList)

// 	// 3) Public proofs
// 	var proofList []OpeningProofPub
// 	_ = json.Unmarshal([]byte(C.GoString(json_prooflist)), &proofList)

// 	// 4) point x = i+1
// 	var point fr.Element
// 	point.SetInt64(int64(i + 1))

// 	// return BatchVerifyPub(comList, proofList, point, Vk)
// 	return BatchVerifyPubTest(comList, proofList, point, Vk)
// }

//export pyBatchVerifyPub
func pyBatchVerifyPub(json_SRS_Vk *C.char,
	json_commitmentlist *C.char,
	json_proofAtZero *C.char,
	json_shareG *C.char,
	json_shareH *C.char,
	i int) bool {

	// 1) Verifying key
	var Vk kzg_ped.VerifyingKey
	_ = json.Unmarshal([]byte(C.GoString(json_SRS_Vk)), &Vk)

	// 2) Commitments
	var comList []kzg_ped.Digest
	_ = json.Unmarshal([]byte(C.GoString(json_commitmentlist)), &comList)

	// 3‑a) Proof‑at‑zero: contains only the witness H elements
	type hOnly struct {
		H curve.G1Affine `json:"H"`
	}
	var p0 []hOnly
	_ = json.Unmarshal([]byte(C.GoString(json_proofAtZero)), &p0)

	// 3‑b) g^{f(0)} claims
	var shareG []curve.G1Affine
	_ = json.Unmarshal([]byte(C.GoString(json_shareG)), &shareG)

	// 3‑c) h^{f̂(0)} claims
	var shareH []curve.G1Affine
	_ = json.Unmarshal([]byte(C.GoString(json_shareH)), &shareH)

	// Sanity‑check equal lengths
	if len(p0) != len(shareG) || len(shareG) != len(shareH) || len(comList) != len(p0) {
		return false
	}

	// Re‑assemble OpeningProofPub slice
	proofList := make([]OpeningProofPub, len(p0))
	for idx := range p0 {
		proofList[idx] = OpeningProofPub{
			H:      p0[idx].H,
			GClaim: shareG[idx],
			HClaim: shareH[idx],
		}
	}

	// 4) evaluation point x = i+1
	var point fr.Element
	point.SetInt64(int64(i + 1))
	// point.SetInt64(int64(0))

	// Verification (one‑by‑one test variant)
	if os.Getenv("DISABLE_RLC") == "1" {
		return BatchVerifyPubTest(comList, proofList, point, Vk)
	}
	return BatchVerifyPub(comList, proofList, point, Vk)
}

//export pyBatchVerifyPubCombined
func pyBatchVerifyPubCombined(json_SRS_Vk *C.char,
	json_commitmentlist *C.char,
	json_witnesslist *C.char,
	json_pedersenlist *C.char,
	i int) bool {

	var vk kzg_ped.VerifyingKey
	if err := decodeStrictJSON([]byte(C.GoString(json_SRS_Vk)), &vk); err != nil {
		return false
	}

	commitments, err := decodeG1Vector(
		[]byte(C.GoString(json_commitmentlist)), "commitments",
	)
	if err != nil {
		return false
	}
	pedersen, err := decodeG1Vector(
		[]byte(C.GoString(json_pedersenlist)), "Pedersen commitments",
	)
	if err != nil {
		return false
	}

	var witnessWire []openingWitnessWire
	if err := decodeStrictJSON([]byte(C.GoString(json_witnesslist)), &witnessWire); err != nil || len(witnessWire) == 0 {
		return false
	}
	witnesses := make([]curve.G1Affine, len(witnessWire))
	for index := range witnessWire {
		witnesses[index].Set(&witnessWire[index].H)
	}

	var point fr.Element
	point.SetInt64(int64(i + 1))
	valid, err := BatchVerifyPubCombinedUnbatched(commitments, witnesses, pedersen, point, vk)
	return err == nil && valid
}

// randomCombinePubCombined samples verifier-local independent coefficients and
// combines C_i, W_i and Ped_i with the same coefficient vector. Randomness
// errors are surfaced to the caller instead of silently using a zero scalar.
func randomCombinePubCombined(commitments []kzg_ped.Digest,
	witnesses []curve.G1Affine,
	pedersen []curve.G1Affine) (kzg_ped.Digest, curve.G1Affine, curve.G1Affine, error) {

	if len(commitments) == 0 || len(commitments) != len(witnesses) || len(commitments) != len(pedersen) {
		return kzg_ped.Digest{}, curve.G1Affine{}, curve.G1Affine{}, fmt.Errorf("combined batch length mismatch")
	}

	coefficients := make([]fr.Element, len(commitments))
	for index := range coefficients {
		if _, err := coefficients[index].SetRandom(); err != nil {
			return kzg_ped.Digest{}, curve.G1Affine{}, curve.G1Affine{}, fmt.Errorf("sample batch coefficient %d: %w", index, err)
		}
	}

	var aggregateCommitment, aggregateWitness, aggregatePedersen curve.G1Affine
	if _, err := aggregateCommitment.MultiExp(commitments, coefficients, ecc.MultiExpConfig{}); err != nil {
		return kzg_ped.Digest{}, curve.G1Affine{}, curve.G1Affine{}, fmt.Errorf("aggregate commitments: %w", err)
	}
	if _, err := aggregateWitness.MultiExp(witnesses, coefficients, ecc.MultiExpConfig{}); err != nil {
		return kzg_ped.Digest{}, curve.G1Affine{}, curve.G1Affine{}, fmt.Errorf("aggregate witnesses: %w", err)
	}
	if _, err := aggregatePedersen.MultiExp(pedersen, coefficients, ecc.MultiExpConfig{}); err != nil {
		return kzg_ped.Digest{}, curve.G1Affine{}, curve.G1Affine{}, fmt.Errorf("aggregate Pedersen commitments: %w", err)
	}
	return aggregateCommitment, aggregateWitness, aggregatePedersen, nil
}

// BatchVerifyPubCombined verifies C_i - Ped_i = W_i * (alpha - point) with
// one verifier-randomized batch pairing. The old and fresh relations call this
// function separately and therefore receive independent coefficient vectors.
func BatchVerifyPubCombined(commitments []kzg_ped.Digest,
	witnesses []curve.G1Affine,
	pedersen []curve.G1Affine,
	point fr.Element,
	vk kzg_ped.VerifyingKey) (bool, error) {

	if len(commitments) == 0 || len(commitments) != len(witnesses) || len(commitments) != len(pedersen) {
		return false, fmt.Errorf("combined batch length mismatch")
	}
	for index := range commitments {
		if err := validateG1(&commitments[index], fmt.Sprintf("commitments[%d]", index)); err != nil {
			return false, err
		}
		if err := validateG1(&witnesses[index], fmt.Sprintf("witnesses[%d]", index)); err != nil {
			return false, err
		}
		if err := validateG1(&pedersen[index], fmt.Sprintf("Pedersen commitments[%d]", index)); err != nil {
			return false, err
		}
	}
	if err := validateG2(&vk.G2[0], "Vk.G2[0]"); err != nil {
		return false, err
	}
	if err := validateG2(&vk.G2[1], "Vk.G2[1]"); err != nil {
		return false, err
	}

	aggregateCommitment, aggregateWitness, aggregatePedersen, err := randomCombinePubCombined(
		commitments, witnesses, pedersen,
	)
	if err != nil {
		return false, err
	}

	var lhs curve.G1Affine
	lhs.Sub(&aggregateCommitment, &aggregatePedersen)

	var pointBig big.Int
	point.BigInt(&pointBig)
	var g2AtPoint, rhsExponent curve.G2Affine
	g2AtPoint.ScalarMultiplication(&vk.G2[0], &pointBig)
	rhsExponent.Sub(&vk.G2[1], &g2AtPoint)

	var negativeWitness curve.G1Affine
	negativeWitness.Neg(&aggregateWitness)
	valid, err := curve.PairingCheck(
		[]curve.G1Affine{lhs, negativeWitness},
		[]curve.G2Affine{vk.G2[0], rhsExponent},
	)
	if err != nil {
		return false, fmt.Errorf("combined batch pairing: %w", err)
	}
	return valid, nil
}

// BatchVerifyPubCombinedUnbatched verifies every combined-Pedersen relation
// independently. No random linear combination is applied, so an honest batch
// of size B performs exactly B pairing checks.
func BatchVerifyPubCombinedUnbatched(commitments []kzg_ped.Digest,
	witnesses []curve.G1Affine,
	pedersen []curve.G1Affine,
	point fr.Element,
	vk kzg_ped.VerifyingKey) (bool, error) {

	if len(commitments) == 0 || len(commitments) != len(witnesses) || len(commitments) != len(pedersen) {
		return false, fmt.Errorf("combined batch length mismatch")
	}
	for index := range commitments {
		if err := validateG1(&commitments[index], fmt.Sprintf("commitments[%d]", index)); err != nil {
			return false, err
		}
		if err := validateG1(&witnesses[index], fmt.Sprintf("witnesses[%d]", index)); err != nil {
			return false, err
		}
		if err := validateG1(&pedersen[index], fmt.Sprintf("Pedersen commitments[%d]", index)); err != nil {
			return false, err
		}
	}
	if err := validateG2(&vk.G2[0], "Vk.G2[0]"); err != nil {
		return false, err
	}
	if err := validateG2(&vk.G2[1], "Vk.G2[1]"); err != nil {
		return false, err
	}

	var pointBig big.Int
	point.BigInt(&pointBig)
	var g2AtPoint, rhsExponent curve.G2Affine
	g2AtPoint.ScalarMultiplication(&vk.G2[0], &pointBig)
	rhsExponent.Sub(&vk.G2[1], &g2AtPoint)

	for index := range commitments {
		var lhs curve.G1Affine
		lhs.Sub(&commitments[index], &pedersen[index])

		var negativeWitness curve.G1Affine
		negativeWitness.Neg(&witnesses[index])

		valid, err := curve.PairingCheck(
			[]curve.G1Affine{lhs, negativeWitness},
			[]curve.G2Affine{vk.G2[0], rhsExponent},
		)
		if err != nil {
			return false, fmt.Errorf("combined proof %d pairing: %w", index, err)
		}
		if !valid {
			return false, nil
		}
	}
	return true, nil
}

// aggregates commitments and proofs using a bunch of random element for batch verification.
func randomCombine(commitment []kzg_ped.Digest, proof []kzg_ped.OpeningProof) (kzg_ped.Digest, kzg_ped.OpeningProof) {
	batchsize := len(commitment)
	randomElement := make([]fr.Element, batchsize)
	wit := make([]curve.G1Affine, batchsize)
	value := make([]fr.Element, batchsize)
	valueAux := make([]fr.Element, batchsize)
	for i := 0; i < batchsize; i++ {
		randomElement[i].SetRandom()
		wit[i].Set(&proof[i].H)
		value[i].Set(&proof[i].ClaimedValue)
		valueAux[i].Set(&proof[i].ClaimedValueAux)
	}

	var resCom curve.G1Affine
	resCom.MultiExp(commitment, randomElement, ecc.MultiExpConfig{})
	var resWit curve.G1Affine
	resWit.MultiExp(wit, randomElement, ecc.MultiExpConfig{})

	resValue := DotProductfrElement(value, randomElement)
	resValueAux := DotProductfrElement(valueAux, randomElement)

	var resProof kzg_ped.OpeningProof
	resProof.H.Set(&resWit)
	resProof.ClaimedValue.Set(&resValue)
	resProof.ClaimedValueAux.Set(&resValueAux)
	return resCom, resProof
}

// BatchVerify verifies a batch of commitments and proofs at a given point.
func BatchVerify(commitment []kzg_ped.Digest, proof []kzg_ped.OpeningProof, point fr.Element, vk kzg_ped.VerifyingKey) bool {
	Aggcom, Aggproofs := randomCombine(commitment, proof)
	return kzg_ped.Verify(&Aggcom, &Aggproofs, point, vk)
}

// BatchVerifyTest is a test variant of BatchVerify that verifies each (commitment, proof)
// pair one-by-one using kzg_ped.Verify without the random linear combination.
// Used for the (A1, B0) ablation: no RLC batch verification.
func BatchVerifyTest(commitment []kzg_ped.Digest, proof []kzg_ped.OpeningProof, point fr.Element, vk kzg_ped.VerifyingKey) bool {
	if len(commitment) != len(proof) {
		return false
	}
	for i := range commitment {
		if !kzg_ped.Verify(&commitment[i], &proof[i], point, vk) {
			return false
		}
	}
	return true
}

func openAllSequential(f [][]fr.Element, f_aux [][]fr.Element, n int, pk kzg_ped.ProvingKey) [][]kzg_ped.OpeningProof {
	res := make([][]kzg_ped.OpeningProof, n)
	for j := 0; j < n; j++ {
		res[j] = make([]kzg_ped.OpeningProof, len(f))
		var point fr.Element
		point.SetInt64(int64(j + 1))
		for idx := 0; idx < len(f); idx++ {
			res[j][idx], _ = kzg_ped.Open(f[idx], f_aux[idx], point, pk)
		}
	}
	return res
}

// randomCombinePub aggregates commitments + public proofs with random r_i.
func randomCombinePub(commitment []kzg_ped.Digest,
	proof []OpeningProofPub) (kzg_ped.Digest, OpeningProofPub) {

	n := len(commitment)
	r := make([]fr.Element, n)

	wArr := make([]curve.G1Affine, n)
	gArr := make([]curve.G1Affine, n)
	hArr := make([]curve.G1Affine, n)

	for i := 0; i < n; i++ {
		r[i].SetRandom()
		wArr[i].Set(&proof[i].H)
		gArr[i].Set(&proof[i].GClaim)
		hArr[i].Set(&proof[i].HClaim)
	}

	var aggC, aggW, aggG, aggH curve.G1Affine
	aggC.MultiExp(commitment, r, ecc.MultiExpConfig{})
	aggW.MultiExp(wArr, r, ecc.MultiExpConfig{})
	aggG.MultiExp(gArr, r, ecc.MultiExpConfig{})
	aggH.MultiExp(hArr, r, ecc.MultiExpConfig{})

	return aggC, OpeningProofPub{
		H:      aggW,
		GClaim: aggG,
		HClaim: aggH,
	}
}

// BatchVerifyPub verifies a batch of public-style proofs at point x.
func BatchVerifyPub(commitment []kzg_ped.Digest, proof []OpeningProofPub,
	point fr.Element, vk kzg_ped.VerifyingKey) bool {
	aggC, aggP := randomCombinePub(commitment, proof)

	// ---------- Left‑hand side:  C / (G* + H*) ----------
	var GH curve.G1Affine
	GH.Add(&aggP.GClaim, &aggP.HClaim)

	var lhs curve.G1Affine
	lhs.Sub(&aggC, &GH) // C - (G*+H*)

	// ---------- Right‑hand side exponent in G2 ----------
	// Convert evaluation point x into *big.Int
	var xBig big.Int
	point.BigInt(&xBig)

	// We assume Vk.G2[0] = g2  , Vk.G2[1] = h2 = g2^α
	g2Gen := vk.G2[0]
	h2Gen := vk.G2[1]

	// Compute g2^x
	var g2x curve.G2Affine
	g2x.ScalarMultiplication(&g2Gen, &xBig)

	// rhsExpo = h2 / g2^x  = g2^α / g2^x
	var rhsExpo curve.G2Affine
	rhsExpo.Sub(&h2Gen, &g2x)

	// ---------- Witness (aggregated) ----------
	W := aggP.H

	// Pairing check: we need e(lhs, g2) * e(-W, rhsExpo) == 1.
	// Negate W (additive inverse in G1) so that PairingCheck verifies the equality.
	var negW curve.G1Affine
	negW.Neg(&W)

	ok, _ := curve.PairingCheck(
		[]curve.G1Affine{lhs, negW},
		[]curve.G2Affine{g2Gen, rhsExpo},
	)
	return ok
}

// BatchVerifyPubTest is a test variant that verifies each proof one by one without random combining.
func BatchVerifyPubTest(commitment []kzg_ped.Digest, proof []OpeningProofPub, point fr.Element, vk kzg_ped.VerifyingKey) bool {
	// g2Gen = Vk.G2[0], h2Gen = Vk.G2[1]
	g2Gen := vk.G2[0]
	h2Gen := vk.G2[1]
	// Convert point to big.Int
	var xBig big.Int
	point.BigInt(&xBig)
	// Compute g2^x
	var g2x curve.G2Affine
	g2x.ScalarMultiplication(&g2Gen, &xBig)
	// rhsExpo = h2Gen - g2x
	var rhsExpo curve.G2Affine
	rhsExpo.Sub(&h2Gen, &g2x)
	// Ensure matching lengths
	if len(commitment) != len(proof) {
		return false
	}
	// Loop through each pair
	for i := range commitment {
		// lhs = C_i - (GClaim_i + HClaim_i)
		var sumGH curve.G1Affine
		sumGH.Add(&proof[i].GClaim, &proof[i].HClaim)
		var lhs curve.G1Affine
		lhs.Sub(&commitment[i], &sumGH)
		// negW = - proof[i].H
		var negW curve.G1Affine
		negW.Neg(&proof[i].H)
		ok, _ := curve.PairingCheck(
			[]curve.G1Affine{lhs, negW},
			[]curve.G2Affine{g2Gen, rhsExpo},
		)
		if !ok {
			return false
		}
	}
	return true
}

//export VMmatrixGen
func VMmatrixGen(t int) *C.char {
	// Deserialize the public key from JSON
	// var publickey []curve.G1Affine
	// _ = json.Unmarshal([]byte(C.GoString(json_publickey)), &publickey)

	// Initialize the Vandermonde matrix
	dim_col := resolveN(t)
	dim_row := t + 1
	vm_matrix := make([][]fr.Element, dim_row)

	for i := 0; i < dim_row; i++ {
		vm_matrix[i] = make([]fr.Element, dim_col)
		var temp fr.Element
		temp.SetInt64(int64(i + 1))
		for j := 0; j < dim_col; j++ {
			ExponentElement := new(big.Int).SetInt64(int64(j))
			vm_matrix[i][j].Exp(temp, ExponentElement) // Compute temp^j
		}
	}

	// Serialize the Vandermonde matrix to JSON
	jsonvm_matrix, _ := json.Marshal(vm_matrix)
	return C.CString(string(jsonvm_matrix))
}

// transposefrElement transposes a 2D slice of fr.Element.
func transposefrElement(matrix [][]fr.Element) [][]fr.Element {
	if len(matrix) == 0 {
		return nil
	}

	rows, cols := len(matrix), len(matrix[0])
	result := make([][]fr.Element, cols)

	for i := range result {
		result[i] = make([]fr.Element, rows)
	}

	for i := 0; i < rows; i++ {
		for j := 0; j < cols; j++ {
			result[j][i] = matrix[i][j]
		}
	}

	return result
}

// DotProductfrElement calculates the dot product of two vectors of fr.Element.
func DotProductfrElement(vector1, vector2 []fr.Element) fr.Element {
	if len(vector1) != len(vector2) {
		panic("Vector lengths do not match")
	}

	var result fr.Element
	result.SetZero()

	for i := 0; i < len(vector1); i++ {
		var temp fr.Element
		temp.Mul(&vector1[i], &vector2[i]) // Multiply corresponding elements
		result.Add(&result, &temp)         // Add to the result
	}

	return result
}

// contains checks if a number is present in a slice of integers.
func contains(num int, set []int) bool {
	for _, value := range set {
		if value == num {
			return true
		}
	}
	return false
}

// FlattenSlice flattens a 2D slice into a 1D slice.
func FlattenSlice[T any](input [][]T) []T {
	var result []T
	for _, slice := range input {
		result = append(result, slice...)
	}
	return result
}

//export pyRandomShareCompute
func pyRandomShareCompute(json_matrix *C.char, json_set *C.char, json_comlist *C.char, json_prooflist *C.char, t int) *C.char {
	// Parse input JSON strings into Go structures
	var vm_matrix [][]fr.Element
	_ = json.Unmarshal([]byte(C.GoString(json_matrix)), &vm_matrix)

	var commonset []int
	_ = json.Unmarshal([]byte(C.GoString(json_set)), &commonset)

	n := resolveN(t)

	var commitmentList_All [][]kzg_ped.Digest
	_ = json.Unmarshal([]byte(C.GoString(json_comlist)), &commitmentList_All)
	var prooflist_All [][]kzg_ped.OpeningProof
	_ = json.Unmarshal([]byte(C.GoString(json_prooflist)), &prooflist_All)

	batchsize := len(commitmentList_All[commonset[0]])

	// Initialize slices for commitments, witnesses, shares, and auxiliary shares
	commits := make([][]curve.G1Affine, batchsize)
	wits := make([][]curve.G1Affine, batchsize)
	shares := make([][]fr.Element, batchsize)
	shares_aux := make([][]fr.Element, batchsize)

	for idx := 0; idx < batchsize; idx++ {
		commits[idx] = make([]curve.G1Affine, n)
		wits[idx] = make([]curve.G1Affine, n)
		shares[idx] = make([]fr.Element, n)
		shares_aux[idx] = make([]fr.Element, n)

		for node := 0; node < n; node++ {
			if contains(node, commonset) {
				// If the node is in the common set, set values from the input
				commits[idx][node].Set(&commitmentList_All[node][idx])
				wits[idx][node].Set(&prooflist_All[node][idx].H)
				shares[idx][node].Set(&prooflist_All[node][idx].ClaimedValue)
				shares_aux[idx][node].Set(&prooflist_All[node][idx].ClaimedValueAux)
			} else {
				// Otherwise, set to zero
				commits[idx][node].X.SetZero()
				commits[idx][node].Y.SetZero()
				wits[idx][node].X.SetZero()
				wits[idx][node].Y.SetZero()
				shares[idx][node].SetZero()
				shares_aux[idx][node].SetZero()
			}
		}
	}

	// Prepare for the extended computation of random shares
	totalshares := batchsize * (t + 1)
	commits_ext := make([][]curve.G1Affine, t+1)
	wits_ext := make([][]curve.G1Affine, t+1)
	shares_ext := make([][]fr.Element, t+1)
	shares_aux_ext := make([][]fr.Element, t+1)

	// Use WaitGroup and Mutex for thread-safe concurrent computation
	var wg sync.WaitGroup
	var mutex sync.Mutex
	sem := make(chan struct{}, runtime.NumCPU()) // Limit the number of Goroutines to CPU cores

	for row_index := 0; row_index < t+1; row_index++ {
		commits_ext[row_index] = make([]curve.G1Affine, batchsize)
		wits_ext[row_index] = make([]curve.G1Affine, batchsize)
		shares_ext[row_index] = make([]fr.Element, batchsize)
		shares_aux_ext[row_index] = make([]fr.Element, batchsize)

		for idx := 0; idx < batchsize; idx++ {
			wg.Add(1)
			sem <- struct{}{} // Acquire semaphore

			go func(row_index, idx int) {
				defer wg.Done()
				defer func() { <-sem }() // Release semaphore

				// Independent computation for each share
				var commit, wit curve.G1Affine
				var share, share_aux fr.Element

				commit.MultiExp(commits[idx], vm_matrix[row_index], ecc.MultiExpConfig{})
				wit.MultiExp(wits[idx], vm_matrix[row_index], ecc.MultiExpConfig{})
				share = DotProductfrElement(shares[idx], vm_matrix[row_index])
				share_aux = DotProductfrElement(shares_aux[idx], vm_matrix[row_index])

				// Safely write results to shared slices
				mutex.Lock()
				commits_ext[row_index][idx].Set(&commit)
				wits_ext[row_index][idx].Set(&wit)
				shares_ext[row_index][idx].Set(&share)
				shares_aux_ext[row_index][idx].Set(&share_aux)
				mutex.Unlock()
			}(row_index, idx)
		}
	}
	wg.Wait()

	// Flatten the 2D slices into 1D slices
	flat_commits_ran := FlattenSlice(commits_ext)
	flat_wits_ran := FlattenSlice(wits_ext)
	flat_shares_ran := FlattenSlice(shares_ext)
	flat_sharesaux_ran := FlattenSlice(shares_aux_ext)

	// Create proofs from the flattened data
	proof_random := make([]kzg_ped.OpeningProof, totalshares)
	for i := 0; i < totalshares; i++ {
		proof_random[i].H.Set(&flat_wits_ran[i])
		proof_random[i].ClaimedValue.Set(&flat_shares_ran[i])
		proof_random[i].ClaimedValueAux.Set(&flat_sharesaux_ran[i])
	}

	// Marshal the results into JSON format
	jsonproofList, err := json.Marshal(proof_random)
	if err != nil {
		fmt.Println("err", err)
	}
	jsoncommitmentList, err := json.Marshal(flat_commits_ran)
	if err != nil {
		fmt.Println("err", err)
	}

	var jsoncomlistandprooflist = "{\"commitment\":" + string(jsoncommitmentList) + ",\"proof\":" + string(jsonproofList) + "}"

	return C.CString(string(jsoncomlistandprooflist))
}

func elementwise_multiply(g_eval []curve.G1Affine, h_eval_aux []curve.G1Affine) []curve.G1Affine {
	// Perform element-wise addition of two slices of G1Affine points
	T := make([]curve.G1Affine, len(g_eval))
	for i := 0; i < len(g_eval); i++ {
		T[i].Add(&g_eval[i], &h_eval_aux[i])
	}
	return T
}

func HiddenEvalcompute(srs_pk kzg_ped.ProvingKey, prooflist []kzg_ped.OpeningProof,
	c_zero_proof []kzg_ped.OpeningProof, ab_com []kzg_ped.Digest, c_com []kzg_ped.Digest,
	my_id int) ([]curve.G1Affine, []curve.G1Affine, []kzg_ped.ProdProof) {
	// batchsize: total number of proofs being processed
	batchsize := len(prooflist)
	halfbatchsize := batchsize / 2

	// Ensure the consistency of the Beaver triples length
	if halfbatchsize != len(c_zero_proof) {
		fmt.Println("The length of Beaver triples is inconsistent")
	}

	// Select the first generator and trapdoor element
	g := srs_pk.G1_g[0]
	h := srs_pk.G1_h[0]

	fmt.Println("hidden g =", g)
	fmt.Println("hidden h =", h)
	fmt.Println("hidden Equal?", g.Equal(&h))

	// Initialize evaluation results
	eval := make([]fr.Element, batchsize)
	eval_aux := make([]fr.Element, batchsize)

	// Extract claimed values and auxiliary values
	for i := 0; i < batchsize; i++ {
		eval[i].Set(&prooflist[i].ClaimedValue)
		eval_aux[i].Set(&prooflist[i].ClaimedValueAux)
	}

	// Compute evaluation points T using element-wise multiplication
	T := elementwise_multiply(
		curve.BatchScalarMultiplicationG1(&g, eval),
		curve.BatchScalarMultiplicationG1(&h, eval_aux),
	)

	// Prepare zero-knowledge proofs (zkProof_ab) for commitment validation
	ZkProof_ab := make([]curve.G1Affine, batchsize+1)
	wit_ab := make([]curve.G1Affine, batchsize)
	for i := 0; i < batchsize; i++ {
		ZkProof_ab[i].Set(&T[i])       // Set committed values
		wit_ab[i].Set(&prooflist[i].H) // Set witness points
	}

	// Fold witnesses for zkProof_ab
	var point fr.Element
	point.SetInt64(int64(my_id + 1)) // Unique identifier for participant
	flodwit := kzg_ped.Foldwit(point, ab_com, T, batchsize, wit_ab)
	ZkProof_ab[batchsize].Set(&flodwit)

	// Process the second set of evaluations for c_zero_proof
	eval_c := make([]fr.Element, halfbatchsize)
	eval_aux_c := make([]fr.Element, halfbatchsize)
	for i := 0; i < halfbatchsize; i++ {
		eval_c[i].Set(&c_zero_proof[i].ClaimedValue)
		eval_aux_c[i].Set(&c_zero_proof[i].ClaimedValueAux)
	}

	// Compute evaluation points for the second batch
	g_eval_c := curve.BatchScalarMultiplicationG1(&g, eval_c)
	h_eval_aux_c := curve.BatchScalarMultiplicationG1(&h, eval_aux_c)
	T_c := elementwise_multiply(g_eval_c, h_eval_aux_c)

	// Prepare zero-knowledge proofs (zkProof_c) for second batch
	ZkProof_c := make([]curve.G1Affine, halfbatchsize+1)
	wit_c := make([]curve.G1Affine, halfbatchsize)
	for i := 0; i < halfbatchsize; i++ {
		ZkProof_c[i].Set(&T_c[i])        // Set committed values
		wit_c[i].Set(&c_zero_proof[i].H) // Set witness points
	}

	// Fold witnesses for zkProof_c
	var point_0 fr.Element
	point_0.SetInt64(int64(0)) // Folding point for zkProof_c
	flodwit_c := kzg_ped.Foldwit(point_0, c_com, T_c, halfbatchsize, wit_c)
	ZkProof_c[halfbatchsize].Set(&flodwit_c)

	// Generate product proofs in parallel
	prodproofs := make([]kzg_ped.ProdProof, halfbatchsize)
	var wg sync.WaitGroup
	for i := 0; i < halfbatchsize; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			prodproofs[i] = kzg_ped.Prodproof(
				srs_pk,
				eval[i], eval_aux[i], eval[i+halfbatchsize], eval_aux[i+halfbatchsize],
				eval_c[i], eval_aux_c[i], T[i], T[i+halfbatchsize], T_c[i],
			)
		}(i)
	}
	wg.Wait()

	return ZkProof_ab, ZkProof_c, prodproofs
}

func pedersenPoint(g curve.G1Affine, h curve.G1Affine, value fr.Element, aux fr.Element) curve.G1Affine {
	var valueBig, auxBig big.Int
	value.BigInt(&valueBig)
	aux.BigInt(&auxBig)

	var gValue, hAux, out curve.G1Affine
	gValue.ScalarMultiplication(&g, &valueBig)
	hAux.ScalarMultiplication(&h, &auxBig)
	out.Add(&gValue, &hAux)
	return out
}

func HiddenEvalcomputeUnbatched(srs_pk kzg_ped.ProvingKey, prooflist []kzg_ped.OpeningProof,
	c_zero_proof []kzg_ped.OpeningProof, ab_com []kzg_ped.Digest, c_com []kzg_ped.Digest,
	my_id int) ([]curve.G1Affine, []curve.G1Affine, []kzg_ped.ProdProof) {
	batchsize := len(prooflist)
	halfbatchsize := batchsize / 2

	if batchsize != len(ab_com) || halfbatchsize != len(c_zero_proof) || halfbatchsize != len(c_com) {
		fmt.Println("The BGW unbatched proof input lengths are inconsistent")
	}

	g := srs_pk.G1_g[0]
	h := srs_pk.G1_h[0]

	eval := make([]fr.Element, batchsize)
	evalAux := make([]fr.Element, batchsize)
	zkProofAB := make([]curve.G1Affine, 2*batchsize)
	for i := 0; i < batchsize; i++ {
		eval[i].Set(&prooflist[i].ClaimedValue)
		evalAux[i].Set(&prooflist[i].ClaimedValueAux)
		zkProofAB[i] = pedersenPoint(g, h, eval[i], evalAux[i])
		zkProofAB[batchsize+i].Set(&prooflist[i].H)
	}

	evalC := make([]fr.Element, halfbatchsize)
	evalAuxC := make([]fr.Element, halfbatchsize)
	zkProofCZero := make([]curve.G1Affine, 2*halfbatchsize)
	for i := 0; i < halfbatchsize; i++ {
		evalC[i].Set(&c_zero_proof[i].ClaimedValue)
		evalAuxC[i].Set(&c_zero_proof[i].ClaimedValueAux)
		zkProofCZero[i] = pedersenPoint(g, h, evalC[i], evalAuxC[i])
		zkProofCZero[halfbatchsize+i].Set(&c_zero_proof[i].H)
	}

	prodproofs := make([]kzg_ped.ProdProof, halfbatchsize)
	for i := 0; i < halfbatchsize; i++ {
		prodproofs[i] = kzg_ped.Prodproof(
			srs_pk,
			eval[i], evalAux[i], eval[i+halfbatchsize], evalAux[i+halfbatchsize],
			evalC[i], evalAuxC[i], zkProofAB[i], zkProofAB[i+halfbatchsize], zkProofCZero[i],
		)
	}

	return zkProofAB, zkProofCZero, prodproofs
}

//export pyParseRandom
func pyParseRandom(json_SRS_Pk *C.char, json_commitmentlist *C.char, json_prooflist *C.char, t int, my_id int) *C.char {
	// Unmarshal input data from JSON to Go structures
	var SRS_pk kzg_ped.ProvingKey
	_ = json.Unmarshal([]byte(C.GoString(json_SRS_Pk)), &SRS_pk)

	var commitmentList []kzg_ped.Digest
	if err := json.Unmarshal([]byte(C.GoString(json_commitmentlist)), &commitmentList); err != nil || len(commitmentList) == 0 {
		fmt.Println("Error: json_commitmentlist is null or empty")
		return C.CString(`{"error": "json_commitmentlist is null or empty"}`)
	}

	var prooflist []kzg_ped.OpeningProof
	if err := json.Unmarshal([]byte(C.GoString(json_prooflist)), &prooflist); err != nil || len(prooflist) == 0 {
		fmt.Println("Error: json_prooflist is null or empty")
		return C.CString(`{"error": "json_prooflist is null or empty"}`)
	}

	batchsize := len(commitmentList) / 2

	// Compute the secret values for the commitments
	secret_c := make([]fr.Element, batchsize)
	for i := 0; i < batchsize; i++ {
		secret_c[i].Mul(&prooflist[i].ClaimedValue, &prooflist[i+batchsize].ClaimedValue)
	}

	// Sample polynomials and their auxiliary counterparts
	polynomialList, polynomialList_aux := samplepolynomial(secret_c, batchsize, t)

	// Generate commitments and zero-opening proofs
	c_commitments := make([]kzg_ped.Digest, batchsize)
	c_zero_proof := make([]kzg_ped.OpeningProof, batchsize)
	var wg sync.WaitGroup
	for i := 0; i < batchsize; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			c_commitments[i], _ = kzg_ped.Commit(polynomialList[i], polynomialList_aux[i], SRS_pk)
			c_zero_proof[i], _ = kzg_ped.OpenZero(polynomialList[i], polynomialList_aux[i], SRS_pk)
		}(i)
	}
	wg.Wait()

	// Batch open commitments for the polynomial list
	n := resolveN(t)
	c_proofs := Batchopen(polynomialList, polynomialList_aux, n, SRS_pk)

	// Compute hidden evaluations and corresponding proofs
	zkProof_ab, zkProof_c_0, prodProofs := HiddenEvalcompute(SRS_pk, prooflist, c_zero_proof, commitmentList, c_commitments, my_id)

	// Marshal outputs into a JSON result
	json_c_commitments, _ := json.Marshal(c_commitments)
	json_c_proofs, _ := json.Marshal(c_proofs)
	json_zkProof_ab, _ := json.Marshal(zkProof_ab)
	json_zkProof_c_0, _ := json.Marshal(zkProof_c_0)
	json_prodProofs, _ := json.Marshal(prodProofs)
	log.Println("prodProofs size = ", len(json_prodProofs))
	log.Println("prodProofs count = ", len(prodProofs))

	jsonResult := "{\"commitments_c\":" + string(json_c_commitments) +
		",\"proofs_c\":" + string(json_c_proofs) +
		",\"zkProof_ab\":" + string(json_zkProof_ab) +
		",\"zkProof_c_zero\":" + string(json_zkProof_c_0) +
		",\"prodProofs\":" + string(json_prodProofs) + "}"

	return C.CString(jsonResult)
}

//export pyParseRandomUnbatched
func pyParseRandomUnbatched(json_SRS_Pk *C.char, json_commitmentlist *C.char, json_prooflist *C.char, t int, my_id int) *C.char {
	var SRS_pk kzg_ped.ProvingKey
	_ = json.Unmarshal([]byte(C.GoString(json_SRS_Pk)), &SRS_pk)

	var commitmentList []kzg_ped.Digest
	if err := json.Unmarshal([]byte(C.GoString(json_commitmentlist)), &commitmentList); err != nil || len(commitmentList) == 0 {
		fmt.Println("Error: json_commitmentlist is null or empty")
		return C.CString(`{"error": "json_commitmentlist is null or empty"}`)
	}

	var prooflist []kzg_ped.OpeningProof
	if err := json.Unmarshal([]byte(C.GoString(json_prooflist)), &prooflist); err != nil || len(prooflist) == 0 {
		fmt.Println("Error: json_prooflist is null or empty")
		return C.CString(`{"error": "json_prooflist is null or empty"}`)
	}

	batchsize := len(commitmentList) / 2

	secretC := make([]fr.Element, batchsize)
	for i := 0; i < batchsize; i++ {
		secretC[i].Mul(&prooflist[i].ClaimedValue, &prooflist[i+batchsize].ClaimedValue)
	}

	polynomialList, polynomialListAux := samplepolynomial(secretC, batchsize, t)

	cCommitments := make([]kzg_ped.Digest, batchsize)
	cZeroProof := make([]kzg_ped.OpeningProof, batchsize)
	for i := 0; i < batchsize; i++ {
		cCommitments[i], _ = kzg_ped.Commit(polynomialList[i], polynomialListAux[i], SRS_pk)
		cZeroProof[i], _ = kzg_ped.OpenZero(polynomialList[i], polynomialListAux[i], SRS_pk)
	}

	n := resolveN(t)
	cProofs := openAllSequential(polynomialList, polynomialListAux, n, SRS_pk)
	zkProofAB, zkProofCZero, prodProofs := HiddenEvalcomputeUnbatched(SRS_pk, prooflist, cZeroProof, commitmentList, cCommitments, my_id)

	jsonCCommitments, _ := json.Marshal(cCommitments)
	jsonCProofs, _ := json.Marshal(cProofs)
	jsonZkProofAB, _ := json.Marshal(zkProofAB)
	jsonZkProofCZero, _ := json.Marshal(zkProofCZero)
	jsonProdProofs, _ := json.Marshal(prodProofs)
	log.Println("unbatched prodProofs size = ", len(jsonProdProofs))
	log.Println("unbatched prodProofs count = ", len(prodProofs))

	jsonResult := "{\"commitments_c\":" + string(jsonCCommitments) +
		",\"proofs_c\":" + string(jsonCProofs) +
		",\"zkProof_ab\":" + string(jsonZkProofAB) +
		",\"zkProof_c_zero\":" + string(jsonZkProofCZero) +
		",\"prodProofs\":" + string(jsonProdProofs) + "}"

	return C.CString(jsonResult)
}

func deriveLegacyChallenge(commitmentJSON []byte) (fr.Element, error) {
	var comList []kzg_ped.Digest
	if err := json.Unmarshal(commitmentJSON, &comList); err != nil {
		return fr.Element{}, fmt.Errorf("invalid commitment list: %w", err)
	}

	// Preserve the historical behavior exactly: decode the caller's list,
	// marshal it with encoding/json, then reduce SHA-256 into Fr.
	input, _ := json.Marshal(comList)
	hash := sha256.Sum256(input)

	var gamma fr.Element
	gamma.SetBytes(hash[:])
	return gamma, nil
}

//export pyDeriveChallenge
func pyDeriveChallenge(json_commitment *C.char) *C.char {
	gamma, err := deriveLegacyChallenge([]byte(C.GoString(json_commitment)))
	if err != nil {
		return C.CString(`{"error": "invalid commitment list"}`)
	}

	// fr.Element 没有 MarshalText 方法，直接转换为字符串返回
	return C.CString(gamma.String())
}

const (
	challengeContextVersion uint32 = 1
	aggEvalDomain                  = "AggEval"
	ipaKZGDomain                   = "IPAKZG"
)

// AggEvalChallengeContext is the typed Fiat-Shamir context for Fig. 5's
// aggregated public evaluation. Field points are decimal Fr strings so the
// JSON boundary cannot silently lose precision.
type AggEvalChallengeContext struct {
	Version        uint32           `json:"version"`
	Domain         string           `json:"domain"`
	OldPoint       string           `json:"old_point"`
	FreshPoint     string           `json:"fresh_point"`
	OldCommitments []kzg_ped.Digest `json:"old_commitments"`
	NewCommitments []kzg_ped.Digest `json:"new_commitments"`
}

// IPAKZGChallengeContext binds all three KZG vectors and all three
// element-wise Pedersen commitment vectors used by AggPedVerEval.
type IPAKZGChallengeContext struct {
	Version           uint32           `json:"version"`
	Domain            string           `json:"domain"`
	LeftPoint         string           `json:"left_point"`
	RightPoint        string           `json:"right_point"`
	OutputPoint       string           `json:"output_point"`
	LeftCommitments   []kzg_ped.Digest `json:"left_commitments"`
	RightCommitments  []kzg_ped.Digest `json:"right_commitments"`
	OutputCommitments []kzg_ped.Digest `json:"output_commitments"`
	LeftPedersen      []curve.G1Affine `json:"left_pedersen"`
	RightPedersen     []curve.G1Affine `json:"right_pedersen"`
	OutputPedersen    []curve.G1Affine `json:"output_pedersen"`
}

func decodeStrictJSON(input []byte, target interface{}) error {
	decoder := json.NewDecoder(bytes.NewReader(input))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return err
	}
	var trailing interface{}
	if err := decoder.Decode(&trailing); err != io.EOF {
		if err == nil {
			return fmt.Errorf("multiple JSON values")
		}
		return err
	}
	return nil
}

func writeCanonicalUint32(buffer *bytes.Buffer, value uint32) {
	var encoded [4]byte
	binary.BigEndian.PutUint32(encoded[:], value)
	buffer.Write(encoded[:])
}

func writeCanonicalBytes(buffer *bytes.Buffer, value []byte) {
	writeCanonicalUint32(buffer, uint32(len(value)))
	buffer.Write(value)
}

func writeCanonicalString(buffer *bytes.Buffer, value string) {
	writeCanonicalBytes(buffer, []byte(value))
}

func validateG1(point *curve.G1Affine, label string) error {
	if !point.IsOnCurve() {
		return fmt.Errorf("%s is not on G1", label)
	}
	if !point.IsInSubGroup() {
		return fmt.Errorf("%s is not in the G1 subgroup", label)
	}
	return nil
}

func validateG2(point *curve.G2Affine, label string) error {
	if !point.IsOnCurve() {
		return fmt.Errorf("%s is not on G2", label)
	}
	if !point.IsInSubGroup() {
		return fmt.Errorf("%s is not in the G2 subgroup", label)
	}
	return nil
}

func writeCanonicalG1(buffer *bytes.Buffer, point *curve.G1Affine, label string) error {
	if err := validateG1(point, label); err != nil {
		return err
	}
	encoded := point.Bytes()
	buffer.Write(encoded[:])
	return nil
}

func writeCanonicalG2(buffer *bytes.Buffer, point *curve.G2Affine, label string) error {
	if err := validateG2(point, label); err != nil {
		return err
	}
	encoded := point.Bytes()
	buffer.Write(encoded[:])
	return nil
}

func writeCanonicalG1Vector(buffer *bytes.Buffer, points []curve.G1Affine, label string) error {
	writeCanonicalUint32(buffer, uint32(len(points)))
	for index := range points {
		if err := writeCanonicalG1(buffer, &points[index], fmt.Sprintf("%s[%d]", label, index)); err != nil {
			return err
		}
	}
	return nil
}

func parseCanonicalFieldScalar(value string, label string) (fr.Element, error) {
	if value == "" {
		return fr.Element{}, fmt.Errorf("%s is empty", label)
	}
	if value == "0" {
		return fr.Element{}, nil
	}
	if value[0] < '1' || value[0] > '9' {
		return fr.Element{}, fmt.Errorf("%s is not a canonical non-negative decimal scalar", label)
	}
	for index := 1; index < len(value); index++ {
		if value[index] < '0' || value[index] > '9' {
			return fr.Element{}, fmt.Errorf("%s is not a canonical non-negative decimal scalar", label)
		}
	}
	integer, ok := new(big.Int).SetString(value, 10)
	if !ok || integer.Sign() < 0 || integer.Cmp(fr.Modulus()) >= 0 {
		return fr.Element{}, fmt.Errorf("%s is outside the scalar field", label)
	}
	var scalar fr.Element
	scalar.SetBigInt(integer)
	return scalar, nil
}

func parseFieldPoint(value string, label string) (fr.Element, error) {
	return parseCanonicalFieldScalar(value, label)
}

func canonicalFieldString(value *fr.Element) string {
	var integer big.Int
	value.BigInt(&integer)
	return integer.String()
}

func writeCanonicalField(buffer *bytes.Buffer, point *fr.Element) {
	encoded := point.Bytes()
	buffer.Write(encoded[:])
}

type parsedPublicParameters struct {
	ProvingKey   kzg_ped.ProvingKey
	VerifyingKey kzg_ped.VerifyingKey
	Digest       [sha256.Size]byte
}

func parsePublicParameters(provingKeyJSON, verifyingKeyJSON []byte) (parsedPublicParameters, error) {
	var provingKey kzg_ped.ProvingKey
	if err := decodeStrictJSON(provingKeyJSON, &provingKey); err != nil {
		return parsedPublicParameters{}, fmt.Errorf("invalid proving key: %w", err)
	}
	var verifyingKey kzg_ped.VerifyingKey
	if err := decodeStrictJSON(verifyingKeyJSON, &verifyingKey); err != nil {
		return parsedPublicParameters{}, fmt.Errorf("invalid verifying key: %w", err)
	}
	if len(provingKey.G1_g) == 0 || len(provingKey.G1_g) != len(provingKey.G1_h) {
		return parsedPublicParameters{}, fmt.Errorf("proving key G1 vectors must be non-empty and equal length")
	}

	var canonical bytes.Buffer
	writeCanonicalString(&canonical, "Continuum-MPC/SP/v1")
	if err := writeCanonicalG1Vector(&canonical, provingKey.G1_g, "Pk.G1_g"); err != nil {
		return parsedPublicParameters{}, err
	}
	if err := writeCanonicalG1Vector(&canonical, provingKey.G1_h, "Pk.G1_h"); err != nil {
		return parsedPublicParameters{}, err
	}
	writeCanonicalUint32(&canonical, uint32(len(verifyingKey.G2)))
	for index := range verifyingKey.G2 {
		if err := writeCanonicalG2(&canonical, &verifyingKey.G2[index], fmt.Sprintf("Vk.G2[%d]", index)); err != nil {
			return parsedPublicParameters{}, err
		}
	}
	if err := writeCanonicalG1(&canonical, &verifyingKey.G1_g, "Vk.G1_g"); err != nil {
		return parsedPublicParameters{}, err
	}
	if err := writeCanonicalG1(&canonical, &verifyingKey.G1_h, "Vk.G1_h"); err != nil {
		return parsedPublicParameters{}, err
	}
	if provingKey.G1_g[0].IsInfinity() || provingKey.G1_h[0].IsInfinity() ||
		verifyingKey.G1_g.IsInfinity() || verifyingKey.G1_h.IsInfinity() ||
		verifyingKey.G2[0].IsInfinity() || verifyingKey.G2[1].IsInfinity() {
		return parsedPublicParameters{}, fmt.Errorf("public parameter generators must not be infinity")
	}
	if !provingKey.G1_g[0].Equal(&verifyingKey.G1_g) ||
		!provingKey.G1_h[0].Equal(&verifyingKey.G1_h) {
		return parsedPublicParameters{}, fmt.Errorf("proving and verifying key G1 bases do not match")
	}
	return parsedPublicParameters{
		ProvingKey: provingKey, VerifyingKey: verifyingKey,
		Digest: sha256.Sum256(canonical.Bytes()),
	}, nil
}

func publicParametersDigest(provingKeyJSON, verifyingKeyJSON []byte) ([sha256.Size]byte, error) {
	parameters, err := parsePublicParameters(provingKeyJSON, verifyingKeyJSON)
	if err != nil {
		return [sha256.Size]byte{}, err
	}
	return parameters.Digest, nil
}

func validateChallengeHeader(version uint32, domain, expectedDomain string) error {
	if version != challengeContextVersion {
		return fmt.Errorf("unsupported context version %d", version)
	}
	if domain != expectedDomain {
		return fmt.Errorf("invalid domain %q; expected %q", domain, expectedDomain)
	}
	return nil
}

func hashCanonicalChallenge(canonical *bytes.Buffer) fr.Element {
	digest := sha256.Sum256(canonical.Bytes())
	var challenge fr.Element
	challenge.SetBytes(digest[:])
	return challenge
}

type parsedAggEvalContext struct {
	Context    AggEvalChallengeContext
	OldPoint   fr.Element
	FreshPoint fr.Element
	Canonical  []byte
}

func parseAggEvalContext(spDigest [sha256.Size]byte, contextJSON []byte) (parsedAggEvalContext, error) {
	var context AggEvalChallengeContext
	if err := decodeStrictJSON(contextJSON, &context); err != nil {
		return parsedAggEvalContext{}, fmt.Errorf("invalid AggEval context: %w", err)
	}
	if err := validateChallengeHeader(context.Version, context.Domain, aggEvalDomain); err != nil {
		return parsedAggEvalContext{}, err
	}
	if len(context.OldCommitments) == 0 || len(context.OldCommitments) != len(context.NewCommitments) {
		return parsedAggEvalContext{}, fmt.Errorf("AggEval commitment vectors must have the same non-zero length")
	}
	oldPoint, err := parseFieldPoint(context.OldPoint, "old_point")
	if err != nil {
		return parsedAggEvalContext{}, err
	}
	freshPoint, err := parseFieldPoint(context.FreshPoint, "fresh_point")
	if err != nil {
		return parsedAggEvalContext{}, err
	}

	var canonical bytes.Buffer
	writeCanonicalString(&canonical, "Continuum-MPC/Fiat-Shamir/v1")
	writeCanonicalString(&canonical, context.Domain)
	writeCanonicalUint32(&canonical, context.Version)
	writeCanonicalBytes(&canonical, spDigest[:])
	writeCanonicalField(&canonical, &oldPoint)
	writeCanonicalField(&canonical, &freshPoint)
	if err := writeCanonicalG1Vector(&canonical, context.OldCommitments, "old_commitments"); err != nil {
		return parsedAggEvalContext{}, err
	}
	if err := writeCanonicalG1Vector(&canonical, context.NewCommitments, "new_commitments"); err != nil {
		return parsedAggEvalContext{}, err
	}
	return parsedAggEvalContext{
		Context: context, OldPoint: oldPoint, FreshPoint: freshPoint,
		Canonical: append([]byte(nil), canonical.Bytes()...),
	}, nil
}

type parsedIPAKZGContext struct {
	Context     IPAKZGChallengeContext
	LeftPoint   fr.Element
	RightPoint  fr.Element
	OutputPoint fr.Element
	Canonical   []byte
}

func parseIPAKZGContext(spDigest [sha256.Size]byte, contextJSON []byte) (parsedIPAKZGContext, error) {
	var context IPAKZGChallengeContext
	if err := decodeStrictJSON(contextJSON, &context); err != nil {
		return parsedIPAKZGContext{}, fmt.Errorf("invalid IPAKZG context: %w", err)
	}
	if err := validateChallengeHeader(context.Version, context.Domain, ipaKZGDomain); err != nil {
		return parsedIPAKZGContext{}, err
	}
	batchSize := len(context.LeftCommitments)
	lengths := []int{
		batchSize, len(context.RightCommitments), len(context.OutputCommitments),
		len(context.LeftPedersen), len(context.RightPedersen), len(context.OutputPedersen),
	}
	if batchSize == 0 {
		return parsedIPAKZGContext{}, fmt.Errorf("IPAKZG vectors must not be empty")
	}
	for _, length := range lengths[1:] {
		if length != batchSize {
			return parsedIPAKZGContext{}, fmt.Errorf("all IPAKZG vectors must have the same length")
		}
	}
	leftPoint, err := parseFieldPoint(context.LeftPoint, "left_point")
	if err != nil {
		return parsedIPAKZGContext{}, err
	}
	rightPoint, err := parseFieldPoint(context.RightPoint, "right_point")
	if err != nil {
		return parsedIPAKZGContext{}, err
	}
	outputPoint, err := parseFieldPoint(context.OutputPoint, "output_point")
	if err != nil {
		return parsedIPAKZGContext{}, err
	}

	var canonical bytes.Buffer
	writeCanonicalString(&canonical, "Continuum-MPC/Fiat-Shamir/v1")
	writeCanonicalString(&canonical, context.Domain)
	writeCanonicalUint32(&canonical, context.Version)
	writeCanonicalBytes(&canonical, spDigest[:])
	writeCanonicalField(&canonical, &leftPoint)
	writeCanonicalField(&canonical, &rightPoint)
	writeCanonicalField(&canonical, &outputPoint)
	if err := writeCanonicalG1Vector(&canonical, context.LeftCommitments, "left_commitments"); err != nil {
		return parsedIPAKZGContext{}, err
	}
	if err := writeCanonicalG1Vector(&canonical, context.RightCommitments, "right_commitments"); err != nil {
		return parsedIPAKZGContext{}, err
	}
	if err := writeCanonicalG1Vector(&canonical, context.OutputCommitments, "output_commitments"); err != nil {
		return parsedIPAKZGContext{}, err
	}
	if err := writeCanonicalG1Vector(&canonical, context.LeftPedersen, "left_pedersen"); err != nil {
		return parsedIPAKZGContext{}, err
	}
	if err := writeCanonicalG1Vector(&canonical, context.RightPedersen, "right_pedersen"); err != nil {
		return parsedIPAKZGContext{}, err
	}
	if err := writeCanonicalG1Vector(&canonical, context.OutputPedersen, "output_pedersen"); err != nil {
		return parsedIPAKZGContext{}, err
	}
	return parsedIPAKZGContext{
		Context: context, LeftPoint: leftPoint, RightPoint: rightPoint,
		OutputPoint: outputPoint, Canonical: append([]byte(nil), canonical.Bytes()...),
	}, nil
}

func deriveAggEvalChallengeWithParameters(parameters parsedPublicParameters, contextJSON []byte) (fr.Element, error) {
	context, err := parseAggEvalContext(parameters.Digest, contextJSON)
	if err != nil {
		return fr.Element{}, err
	}
	canonical := bytes.NewBuffer(context.Canonical)
	return hashCanonicalChallenge(canonical), nil
}

func deriveAggEvalChallenge(provingKeyJSON, verifyingKeyJSON, contextJSON []byte) (fr.Element, error) {
	parameters, err := parsePublicParameters(provingKeyJSON, verifyingKeyJSON)
	if err != nil {
		return fr.Element{}, err
	}
	return deriveAggEvalChallengeWithParameters(parameters, contextJSON)
}

func deriveIPAKZGChallengeWithParameters(parameters parsedPublicParameters, contextJSON []byte) (fr.Element, error) {
	context, err := parseIPAKZGContext(parameters.Digest, contextJSON)
	if err != nil {
		return fr.Element{}, err
	}
	canonical := bytes.NewBuffer(context.Canonical)
	return hashCanonicalChallenge(canonical), nil
}

func deriveIPAKZGChallenge(provingKeyJSON, verifyingKeyJSON, contextJSON []byte) (fr.Element, error) {
	parameters, err := parsePublicParameters(provingKeyJSON, verifyingKeyJSON)
	if err != nil {
		return fr.Element{}, err
	}
	return deriveIPAKZGChallengeWithParameters(parameters, contextJSON)
}

func challengeResult(challenge fr.Element, err error) *C.char {
	if err == nil {
		return C.CString(canonicalFieldString(&challenge))
	}
	encoded, _ := json.Marshal(map[string]string{"error": err.Error()})
	return C.CString(string(encoded))
}

func jsonErrorResult(err error) *C.char {
	encoded, _ := json.Marshal(map[string]string{"error": err.Error()})
	return C.CString(string(encoded))
}

//export pyDeriveAggEvalChallenge
func pyDeriveAggEvalChallenge(json_SRS_Pk, json_SRS_Vk, json_context *C.char) *C.char {
	challenge, err := deriveAggEvalChallenge(
		[]byte(C.GoString(json_SRS_Pk)),
		[]byte(C.GoString(json_SRS_Vk)),
		[]byte(C.GoString(json_context)),
	)
	return challengeResult(challenge, err)
}

//export pyDeriveIPAKZGChallenge
func pyDeriveIPAKZGChallenge(json_SRS_Pk, json_SRS_Vk, json_context *C.char) *C.char {
	challenge, err := deriveIPAKZGChallenge(
		[]byte(C.GoString(json_SRS_Pk)),
		[]byte(C.GoString(json_SRS_Vk)),
		[]byte(C.GoString(json_context)),
	)
	return challengeResult(challenge, err)
}

// PokPedProof is a Schnorr proof of knowledge of a Pedersen representation
// T = value*G + valueAux*H. Scalars use a dedicated wire type below so the
// FFI rejects non-canonical decimal encodings instead of silently reducing.
type PokPedProof struct {
	A    curve.G1Affine
	Z    fr.Element
	ZHat fr.Element
}

type pokPedProofWire struct {
	A    *curve.G1Affine `json:"A"`
	Z    string          `json:"z"`
	ZHat string          `json:"z_hat"`
}

type aggOpeningWire struct {
	H               curve.G1Affine `json:"H"`
	ClaimedValue    string         `json:"ClaimedValue"`
	ClaimedValueAux string         `json:"ClaimedValueAux"`
}

type aggPubProofWire struct {
	T      *curve.G1Affine `json:"T"`
	W      *curve.G1Affine `json:"W"`
	PokPed pokPedProofWire `json:"pokPed"`
}

// aggPubBatchProofWire is the AggTrans wire proof produced from the old and
// fresh opening vectors in one native call. It carries exactly the same
// protocol fields as the former Python composition; only the local execution
// boundary changes so the context and Fiat-Shamir challenge are parsed once.
type aggPubBatchProofWire struct {
	T      *curve.G1Affine `json:"T"`
	WOld   *curve.G1Affine `json:"W_old"`
	WNew   *curve.G1Affine `json:"W_new"`
	PokPed pokPedProofWire `json:"pokPed"`
}

type aggPubProof struct {
	T      curve.G1Affine
	W      curve.G1Affine
	PokPed PokPedProof
}

type aggPubBatchProof struct {
	T      curve.G1Affine
	WOld   curve.G1Affine
	WNew   curve.G1Affine
	PokPed PokPedProof
}

const (
	ipaKZGLeftValidMask C.int = 1 << iota
	ipaKZGRightValidMask
	ipaKZGOutputValidMask
)

const (
	aggTransPokPedValidMask C.int = 1 << iota
	aggTransFreshValidMask
	aggTransOldValidMask
)

func pokPedProofToWire(proof PokPedProof) pokPedProofWire {
	return pokPedProofWire{
		A: &proof.A, Z: canonicalFieldString(&proof.Z),
		ZHat: canonicalFieldString(&proof.ZHat),
	}
}

func pokPedProofFromWire(wire pokPedProofWire) (PokPedProof, error) {
	if wire.A == nil {
		return PokPedProof{}, fmt.Errorf("pokPed.A is required")
	}
	if err := validateG1(wire.A, "pokPed.A"); err != nil {
		return PokPedProof{}, err
	}
	z, err := parseCanonicalFieldScalar(wire.Z, "pokPed.z")
	if err != nil {
		return PokPedProof{}, err
	}
	zHat, err := parseCanonicalFieldScalar(wire.ZHat, "pokPed.z_hat")
	if err != nil {
		return PokPedProof{}, err
	}
	return PokPedProof{A: *wire.A, Z: z, ZHat: zHat}, nil
}

func decodeG1(input []byte, label string) (curve.G1Affine, error) {
	var point curve.G1Affine
	if err := decodeStrictJSON(input, &point); err != nil {
		return curve.G1Affine{}, fmt.Errorf("invalid %s: %w", label, err)
	}
	if err := validateG1(&point, label); err != nil {
		return curve.G1Affine{}, err
	}
	return point, nil
}

func decodeG1Vector(input []byte, label string) ([]curve.G1Affine, error) {
	var points []curve.G1Affine
	if err := decodeStrictJSON(input, &points); err != nil {
		return nil, fmt.Errorf("invalid %s: %w", label, err)
	}
	if len(points) == 0 {
		return nil, fmt.Errorf("%s must not be empty", label)
	}
	for index := range points {
		if err := validateG1(&points[index], fmt.Sprintf("%s[%d]", label, index)); err != nil {
			return nil, err
		}
	}
	return points, nil
}

func decodeOpeningVector(input []byte) ([]aggOpeningWire, error) {
	var openings []aggOpeningWire
	if err := decodeStrictJSON(input, &openings); err != nil {
		return nil, fmt.Errorf("invalid evaluation openings: %w", err)
	}
	if len(openings) == 0 {
		return nil, fmt.Errorf("evaluation openings must not be empty")
	}
	for index := range openings {
		if err := validateG1(&openings[index].H, fmt.Sprintf("openings[%d].H", index)); err != nil {
			return nil, err
		}
		if _, err := parseCanonicalFieldScalar(openings[index].ClaimedValue, fmt.Sprintf("openings[%d].ClaimedValue", index)); err != nil {
			return nil, err
		}
		if _, err := parseCanonicalFieldScalar(openings[index].ClaimedValueAux, fmt.Sprintf("openings[%d].ClaimedValueAux", index)); err != nil {
			return nil, err
		}
	}
	return openings, nil
}

func randomFieldScalar(reader io.Reader) (fr.Element, error) {
	integer, err := cryptorand.Int(reader, fr.Modulus())
	if err != nil {
		return fr.Element{}, fmt.Errorf("sample Fr randomness: %w", err)
	}
	var scalar fr.Element
	scalar.SetBigInt(integer)
	return scalar, nil
}

func pedersenCommitment(g, h *curve.G1Affine, value, valueAux *fr.Element) (curve.G1Affine, error) {
	points := []curve.G1Affine{*g, *h}
	scalars := []fr.Element{*value, *valueAux}
	var commitment curve.G1Affine
	if _, err := commitment.MultiExp(points, scalars, ecc.MultiExpConfig{}); err != nil {
		return curve.G1Affine{}, err
	}
	return commitment, nil
}

func pokPedChallenge(canonicalContext []byte, statement, announcement *curve.G1Affine) (fr.Element, error) {
	var transcript bytes.Buffer
	writeCanonicalString(&transcript, "Continuum-MPC/pokPed/v1")
	writeCanonicalBytes(&transcript, canonicalContext)
	if err := writeCanonicalG1(&transcript, statement, "pokPed.T"); err != nil {
		return fr.Element{}, err
	}
	if err := writeCanonicalG1(&transcript, announcement, "pokPed.A"); err != nil {
		return fr.Element{}, err
	}
	return hashCanonicalChallenge(&transcript), nil
}

func pokPedProveWithReader(
	parameters parsedPublicParameters,
	context parsedAggEvalContext,
	statement curve.G1Affine,
	value, valueAux fr.Element,
	randomness io.Reader,
) (PokPedProof, error) {
	if randomness == nil {
		return PokPedProof{}, fmt.Errorf("pokPed randomness reader is nil")
	}
	if err := validateG1(&statement, "pokPed.T"); err != nil {
		return PokPedProof{}, err
	}
	expected, err := pedersenCommitment(
		&parameters.VerifyingKey.G1_g, &parameters.VerifyingKey.G1_h,
		&value, &valueAux,
	)
	if err != nil {
		return PokPedProof{}, err
	}
	if !expected.Equal(&statement) {
		return PokPedProof{}, fmt.Errorf("pokPed witness does not open T")
	}
	randomValue, err := randomFieldScalar(randomness)
	if err != nil {
		return PokPedProof{}, err
	}
	randomValueAux, err := randomFieldScalar(randomness)
	if err != nil {
		return PokPedProof{}, err
	}
	announcement, err := pedersenCommitment(
		&parameters.VerifyingKey.G1_g, &parameters.VerifyingKey.G1_h,
		&randomValue, &randomValueAux,
	)
	if err != nil {
		return PokPedProof{}, err
	}
	challenge, err := pokPedChallenge(context.Canonical, &statement, &announcement)
	if err != nil {
		return PokPedProof{}, err
	}
	var challengeValue, challengeValueAux, z, zHat fr.Element
	challengeValue.Mul(&challenge, &value)
	challengeValueAux.Mul(&challenge, &valueAux)
	z.Add(&randomValue, &challengeValue)
	zHat.Add(&randomValueAux, &challengeValueAux)
	return PokPedProof{A: announcement, Z: z, ZHat: zHat}, nil
}

func pokPedVerify(
	parameters parsedPublicParameters,
	context parsedAggEvalContext,
	statement curve.G1Affine,
	proof PokPedProof,
) bool {
	if validateG1(&statement, "pokPed.T") != nil || validateG1(&proof.A, "pokPed.A") != nil {
		return false
	}
	challenge, err := pokPedChallenge(context.Canonical, &statement, &proof.A)
	if err != nil {
		return false
	}
	left, err := pedersenCommitment(
		&parameters.VerifyingKey.G1_g, &parameters.VerifyingKey.G1_h,
		&proof.Z, &proof.ZHat,
	)
	if err != nil {
		return false
	}
	var challengeStatement, right curve.G1Affine
	var challengeBig big.Int
	challenge.BigInt(&challengeBig)
	challengeStatement.ScalarMultiplication(&statement, &challengeBig)
	right.Add(&proof.A, &challengeStatement)
	return left.Equal(&right)
}

func pointFromInt(point int) (fr.Element, error) {
	if point < 0 {
		return fr.Element{}, fmt.Errorf("evaluation point must be non-negative")
	}
	var result fr.Element
	result.SetInt64(int64(point))
	return result, nil
}

func pointToInt(point *fr.Element, label string) (int, error) {
	var integer big.Int
	point.BigInt(&integer)
	if !integer.IsInt64() {
		return 0, fmt.Errorf("%s does not fit the native evaluation-point interface", label)
	}
	value := integer.Int64()
	pointInt := int(value)
	if value < 0 || int64(pointInt) != value {
		return 0, fmt.Errorf("%s does not fit the native evaluation-point interface", label)
	}
	return pointInt, nil
}

func equalG1Vectors(left, right []curve.G1Affine) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if !left[index].Equal(&right[index]) {
			return false
		}
	}
	return true
}

func aggEvalRelationMatches(context parsedAggEvalContext, point fr.Element, commitments []curve.G1Affine) bool {
	oldMatches := point.Equal(&context.OldPoint) && equalG1Vectors(commitments, context.Context.OldCommitments)
	freshMatches := point.Equal(&context.FreshPoint) && equalG1Vectors(commitments, context.Context.NewCommitments)
	return oldMatches || freshMatches
}

func ipaKZGRelationMatches(
	context parsedIPAKZGContext,
	point fr.Element,
	commitments, pedersen []curve.G1Affine,
) bool {
	leftMatches := point.Equal(&context.LeftPoint) &&
		equalG1Vectors(commitments, context.Context.LeftCommitments) &&
		equalG1Vectors(pedersen, context.Context.LeftPedersen)
	rightMatches := point.Equal(&context.RightPoint) &&
		equalG1Vectors(commitments, context.Context.RightCommitments) &&
		equalG1Vectors(pedersen, context.Context.RightPedersen)
	outputMatches := point.Equal(&context.OutputPoint) &&
		equalG1Vectors(commitments, context.Context.OutputCommitments) &&
		equalG1Vectors(pedersen, context.Context.OutputPedersen)
	return leftMatches || rightMatches || outputMatches
}

func challengePowers(challenge fr.Element, length int) ([]fr.Element, error) {
	if length <= 0 {
		return nil, fmt.Errorf("aggregation vector must not be empty")
	}
	coefficients := make([]fr.Element, length)
	coefficients[0].SetOne()
	for index := 1; index < length; index++ {
		coefficients[index].Mul(&coefficients[index-1], &challenge)
	}
	return coefficients, nil
}

func aggregateG1(points []curve.G1Affine, coefficients []fr.Element, label string) (curve.G1Affine, error) {
	if len(points) == 0 || len(points) != len(coefficients) {
		return curve.G1Affine{}, fmt.Errorf("%s has invalid length", label)
	}
	for index := range points {
		if err := validateG1(&points[index], fmt.Sprintf("%s[%d]", label, index)); err != nil {
			return curve.G1Affine{}, err
		}
	}
	return aggregateValidatedG1(points, coefficients, label)
}

// aggregateValidatedG1 is used only with points already checked by a strict
// context/opening decoder. Keeping it separate avoids repeating expensive
// subgroup checks inside the batched Fig. 5 verification paths.
func aggregateValidatedG1(points []curve.G1Affine, coefficients []fr.Element, label string) (curve.G1Affine, error) {
	if len(points) == 0 || len(points) != len(coefficients) {
		return curve.G1Affine{}, fmt.Errorf("%s has invalid length", label)
	}
	var aggregate curve.G1Affine
	if _, err := aggregate.MultiExp(points, coefficients, ecc.MultiExpConfig{}); err != nil {
		return curve.G1Affine{}, err
	}
	return aggregate, nil
}

func aggregateOpeningVector(
	openings []aggOpeningWire,
	challenge fr.Element,
) (curve.G1Affine, fr.Element, fr.Element, error) {
	coefficients, err := challengePowers(challenge, len(openings))
	if err != nil {
		return curve.G1Affine{}, fr.Element{}, fr.Element{}, err
	}
	witnesses := make([]curve.G1Affine, len(openings))
	values := make([]fr.Element, len(openings))
	valuesAux := make([]fr.Element, len(openings))
	for index := range openings {
		witnesses[index] = openings[index].H
		values[index], err = parseCanonicalFieldScalar(openings[index].ClaimedValue, fmt.Sprintf("openings[%d].ClaimedValue", index))
		if err != nil {
			return curve.G1Affine{}, fr.Element{}, fr.Element{}, err
		}
		valuesAux[index], err = parseCanonicalFieldScalar(openings[index].ClaimedValueAux, fmt.Sprintf("openings[%d].ClaimedValueAux", index))
		if err != nil {
			return curve.G1Affine{}, fr.Element{}, fr.Element{}, err
		}
	}
	witness, err := aggregateG1(witnesses, coefficients, "evaluation witnesses")
	if err != nil {
		return curve.G1Affine{}, fr.Element{}, fr.Element{}, err
	}
	value := DotProductfrElement(values, coefficients)
	valueAux := DotProductfrElement(valuesAux, coefficients)
	return witness, value, valueAux, nil
}

// aggregateDecodedOpeningVector reuses coefficients and subgroup checks
// already completed by decodeOpeningVector. It is deliberately kept separate
// from aggregateOpeningVector, whose callers may provide in-memory points that
// have not crossed the strict FFI decoder.
func aggregateDecodedOpeningVector(
	openings []aggOpeningWire,
	coefficients []fr.Element,
) (curve.G1Affine, fr.Element, fr.Element, error) {
	if len(openings) == 0 || len(openings) != len(coefficients) {
		return curve.G1Affine{}, fr.Element{}, fr.Element{}, fmt.Errorf("decoded openings and coefficients must have the same non-zero length")
	}
	witnesses := make([]curve.G1Affine, len(openings))
	values := make([]fr.Element, len(openings))
	valuesAux := make([]fr.Element, len(openings))
	for index := range openings {
		witnesses[index] = openings[index].H
		var err error
		values[index], err = parseCanonicalFieldScalar(openings[index].ClaimedValue, fmt.Sprintf("openings[%d].ClaimedValue", index))
		if err != nil {
			return curve.G1Affine{}, fr.Element{}, fr.Element{}, err
		}
		valuesAux[index], err = parseCanonicalFieldScalar(openings[index].ClaimedValueAux, fmt.Sprintf("openings[%d].ClaimedValueAux", index))
		if err != nil {
			return curve.G1Affine{}, fr.Element{}, fr.Element{}, err
		}
	}
	witness, err := aggregateValidatedG1(witnesses, coefficients, "decoded evaluation witnesses")
	if err != nil {
		return curve.G1Affine{}, fr.Element{}, fr.Element{}, err
	}
	return witness, DotProductfrElement(values, coefficients),
		DotProductfrElement(valuesAux, coefficients), nil
}

func aggPubProEvalWithReader(
	parameters parsedPublicParameters,
	contextJSON []byte,
	commitments []curve.G1Affine,
	openings []aggOpeningWire,
	point int,
	randomness io.Reader,
) (aggPubProof, error) {
	context, err := parseAggEvalContext(parameters.Digest, contextJSON)
	if err != nil {
		return aggPubProof{}, err
	}
	if len(commitments) == 0 || len(commitments) != len(openings) || len(commitments) != len(context.Context.OldCommitments) {
		return aggPubProof{}, fmt.Errorf("commitments, openings, and context vectors must have the same non-zero length")
	}
	fieldPoint, err := pointFromInt(point)
	if err != nil {
		return aggPubProof{}, err
	}
	if !aggEvalRelationMatches(context, fieldPoint, commitments) {
		return aggPubProof{}, fmt.Errorf("commitments and evaluation point do not match AggEval context")
	}
	canonical := bytes.NewBuffer(context.Canonical)
	challenge := hashCanonicalChallenge(canonical)
	witness, value, valueAux, err := aggregateOpeningVector(openings, challenge)
	if err != nil {
		return aggPubProof{}, err
	}
	statement, err := pedersenCommitment(
		&parameters.VerifyingKey.G1_g, &parameters.VerifyingKey.G1_h,
		&value, &valueAux,
	)
	if err != nil {
		return aggPubProof{}, err
	}
	pok, err := pokPedProveWithReader(parameters, context, statement, value, valueAux, randomness)
	if err != nil {
		return aggPubProof{}, err
	}
	return aggPubProof{T: statement, W: witness, PokPed: pok}, nil
}

func aggPubProEvalBatch2WithReader(
	parameters parsedPublicParameters,
	contextJSON []byte,
	oldOpenings, freshOpenings []aggOpeningWire,
	randomness io.Reader,
) (aggPubBatchProof, error) {
	for label, openings := range map[string][]aggOpeningWire{
		"old openings": oldOpenings, "fresh openings": freshOpenings,
	} {
		for index := range openings {
			if err := validateG1(&openings[index].H, fmt.Sprintf("%s[%d].H", label, index)); err != nil {
				return aggPubBatchProof{}, err
			}
		}
	}
	return aggPubProEvalBatch2DecodedWithReader(
		parameters, contextJSON, oldOpenings, freshOpenings, randomness,
	)
}

func aggPubProEvalBatch2DecodedWithReader(
	parameters parsedPublicParameters,
	contextJSON []byte,
	oldOpenings, freshOpenings []aggOpeningWire,
	randomness io.Reader,
) (aggPubBatchProof, error) {
	context, err := parseAggEvalContext(parameters.Digest, contextJSON)
	if err != nil {
		return aggPubBatchProof{}, err
	}
	batchSize := len(context.Context.OldCommitments)
	if len(oldOpenings) != batchSize || len(freshOpenings) != batchSize {
		return aggPubBatchProof{}, fmt.Errorf("context and old/fresh openings must have the same non-zero length")
	}
	challenge := hashCanonicalChallenge(bytes.NewBuffer(context.Canonical))
	coefficients, err := challengePowers(challenge, batchSize)
	if err != nil {
		return aggPubBatchProof{}, err
	}
	oldWitness, oldValue, oldValueAux, err := aggregateDecodedOpeningVector(oldOpenings, coefficients)
	if err != nil {
		return aggPubBatchProof{}, err
	}
	freshWitness, freshValue, freshValueAux, err := aggregateDecodedOpeningVector(freshOpenings, coefficients)
	if err != nil {
		return aggPubBatchProof{}, err
	}
	if !oldValue.Equal(&freshValue) || !oldValueAux.Equal(&freshValueAux) {
		return aggPubBatchProof{}, fmt.Errorf("old and fresh aggregate openings produce different Pedersen claims")
	}
	statement, err := pedersenCommitment(
		&parameters.VerifyingKey.G1_g, &parameters.VerifyingKey.G1_h,
		&freshValue, &freshValueAux,
	)
	if err != nil {
		return aggPubBatchProof{}, err
	}
	pok, err := pokPedProveWithReader(
		parameters, context, statement, freshValue, freshValueAux, randomness,
	)
	if err != nil {
		return aggPubBatchProof{}, err
	}
	return aggPubBatchProof{
		T: statement, WOld: oldWitness, WNew: freshWitness, PokPed: pok,
	}, nil
}

func aggPubVerEvalBatch2(
	parameters parsedPublicParameters,
	contextJSON []byte,
	statement, oldWitness, freshWitness curve.G1Affine,
	pok PokPedProof,
) (C.int, error) {
	context, err := parseAggEvalContext(parameters.Digest, contextJSON)
	if err != nil {
		return 0, err
	}
	oldPoint, err := pointToInt(&context.OldPoint, "old_point")
	if err != nil {
		return 0, err
	}
	freshPoint, err := pointToInt(&context.FreshPoint, "fresh_point")
	if err != nil {
		return 0, err
	}
	challenge := hashCanonicalChallenge(bytes.NewBuffer(context.Canonical))
	coefficients, err := challengePowers(challenge, len(context.Context.OldCommitments))
	if err != nil {
		return 0, err
	}
	var result C.int
	if pokPedVerify(parameters, context, statement, pok) {
		result |= aggTransPokPedValidMask
	}
	if pubAggVerifyEvalCombinedWithCoefficients(
		parameters.VerifyingKey, context.Context.NewCommitments, freshPoint,
		statement, freshWitness, coefficients,
	) {
		result |= aggTransFreshValidMask
	}
	if pubAggVerifyEvalCombinedWithCoefficients(
		parameters.VerifyingKey, context.Context.OldCommitments, oldPoint,
		statement, oldWitness, coefficients,
	) {
		result |= aggTransOldValidMask
	}
	return result, nil
}

func aggPubVerEval(
	parameters parsedPublicParameters,
	contextJSON []byte,
	commitments []curve.G1Affine,
	point int,
	statement, witness curve.G1Affine,
	pok PokPedProof,
) bool {
	context, err := parseAggEvalContext(parameters.Digest, contextJSON)
	if err != nil || len(commitments) == 0 || len(commitments) != len(context.Context.OldCommitments) {
		return false
	}
	fieldPoint, err := pointFromInt(point)
	if err != nil || !aggEvalRelationMatches(context, fieldPoint, commitments) {
		return false
	}
	if validateG1(&witness, "aggregated witness") != nil || !pokPedVerify(parameters, context, statement, pok) {
		return false
	}
	canonical := bytes.NewBuffer(context.Canonical)
	challenge := hashCanonicalChallenge(canonical)
	return PubAggVerifyEvalCombined(
		parameters.VerifyingKey, commitments, point, statement, witness, challenge,
	)
}

func aggPedVerEval(
	parameters parsedPublicParameters,
	contextJSON []byte,
	commitments, pedersen []curve.G1Affine,
	point int,
	witness curve.G1Affine,
) (bool, error) {
	context, err := parseIPAKZGContext(parameters.Digest, contextJSON)
	if err != nil {
		return false, err
	}
	if len(commitments) == 0 || len(commitments) != len(pedersen) || len(commitments) != len(context.Context.LeftCommitments) {
		return false, fmt.Errorf("commitment and Pedersen vectors must have the same non-zero context length")
	}
	fieldPoint, err := pointFromInt(point)
	if err != nil {
		return false, err
	}
	if !ipaKZGRelationMatches(context, fieldPoint, commitments, pedersen) {
		return false, nil
	}
	if err := validateG1(&witness, "aggregated witness"); err != nil {
		return false, err
	}
	canonical := bytes.NewBuffer(context.Canonical)
	challenge := hashCanonicalChallenge(canonical)
	coefficients, err := challengePowers(challenge, len(pedersen))
	if err != nil {
		return false, err
	}
	statement, err := aggregateG1(pedersen, coefficients, "Pedersen commitments")
	if err != nil {
		return false, err
	}
	return PubAggVerifyEvalCombined(
		parameters.VerifyingKey, commitments, point, statement, witness, challenge,
	), nil
}

func aggPedVerEvalBatch3(
	parameters parsedPublicParameters,
	contextJSON []byte,
	leftWitness, rightWitness, outputWitness curve.G1Affine,
) (C.int, error) {
	context, err := parseIPAKZGContext(parameters.Digest, contextJSON)
	if err != nil {
		return 0, err
	}
	leftPoint, err := pointToInt(&context.LeftPoint, "left_point")
	if err != nil {
		return 0, err
	}
	rightPoint, err := pointToInt(&context.RightPoint, "right_point")
	if err != nil {
		return 0, err
	}
	outputPoint, err := pointToInt(&context.OutputPoint, "output_point")
	if err != nil {
		return 0, err
	}
	challenge := hashCanonicalChallenge(bytes.NewBuffer(context.Canonical))
	coefficients, err := challengePowers(challenge, len(context.Context.LeftCommitments))
	if err != nil {
		return 0, err
	}
	leftStatement, err := aggregateValidatedG1(
		context.Context.LeftPedersen, coefficients, "left Pedersen commitments",
	)
	if err != nil {
		return 0, err
	}
	rightStatement, err := aggregateValidatedG1(
		context.Context.RightPedersen, coefficients, "right Pedersen commitments",
	)
	if err != nil {
		return 0, err
	}
	outputStatement, err := aggregateValidatedG1(
		context.Context.OutputPedersen, coefficients, "output Pedersen commitments",
	)
	if err != nil {
		return 0, err
	}
	var result C.int
	if pubAggVerifyEvalCombinedWithCoefficients(
		parameters.VerifyingKey, context.Context.LeftCommitments, leftPoint,
		leftStatement, leftWitness, coefficients,
	) {
		result |= ipaKZGLeftValidMask
	}
	if pubAggVerifyEvalCombinedWithCoefficients(
		parameters.VerifyingKey, context.Context.RightCommitments, rightPoint,
		rightStatement, rightWitness, coefficients,
	) {
		result |= ipaKZGRightValidMask
	}
	if pubAggVerifyEvalCombinedWithCoefficients(
		parameters.VerifyingKey, context.Context.OutputCommitments, outputPoint,
		outputStatement, outputWitness, coefficients,
	) {
		result |= ipaKZGOutputValidMask
	}
	return result, nil
}

//export pyPokPedProve
func pyPokPedProve(
	json_SRS_Pk, json_SRS_Vk, json_context, json_T, value, valueAux *C.char,
) *C.char {
	parameters, err := parsePublicParameters(
		[]byte(C.GoString(json_SRS_Pk)), []byte(C.GoString(json_SRS_Vk)),
	)
	if err != nil {
		return jsonErrorResult(err)
	}
	context, err := parseAggEvalContext(parameters.Digest, []byte(C.GoString(json_context)))
	if err != nil {
		return jsonErrorResult(err)
	}
	statement, err := decodeG1([]byte(C.GoString(json_T)), "pokPed.T")
	if err != nil {
		return jsonErrorResult(err)
	}
	parsedValue, err := parseCanonicalFieldScalar(C.GoString(value), "value")
	if err != nil {
		return jsonErrorResult(err)
	}
	parsedValueAux, err := parseCanonicalFieldScalar(C.GoString(valueAux), "value_aux")
	if err != nil {
		return jsonErrorResult(err)
	}
	proof, err := pokPedProveWithReader(
		parameters, context, statement, parsedValue, parsedValueAux, cryptorand.Reader,
	)
	if err != nil {
		return jsonErrorResult(err)
	}
	encoded, err := json.Marshal(pokPedProofToWire(proof))
	if err != nil {
		return jsonErrorResult(err)
	}
	return C.CString(string(encoded))
}

//export pyPokPedVerify
func pyPokPedVerify(
	json_SRS_Pk, json_SRS_Vk, json_context, json_T, json_proof *C.char,
) bool {
	parameters, err := parsePublicParameters(
		[]byte(C.GoString(json_SRS_Pk)), []byte(C.GoString(json_SRS_Vk)),
	)
	if err != nil {
		return false
	}
	context, err := parseAggEvalContext(parameters.Digest, []byte(C.GoString(json_context)))
	if err != nil {
		return false
	}
	statement, err := decodeG1([]byte(C.GoString(json_T)), "pokPed.T")
	if err != nil {
		return false
	}
	var proofWire pokPedProofWire
	if err := decodeStrictJSON([]byte(C.GoString(json_proof)), &proofWire); err != nil {
		return false
	}
	proof, err := pokPedProofFromWire(proofWire)
	return err == nil && pokPedVerify(parameters, context, statement, proof)
}

//export pyAggPubProEval
func pyAggPubProEval(
	json_SRS_Pk, json_SRS_Vk, json_context, json_commitments, json_openings *C.char,
	point int,
) *C.char {
	parameters, err := parsePublicParameters(
		[]byte(C.GoString(json_SRS_Pk)), []byte(C.GoString(json_SRS_Vk)),
	)
	if err != nil {
		return jsonErrorResult(err)
	}
	commitments, err := decodeG1Vector([]byte(C.GoString(json_commitments)), "commitments")
	if err != nil {
		return jsonErrorResult(err)
	}
	openings, err := decodeOpeningVector([]byte(C.GoString(json_openings)))
	if err != nil {
		return jsonErrorResult(err)
	}
	proof, err := aggPubProEvalWithReader(
		parameters, []byte(C.GoString(json_context)), commitments, openings, point, cryptorand.Reader,
	)
	if err != nil {
		return jsonErrorResult(err)
	}
	encoded, err := json.Marshal(aggPubProofWire{
		T: &proof.T, W: &proof.W, PokPed: pokPedProofToWire(proof.PokPed),
	})
	if err != nil {
		return jsonErrorResult(err)
	}
	return C.CString(string(encoded))
}

//export pyAggPubProEvalBatch2
func pyAggPubProEvalBatch2(
	json_SRS_Pk, json_SRS_Vk, json_context,
	json_old_openings, json_fresh_openings *C.char,
) *C.char {
	parameters, err := parsePublicParameters(
		[]byte(C.GoString(json_SRS_Pk)), []byte(C.GoString(json_SRS_Vk)),
	)
	if err != nil {
		return jsonErrorResult(err)
	}
	oldOpenings, err := decodeOpeningVector([]byte(C.GoString(json_old_openings)))
	if err != nil {
		return jsonErrorResult(fmt.Errorf("old openings: %w", err))
	}
	freshOpenings, err := decodeOpeningVector([]byte(C.GoString(json_fresh_openings)))
	if err != nil {
		return jsonErrorResult(fmt.Errorf("fresh openings: %w", err))
	}
	proof, err := aggPubProEvalBatch2DecodedWithReader(
		parameters, []byte(C.GoString(json_context)), oldOpenings, freshOpenings,
		cryptorand.Reader,
	)
	if err != nil {
		return jsonErrorResult(err)
	}
	encoded, err := json.Marshal(aggPubBatchProofWire{
		T: &proof.T, WOld: &proof.WOld, WNew: &proof.WNew,
		PokPed: pokPedProofToWire(proof.PokPed),
	})
	if err != nil {
		return jsonErrorResult(err)
	}
	return C.CString(string(encoded))
}

//export pyAggPubVerEval
func pyAggPubVerEval(
	json_SRS_Pk, json_SRS_Vk, json_context, json_commitments,
	json_T, json_W, json_pokPed *C.char,
	point int,
) bool {
	parameters, err := parsePublicParameters(
		[]byte(C.GoString(json_SRS_Pk)), []byte(C.GoString(json_SRS_Vk)),
	)
	if err != nil {
		return false
	}
	commitments, err := decodeG1Vector([]byte(C.GoString(json_commitments)), "commitments")
	if err != nil {
		return false
	}
	statement, err := decodeG1([]byte(C.GoString(json_T)), "T")
	if err != nil {
		return false
	}
	witness, err := decodeG1([]byte(C.GoString(json_W)), "W")
	if err != nil {
		return false
	}
	var proofWire pokPedProofWire
	if err := decodeStrictJSON([]byte(C.GoString(json_pokPed)), &proofWire); err != nil {
		return false
	}
	pok, err := pokPedProofFromWire(proofWire)
	return err == nil && aggPubVerEval(
		parameters, []byte(C.GoString(json_context)), commitments,
		point, statement, witness, pok,
	)
}

//export pyAggPubVerEvalBatch2
func pyAggPubVerEvalBatch2(
	json_SRS_Pk, json_SRS_Vk, json_context, json_T,
	json_W_old, json_W_new, json_pokPed *C.char,
) C.int {
	parameters, err := parsePublicParameters(
		[]byte(C.GoString(json_SRS_Pk)), []byte(C.GoString(json_SRS_Vk)),
	)
	if err != nil {
		return 0
	}
	statement, err := decodeG1([]byte(C.GoString(json_T)), "T")
	if err != nil {
		return 0
	}
	oldWitness, err := decodeG1([]byte(C.GoString(json_W_old)), "W_old")
	if err != nil {
		return 0
	}
	freshWitness, err := decodeG1([]byte(C.GoString(json_W_new)), "W_new")
	if err != nil {
		return 0
	}
	var proofWire pokPedProofWire
	if err := decodeStrictJSON([]byte(C.GoString(json_pokPed)), &proofWire); err != nil {
		return 0
	}
	pok, err := pokPedProofFromWire(proofWire)
	if err != nil {
		return 0
	}
	result, err := aggPubVerEvalBatch2(
		parameters, []byte(C.GoString(json_context)), statement,
		oldWitness, freshWitness, pok,
	)
	if err != nil {
		return 0
	}
	return result
}

//export pyAggPedVerEval
func pyAggPedVerEval(
	json_SRS_Pk, json_SRS_Vk, json_context, json_commitments,
	json_pedersen, json_W *C.char,
	point int,
) bool {
	parameters, err := parsePublicParameters(
		[]byte(C.GoString(json_SRS_Pk)), []byte(C.GoString(json_SRS_Vk)),
	)
	if err != nil {
		return false
	}
	commitments, err := decodeG1Vector([]byte(C.GoString(json_commitments)), "commitments")
	if err != nil {
		return false
	}
	pedersen, err := decodeG1Vector([]byte(C.GoString(json_pedersen)), "Pedersen commitments")
	if err != nil {
		return false
	}
	witness, err := decodeG1([]byte(C.GoString(json_W)), "W")
	if err != nil {
		return false
	}
	valid, err := aggPedVerEval(
		parameters, []byte(C.GoString(json_context)), commitments, pedersen, point, witness,
	)
	return err == nil && valid
}

//export pyAggPedVerEvalBatch3
func pyAggPedVerEvalBatch3(
	json_SRS_Pk, json_SRS_Vk, json_context,
	json_W_left, json_W_right, json_W_output *C.char,
) C.int {
	parameters, err := parsePublicParameters(
		[]byte(C.GoString(json_SRS_Pk)), []byte(C.GoString(json_SRS_Vk)),
	)
	if err != nil {
		return 0
	}
	leftWitness, err := decodeG1([]byte(C.GoString(json_W_left)), "W_left")
	if err != nil {
		return 0
	}
	rightWitness, err := decodeG1([]byte(C.GoString(json_W_right)), "W_right")
	if err != nil {
		return 0
	}
	outputWitness, err := decodeG1([]byte(C.GoString(json_W_output)), "W_output")
	if err != nil {
		return 0
	}
	result, err := aggPedVerEvalBatch3(
		parameters, []byte(C.GoString(json_context)),
		leftWitness, rightWitness, outputWitness,
	)
	if err != nil {
		return 0
	}
	return result
}

// deterministicCombine aggregates B opening proofs at the SAME evaluation
// point using a *deterministic* linear combination with respect to the
// challenge γ ∈ 𝔽.  It corresponds to line 106 of Algorithm 2 in the paper.
func deterministicCombine(
	commitments []kzg_ped.Digest,
	proofs []kzg_ped.OpeningProof,
	gamma fr.Element,
) (kzg_ped.Digest, kzg_ped.OpeningProof) {

	if len(commitments) != len(proofs) {
		panic("deterministicCombine: length mismatch")
	}
	B := len(commitments)

	// Pre‑compute γ⁰,…,γ^{B‑1}
	coeff := make([]fr.Element, B)
	coeff[0].SetOne()
	for i := 1; i < B; i++ {
		coeff[i].Mul(&coeff[i-1], &gamma)
	}

	// --- aggregate commitment and witness H with multi‑exp ---
	var aggCom curve.G1Affine
	var aggW curve.G1Affine
	wArr := make([]curve.G1Affine, B)
	for i := 0; i < B; i++ {
		wArr[i].Set(&proofs[i].H)
	}
	aggCom.MultiExp(commitments, coeff, ecc.MultiExpConfig{})
	aggW.MultiExp(wArr, coeff, ecc.MultiExpConfig{})

	// --- aggregate claimed values scalarly ---
	valArr := make([]fr.Element, B)
	valAuxArr := make([]fr.Element, B)
	for i := 0; i < B; i++ {
		valArr[i].Set(&proofs[i].ClaimedValue)
		valAuxArr[i].Set(&proofs[i].ClaimedValueAux)
	}
	aggVal := DotProductfrElement(valArr, coeff)
	aggValAux := DotProductfrElement(valAuxArr, coeff)

	// build aggregated proof
	var aggProof kzg_ped.OpeningProof
	aggProof.H.Set(&aggW)
	aggProof.ClaimedValue.Set(&aggVal)
	aggProof.ClaimedValueAux.Set(&aggValAux)

	return aggCom, aggProof
}

// aggregateWitnessAtZero aggregates the *witnesses at x = 0* (only the H part)
// using γ⁰, γ¹, … γ^{B‑1}.   It realises
//
//	W_agg = ∏_{i=1}^{B} (w_{i,0})^{γ^{i-1}}
//
// where the product is expressed in additive form on G1.
func aggregateWitnessAtZero(
	proofs []kzg_ped.OpeningProof,
	gamma fr.Element,
) curve.G1Affine {
	B := len(proofs)
	if B == 0 {
		var zero curve.G1Affine
		return zero
	}

	// γ^0 … γ^{B‑1}
	coef := make([]fr.Element, B)
	coef[0].SetOne()
	for i := 1; i < B; i++ {
		coef[i].Mul(&coef[i-1], &gamma)
	}

	wArr := make([]curve.G1Affine, B)
	for i := 0; i < B; i++ {
		wArr[i].Set(&proofs[i].H) // each w_{i,0}
	}

	var aggW curve.G1Affine
	aggW.MultiExp(wArr, coef, ecc.MultiExpConfig{}) // Σ γ^{i-1} · H_i
	return aggW
}

// PubAggVerifyEval verifies the aggregated opening proof produced by
// deterministicCombine / aggregateWitnessAtZero at a *public* evaluation
// point.  It recomputes the aggregated commitment using the deterministic
// γ‑powers and then runs a single pairing check analogously to Verify.
//
// Inputs:
//
//	vk            — the public verifying key (contains G2 generator & h2Gen)
//	commitments   — slice of commitments C_0 … C_{B-1}
//	pointIdx      — the evaluation point (0 for constant term, otherwise dealer index+1)
//	gClaim, hClaim— aggregated group elements g^{v} and h^{v_aux}
//	aggW          — aggregated witness  W_agg  = Σ γ^{i} · H_i
//	gamma         — the challenge γ used in deterministic aggregation
//
// Returns true iff the aggregated proof is valid.
func PubAggVerifyEval(
	vk kzg_ped.VerifyingKey,
	commitments []kzg_ped.Digest,
	pointIdx int,
	gClaim, hClaim curve.G1Affine,
	aggW curve.G1Affine,
	gamma fr.Element,
) bool {
	// Empty input is invalid
	if len(commitments) == 0 {
		return false
	}

	// ---------- 1) γ⁰,…,γ^{B-1} ----------
	B := len(commitments)
	coeff := make([]fr.Element, B)
	coeff[0].SetOne()
	for i := 1; i < B; i++ {
		coeff[i].Mul(&coeff[i-1], &gamma)
	}

	// ---------- 2) Aggregate commitment ----------
	var aggCom curve.G1Affine
	aggCom.MultiExp(commitments, coeff, ecc.MultiExpConfig{})

	// ---------- 3) Build LHS = C_agg − (G_claim + H_claim) ----------
	var sumGH curve.G1Affine
	sumGH.Add(&gClaim, &hClaim)

	var lhs curve.G1Affine
	lhs.Sub(&aggCom, &sumGH)

	// ---------- 4) RHS exponent in G2: h2Gen − g2Gen^{x} ----------
	g2Gen := vk.G2[0]
	h2Gen := vk.G2[1]

	var xBig big.Int
	xBig.SetInt64(int64(pointIdx))

	var g2x curve.G2Affine
	g2x.ScalarMultiplication(&g2Gen, &xBig)

	var rhsExpo curve.G2Affine
	rhsExpo.Sub(&h2Gen, &g2x)

	// ---------- 5) Final pairing check ----------
	var negW curve.G1Affine
	negW.Neg(&aggW)

	ok, _ := curve.PairingCheck(
		[]curve.G1Affine{lhs, negW},
		[]curve.G2Affine{g2Gen, rhsExpo},
	)

	return ok
}

// pyAggProveEvalZero(json_proofs, json_gamma) → {"aggH": {...}}
//
//export pyAggProveEvalZero
func pyAggProveEvalZero(json_proofs *C.char,
	json_gamma *C.char) *C.char {

	// --- decode proofs --------------------------------------------------------
	var proofList []kzg_ped.OpeningProof
	if err := json.Unmarshal([]byte(C.GoString(json_proofs)), &proofList); err != nil {
		return C.CString(`{"error":"invalid proofs"}`)
	}

	// --- decode γ -------------------------------------------------------------
	var gamma fr.Element
	s := C.GoString(json_gamma)
	var bigTmp big.Int
	if _, ok := bigTmp.SetString(s, 10); !ok {
		return C.CString(`{"error":"invalid gamma"}`)
	}
	gamma.SetBigInt(&bigTmp)

	// --- aggregate ------------------------------------------------------------
	aggW := aggregateWitnessAtZero(proofList, gamma)

	// --- marshal output -------------------------------------------------------
	// Wrap the aggregated point into a Digest for consistent JSON formatting
	// aggDigest := kzg_ped.Digest(aggW)
	// type out struct {
	// 	AggH kzg_ped.Digest `json:"aggH"`
	// }
	// j, _ := json.Marshal(out{AggH: aggDigest})
	// return C.CString(string(j))
	var xb, yb big.Int
	aggW.X.BigInt(&xb)
	aggW.Y.BigInt(&yb)

	outJSON := fmt.Sprintf(`{"aggH":{"X":"%s","Y":"%s"}}`, xb.String(), yb.String())
	return C.CString(outJSON)
}

// pyPubAggVerifyEval(vk, commitmentList, gClaim, hClaim, aggH, gamma, pointIdx) -> bool
//
//	vk               : VerifyingKey JSON
//	commitmentList   : []Digest JSON (same as serialized_commitment)
//	gClaim / hClaim  : Digest JSON  (single G1 point each)
//	aggH             : Digest JSON  (aggregated witness)
//	gamma            : decimal string
//	pointIdx         : evaluation point index (int)
//
// Returns C.bool(1) if verification passes, else 0.
//
//export pyPubAggVerifyEval
func pyPubAggVerifyEval(json_vk *C.char,
	json_commitments *C.char,
	json_gClaim *C.char,
	json_hClaim *C.char,
	json_aggH *C.char,
	json_gamma *C.char,
	pointIdx int,
) bool {

	// ---------- decode verifying key ----------
	var vk kzg_ped.VerifyingKey
	if err := json.Unmarshal([]byte(C.GoString(json_vk)), &vk); err != nil {
		return false
	}

	// ---------- decode commitments ----------
	var comList []kzg_ped.Digest
	if err := json.Unmarshal([]byte(C.GoString(json_commitments)), &comList); err != nil {
		return false
	}

	// helper to decode a single Digest JSON into curve.G1Affine
	decodePt := func(js *C.char) (curve.G1Affine, bool) {
		var d kzg_ped.Digest
		if err := json.Unmarshal([]byte(C.GoString(js)), &d); err != nil {
			return curve.G1Affine{}, false
		}
		return curve.G1Affine(d), true
	}

	gClaim, ok := decodePt(json_gClaim)
	if !ok {
		return false
	}
	hClaim, ok := decodePt(json_hClaim)
	if !ok {
		return false
	}
	aggW, ok := decodePt(json_aggH)
	if !ok {
		return false
	}

	// ---------- decode gamma ----------
	var gamma fr.Element
	var bigTmp big.Int
	if _, ok := bigTmp.SetString(C.GoString(json_gamma), 10); !ok {
		return false
	}
	gamma.SetBigInt(&bigTmp)

	// ---------- call verifier ----------
	okBool := PubAggVerifyEval(
		vk,
		comList,
		int(pointIdx),
		gClaim,
		hClaim,
		aggW,
		gamma,
	)

	// if okBool {
	// 	return true
	// }
	// return false
	return okBool
}

// PubAggVerifyEvalCombined verifies the aggregated opening proof using a pre-combined claim.
// It expects combinedClaim = g^v · h^{v_aux} already computed in G1.
func PubAggVerifyEvalCombined(
	vk kzg_ped.VerifyingKey,
	commitments []kzg_ped.Digest,
	pointIdx int,
	combinedClaim curve.G1Affine,
	aggW curve.G1Affine,
	gamma fr.Element,
) bool {
	if len(commitments) == 0 {
		return false
	}
	coeff, err := challengePowers(gamma, len(commitments))
	if err != nil {
		return false
	}
	return pubAggVerifyEvalCombinedWithCoefficients(
		vk, commitments, pointIdx, combinedClaim, aggW, coeff,
	)
}

// pubAggVerifyEvalCombinedWithCoefficients performs the actual KZG check after
// the shared Fiat-Shamir powers have already been computed. The batched Fig. 5
// interfaces use it for several relations under one context/challenge.
func pubAggVerifyEvalCombinedWithCoefficients(
	vk kzg_ped.VerifyingKey,
	commitments []kzg_ped.Digest,
	pointIdx int,
	combinedClaim curve.G1Affine,
	aggW curve.G1Affine,
	coeff []fr.Element,
) bool {
	if len(commitments) == 0 || len(commitments) != len(coeff) {
		return false
	}
	// 2) Aggregate commitments: C_agg = Σ coeff[i] · commitments[i]
	var aggCom curve.G1Affine
	if _, err := aggCom.MultiExp(commitments, coeff, ecc.MultiExpConfig{}); err != nil {
		return false
	}
	// 3) Build LHS = C_agg − combinedClaim
	var lhs curve.G1Affine
	lhs.Sub(&aggCom, &combinedClaim)
	// 4) Compute RHS exponent in G2: h2Gen − g2Gen^{pointIdx}
	g2Gen := vk.G2[0]
	h2Gen := vk.G2[1]
	var xBig big.Int
	xBig.SetInt64(int64(pointIdx))
	var g2x curve.G2Affine
	g2x.ScalarMultiplication(&g2Gen, &xBig)
	var rhsExpo curve.G2Affine
	rhsExpo.Sub(&h2Gen, &g2x)
	// 5) Final pairing check
	var negW curve.G1Affine
	negW.Neg(&aggW)
	ok, _ := curve.PairingCheck(
		[]curve.G1Affine{lhs, negW},
		[]curve.G2Affine{g2Gen, rhsExpo},
	)
	return ok
}

//export pyPubAggVerifyEvalCombined
func pyPubAggVerifyEvalCombined(
	json_vk *C.char,
	json_commitments *C.char,
	json_combinedClaim *C.char,
	json_aggH *C.char,
	json_gamma *C.char,
	pointIdx int,
) bool {
	// Decode verifying key
	var vk kzg_ped.VerifyingKey
	if err := json.Unmarshal([]byte(C.GoString(json_vk)), &vk); err != nil {
		return false
	}
	// Decode commitments list
	var comList []kzg_ped.Digest
	if err := json.Unmarshal([]byte(C.GoString(json_commitments)), &comList); err != nil {
		return false
	}
	// Decode combinedClaim (Digest → G1Affine)
	var dCombined kzg_ped.Digest
	if err := json.Unmarshal([]byte(C.GoString(json_combinedClaim)), &dCombined); err != nil {
		return false
	}
	combinedClaim := curve.G1Affine(dCombined)
	// Decode aggregated witness
	var dAggH kzg_ped.Digest
	if err := json.Unmarshal([]byte(C.GoString(json_aggH)), &dAggH); err != nil {
		return false
	}
	aggH := curve.G1Affine(dAggH)
	// Decode gamma
	var gamma fr.Element
	var bigTmp big.Int
	s := C.GoString(json_gamma)
	if _, ok := bigTmp.SetString(s, 10); !ok {
		return false
	}
	gamma.SetBigInt(&bigTmp)
	// Call the combined verifier
	return PubAggVerifyEvalCombined(vk, comList, pointIdx, combinedClaim, aggH, gamma)
}

//export pyAggProveEval
func pyAggProveEval(json_commitments *C.char,
	json_proofs *C.char,
	json_gamma *C.char) *C.char {

	// 1) decode inputs ---------------------------------------------------------
	var comList []kzg_ped.Digest
	if err := json.Unmarshal([]byte(C.GoString(json_commitments)), &comList); err != nil {
		return C.CString(`{"error":"invalid commitments"}`)
	}
	var proofList []kzg_ped.OpeningProof
	if err := json.Unmarshal([]byte(C.GoString(json_proofs)), &proofList); err != nil {
		return C.CString(`{"error":"invalid proofs"}`)
	}
	var gamma fr.Element
	// Parse gamma from decimal string
	s := C.GoString(json_gamma)
	var bigTmp big.Int
	if _, ok := bigTmp.SetString(s, 10); !ok {
		return C.CString(`{"error":"invalid gamma"}`)
	}
	gamma.SetBigInt(&bigTmp)

	// 2) aggregate -------------------------------------------------------------
	aggCom, aggProof := deterministicCombine(comList, proofList, gamma)

	// 3) marshal result --------------------------------------------------------
	type outStruct struct {
		Commitment kzg_ped.Digest       `json:"aggCommitment"`
		Proof      kzg_ped.OpeningProof `json:"aggProof"`
	}
	out, _ := json.Marshal(outStruct{
		Commitment: aggCom,
		Proof:      aggProof,
	})
	return C.CString(string(out))
}

//export pyMultiplyClaimedValuesWithAux
func pyMultiplyClaimedValuesWithAux(json_prooflist_left *C.char, json_prooflist_right *C.char) *C.char {
	var prooflist_left []kzg_ped.OpeningProof
	var prooflist_right []kzg_ped.OpeningProof
	if err := json.Unmarshal([]byte(C.GoString(json_prooflist_left)), &prooflist_left); err != nil {
		return C.CString(`{"error": "invalid prooflist_left"}`)
	}
	if err := json.Unmarshal([]byte(C.GoString(json_prooflist_right)), &prooflist_right); err != nil {
		return C.CString(`{"error": "invalid prooflist_right"}`)
	}

	if len(prooflist_left) != len(prooflist_right) {
		return C.CString(`{"error": "prooflists must have equal length"}`)
	}

	batchsize := len(prooflist_left)
	productVals := make([]fr.Element, batchsize)
	productAux := make([]fr.Element, batchsize)

	for i := 0; i < batchsize; i++ {
		productVals[i].Mul(&prooflist_left[i].ClaimedValue, &prooflist_right[i].ClaimedValue)
		productAux[i].Mul(&prooflist_left[i].ClaimedValueAux, &prooflist_right[i].ClaimedValueAux)
	}

	result := struct {
		Value []fr.Element `json:"value"`
		Aux   []fr.Element `json:"aux"`
	}{
		Value: productVals,
		Aux:   productAux,
	}

	jsonResult, _ := json.Marshal(result)
	return C.CString(string(jsonResult))
}

// Agg_zeroknowledgeproofs aggregates zero-knowledge proofs into a single proof.
func Agg_zeroknowledgeproofs(proof *[]kzg_ped.ZeroKnowledgeOpeningProof) kzg_ped.ZeroKnowledgeOpeningProof {
	batchsize := len(*proof)
	var HAddG1Jac, HG1Jac curve.G1Jac
	var committedvalueAddG1Jac, committedvalueG1Jac curve.G1Jac
	zkproof := *proof

	// Aggregate H and committed values from all proofs
	for i := 0; i < batchsize; i++ {
		HG1Jac.FromAffine(&zkproof[i].H)
		committedvalueG1Jac.FromAffine(&zkproof[i].CommittedValue)
		if i == 0 {
			HAddG1Jac.Set(&HG1Jac)
			committedvalueAddG1Jac.Set(&committedvalueG1Jac)
			continue
		}
		HAddG1Jac.AddAssign(&HG1Jac)
		committedvalueAddG1Jac.AddAssign(&committedvalueG1Jac)
	}

	// Convert aggregated results back to affine representation
	var Aggproof kzg_ped.ZeroKnowledgeOpeningProof
	var HG1Aff, committedvalueG1Aff curve.G1Affine
	HG1Aff.FromJacobian(&HAddG1Jac)
	committedvalueG1Aff.FromJacobian(&committedvalueAddG1Jac)
	Aggproof.H.Set(&HG1Aff)
	Aggproof.CommittedValue.Set(&committedvalueG1Aff)

	return Aggproof
}

// pyBatchhiddenverify verifies hidden evaluation for a fixed point.
//
//export pyBatchhiddenverify
func pyBatchhiddenverify(json_SRS_Vk *C.char, json_commitmentlist_ab *C.char, json_zkProof_ab *C.char, dealer_id int) bool {

	var result = true
	var Vk kzg_ped.VerifyingKey
	_ = json.Unmarshal([]byte(C.GoString(json_SRS_Vk)), &Vk)

	var commitmentlist_ab []kzg_ped.Digest
	_ = json.Unmarshal([]byte(C.GoString(json_commitmentlist_ab)), &commitmentlist_ab)

	var zkProof_ab []curve.G1Affine
	_ = json.Unmarshal([]byte(C.GoString(json_zkProof_ab)), &zkProof_ab)

	var wg sync.WaitGroup

	// Verify that ab commitments are bound to the hidden values
	wg.Add(1)
	go func() {
		defer wg.Done()
		var point fr.Element
		point.SetInt64(int64(dealer_id + 1))
		if !kzg_ped.BatchhiddenVerifySinglePoint(commitmentlist_ab, zkProof_ab, point, Vk) {
			fmt.Println("Hidden verification of ab failed!")
			result = false
		}
	}()

	// Wait for all verification tasks to complete
	wg.Wait()
	return result
}

// pyBatchhiddenzeroverify verifies hidden evaluation for zero point.
//
//export pyBatchhiddenzeroverify
func pyBatchhiddenzeroverify(json_SRS_Vk *C.char, json_commitment_c *C.char, json_zkProof_c_zero *C.char) bool {

	var result = true
	var Vk kzg_ped.VerifyingKey
	_ = json.Unmarshal([]byte(C.GoString(json_SRS_Vk)), &Vk)

	var commitmentlist_c []kzg_ped.Digest
	_ = json.Unmarshal([]byte(C.GoString(json_commitment_c)), &commitmentlist_c)

	var zkProof_c_zero []curve.G1Affine
	_ = json.Unmarshal([]byte(C.GoString(json_zkProof_c_zero)), &zkProof_c_zero)

	var wg sync.WaitGroup
	// Verify that c commitments are bound to the zero point
	wg.Add(1)
	go func() {
		defer wg.Done()
		var point_0 fr.Element
		point_0.SetInt64(int64(0))
		if !kzg_ped.BatchhiddenVerifySinglePoint(commitmentlist_c, zkProof_c_zero, point_0, Vk) {
			fmt.Println("Hidden verification of zero point of c failed!")
			result = false
		}
	}()

	// Wait for all verification tasks to complete
	wg.Wait()
	return result
}

//export pyBatchhiddenverifyUnbatched
func pyBatchhiddenverifyUnbatched(json_SRS_Vk *C.char, json_commitmentlist_ab *C.char, json_zkProof_ab *C.char, dealer_id int) bool {
	var Vk kzg_ped.VerifyingKey
	_ = json.Unmarshal([]byte(C.GoString(json_SRS_Vk)), &Vk)

	var commitmentlistAB []kzg_ped.Digest
	_ = json.Unmarshal([]byte(C.GoString(json_commitmentlist_ab)), &commitmentlistAB)

	var zkProofAB []curve.G1Affine
	_ = json.Unmarshal([]byte(C.GoString(json_zkProof_ab)), &zkProofAB)

	if len(zkProofAB) != 2*len(commitmentlistAB) {
		fmt.Println("Unbatched hidden verification of ab got inconsistent lengths")
		return false
	}

	var point fr.Element
	point.SetInt64(int64(dealer_id + 1))
	batchsize := len(commitmentlistAB)
	for i := 0; i < batchsize; i++ {
		var proof kzg_ped.ZeroKnowledgeOpeningProof
		proof.CommittedValue.Set(&zkProofAB[i])
		proof.H.Set(&zkProofAB[batchsize+i])
		if !kzg_ped.HiddenVerify(&commitmentlistAB[i], &proof, point, Vk) {
			fmt.Println("Unbatched hidden verification of ab failed!")
			return false
		}
	}
	return true
}

//export pyBatchhiddenzeroverifyUnbatched
func pyBatchhiddenzeroverifyUnbatched(json_SRS_Vk *C.char, json_commitment_c *C.char, json_zkProof_c_zero *C.char) bool {
	var Vk kzg_ped.VerifyingKey
	_ = json.Unmarshal([]byte(C.GoString(json_SRS_Vk)), &Vk)

	var commitmentlistC []kzg_ped.Digest
	_ = json.Unmarshal([]byte(C.GoString(json_commitment_c)), &commitmentlistC)

	var zkProofCZero []curve.G1Affine
	_ = json.Unmarshal([]byte(C.GoString(json_zkProof_c_zero)), &zkProofCZero)

	if len(zkProofCZero) != 2*len(commitmentlistC) {
		fmt.Println("Unbatched hidden zero verification got inconsistent lengths")
		return false
	}

	var point0 fr.Element
	point0.SetInt64(int64(0))
	batchsize := len(commitmentlistC)
	for i := 0; i < batchsize; i++ {
		var proof kzg_ped.ZeroKnowledgeOpeningProof
		proof.CommittedValue.Set(&zkProofCZero[i])
		proof.H.Set(&zkProofCZero[batchsize+i])
		if !kzg_ped.HiddenVerify(&commitmentlistC[i], &proof, point0, Vk) {
			fmt.Println("Unbatched hidden verification of zero point of c failed!")
			return false
		}
	}
	return true
}

// pyProdverify verifies product proofs.
//
//export pyProdverify
func pyProdverify(json_SRS_Vk *C.char, json_zkProof_ab *C.char, json_zkProof_c_zero *C.char, json_proofproduct *C.char) bool {

	var result = true
	var Vk kzg_ped.VerifyingKey
	_ = json.Unmarshal([]byte(C.GoString(json_SRS_Vk)), &Vk)

	var zkProof_ab []curve.G1Affine
	_ = json.Unmarshal([]byte(C.GoString(json_zkProof_ab)), &zkProof_ab)

	var zkProof_c_zero []curve.G1Affine
	_ = json.Unmarshal([]byte(C.GoString(json_zkProof_c_zero)), &zkProof_c_zero)

	batchsize := len(zkProof_ab) - 1

	var wg sync.WaitGroup

	// Verify the product proof
	wg.Add(1)
	go func() {
		defer wg.Done()
		var proofproduct []kzg_ped.ProdProof
		_ = json.Unmarshal([]byte(C.GoString(json_proofproduct)), &proofproduct)
		if !kzg_ped.BatchProductVerify(Vk, proofproduct, zkProof_ab[:batchsize], zkProof_c_zero[:batchsize/2]) {
			fmt.Println("Verification of product proof for party failed!")
			result = false
		}
	}()

	// Wait for all verification tasks to complete
	wg.Wait()
	return result
}

//export pyProdverifyUnbatched
func pyProdverifyUnbatched(json_SRS_Vk *C.char, json_zkProof_ab *C.char, json_zkProof_c_zero *C.char, json_proofproduct *C.char) bool {
	var Vk kzg_ped.VerifyingKey
	_ = json.Unmarshal([]byte(C.GoString(json_SRS_Vk)), &Vk)

	var zkProofAB []curve.G1Affine
	_ = json.Unmarshal([]byte(C.GoString(json_zkProof_ab)), &zkProofAB)

	var zkProofCZero []curve.G1Affine
	_ = json.Unmarshal([]byte(C.GoString(json_zkProof_c_zero)), &zkProofCZero)

	var proofproduct []kzg_ped.ProdProof
	_ = json.Unmarshal([]byte(C.GoString(json_proofproduct)), &proofproduct)

	batchsize := len(proofproduct)
	if len(zkProofAB) < 2*batchsize || len(zkProofCZero) < batchsize {
		fmt.Println("Unbatched product verification got inconsistent lengths")
		return false
	}

	for i := 0; i < batchsize; i++ {
		if !kzg_ped.Prodproofverify(Vk, proofproduct[i], zkProofAB[i], zkProofAB[i+batchsize], zkProofCZero[i]) {
			fmt.Println("Unbatched product verification failed!")
			return false
		}
	}
	return true
}

// lagrangeCoefficient computes the Lagrange coefficient for the given x value.
func lagrangeCoefficient(xs []fr.Element, x fr.Element, commonset []int) fr.Element {
	var res fr.Element
	res.SetOne()
	var temp fr.Element

	for _, index := range commonset {
		if xs[index] != x {
			temp.Sub(&xs[index], &x)
			temp.Inverse(&temp)
			temp.Mul(&xs[index], &temp)
			res.Mul(&res, &temp)
		}
	}
	return res
}

func degreereduction(lagrangeCoefficientList []fr.Element, commonset []int, shares_c_2t [][]kzg_ped.OpeningProof) []fr.Element {
	batchsize := len(shares_c_2t[commonset[0]])
	c_shares_temp := make([]fr.Element, batchsize)
	var temp fr.Element
	for j := 0; j < batchsize; j++ {
		c_shares_temp[j].SetZero()
		for _, index := range commonset {
			temp.Mul(&lagrangeCoefficientList[index], &shares_c_2t[index][j].ClaimedValue)
			c_shares_temp[j].Add(&c_shares_temp[j], &temp)
		}
	}
	return c_shares_temp
}

// pyTriplesCompute reconstructs triples from secret shares using Lagrange interpolation.
//
//export pyTriplesCompute
func pyTriplesCompute(json_commonset *C.char, json_shares_ab *C.char, json_c_shares *C.char, json_c_com *C.char) *C.char {
	var commonset []int
	_ = json.Unmarshal([]byte(C.GoString(json_commonset)), &commonset)

	var shares_ab []kzg_ped.OpeningProof
	_ = json.Unmarshal([]byte(C.GoString(json_shares_ab)), &shares_ab)

	var shares_c_2t [][]kzg_ped.OpeningProof
	_ = json.Unmarshal([]byte(C.GoString(json_c_shares)), &shares_c_2t)

	total_parties := len(shares_c_2t)
	commonsetFrElement := make([]fr.Element, total_parties)

	for _, index := range commonset {
		commonsetFrElement[index].SetInt64(int64(index + 1))
	}

	batchsize := len(shares_c_2t[commonset[0]])
	lagrangeCoefficientList := make([]fr.Element, total_parties)
	for _, index := range commonset {
		var point fr.Element
		point.SetInt64(int64(index + 1))
		lagrangeCoefficientList[index] = lagrangeCoefficient(commonsetFrElement, point, commonset)
	}

	c_shares_temp := degreereduction(lagrangeCoefficientList, commonset, shares_c_2t)

	// Marshal triples to JSON and return as C string
	var triples kzg_ped.Triples
	triples.A = make([]fr.Element, batchsize)
	triples.B = make([]fr.Element, batchsize)
	triples.C = make([]fr.Element, batchsize)

	for i := 0; i < batchsize; i++ {
		triples.A[i].Set(&shares_ab[i].ClaimedValue)
		triples.B[i].Set(&shares_ab[i+batchsize].ClaimedValue)
		triples.C[i].Set(&c_shares_temp[i])
	}

	// Marshal triples to JSON and return as C string
	json_triples, _ := json.Marshal(triples)
	return C.CString(string(json_triples))
}

// ---------- 辅助：计算拉格朗日系数 ----------
func lagrangeCoefficientwithTransfer(xs []fr.Element, x fr.Element, S []int) fr.Element {
	var num, den, res fr.Element
	res.SetOne()
	for _, j := range S {
		if xs[j].Equal(&x) {
			continue
		}
		num.Set(&xs[j])     // x_j
		den.Sub(&xs[j], &x) // x_j - x_i
		den.Inverse(&den)
		num.Mul(&num, &den) // x_j / (x_j - x_i)
		res.Mul(&res, &num)
	}
	return res
}

//export pyInterpolateShareswithTransfer
func pyInterpolateShareswithTransfer(json_commonset *C.char,
	json_commitAll *C.char,
	json_shareAll *C.char) *C.char {

	// ---------- 1) 反序列化 ----------
	var commonSet []int
	_ = json.Unmarshal([]byte(C.GoString(json_commonset)), &commonSet)
	sort.Ints(commonSet)

	var commitAll [][]kzg_ped.Digest      // [dealer][batch]
	var shareAll [][]kzg_ped.OpeningProof // [dealer][batch]
	_ = json.Unmarshal([]byte(C.GoString(json_commitAll)), &commitAll)
	_ = json.Unmarshal([]byte(C.GoString(json_shareAll)), &shareAll)

	if len(commonSet) == 0 {
		return C.CString("{}")
	}
	batch := len(commitAll[commonSet[0]])

	// ---------- 2) 预计算 λ_i ----------
	k := len(commonSet)         // |S|
	xs := make([]fr.Element, k) // x‑coordinates of selected dealers
	for i, id := range commonSet {
		xs[i].SetInt64(int64(id + 1)) // x_i = (dealerID)+1
	}

	// helper slice [0,1,…,k-1] for lagrangeCoefficientwithTransfer
	idxSlice := make([]int, k)
	for i := 0; i < k; i++ {
		idxSlice[i] = i
	}

	λ := make([]fr.Element, k) // λ_i for each pos in S
	for i := 0; i < k; i++ {
		λ[i] = lagrangeCoefficientwithTransfer(xs, xs[i], idxSlice)
	}

	// ---------- 3) 聚合 ----------
	aggCom := make([]kzg_ped.Digest, batch)
	aggShare := make([]kzg_ped.OpeningProof, batch)

	for j := 0; j < batch; j++ {
		// G1 累加
		var cSum, hSum curve.G1Affine

		var vSum, vAuxSum fr.Element
		vSum.SetZero()
		vAuxSum.SetZero()

		for pos := 0; pos < k; pos++ {
			lbd := λ[pos]

			// original dealer index in acsset order
			// commitAll / shareAll were already sliced to this order by caller
			var lbdBig big.Int
			lbd.BigInt(&lbdBig)

			// ---- commitment ----
			var tmpC curve.G1Affine
			tmpC.ScalarMultiplication(&commitAll[pos][j], &lbdBig)
			cSum.Add(&cSum, &tmpC)

			// ---- witness H ----
			var tmpH curve.G1Affine
			tmpH.ScalarMultiplication(&shareAll[pos][j].H, &lbdBig)
			hSum.Add(&hSum, &tmpH)

			// ---- scalar shares ----
			var t fr.Element
			t.Mul(&lbd, &shareAll[pos][j].ClaimedValue)
			vSum.Add(&vSum, &t)

			t.Mul(&lbd, &shareAll[pos][j].ClaimedValueAux)
			vAuxSum.Add(&vAuxSum, &t)
		}

		aggCom[j] = kzg_ped.Digest(cSum)
		aggShare[j].H.Set(&hSum)
		aggShare[j].ClaimedValue.Set(&vSum)
		aggShare[j].ClaimedValueAux.Set(&vAuxSum)
	}

	// ---------- 4) 输出 ----------
	type result struct {
		Commit []kzg_ped.Digest       `json:"commitment"`
		Shares []kzg_ped.OpeningProof `json:"shares"`
	}
	out, _ := json.Marshal(result{aggCom, aggShare})
	return C.CString(string(out))
}

//export pyReconstruct
func pyReconstruct(json_0 *C.char, json_1 *C.char, json_2 *C.char, json_3 *C.char) {
	// fmt.Println("alltriples", alltriples)
	alltriples := make([]kzg_ped.Triples, 4)
	_ = json.Unmarshal([]byte(C.GoString(json_0)), &alltriples[0])
	_ = json.Unmarshal([]byte(C.GoString(json_1)), &alltriples[1])
	_ = json.Unmarshal([]byte(C.GoString(json_2)), &alltriples[2])
	_ = json.Unmarshal([]byte(C.GoString(json_3)), &alltriples[3])
	// fmt.Println("alltriples", alltriples)
	log.Println("alltriples", alltriples[0])
	commonset := []int{2, 3}
	commonsetFrElement := make([]fr.Element, 4)
	for _, index := range commonset {
		commonsetFrElement[index].SetInt64(int64(index + 1))
		// log.Println("commonsetFrElement: ", index,  commonsetFrElement[index])
	}

	lagrangeCoefficientList := make([]fr.Element, 4)
	for _, index := range commonset {
		var point fr.Element
		point.SetInt64(int64(index + 1))
		// log.Println("point: ", index, point)
		lagrangeCoefficientList[index] = lagrangeCoefficient(commonsetFrElement, point, commonset)
	}

	// interpolation
	var res_A fr.Element
	var temp fr.Element
	res_A.SetZero()
	for _, index := range commonset {
		temp.Mul(&lagrangeCoefficientList[index], &alltriples[index].A[0])
		res_A.Add(&res_A, &temp)
	}
	log.Println("res_A: ", res_A)

	var res_B fr.Element
	res_B.SetZero()
	for _, index := range commonset {
		temp.Mul(&lagrangeCoefficientList[index], &alltriples[index].B[0])
		res_B.Add(&res_B, &temp)
	}
	log.Println("res_B: ", res_B)

	var res_C fr.Element

	res_C.SetZero()
	for _, index := range commonset {
		temp.Mul(&lagrangeCoefficientList[index], &alltriples[index].C[0])
		res_C.Add(&res_C, &temp)
	}
	log.Println("res_C: ", res_C)

	var res_product fr.Element
	res_product.Mul(&res_A, &res_B)
	log.Println("res_product: ", res_product)
	log.Println("res_product: ", res_product.Mul(&res_A, &res_B))
	var ele_one fr.Element
	ele_one.SetOne()

	// log.Println("one: ", ele_one)
	// log.Println("one: ", ele_one.SetOne())
	// log.Println("one: ", ele_one.SetInt64(int64(1)))
	// log.Println("2: ", ele_one.SetInt64(int64(2)))

}

func main() {

	logFile, err := os.OpenFile("output.log", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		fmt.Println("Failed to open log file:", err)
		return
	}
	defer logFile.Close()

	log.SetOutput(logFile)

	log.SetFlags(log.Ldate | log.Ltime | log.Lshortfile)
	log.SetPrefix("[LOG] ")

	t := 1
	// n :=
	n := 4
	// SRS, _ := kzg_ped.NewSRS(ecc.NextPowerOfTwo(uint64(t+1)), new(big.Int).SetInt64(42))
	// build independent g‑ and h‑chains
	size := ecc.NextPowerOfTwo(uint64(t + 1))

	srsG, _ := kzg_ped.NewSRS(size, new(big.Int).SetInt64(42))  // chain for g
	srsH, _ := kzg_ped.NewSRS(size, new(big.Int).SetInt64(137)) // separate chain for h

	// overwrite G1_h with the β‑chain shifted by 1
	// note: G1_g[0] == generator^0, identical for any seed,
	// so copy from index 1 to guarantee h ≠ g
	for i := range srsG.Pk.G1_h {
		idx := (i + 1) % len(srsH.Pk.G1_g)
		srsG.Pk.G1_h[i].Set(&srsH.Pk.G1_g[idx])
	}
	// Vk part: just take β‑chain[1] to avoid clash
	// srsG.Vk.G1_h.Set(&srsH.Vk.G1_g)

	// use β‑chain[1] so that Vk’s h matches Pk.G1_h[0]
	srsG.Vk.G1_h.Set(&srsH.Pk.G1_g[1])

	SRS := srsG // use the combined SRS from here on

	// publickeys_per_dealer, secretkeys_per_party := KeyGeneration(SRS.Pk.G1_g[0], n)
	// for i := 0; i < n; i++ {
	// 	epk, serialized_esk := KeyEphemeralGen(SRS.Pk.G1_g[0])
	// 	var esk fr.Element
	// 	esk.UnmarshalJSON(serialized_esk) // Restore the secret key from JSON
	// 	for j := 0; j < n; j++ {
	// 		tmp_share_key := SharedKeysGen_sender(esk, publickeys_per_dealer[i][j])

	// 		var skji fr.Element
	// 		skji.UnmarshalJSON(secretkeys_per_party[j][i]) // Restore the secret key from JSON

	// 		kji := SharedKeysGen_recv(skji, epk)

	// 		if !tmp_share_key.Equal(&kji) {
	// 			fmt.Println("incorrect key")
	// 		}

	// 	}

	// }

	batchsize := 1

	secret := make([]fr.Element, batchsize)
	for i := 0; i < batchsize; i++ {
		secret[i].SetRandom()
	}
	log.Println("secret: ", secret)

	log.Printf("t=:%d, n=:%d, batchsize:%d\n", t, n, batchsize)

	begin_time := time.Now()
	polynomialList, polynomialList_aux := samplepolynomial(secret, batchsize, t)
	end_time := time.Now()
	log.Printf("time to sample polynomial: %s\n", end_time.Sub(begin_time))

	begin_time = time.Now()
	commitments := make([]kzg_ped.Digest, batchsize)
	for i := 0; i < batchsize; i++ {
		commitments[i], _ = kzg_ped.Commit(polynomialList[i], polynomialList_aux[i], SRS.Pk)
	}
	end_time = time.Now()
	log.Printf("time to commit polynomial: %s\n", end_time.Sub(begin_time))

	begin_time = time.Now()
	batchproofsofallparties := Batchopen(polynomialList, polynomialList_aux, n, SRS.Pk)
	end_time = time.Now()
	log.Printf("time to generate proofs: %s\n", end_time.Sub(begin_time))

	log.Printf("num proof:%d\n", len(batchproofsofallparties[0]))

	// test begin
	var point fr.Element
	point.SetInt64(int64(0 + 1))

	Aggcom, Aggproofs := randomCombine(commitments, batchproofsofallparties[0])
	if kzg_ped.Verify(&Aggcom, &Aggproofs, point, SRS.Vk) {
		log.Printf("randomCombine verification passed:\n")
	}

	if BatchVerify(commitments, batchproofsofallparties[0], point, SRS.Vk) {
		log.Printf("pass:\n")
	}

	// test lagrange interpolation
	commonset := []int{2, 3}
	commonsetFrElement := make([]fr.Element, n)
	for _, index := range commonset {
		commonsetFrElement[index].SetInt64(int64(index + 1))
		log.Println("commonsetFrElement: ", index, commonsetFrElement[index])
	}

	lagrangeCoefficientList := make([]fr.Element, n)
	for _, index := range commonset {
		var point fr.Element
		point.SetInt64(int64(index + 1))
		log.Println("point: ", index, point)
		lagrangeCoefficientList[index] = lagrangeCoefficient(commonsetFrElement, point, commonset)
		log.Println("lagrangeCoefficientList: ", index, lagrangeCoefficientList[index])
	}

	c_shares_temp := degreereduction(lagrangeCoefficientList, commonset, batchproofsofallparties)

	log.Println("larange interpolation: ", c_shares_temp)
	log.Println("larange interpolation: ", secret)
	if c_shares_temp[0].Equal(&secret[0]) {
		log.Printf("Interpolation correct:\n")
	}

	var triples kzg_ped.Triples
	triples.C = make([]fr.Element, batchsize)

	for i := 0; i < batchsize; i++ {

		triples.C[i].Set(&c_shares_temp[i])
		// for j := 0; j < len(shares_c_2t); j++ {
		// 	// triples.C[i].Add(&triples.C[i], &tran_shares_temp[i][j])
		// }
	}

	// Marshal triples to JSON and return as C string
	// json_triples, _ := json.Marshal(triples)
	log.Println(triples)

	// // //test end

	// // begin_time = time.Now()
	// // for i := 0; i < n; i++ {
	// // 	point.SetInt64(int64(i + 1))
	// // 	BatchVerify(&commitments, &batchproofsofallparties[i], point, SRS.Vk)
	// // 	if kzg_ped.Verify(&commitments[0], &batchproofsofallparties[i][0], point, SRS.Vk) {
	// // 		log.Printf("pass:\n")
	// // 	}
	// // 	if batchproofsofallparties[i][0].H.Equal(&batchproofsofallparties[0][0].H) {
	// // 		log.Printf("all witness equal:\n")
	// // 	}
	// // }
	// // end_time = time.Now()
	// // log.Printf("time to verify proofs: %s\n", end_time.Sub(begin_time))

	// // var point fr.Element
	// // var res1 kzg_ped.OpeningProof
	// // fmt.Println("open for point", 1)
	// // point.SetString("1")
	// // res1, err := kzg_ped.Open(polynomialList[0], polynomialList_aux[0], point, SRS.Pk)
	// // if err != nil {
	// // 	fmt.Println("wrong proof")
	// // }
	// // fmt.Println("res1 proof", res1.H)
	// // fmt.Println("open for point", 2)

	// // var point1 fr.Element
	// // point1.SetString("2")
	// // res2, err := kzg_ped.Open(polynomialList[0], polynomialList_aux[0], point1, SRS.Pk)
	// // if err != nil {
	// // 	fmt.Println("wrong proof")
	// // }
	// // fmt.Println("res2 proof", res2.H)
	// // if !res1.H.Equal(&res2.H) {
	// // 	fmt.Println("correct proof")
	// // }

	// serialized_secretkeys := make([][]byte, n)
	// secretkeys := make([]fr.Element, n)
	// for i := 0; i < n; i++ {
	// 	secretkeys[i].SetRandom()                                 // Generate a random secret key
	// 	serialized_secretkeys[i], _ = secretkeys[i].MarshalJSON() // Serialize the secret key
	// }

	// var secretKeysAsStrings []string
	// for _, key := range serialized_secretkeys {
	// 	secretKeysAsStrings = append(secretKeysAsStrings, base64.StdEncoding.EncodeToString(key))
	// }

	// jsonMap := make(map[string]string)
	// for i, key := range secretKeysAsStrings {
	// 	jsonMap[fmt.Sprintf("%d", i)] = key
	// }

	// jsonBytes, err := json.Marshal(jsonMap)
	// if err != nil {
	// 	fmt.Println("Error marshaling JSON:", err)
	// 	return
	// }

	// fmt.Println("JSON Bytes:", string(jsonBytes))

	// var decodedMap map[string]string
	// err = json.Unmarshal(jsonBytes, &decodedMap)
	// if err != nil {
	// 	fmt.Println("Error unmarshaling JSON:", err)
	// 	return
	// }

	// fmt.Println("Decoded Map:", decodedMap)

	// var decodedSecretKeys []fr.Element
	// for _, base64Key := range decodedMap {
	// 	decodedBytes, err := base64.StdEncoding.DecodeString(base64Key)
	// 	if err != nil {
	// 		fmt.Println("Error decoding Base64:", err)
	// 		return
	// 	}

	// 	var secretKey fr.Element
	// 	err = secretKey.UnmarshalJSON(decodedBytes)
	// 	if err != nil {
	// 		fmt.Println("Error unmarshaling secret key:", err)
	// 		return
	// 	}

	// 	decodedSecretKeys = append(decodedSecretKeys, secretKey)
	// }

	// fmt.Println("Decoded Secret Keys:", decodedSecretKeys)
	// fmt.Println("Decoded Secret Keys:", secretkeys)
}
