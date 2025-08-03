// Copyright 2017 The go-ethereum Authors
// This file is part of the go-ethereum library.
//
// The go-ethereum library is free software: you can redistribute it and/or modify
// it under the terms of the GNU Lesser General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// The go-ethereum library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with the go-ethereum library. If not, see <http://www.gnu.org/licenses/>.

package vm

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/params"
	"github.com/yhl125/ETHFALCON/falcon"
)

// precompiledTest defines the input/output pairs for precompiled contract tests.
type precompiledTest struct {
	Input, Expected string
	Gas             uint64
	Name            string
	NoBenchmark     bool // Benchmark primarily the worst-cases
}

// precompiledFailureTest defines the input/error pairs for precompiled
// contract failure tests.
type precompiledFailureTest struct {
	Input         string
	ExpectedError string
	Name          string
}

// allPrecompiles does not map to the actual set of precompiles, as it also contains
// repriced versions of precompiles at certain slots
var allPrecompiles = map[common.Address]PrecompiledContract{
	common.BytesToAddress([]byte{1}):    &ecrecover{},
	common.BytesToAddress([]byte{2}):    &sha256hash{},
	common.BytesToAddress([]byte{3}):    &ripemd160hash{},
	common.BytesToAddress([]byte{4}):    &dataCopy{},
	common.BytesToAddress([]byte{5}):    &bigModExp{eip2565: false},
	common.BytesToAddress([]byte{0xf5}): &bigModExp{eip2565: true},
	common.BytesToAddress([]byte{6}):    &bn256AddIstanbul{},
	common.BytesToAddress([]byte{7}):    &bn256ScalarMulIstanbul{},
	common.BytesToAddress([]byte{8}):    &bn256PairingGranite{},
	common.BytesToAddress([]byte{9}):    &blake2F{},
	common.BytesToAddress([]byte{0x0a}): &kzgPointEvaluation{},

	common.BytesToAddress([]byte{0x0f, 0x0a}): &bls12381G1Add{},
	common.BytesToAddress([]byte{0x0f, 0x0b}): &bls12381G1MultiExpPrague{},
	common.BytesToAddress([]byte{0x1f, 0x0b}): &bls12381G1MultiExpIsthmus{},
	common.BytesToAddress([]byte{0x0f, 0x0c}): &bls12381G2Add{},
	common.BytesToAddress([]byte{0x0f, 0x0d}): &bls12381G2MultiExpPrague{},
	common.BytesToAddress([]byte{0x1f, 0x0d}): &bls12381G2MultiExpIsthmus{},
	common.BytesToAddress([]byte{0x0f, 0x0e}): &bls12381PairingPrague{},
	common.BytesToAddress([]byte{0x1f, 0x0e}): &bls12381PairingIsthmus{},
	common.BytesToAddress([]byte{0x0f, 0x0f}): &bls12381MapG1{},
	common.BytesToAddress([]byte{0x0f, 0x10}): &bls12381MapG2{},

	common.BytesToAddress([]byte{0x01, 0x00}): &p256Verify{},
	common.BytesToAddress([]byte{0x13}):       &falconvrfy{},
	common.BytesToAddress([]byte{0x14}):       &pureNTT{},        // Pure NTT (no caching)
	common.BytesToAddress([]byte{0x15}):       &precomputedNTT{}, // Precomputed NTT (with caching)
}

// EIP-152 test vectors
var blake2FMalformedInputTests = []precompiledFailureTest{
	{
		Input:         "",
		ExpectedError: errBlake2FInvalidInputLength.Error(),
		Name:          "vector 0: empty input",
	},
	{
		Input:         "00000c48c9bdf267e6096a3ba7ca8485ae67bb2bf894fe72f36e3cf1361d5f3af54fa5d182e6ad7f520e511f6c3e2b8c68059b6bbd41fbabd9831f79217e1319cde05b61626300000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000300000000000000000000000000000001",
		ExpectedError: errBlake2FInvalidInputLength.Error(),
		Name:          "vector 1: less than 213 bytes input",
	},
	{
		Input:         "000000000c48c9bdf267e6096a3ba7ca8485ae67bb2bf894fe72f36e3cf1361d5f3af54fa5d182e6ad7f520e511f6c3e2b8c68059b6bbd41fbabd9831f79217e1319cde05b61626300000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000300000000000000000000000000000001",
		ExpectedError: errBlake2FInvalidInputLength.Error(),
		Name:          "vector 2: more than 213 bytes input",
	},
	{
		Input:         "0000000c48c9bdf267e6096a3ba7ca8485ae67bb2bf894fe72f36e3cf1361d5f3af54fa5d182e6ad7f520e511f6c3e2b8c68059b6bbd41fbabd9831f79217e1319cde05b61626300000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000300000000000000000000000000000002",
		ExpectedError: errBlake2FInvalidFinalFlag.Error(),
		Name:          "vector 3: malformed final block indicator flag",
	},
}

func testPrecompiled(addr string, test precompiledTest, t *testing.T) {
	p := allPrecompiles[common.HexToAddress(addr)]
	in := common.Hex2Bytes(test.Input)
	gas := p.RequiredGas(in)
	t.Run(fmt.Sprintf("%s-Gas=%d", test.Name, gas), func(t *testing.T) {
		if res, _, err := RunPrecompiledContract(p, in, gas, nil); err != nil {
			t.Error(err)
		} else if common.Bytes2Hex(res) != test.Expected {
			t.Errorf("Expected %v, got %v", test.Expected, common.Bytes2Hex(res))
		}
		if expGas := test.Gas; expGas != gas {
			t.Errorf("%v: gas wrong, expected %d, got %d", test.Name, expGas, gas)
		}
		// Verify that the precompile did not touch the input buffer
		exp := common.Hex2Bytes(test.Input)
		if !bytes.Equal(in, exp) {
			t.Errorf("Precompiled %v modified input data", addr)
		}
	})
}

func testPrecompiledOOG(addr string, test precompiledTest, t *testing.T) {
	p := allPrecompiles[common.HexToAddress(addr)]
	in := common.Hex2Bytes(test.Input)
	gas := p.RequiredGas(in) - 1

	t.Run(fmt.Sprintf("%s-Gas=%d", test.Name, gas), func(t *testing.T) {
		_, _, err := RunPrecompiledContract(p, in, gas, nil)
		if err.Error() != "out of gas" {
			t.Errorf("Expected error [out of gas], got [%v]", err)
		}
		// Verify that the precompile did not touch the input buffer
		exp := common.Hex2Bytes(test.Input)
		if !bytes.Equal(in, exp) {
			t.Errorf("Precompiled %v modified input data", addr)
		}
	})
}

func testPrecompiledFailure(addr string, test precompiledFailureTest, t *testing.T) {
	p := allPrecompiles[common.HexToAddress(addr)]
	in := common.Hex2Bytes(test.Input)
	gas := p.RequiredGas(in)
	t.Run(test.Name, func(t *testing.T) {
		_, _, err := RunPrecompiledContract(p, in, gas, nil)
		if err.Error() != test.ExpectedError {
			t.Errorf("Expected error [%v], got [%v]", test.ExpectedError, err)
		}
		// Verify that the precompile did not touch the input buffer
		exp := common.Hex2Bytes(test.Input)
		if !bytes.Equal(in, exp) {
			t.Errorf("Precompiled %v modified input data", addr)
		}
	})
}

func benchmarkPrecompiled(addr string, test precompiledTest, bench *testing.B) {
	if test.NoBenchmark {
		return
	}
	p := allPrecompiles[common.HexToAddress(addr)]
	in := common.Hex2Bytes(test.Input)
	reqGas := p.RequiredGas(in)

	var (
		res  []byte
		err  error
		data = make([]byte, len(in))
	)

	bench.Run(fmt.Sprintf("%s-Gas=%d", test.Name, reqGas), func(bench *testing.B) {
		bench.ReportAllocs()
		start := time.Now()
		bench.ResetTimer()
		for i := 0; i < bench.N; i++ {
			copy(data, in)
			res, _, err = RunPrecompiledContract(p, data, reqGas, nil)
		}
		bench.StopTimer()
		elapsed := uint64(time.Since(start))
		if elapsed < 1 {
			elapsed = 1
		}
		gasUsed := reqGas * uint64(bench.N)
		bench.ReportMetric(float64(reqGas), "gas/op")
		// Keep it as uint64, multiply 100 to get two digit float later
		mgasps := (100 * 1000 * gasUsed) / elapsed
		bench.ReportMetric(float64(mgasps)/100, "mgas/s")
		//Check if it is correct
		if err != nil {
			bench.Error(err)
			return
		}
		if common.Bytes2Hex(res) != test.Expected {
			bench.Errorf("Expected %v, got %v", test.Expected, common.Bytes2Hex(res))
			return
		}
	})
}

// Benchmarks the sample inputs from the ECRECOVER precompile.
func BenchmarkPrecompiledEcrecover(bench *testing.B) {
	t := precompiledTest{
		Input:    "38d18acb67d25c8bb9942764b62f18e17054f66a817bd4295423adf9ed98873e000000000000000000000000000000000000000000000000000000000000001b38d18acb67d25c8bb9942764b62f18e17054f66a817bd4295423adf9ed98873e789d1dd423d25f0772d2748d60f7e4b81bb14d086eba8e8e8efb6dcff8a4ae02",
		Expected: "000000000000000000000000ceaccac640adf55b2028469bd36ba501f28b699d",
		Name:     "",
	}
	benchmarkPrecompiled("01", t, bench)
}

// Benchmarks the sample inputs from the SHA256 precompile.
func BenchmarkPrecompiledSha256(bench *testing.B) {
	t := precompiledTest{
		Input:    "38d18acb67d25c8bb9942764b62f18e17054f66a817bd4295423adf9ed98873e000000000000000000000000000000000000000000000000000000000000001b38d18acb67d25c8bb9942764b62f18e17054f66a817bd4295423adf9ed98873e789d1dd423d25f0772d2748d60f7e4b81bb14d086eba8e8e8efb6dcff8a4ae02",
		Expected: "811c7003375852fabd0d362e40e68607a12bdabae61a7d068fe5fdd1dbbf2a5d",
		Name:     "128",
	}
	benchmarkPrecompiled("02", t, bench)
}

// Benchmarks the sample inputs from the RIPEMD precompile.
func BenchmarkPrecompiledRipeMD(bench *testing.B) {
	t := precompiledTest{
		Input:    "38d18acb67d25c8bb9942764b62f18e17054f66a817bd4295423adf9ed98873e000000000000000000000000000000000000000000000000000000000000001b38d18acb67d25c8bb9942764b62f18e17054f66a817bd4295423adf9ed98873e789d1dd423d25f0772d2748d60f7e4b81bb14d086eba8e8e8efb6dcff8a4ae02",
		Expected: "0000000000000000000000009215b8d9882ff46f0dfde6684d78e831467f65e6",
		Name:     "128",
	}
	benchmarkPrecompiled("03", t, bench)
}

// Benchmarks the sample inputs from the identity precompile.
func BenchmarkPrecompiledIdentity(bench *testing.B) {
	t := precompiledTest{
		Input:    "38d18acb67d25c8bb9942764b62f18e17054f66a817bd4295423adf9ed98873e000000000000000000000000000000000000000000000000000000000000001b38d18acb67d25c8bb9942764b62f18e17054f66a817bd4295423adf9ed98873e789d1dd423d25f0772d2748d60f7e4b81bb14d086eba8e8e8efb6dcff8a4ae02",
		Expected: "38d18acb67d25c8bb9942764b62f18e17054f66a817bd4295423adf9ed98873e000000000000000000000000000000000000000000000000000000000000001b38d18acb67d25c8bb9942764b62f18e17054f66a817bd4295423adf9ed98873e789d1dd423d25f0772d2748d60f7e4b81bb14d086eba8e8e8efb6dcff8a4ae02",
		Name:     "128",
	}
	benchmarkPrecompiled("04", t, bench)
}

// Tests the sample inputs from the ModExp EIP 198.
func TestPrecompiledModExp(t *testing.T)      { testJson("modexp", "05", t) }
func BenchmarkPrecompiledModExp(b *testing.B) { benchJson("modexp", "05", b) }

func TestPrecompiledModExpEip2565(t *testing.T)      { testJson("modexp_eip2565", "f5", t) }
func BenchmarkPrecompiledModExpEip2565(b *testing.B) { benchJson("modexp_eip2565", "f5", b) }

// Tests the sample inputs from the elliptic curve addition EIP 213.
func TestPrecompiledBn256Add(t *testing.T)      { testJson("bn256Add", "06", t) }
func BenchmarkPrecompiledBn256Add(b *testing.B) { benchJson("bn256Add", "06", b) }

// Tests OOG
func TestPrecompiledModExpOOG(t *testing.T) {
	modexpTests, err := loadJson("modexp")
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range modexpTests {
		testPrecompiledOOG("05", test, t)
	}
}

// Tests the sample inputs from the elliptic curve scalar multiplication EIP 213.
func TestPrecompiledBn256ScalarMul(t *testing.T)      { testJson("bn256ScalarMul", "07", t) }
func BenchmarkPrecompiledBn256ScalarMul(b *testing.B) { benchJson("bn256ScalarMul", "07", b) }

// Tests the sample inputs from the elliptic curve pairing check EIP 197.
func TestPrecompiledBn256Pairing(t *testing.T)      { testJson("bn256Pairing", "08", t) }
func BenchmarkPrecompiledBn256Pairing(b *testing.B) { benchJson("bn256Pairing", "08", b) }

func TestPrecompiledBlake2F(t *testing.T)      { testJson("blake2F", "09", t) }
func BenchmarkPrecompiledBlake2F(b *testing.B) { benchJson("blake2F", "09", b) }

func TestPrecompileBlake2FMalformedInput(t *testing.T) {
	for _, test := range blake2FMalformedInputTests {
		testPrecompiledFailure("09", test, t)
	}
}

func TestPrecompileBn256PairingTooLargeInput(t *testing.T) {
	big := make([]byte, params.Bn256PairingMaxInputSizeGranite+1)
	testPrecompiledFailure("08", precompiledFailureTest{
		Input:         common.Bytes2Hex(big),
		ExpectedError: "bad elliptic curve pairing input size",
		Name:          "bn256Pairing_input_too_big",
	}, t)
}

func TestPrecompileBlsInputSize(t *testing.T) {
	big := make([]byte, params.Bls12381G1MulMaxInputSizeIsthmus+1)
	testPrecompiledFailure("1f0b", precompiledFailureTest{
		Input:         common.Bytes2Hex(big),
		ExpectedError: "g1 msm input size exceeds maximum",
		Name:          "bls12381G1MSM_input_too_big",
	}, t)

	big = make([]byte, params.Bls12381G2MulMaxInputSizeIsthmus+1)
	testPrecompiledFailure("1f0d", precompiledFailureTest{
		Input:         common.Bytes2Hex(big),
		ExpectedError: "g2 msm input size exceeds maximum",
		Name:          "bls12381G2MSM_input_too_big",
	}, t)

	big = make([]byte, params.Bls12381PairingMaxInputSizeIsthmus+1)
	testPrecompiledFailure("1f0e", precompiledFailureTest{
		Input:         common.Bytes2Hex(big),
		ExpectedError: "pairing input size exceeds maximum",
		Name:          "bls12381Pairing_input_too_big",
	}, t)
}

func TestPrecompiledEcrecover(t *testing.T) { testJson("ecRecover", "01", t) }

func testJson(name, addr string, t *testing.T) {
	tests, err := loadJson(name)
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range tests {
		testPrecompiled(addr, test, t)
	}
}

func testJsonFail(name, addr string, t *testing.T) {
	tests, err := loadJsonFail(name)
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range tests {
		testPrecompiledFailure(addr, test, t)
	}
}

func benchJson(name, addr string, b *testing.B) {
	tests, err := loadJson(name)
	if err != nil {
		b.Fatal(err)
	}
	for _, test := range tests {
		benchmarkPrecompiled(addr, test, b)
	}
}

func TestPrecompiledBLS12381G1Add(t *testing.T)      { testJson("blsG1Add", "f0a", t) }
func TestPrecompiledBLS12381G1Mul(t *testing.T)      { testJson("blsG1Mul", "f0b", t) }
func TestPrecompiledBLS12381G1MultiExp(t *testing.T) { testJson("blsG1MultiExp", "f0b", t) }
func TestPrecompiledBLS12381G2Add(t *testing.T)      { testJson("blsG2Add", "f0c", t) }
func TestPrecompiledBLS12381G2Mul(t *testing.T)      { testJson("blsG2Mul", "f0d", t) }
func TestPrecompiledBLS12381G2MultiExp(t *testing.T) { testJson("blsG2MultiExp", "f0d", t) }
func TestPrecompiledBLS12381Pairing(t *testing.T)    { testJson("blsPairing", "f0e", t) }
func TestPrecompiledBLS12381MapG1(t *testing.T)      { testJson("blsMapG1", "f0f", t) }
func TestPrecompiledBLS12381MapG2(t *testing.T)      { testJson("blsMapG2", "f10", t) }

func TestPrecompiledPointEvaluation(t *testing.T) { testJson("pointEvaluation", "0a", t) }

func BenchmarkPrecompiledPointEvaluation(b *testing.B) { benchJson("pointEvaluation", "0a", b) }

func BenchmarkPrecompiledBLS12381G1Add(b *testing.B)      { benchJson("blsG1Add", "f0a", b) }
func BenchmarkPrecompiledBLS12381G1MultiExp(b *testing.B) { benchJson("blsG1MultiExp", "f0b", b) }
func BenchmarkPrecompiledBLS12381G2Add(b *testing.B)      { benchJson("blsG2Add", "f0c", b) }
func BenchmarkPrecompiledBLS12381G2MultiExp(b *testing.B) { benchJson("blsG2MultiExp", "f0d", b) }
func BenchmarkPrecompiledBLS12381Pairing(b *testing.B)    { benchJson("blsPairing", "f0e", b) }
func BenchmarkPrecompiledBLS12381MapG1(b *testing.B)      { benchJson("blsMapG1", "f0f", b) }
func BenchmarkPrecompiledBLS12381MapG2(b *testing.B)      { benchJson("blsMapG2", "f10", b) }

// Failure tests
func TestPrecompiledBLS12381G1AddFail(t *testing.T)      { testJsonFail("blsG1Add", "f0a", t) }
func TestPrecompiledBLS12381G1MulFail(t *testing.T)      { testJsonFail("blsG1Mul", "f0b", t) }
func TestPrecompiledBLS12381G1MultiExpFail(t *testing.T) { testJsonFail("blsG1MultiExp", "f0b", t) }
func TestPrecompiledBLS12381G2AddFail(t *testing.T)      { testJsonFail("blsG2Add", "f0c", t) }
func TestPrecompiledBLS12381G2MulFail(t *testing.T)      { testJsonFail("blsG2Mul", "f0d", t) }
func TestPrecompiledBLS12381G2MultiExpFail(t *testing.T) { testJsonFail("blsG2MultiExp", "f0d", t) }
func TestPrecompiledBLS12381PairingFail(t *testing.T)    { testJsonFail("blsPairing", "f0e", t) }
func TestPrecompiledBLS12381MapG1Fail(t *testing.T)      { testJsonFail("blsMapG1", "f0f", t) }
func TestPrecompiledBLS12381MapG2Fail(t *testing.T)      { testJsonFail("blsMapG2", "f10", t) }

func loadJson(name string) ([]precompiledTest, error) {
	data, err := os.ReadFile(fmt.Sprintf("testdata/precompiles/%v.json", name))
	if err != nil {
		return nil, err
	}
	var testcases []precompiledTest
	err = json.Unmarshal(data, &testcases)
	return testcases, err
}

func loadJsonFail(name string) ([]precompiledFailureTest, error) {
	data, err := os.ReadFile(fmt.Sprintf("testdata/precompiles/fail-%v.json", name))
	if err != nil {
		return nil, err
	}
	var testcases []precompiledFailureTest
	err = json.Unmarshal(data, &testcases)
	return testcases, err
}

// BenchmarkPrecompiledBLS12381G1MultiExpWorstCase benchmarks the worst case we could find that still fits a gaslimit of 10MGas.
func BenchmarkPrecompiledBLS12381G1MultiExpWorstCase(b *testing.B) {
	task := "0000000000000000000000000000000008d8c4a16fb9d8800cce987c0eadbb6b3b005c213d44ecb5adeed713bae79d606041406df26169c35df63cf972c94be1" +
		"0000000000000000000000000000000011bc8afe71676e6730702a46ef817060249cd06cd82e6981085012ff6d013aa4470ba3a2c71e13ef653e1e223d1ccfe9" +
		"FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"
	input := task
	for i := 0; i < 4787; i++ {
		input = input + task
	}
	testcase := precompiledTest{
		Input:       input,
		Expected:    "0000000000000000000000000000000005a6310ea6f2a598023ae48819afc292b4dfcb40aabad24a0c2cb6c19769465691859eeb2a764342a810c5038d700f18000000000000000000000000000000001268ac944437d15923dc0aec00daa9250252e43e4b35ec7a19d01f0d6cd27f6e139d80dae16ba1c79cc7f57055a93ff5",
		Name:        "WorstCaseG1",
		NoBenchmark: false,
	}
	benchmarkPrecompiled("f0c", testcase, b)
}

// BenchmarkPrecompiledBLS12381G2MultiExpWorstCase benchmarks the worst case we could find that still fits a gaslimit of 10MGas.
func BenchmarkPrecompiledBLS12381G2MultiExpWorstCase(b *testing.B) {
	task := "000000000000000000000000000000000d4f09acd5f362e0a516d4c13c5e2f504d9bd49fdfb6d8b7a7ab35a02c391c8112b03270d5d9eefe9b659dd27601d18f" +
		"000000000000000000000000000000000fd489cb75945f3b5ebb1c0e326d59602934c8f78fe9294a8877e7aeb95de5addde0cb7ab53674df8b2cfbb036b30b99" +
		"00000000000000000000000000000000055dbc4eca768714e098bbe9c71cf54b40f51c26e95808ee79225a87fb6fa1415178db47f02d856fea56a752d185f86b" +
		"000000000000000000000000000000001239b7640f416eb6e921fe47f7501d504fadc190d9cf4e89ae2b717276739a2f4ee9f637c35e23c480df029fd8d247c7" +
		"FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"
	input := task
	for i := 0; i < 1040; i++ {
		input = input + task
	}

	testcase := precompiledTest{
		Input:       input,
		Expected:    "0000000000000000000000000000000018f5ea0c8b086095cfe23f6bb1d90d45de929292006dba8cdedd6d3203af3c6bbfd592e93ecb2b2c81004961fdcbb46c00000000000000000000000000000000076873199175664f1b6493a43c02234f49dc66f077d3007823e0343ad92e30bd7dc209013435ca9f197aca44d88e9dac000000000000000000000000000000000e6f07f4b23b511eac1e2682a0fc224c15d80e122a3e222d00a41fab15eba645a700b9ae84f331ae4ed873678e2e6c9b000000000000000000000000000000000bcb4849e460612aaed79617255fd30c03f51cf03d2ed4163ca810c13e1954b1e8663157b957a601829bb272a4e6c7b8",
		Name:        "WorstCaseG2",
		NoBenchmark: false,
	}
	benchmarkPrecompiled("f0f", testcase, b)
}

// Benchmarks the sample inputs from the P256VERIFY precompile.
func BenchmarkPrecompiledP256Verify(bench *testing.B) {
	t := precompiledTest{
		Input:    "4cee90eb86eaa050036147a12d49004b6b9c72bd725d39d4785011fe190f0b4da73bd4903f0ce3b639bbbf6e8e80d16931ff4bcf5993d58468e8fb19086e8cac36dbcd03009df8c59286b162af3bd7fcc0450c9aa81be5d10d312af6c66b1d604aebd3099c618202fcfe16ae7770b0c49ab5eadf74b754204a3bb6060e44eff37618b065f9832de4ca6ca971a7a1adc826d0f7c00181a5fb2ddf79ae00b4e10e",
		Expected: "0000000000000000000000000000000000000000000000000000000000000001",
		Name:     "p256Verify",
	}
	benchmarkPrecompiled("100", t, bench)
}

func TestPrecompiledP256Verify(t *testing.T) { testJson("p256Verify", "100", t) }

// Helper function to create ABI-encoded data for Falcon tests
func createFalconABIInput(signature, message, publicKey []byte) ([]byte, error) {
	bytesType, err := abi.NewType("bytes", "", nil)
	if err != nil {
		return nil, err
	}

	args := abi.Arguments{
		{Type: bytesType},
		{Type: bytesType},
		{Type: bytesType},
	}

	return args.Pack(signature, message, publicKey)
}

// Tests for Falcon signature verification precompile
func TestPrecompiledFalconVerify(t *testing.T) {
	// Real Falcon test data
	publicKeyHex := "09b4c44913e71be367081636c4d1cc5e59e9d17724891f4a4bc5505db1a53a124bd798128ec693f4d96ab4a77a8768f4d06abac4adc1a168bf81b25cc3a745ab65e0eb825743c354fed4e6ab54c50e899cf3d843e624e294ea3ce3ec9761a4b79fe17d2a4c2c134c24e95e29751355ea010a510415ddd5b96f625679012b319952cd265cec8c3a7498980283838434164abfde46b8502b83005ab94e91dc05cfa6cf7ec06d3194cc3854ed3933d4c5124299899ade8bda26cc43f2f649665615a1522cd4c3b074de4506a9db17dd0108326d148ada8dd355affc8684a353b943714f5dc5c91f0be48da9a3d7c3db050144b5c79d071673111b13e0a9e81470aa509902174a3c20d56f2743a63e6b03d3acc0b978f3b7e1d22a86a58942f891ca8ee6a519bb1fc11a4598a2a2582d92d9ad05294141ba564f66ace04657cd3ba36151c60e7e22603ba2334192dc866e51930f24b0b5ac92cc5b4ab5a0f886d9ac846191e742924fb47d46d40c0ba6807f9b4494539d15e770cf0c43762d9741d22380801a3e27a60d00326aa7665446342aea80f5796e831095e6a893805591f141a34f57bdbb5a29bbd21a2182e112e32095f429d54cea314b731e450fc901a7c62e2cea815fe5b51e5a76f0eb9d228bed24e3500f8a324988c69615f6be16f5eb8c0354439dc3ea84eefdbc5ac9e115c0a23ab40cbbe7015630c5af6b36ddaabe3d506bbaa1ce95808268c609e92e0db6d7bc0a8b61c1b738ec58787be9b141e196a36a059570e68fadaacd991033c24e6a98b75a5403da7dcdcdcbb891ac69649b813116c6268c2497ef81180a1a2a7aca00761a29968049cdc031ca8551c8a4178bd29ab1b2a8286f2c147788836906a5cf7bd419c526ce1244ab50be78f108f693133f8cfdbe2369d4cf269124286ed2e0476e1cc4be640836be02c5b785a21c4181f48daa612afc30946e102122c983fb1326609ba670c4b681fa64be3a443c24aa93fdafd72c1d4d15c89010c011790a4542232c28ce752cef054b6de1b3ae50942a2f08b0b61114b52ea822bcd0513ce1931eb45889519cef28b9a42618a5e8a70d865875e1aa6f395052294963585c01ba39ac0a65d64dd760d2757d32de3a6ac9073740d3c587d87d1e38e4d70653b866bde9691684ac1bc2aa25ce2bea3f165d88bf5f693541ea97cfaa6520c6dcebaea82c58b1025433d23022f0713a7392da99ee9927be842f562a1015e1987966c84550dca81a92e8b0f67625c6"
	signatureHex := "026699b77ab3eb4e18e85ea5b9affa1d68b2d223dee20d1f855fd1a8222b31b53cb5c7328f685f90545c48656c6c6f2046616c636f6e212937f0b0679e12357a282b308d33c74959fb66b4394acccf10897f61cb937c8c7ff608ce5331335b609104229de69d377ab77da5dc5eb82cb5de3c8df8d7f65644e018bc2da09163968126c2cd619df82d9b886dd63b044ef49d3c3bd4a671b78c4918141f185d1e5cb9af83ae8b86b99c6737aae342b76da87154454181be5005c3a0ea25be062513c1b0493947c2cc35547486ada4e220478fb70d66d0aae621046094aa34a28fd64a5d599f24d9f7a0b0b9a5ea2bd4f82fcd31adc63a77bb62613df8258ab2a734e888a28290e1e7ece5250fca3b1c475b00bda09d86a3a84419c53b91125d53b44f14c69d2ccbed023618460d8ba8f9b87745dca2a4f2d2ab893d6ff4cf2853b883f1a789e18c479760cd9aa770d8636186f11723f7fd7fcf3cb1a8c984e99cfbf5f79687090a26c5630a4fed5666c4875d7d781b72228f890d4a5fa27c233b4edab0891bc953f8af6e598287a24f894e4b2e4e60705fc52d4961f9f9144aa1c3661bdd9de33fc3eaae51fa82173f600c03a8cde6a5377f7c3983a169353b1203c493747c3b3ccba5d3b5e57f313a93fb0b4a68bea4788511a2419090a24ed4d6ec9eb5d822c51d383bc8624382aa5112732ad9b9ab23fd8d64bbec2772b9f3cb3ecf9c6a4643ef173b6fe7a7d45710a39e66b4287e8b53226a0c211335f589b6f6aad9442464ad37e8344feef23ccd5558d75e7b62b6c65bc5bba5a840ae728fdf2317973c489c5706dd335c38334511e231c716ce88fc7c085f62c274fafb4cdb177758c612c69ce3230460c9b45476e61bf399a9f4e29b91d1bdd94227c6e06dd2ef1afce3a5daaa6e2cca6ad886db99d1cee2f663373bee7ae4237f"
	message := []byte("Hello Falcon!")

	// Decode hex strings to bytes
	publicKey := common.Hex2Bytes(publicKeyHex)
	signature := common.Hex2Bytes(signatureHex)

	// Test case 1: Valid signature verification
	t.Run("ValidSignature", func(t *testing.T) {
		// Create ABI-encoded input
		abiInput, err := createFalconABIInput(signature, message, publicKey)
		if err != nil {
			t.Fatalf("Failed to create ABI input: %v", err)
		}

		p := allPrecompiles[common.BytesToAddress([]byte{0x13})]
		gas := p.RequiredGas(abiInput)

		if gas != 2500 {
			t.Errorf("Expected gas cost 2500, got %d", gas)
		}

		result, _, err := RunPrecompiledContract(p, abiInput, gas, nil)
		if err != nil {
			t.Errorf("Failed to run precompiled contract: %v", err)
		}

		// Check if signature verification succeeded (result should be 1)
		expected := common.LeftPadBytes([]byte{1}, 32)
		if !bytes.Equal(result, expected) {
			t.Errorf("Expected valid signature result %x, got %x", expected, result)
		}
	})

	// Test case 2: Test with Falcon library directly for comparison
	t.Run("FalconLibraryDirectTest", func(t *testing.T) {
		isValid, err := falcon.VerifySignature(signature, message, publicKey)
		if err != nil {
			t.Errorf("Direct Falcon verification failed: %v", err)
		}
		if !isValid {
			t.Error("Direct Falcon verification returned false for valid signature")
		}
	})

	// Test case 3: Invalid signature (tamper with signature)
	t.Run("InvalidSignature", func(t *testing.T) {
		// Tamper with signature
		tamperedSignature := make([]byte, len(signature))
		copy(tamperedSignature, signature)
		tamperedSignature[0] ^= 0xFF // Flip bits in first byte

		abiInput, err := createFalconABIInput(tamperedSignature, message, publicKey)

		if err != nil {
			t.Fatalf("Failed to create ABI input: %v", err)
		}

		p := allPrecompiles[common.BytesToAddress([]byte{0x13})]
		gas := p.RequiredGas(abiInput)

		result, _, err := RunPrecompiledContract(p, abiInput, gas, nil)
		if err != nil {
			t.Errorf("Failed to run precompiled contract: %v", err)
		}

		// Check if signature verification failed (result should be 0)
		expected := common.LeftPadBytes([]byte{0}, 32)
		if !bytes.Equal(result, expected) {
			t.Errorf("Expected invalid signature result %x, got %x", expected, result)
		}
	})
}

// Benchmark for Falcon signature verification
func BenchmarkPrecompiledFalconVerify(b *testing.B) {
	// Falcon test data
	publicKeyHex := "09b4c44913e71be367081636c4d1cc5e59e9d17724891f4a4bc5505db1a53a124bd798128ec693f4d96ab4a77a8768f4d06abac4adc1a168bf81b25cc3a745ab65e0eb825743c354fed4e6ab54c50e899cf3d843e624e294ea3ce3ec9761a4b79fe17d2a4c2c134c24e95e29751355ea010a510415ddd5b96f625679012b319952cd265cec8c3a7498980283838434164abfde46b8502b83005ab94e91dc05cfa6cf7ec06d3194cc3854ed3933d4c5124299899ade8bda26cc43f2f649665615a1522cd4c3b074de4506a9db17dd0108326d148ada8dd355affc8684a353b943714f5dc5c91f0be48da9a3d7c3db050144b5c79d071673111b13e0a9e81470aa509902174a3c20d56f2743a63e6b03d3acc0b978f3b7e1d22a86a58942f891ca8ee6a519bb1fc11a4598a2a2582d92d9ad05294141ba564f66ace04657cd3ba36151c60e7e22603ba2334192dc866e51930f24b0b5ac92cc5b4ab5a0f886d9ac846191e742924fb47d46d40c0ba6807f9b4494539d15e770cf0c43762d9741d22380801a3e27a60d00326aa7665446342aea80f5796e831095e6a893805591f141a34f57bdbb5a29bbd21a2182e112e32095f429d54cea314b731e450fc901a7c62e2cea815fe5b51e5a76f0eb9d228bed24e3500f8a324988c69615f6be16f5eb8c0354439dc3ea84eefdbc5ac9e115c0a23ab40cbbe7015630c5af6b36ddaabe3d506bbaa1ce95808268c609e92e0db6d7bc0a8b61c1b738ec58787be9b141e196a36a059570e68fadaacd991033c24e6a98b75a5403da7dcdcdcbb891ac69649b813116c6268c2497ef81180a1a2a7aca00761a29968049cdc031ca8551c8a4178bd29ab1b2a8286f2c147788836906a5cf7bd419c526ce1244ab50be78f108f693133f8cfdbe2369d4cf269124286ed2e0476e1cc4be640836be02c5b785a21c4181f48daa612afc30946e102122c983fb1326609ba670c4b681fa64be3a443c24aa93fdafd72c1d4d15c89010c011790a4542232c28ce752cef054b6de1b3ae50942a2f08b0b61114b52ea822bcd0513ce1931eb45889519cef28b9a42618a5e8a70d865875e1aa6f395052294963585c01ba39ac0a65d64dd760d2757d32de3a6ac9073740d3c587d87d1e38e4d70653b866bde9691684ac1bc2aa25ce2bea3f165d88bf5f693541ea97cfaa6520c6dcebaea82c58b1025433d23022f0713a7392da99ee9927be842f562a1015e1987966c84550dca81a92e8b0f67625c6"
	signatureHex := "026699b77ab3eb4e18e85ea5b9affa1d68b2d223dee20d1f855fd1a8222b31b53cb5c7328f685f90545c48656c6c6f2046616c636f6e212937f0b0679e12357a282b308d33c74959fb66b4394acccf10897f61cb937c8c7ff608ce5331335b609104229de69d377ab77da5dc5eb82cb5de3c8df8d7f65644e018bc2da09163968126c2cd619df82d9b886dd63b044ef49d3c3bd4a671b78c4918141f185d1e5cb9af83ae8b86b99c6737aae342b76da87154454181be5005c3a0ea25be062513c1b0493947c2cc35547486ada4e220478fb70d66d0aae621046094aa34a28fd64a5d599f24d9f7a0b0b9a5ea2bd4f82fcd31adc63a77bb62613df8258ab2a734e888a28290e1e7ece5250fca3b1c475b00bda09d86a3a84419c53b91125d53b44f14c69d2ccbed023618460d8ba8f9b87745dca2a4f2d2ab893d6ff4cf2853b883f1a789e18c479760cd9aa770d8636186f11723f7fd7fcf3cb1a8c984e99cfbf5f79687090a26c5630a4fed5666c4875d7d781b72228f890d4a5fa27c233b4edab0891bc953f8af6e598287a24f894e4b2e4e60705fc52d4961f9f9144aa1c3661bdd9de33fc3eaae51fa82173f600c03a8cde6a5377f7c3983a169353b1203c493747c3b3ccba5d3b5e57f313a93fb0b4a68bea4788511a2419090a24ed4d6ec9eb5d822c51d383bc8624382aa5112732ad9b9ab23fd8d64bbec2772b9f3cb3ecf9c6a4643ef173b6fe7a7d45710a39e66b4287e8b53226a0c211335f589b6f6aad9442464ad37e8344feef23ccd5558d75e7b62b6c65bc5bba5a840ae728fdf2317973c489c5706dd335c38334511e231c716ce88fc7c085f62c274fafb4cdb177758c612c69ce3230460c9b45476e61bf399a9f4e29b91d1bdd94227c6e06dd2ef1afce3a5daaa6e2cca6ad886db99d1cee2f663373bee7ae4237f"
	message := []byte("Hello Falcon!")

	// Decode hex strings to bytes
	publicKey := common.Hex2Bytes(publicKeyHex)
	signature := common.Hex2Bytes(signatureHex)

	// Create ABI-encoded input
	abiInput, err := createFalconABIInput(signature, message, publicKey)
	if err != nil {
		b.Fatalf("Failed to create ABI input: %v", err)
	}

	test := precompiledTest{
		Input:    common.Bytes2Hex(abiInput),
		Expected: "0000000000000000000000000000000000000000000000000000000000000001", // Expected valid signature
		Name:     "FalconVerify",
	}

	benchmarkPrecompiled("13", test, b)
}

// Helper function to create properly formatted input for NTT tests
func createNTTInput(isForward bool, ringDegree uint32, modulus uint64, coefficients []uint64) []byte {
	input := make([]byte, 1+4+8+len(coefficients)*8)

	// Operation: 0 = forward NTT, 1 = inverse NTT
	if isForward {
		input[0] = 0
	} else {
		input[0] = 1
	}

	// Ring degree (4 bytes, big endian)
	binary.BigEndian.PutUint32(input[1:5], ringDegree)

	// Modulus (8 bytes, big endian)
	binary.BigEndian.PutUint64(input[5:13], modulus)

	// Coefficients (8 bytes each, big endian)
	for i, coeff := range coefficients {
		binary.BigEndian.PutUint64(input[13+i*8:13+(i+1)*8], coeff)
	}

	return input
}

// Test NTT precompile
func TestPrecompiledNTT(t *testing.T) {
	t.Run("NTT Forward Transform", func(t *testing.T) {
		// Test parameters: ring degree 512, modulus 12289 (Falcon NTT-friendly)
		ringDegree := uint32(512)
		modulus := uint64(12289) // Falcon modulus from Python reference

		// Create input: operation(1) + ring_degree(4) + modulus(8) + coefficients(512*8)
		input := make([]byte, 1+4+8+512*8)

		// Operation: 0 = forward NTT
		input[0] = 0

		// Ring degree (big endian)
		binary.BigEndian.PutUint32(input[1:5], ringDegree)

		// Modulus (big endian)
		binary.BigEndian.PutUint64(input[5:13], modulus)

		// Test coefficients: simple pattern
		testCoeffs := []uint64{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}
		for i, coeff := range testCoeffs {
			binary.BigEndian.PutUint64(input[13+i*8:13+(i+1)*8], coeff)
		}

		// Run precompile
		p := &precomputedNTT{}
		gas := p.RequiredGas(input)
		result, err := p.Run(input)

		if err != nil {
			t.Fatalf("NTT precompile failed: %v", err)
		}

		if len(result) != int(ringDegree)*8 {
			t.Fatalf("Expected result length %d, got %d", ringDegree*8, len(result))
		}

		// Verify that result is different from input (NTT should transform the coefficients)
		resultChanged := false
		for i := 0; i < int(ringDegree); i++ {
			resultCoeff := binary.BigEndian.Uint64(result[i*8 : (i+1)*8])
			if resultCoeff != testCoeffs[i] {
				resultChanged = true
				break
			}
		}

		if !resultChanged {
			t.Error("NTT result should be different from input coefficients")
		}

		t.Logf("NTT forward transform succeeded, gas used: %d", gas)
	})

	t.Run("NTT Inverse Transform", func(t *testing.T) {
		ringDegree := uint32(16)
		modulus := uint64(12289) // Falcon modulus

		// First, do a forward transform
		inputForward := make([]byte, 1+4+8+16*8)
		inputForward[0] = 0 // forward
		binary.BigEndian.PutUint32(inputForward[1:5], ringDegree)
		binary.BigEndian.PutUint64(inputForward[5:13], modulus)

		testCoeffs := []uint64{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}
		for i, coeff := range testCoeffs {
			binary.BigEndian.PutUint64(inputForward[13+i*8:13+(i+1)*8], coeff)
		}

		p := &precomputedNTT{}
		forwardResult, err := p.Run(inputForward)
		if err != nil {
			t.Fatalf("Forward NTT failed: %v", err)
		}

		// Now do inverse transform on the result
		inputInverse := make([]byte, 1+4+8+16*8)
		inputInverse[0] = 1 // inverse
		binary.BigEndian.PutUint32(inputInverse[1:5], ringDegree)
		binary.BigEndian.PutUint64(inputInverse[5:13], modulus)
		copy(inputInverse[13:], forwardResult)

		inverseResult, err := p.Run(inputInverse)
		if err != nil {
			t.Fatalf("Inverse NTT failed: %v", err)
		}

		// Verify that forward + inverse gives back original (approximately, due to modular arithmetic)
		for i := 0; i < int(ringDegree); i++ {
			originalCoeff := testCoeffs[i]
			recoveredCoeff := binary.BigEndian.Uint64(inverseResult[i*8 : (i+1)*8])

			// Allow for modular reduction
			if recoveredCoeff != originalCoeff && recoveredCoeff != originalCoeff%modulus {
				t.Errorf("Coefficient %d: expected %d or %d, got %d", i, originalCoeff, originalCoeff%modulus, recoveredCoeff)
			}
		}

		t.Log("NTT round-trip (forward + inverse) succeeded")
	})

	t.Run("NTT Invalid Inputs", func(t *testing.T) {
		p := &precomputedNTT{}

		// Test empty input
		_, err := p.Run([]byte{})
		if err == nil {
			t.Error("Expected error for empty input")
		}

		// Test invalid operation
		invalidOp := make([]byte, 13)
		invalidOp[0] = 2 // invalid operation
		_, err = p.Run(invalidOp)
		if err == nil {
			t.Error("Expected error for invalid operation")
		}

		// Test invalid ring degree (not power of 2)
		invalidDegree := make([]byte, 1+4+8+15*8)
		invalidDegree[0] = 0
		binary.BigEndian.PutUint32(invalidDegree[1:5], 15) // not power of 2
		_, err = p.Run(invalidDegree)
		if err == nil {
			t.Error("Expected error for invalid ring degree")
		}

		t.Log("Invalid input tests passed")
	})
}

// Test NTT transforms with specific cryptographic standards
func TestNTTCryptographicStandards(t *testing.T) {
	// Test parameters based on cryptographic standards
	testCases := []struct {
		name      string
		degree    uint32
		modulus   uint64
		cryptoStd string
	}{
		{"Falcon-512", 512, 12289, "Falcon (NIST PQC)"},
		{"Dilithium-256", 256, 8380417, "Dilithium (NIST PQC)"},
		{"Kyber-128", 128, 3329, "Kyber (NIST PQC)"},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Generate test coefficients
			coeffs := make([]uint64, tc.degree)
			for i := uint32(0); i < tc.degree; i++ {
				coeffs[i] = uint64(i+1) % tc.modulus
			}

			// Test Precomputed NTT
			t.Run("PrecomputedNTT", func(t *testing.T) {
				input := createNTTInput(true, tc.degree, tc.modulus, coeffs)

				p := &precomputedNTT{}
				gas := p.RequiredGas(input)
				result, err := p.Run(input)

				if err != nil {
					t.Fatalf("Precomputed NTT failed for %s: %v", tc.cryptoStd, err)
				}

				if len(result) != int(tc.degree)*8 {
					t.Fatalf("Expected result length %d, got %d", tc.degree*8, len(result))
				}

				// Verify result is different from input (NTT transform)
				transformed := false
				for i := uint32(0); i < tc.degree; i++ {
					resultCoeff := binary.BigEndian.Uint64(result[i*8 : (i+1)*8])
					if resultCoeff != coeffs[i] {
						transformed = true
						break
					}
				}

				if !transformed {
					t.Errorf("NTT should transform coefficients for %s", tc.cryptoStd)
				}

				t.Logf("✓ Precomputed NTT succeeded for %s (degree=%d, modulus=%d, gas=%d)",
					tc.cryptoStd, tc.degree, tc.modulus, gas)
			})

			// Test Pure NTT
			t.Run("PureNTT", func(t *testing.T) {
				input := createNTTInput(true, tc.degree, tc.modulus, coeffs)

				p := &pureNTT{}
				gas := p.RequiredGas(input)
				result, err := p.Run(input)

				if err != nil {
					t.Fatalf("Pure NTT failed for %s: %v", tc.cryptoStd, err)
				}

				if len(result) != int(tc.degree)*8 {
					t.Fatalf("Expected result length %d, got %d", tc.degree*8, len(result))
				}

				// Verify result is different from input (NTT transform)
				transformed := false
				for i := uint32(0); i < tc.degree; i++ {
					resultCoeff := binary.BigEndian.Uint64(result[i*8 : (i+1)*8])
					if resultCoeff != coeffs[i] {
						transformed = true
						break
					}
				}

				if !transformed {
					t.Errorf("NTT should transform coefficients for %s", tc.cryptoStd)
				}

				t.Logf("✓ Pure NTT succeeded for %s (degree=%d, modulus=%d, gas=%d)",
					tc.cryptoStd, tc.degree, tc.modulus, gas)
			})

			// Test round-trip: Forward + Inverse NTT
			t.Run("RoundTrip", func(t *testing.T) {
				// Forward transform
				forwardInput := createNTTInput(true, tc.degree, tc.modulus, coeffs)
				p := &precomputedNTT{}
				forwardResult, err := p.Run(forwardInput)
				if err != nil {
					t.Fatalf("Forward NTT failed: %v", err)
				}

				// Extract transformed coefficients
				transformedCoeffs := make([]uint64, tc.degree)
				for i := uint32(0); i < tc.degree; i++ {
					transformedCoeffs[i] = binary.BigEndian.Uint64(forwardResult[i*8 : (i+1)*8])
				}

				// Inverse transform
				inverseInput := createNTTInput(false, tc.degree, tc.modulus, transformedCoeffs)
				inverseResult, err := p.Run(inverseInput)
				if err != nil {
					t.Fatalf("Inverse NTT failed: %v", err)
				}

				// Verify round-trip recovery
				maxError := uint64(0)
				for i := uint32(0); i < tc.degree; i++ {
					original := coeffs[i]
					recovered := binary.BigEndian.Uint64(inverseResult[i*8 : (i+1)*8])

					// Allow for modular reduction
					if recovered != original && recovered != original%tc.modulus {
						error := uint64(0)
						if recovered > original {
							error = recovered - original
						} else {
							error = original - recovered
						}
						if error > maxError {
							maxError = error
						}

						// Check if difference is due to modular arithmetic
						if (original % tc.modulus) != (recovered % tc.modulus) {
							t.Errorf("Round-trip failed at coefficient %d for %s: original=%d, recovered=%d",
								i, tc.cryptoStd, original, recovered)
						}
					}
				}

				t.Logf("✓ Round-trip test passed for %s (max_error=%d)", tc.cryptoStd, maxError)
			})
		})
	}
}

// Benchmark NTT transforms for cryptographic standards
func BenchmarkNTTCryptographicStandards(b *testing.B) {
	testCases := []struct {
		name      string
		degree    uint32
		modulus   uint64
		cryptoStd string
	}{
		{"Falcon-512", 512, 12289, "Falcon"},
		{"Dilithium-256", 256, 8380417, "Dilithium"},
		{"Kyber-128", 128, 3329, "Kyber"},
	}

	for _, tc := range testCases {
		// Generate test coefficients
		coeffs := make([]uint64, tc.degree)
		for i := uint32(0); i < tc.degree; i++ {
			coeffs[i] = uint64(i+1) % tc.modulus
		}
		input := createNTTInput(true, tc.degree, tc.modulus, coeffs)

		// Benchmark Precomputed NTT
		b.Run("Precomputed-"+tc.name, func(b *testing.B) {
			p := &precomputedNTT{}
			gas := p.RequiredGas(input)

			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				result, err := p.Run(input)
				if err != nil {
					b.Fatalf("Precomputed NTT failed: %v", err)
				}
				_ = result // Prevent optimization
			}

			b.ReportMetric(float64(gas), "gas/op")
			b.ReportMetric(float64(gas)/b.Elapsed().Seconds()*float64(b.N)/1e6, "mgas/s")
		})

		// Benchmark Pure NTT
		b.Run("Pure-"+tc.name, func(b *testing.B) {
			p := &pureNTT{}
			gas := p.RequiredGas(input)

			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				result, err := p.Run(input)
				if err != nil {
					b.Fatalf("Pure NTT failed: %v", err)
				}
				_ = result // Prevent optimization
			}

			b.ReportMetric(float64(gas), "gas/op")
			b.ReportMetric(float64(gas)/b.Elapsed().Seconds()*float64(b.N)/1e6, "mgas/s")
		})
	}
}

// Test NTT parameter validation
func TestNTTParameterValidation(t *testing.T) {
	testCases := []struct {
		name          string
		degree        uint32
		modulus       uint64
		shouldFail    bool
		expectedError string
	}{
		{"Falcon-Valid", 512, 12289, false, ""},
		{"Dilithium-Valid", 256, 8380417, false, ""},
		{"Kyber-Valid", 128, 3329, false, ""},
		{"InvalidDegree-NotPowerOf2", 100, 12289, true, "invalid ring degree"},
		{"InvalidDegree-TooSmall", 8, 12289, true, "invalid ring degree"},
		{"InvalidModulus-Zero", 256, 0, true, "invalid modulus"},
		{"InvalidModulus-TooLarge", 256, 1 << 62, true, "invalid modulus"},
		{"InvalidModulus-NotNTTFriendly", 256, 12290, true, "modulus must be congruent to 1"},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Generate simple test coefficients
			coeffs := make([]uint64, tc.degree)
			for i := uint32(0); i < tc.degree && i < 100; i++ {
				if tc.modulus > 0 {
					coeffs[i] = uint64(i+1) % tc.modulus
				} else {
					coeffs[i] = uint64(i + 1)
				}
			}

			input := createNTTInput(true, tc.degree, tc.modulus, coeffs)

			p := &precomputedNTT{}
			_, err := p.Run(input)

			if tc.shouldFail {
				if err == nil {
					t.Errorf("Expected error for %s, but got none", tc.name)
				} else if tc.expectedError != "" && !bytes.Contains([]byte(err.Error()), []byte(tc.expectedError)) {
					t.Errorf("Expected error containing '%s', got: %v", tc.expectedError, err)
				} else {
					t.Logf("✓ Correctly rejected invalid parameters: %v", err)
				}
			} else {
				if err != nil {
					t.Errorf("Expected success for %s, got error: %v", tc.name, err)
				} else {
					t.Logf("✓ Correctly accepted valid parameters for %s", tc.name)
				}
			}
		})
	}
}
