// Copyright 2014 The go-ethereum Authors
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

// @anson
// 目前，Ethereum代码中已经加入了多个预编译合约，包括：
// 椭圆曲线秘钥恢复、SHA-3哈希算法、RIPEMD-160加密算法

package vm

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"fmt"
	"math/big"
	"strings"

	"github.com/Anson5Lee/anson_bc/accounts/abi"
	"github.com/Anson5Lee/anson_bc/common"
	"github.com/Anson5Lee/anson_bc/common/hexutil"
	"github.com/Anson5Lee/anson_bc/crypto"
	"github.com/Anson5Lee/anson_bc/log"
	"github.com/Anson5Lee/anson_bc/params"
	"golang.org/x/crypto/ripemd160"
)

var (
	coinSCABIJSON            = `[{"constant":false,"type":"function","stateMutability":"nonpayable","inputs":[{"name":"OtaAddr","type":"string"},{"name":"Value","type":"uint256"}],"name":"buyCoinNote","outputs":[{"name":"OtaAddr","type":"string"},{"name":"Value","type":"uint256"}]},{"constant":false,"type":"function","inputs":[{"name":"RingSignedData","type":"string"},{"name":"Value","type":"uint256"}],"name":"refundCoin","outputs":[{"name":"RingSignedData","type":"string"},{"name":"Value","type":"uint256"}]},{"constant":false,"inputs":[],"name":"getCoins","outputs":[{"name":"Value","type":"uint256"}]}]`
	coinSCABI, errCoinSCInit = abi.JSON(strings.NewReader(coinSCABIJSON))
	buyCoinId                []byte
)

var errBadPrecompileInput = errors.New("bad pre compile input")

// Precompiled contract is the basic interface for native Go contracts. The implementation
// requires a deterministic gas count based on the input size of the Run method of the
// contract.
type PrecompiledContract interface {
	RequiredGas(inputLen int) uint64                                        // RequiredPrice calculates the contract gas use
	Run(input []byte, contract *Contract, evm *Interpreter) ([]byte, error) // Run runs the precompiled contract
}

// PrecompiledContracts contains the default set of ethereum contracts
var PrecompiledContracts = map[common.Address]PrecompiledContract{
	common.BytesToAddress([]byte{1}): &ecrecover{},
	common.BytesToAddress([]byte{2}): &sha256hash{},
	common.BytesToAddress([]byte{3}): &ripemd160hash{},
	common.BytesToAddress([]byte{4}): &dataCopy{},
	common.BytesToAddress([]byte{5}): &coinSC{},
}

func init() {
	if errCoinSCInit != nil {
		// @anson
		// TODO: refact panic
	}

	copy(buyCoinId[:], coinSCABI.Methods["buyCoinNote"].Id())
}

// RunPrecompile runs and evaluate the output of a precompiled contract defined in contracts.go
func RunPrecompiledContract(p PrecompiledContract, input []byte, contract *Contract, evm *Interpreter) (ret []byte, err error) {
	// @anson
	gas := p.RequiredGas(len(input))
	if contract.UseGas(gas) {
		// return p.Run(input)
		ret, err = p.Run(input, contract, evm)
		if ret != nil && err == nil {
			return ret, nil
		} else {
			return nil, ErrOutOfGas
		}
	} else {
		return nil, ErrOutOfGas
	}
}

// ECRECOVER implemented as a native contract
type ecrecover struct{}

func (c *ecrecover) RequiredGas(l int) uint64 {
	return params.EcrecoverGas
}

func (c *ecrecover) Run(in []byte, contract *Contract, evm *Interpreter) ([]byte, error) {
	const ecRecoverInputLength = 128

	in = common.RightPadBytes(in, ecRecoverInputLength)
	// "in" is (hash, v, r, s), each 32 bytes
	// but for ecrecover we want (r, s, v)

	r := new(big.Int).SetBytes(in[64:96])
	s := new(big.Int).SetBytes(in[96:128])
	v := in[63] - 27

	// tighter sig s values in homestead only apply to tx sigs
	if !allZero(in[32:63]) || !crypto.ValidateSignatureValues(v, r, s, false) {
		log.Trace("ECRECOVER error: v, r or s value invalid")
		return nil, nil
	}
	// v needs to be at the end for libsecp256k1
	pubKey, err := crypto.Ecrecover(in[:32], append(in[64:128], v))
	// make sure the public key is a valid one
	if err != nil {
		log.Trace("ECRECOVER failed", "err", err)
		return nil, nil
	}

	// the first byte of pubkey is bitcoin heritage
	return common.LeftPadBytes(crypto.Keccak256(pubKey[1:])[12:], 32), nil
}

// SHA256 implemented as a native contract
type sha256hash struct{}

// RequiredGas returns the gas required to execute the pre-compiled contract.
//
// This method does not require any overflow checking as the input size gas costs
// required for anything significant is so high it's impossible to pay for.
func (c *sha256hash) RequiredGas(l int) uint64 {
	return uint64(l+31)/32*params.Sha256WordGas + params.Sha256Gas
}
func (c *sha256hash) Run(in []byte, contract *Contract, evm *Interpreter) ([]byte, error) {
	h := sha256.Sum256(in)
	return h[:], nil
}

// RIPMED160 implemented as a native contract
type ripemd160hash struct{}

// RequiredGas returns the gas required to execute the pre-compiled contract.
//
// This method does not require any overflow checking as the input size gas costs
// required for anything significant is so high it's impossible to pay for.
func (c *ripemd160hash) RequiredGas(l int) uint64 {
	return uint64(l+31)/32*params.Ripemd160WordGas + params.Ripemd160Gas
}
func (c *ripemd160hash) Run(in []byte, contract *Contract, evm *Interpreter) ([]byte, error) {
	ripemd := ripemd160.New()
	ripemd.Write(in)
	return common.LeftPadBytes(ripemd.Sum(nil), 32), nil
}

// data copy implemented as a native contract
type dataCopy struct{}

// RequiredGas returns the gas required to execute the pre-compiled contract.
//
// This method does not require any overflow checking as the input size gas costs
// required for anything significant is so high it's impossible to pay for.
func (c *dataCopy) RequiredGas(l int) uint64 {
	return uint64(l+31)/32*params.IdentityWordGas + params.IdentityGas
}
func (c *dataCopy) Run(in []byte, contract *Contract, evm *Interpreter) ([]byte, error) {
	return in, nil
}

// @anson: native coin implemented as a pre-compiled contract
type coinSC struct{}

// RequiredGas returns the gas required to exetute the pre-compiled contract

func (c *coinSC) RequiredGas(l int) uint64 {
	return params.EcrecoverGas
}

func (c *coinSC) Run(input []byte, contract *Contract, evm *Interpreter) ([]byte, error) {
	inStr := hexutil.Encode(input)
	fmt.Printf("input in string: %s\n", inStr)
	fmt.Println("\n")
	var method []byte
	copy(method[:], input[:4])
	if equal := bytes.Equal(method, buyCoinId); equal {
		return c.mint(input[4:], contract, evm)
	}

	return nil, nil
}

func (c *coinSC) mint(input []byte, contract *Contract, evm *Interpreter) ([]byte, error) {
	var outStruct struct {
		OtaAddr string
		Value   *big.Int
	}

	err := coinSCABI.Unpack(&outStruct, "buyCoinNote", input)

	if err != nil {
		return nil, err
	}

	fmt.Printf("otaAddr: %v\n", outStruct.OtaAddr)
	fmt.Printf("value: %v\n", outStruct.Value)
	fmt.Println("\n")
	wanAddr, err := hexutil.Decode(outStruct.OtaAddr)
	if err != nil {
		return nil, err
	}

	fmt.Printf("wan address: %v\n", wanAddr)
	fmt.Printf("wanAddr len: %d\n", len(wanAddr))
	fmt.Println("\n")

	add, err := AddOTAIfNotExist(evm.evm.StateDB, contract.value, wanAddr)
	// fmt.Printf("\nadd flag: %v\n", add)
	if err != nil || !add {
		return nil, err
	}

	fmt.Printf("addFlag: %v\n", add)

	addrSrc := contract.CallerAddress
	balance := evm.evm.StateDB.GetBalance(addrSrc)

	if balance.Cmp(contract.value) >= 0 {
		// Need check contract value in build in value sets
		evm.evm.StateDB.SubBalance(addrSrc, contract.value)
	}

	return nil, nil
}
