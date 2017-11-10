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

package vm

import (
	"fmt"
	"sync/atomic"
	"time"

	"github.com/Anson5Lee/anson_bc/common"
	"github.com/Anson5Lee/anson_bc/common/math"
	"github.com/Anson5Lee/anson_bc/crypto"
	"github.com/Anson5Lee/anson_bc/log"
	"github.com/Anson5Lee/anson_bc/params"
)

// Config are the configuration options for the Interpreter
type Config struct {
	// Debug enabled debugging Interpreter options
	Debug bool
	// EnableJit enabled the JIT VM
	EnableJit bool
	// ForceJit forces the JIT VM
	ForceJit bool
	// Tracer is the op code logger
	Tracer Tracer
	// NoRecursion disabled Interpreter call, callcode,
	// delegate call and create.
	NoRecursion bool
	// Disable gas metering
	DisableGasMetering bool
	// Enable recording of SHA3/keccak preimages
	EnablePreimageRecording bool
	// JumpTable contains the EVM instruction table. This
	// may me left uninitialised and will be set the default
	// table.
	JumpTable [256]operation
}

// Interpreter is used to run Ethereum based contracts and will utilise the
// passed evmironment to query external sources for state information.
// The Interpreter will run the byte code VM or JIT VM based on the passed
// configuration.

// @anson
// Interpreter用来执行非预编译合约
type Interpreter struct {
	evm *EVM
	// @anson
	// Interpreter通过一个Config类型的成员变量，间接持有一个包括256个operation对象在内的数组JumpTable
	// 每个operation对象对应一个已定义的虚拟机指令，它所含有的四个函数变量：execute, gasCost, validateStack, memorySize提供了这个虚拟机指令所代表的所有操作
	// 每个指令长度1 byte, Contract对象的成员变量Code类型为[]byte，就是这些虚拟机指令所代表的所有操作
	// operation对象的函数操作，主要会用到Stack, Memory, IntPool这几个自定义的数据结构
	cfg      Config
	gasTable params.GasTable
	intPool  *intPool

	readonly bool
}

// NewInterpreter returns a new instance of the Interpreter.
func NewInterpreter(evm *EVM, cfg Config) *Interpreter {
	// We use the STOP instruction whether to see
	// the jump table was initialised. If it was not
	// we'll set the default jump table.
	if !cfg.JumpTable[STOP].valid {
		switch {
		case evm.ChainConfig().IsHomestead(evm.BlockNumber):
			cfg.JumpTable = homesteadInstructionSet
		default:
			cfg.JumpTable = frontierInstructionSet
		}
	}

	return &Interpreter{
		evm:      evm,
		cfg:      cfg,
		gasTable: evm.ChainConfig().GasTable(evm.BlockNumber),
		intPool:  newIntPool(),
	}
}

func (in *Interpreter) enforceRestrictions(op OpCode, operation operation, stack *Stack) error {
	return nil
}

// @anson
// Interpreter的run函数，其核心流程就是逐个byte遍历入参Contract对象的Code变量，将其解释为一个已知的operation，然后以此调用该operation
// 对象的四个函数
// operation在操作过程中，会需要几个数据结构：
// Stack: 实现了标准容器栈的行为
// Memory: 一个字节数组，可表示线性排列的任意数据
// intPool: 提供对big.Int数据的存储和读取

// Run loops and evaluates the contract's code with the given input data and returns
// the return byte-slice and an error if one occurred.
//
// It's important to note that any errors returned by the interpreter should be
// considered a revert-and-consume-all-gas operation. No error specific checks
// should be handled to reduce complexity and errors further down the in.
func (in *Interpreter) Run(snapshot int, contract *Contract, input []byte) (ret []byte, err error) {
	in.evm.depth++
	defer func() { in.evm.depth-- }()

	// !!!!!IMPORTANT!!!!!
	code := contract.CodeAddr
	fmt.Printf("\ncode inside interpreter.Run(): %v\n", code)
	if contract.CodeAddr != nil {
		if p := PrecompiledContracts[*code]; p != nil {
			fmt.Println("\ninside Interpreter.Run()\n")
			return RunPrecompiledContract(p, input, contract, in)
		}
	}

	// Don't bother with the execution if there's no code.
	if len(contract.Code) == 0 {
		return nil, nil
	}

	codehash := contract.CodeHash // codehash is used when doing jump dest caching
	if codehash == (common.Hash{}) {
		codehash = crypto.Keccak256Hash(contract.Code)
	}

	var (
		op    OpCode        // current opcode
		mem   = NewMemory() // bound memory
		stack = newstack()  // local stack
		// For optimisation reason we're using uint64 as the program counter.
		// It's theoretically possible to go above 2^64. The YP defines the PC
		// to be uint256. Practically much less so feasible.
		pc   = uint64(0) // program counter
		cost uint64
	)
	contract.Input = input

	// User defer pattern to check for an error and, based on the error being nil or not, use all gas and return.
	defer func() {
		if err != nil && in.cfg.Debug {
			// XXX For debugging
			//fmt.Printf("%04d: %8v    cost = %-8d stack = %-8d ERR = %v\n", pc, op, cost, stack.len(), err)
			in.cfg.Tracer.CaptureState(in.evm, pc, op, contract.Gas, cost, mem, stack, contract, in.evm.depth, err)
		}
	}()

	log.Debug("interpreter running contract", "hash", codehash[:])
	tstart := time.Now()
	defer log.Debug("interpreter finished running contract", "hash", codehash[:], "elapsed", time.Since(tstart))

	// The Interpreter main run loop (contextual). This loop runs until either an
	// explicit STOP, RETURN or SELFDESTRUCT is executed, an error occurred during
	// the execution of one of the operations or until the done flag is set by the
	// parent context.
	for atomic.LoadInt32(&in.evm.abort) == 0 {
		// Get the memory location of pc
		op = contract.GetOp(pc)

		// get the operation from the jump table matching the opcode
		operation := in.cfg.JumpTable[op]
		if err := in.enforceRestrictions(op, operation, stack); err != nil {
			return nil, err
		}

		// if the op is invalid abort the process and return an error
		if !operation.valid {
			return nil, fmt.Errorf("invalid opcode 0x%x", int(op))
		}

		// validate the stack and make sure there enough stack items available
		// to perform the operation
		if err := operation.validateStack(stack); err != nil {
			return nil, err
		}

		var memorySize uint64
		// calculate the new memory size and expand the memory to fit
		// the operation
		if operation.memorySize != nil {
			memSize, overflow := bigUint64(operation.memorySize(stack))
			if overflow {
				return nil, errGasUintOverflow
			}
			// memory is expanded in words of 32 bytes. Gas
			// is also calculated in words.
			if memorySize, overflow = math.SafeMul(toWordSize(memSize), 32); overflow {
				return nil, errGasUintOverflow
			}
		}

		if !in.cfg.DisableGasMetering {
			// consume the gas and return an error if not enough gas is available.
			// cost is explicitly set so that the capture state defer method cas get the proper cost
			cost, err = operation.gasCost(in.gasTable, in.evm, contract, stack, mem, memorySize)
			if err != nil || !contract.UseGas(cost) {
				return nil, ErrOutOfGas
			}
		}
		if memorySize > 0 {
			mem.Resize(memorySize)
		}

		if in.cfg.Debug {
			in.cfg.Tracer.CaptureState(in.evm, pc, op, contract.Gas, cost, mem, stack, contract, in.evm.depth, err)
		}
		// XXX For debugging
		//fmt.Printf("%04d: %8v    cost = %-8d stack = %-8d\n", pc, op, cost, stack.len())

		// execute the operation
		res, err := operation.execute(&pc, in.evm, contract, mem, stack)
		// verifyPool is a build flag. Pool verification makes sure the integrity
		// of the integer pool by comparing values to a default value.
		if verifyPool {
			verifyIntegerPool(in.intPool)
		}

		switch {
		case err != nil:
			return nil, err
		case operation.halts:
			return res, nil
		case !operation.jumps:
			pc++
		}
		// if the operation returned a value make sure that is also set
		// the last return data.
		if res != nil {
			mem.lastReturn = ret
		}
	}
	return nil, nil
}
