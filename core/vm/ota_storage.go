// @anson

package vm

import (
	"errors"
	"fmt"
	"github.com/Anson5Lee/anson_bc/common"
	"github.com/Anson5Lee/anson_bc/crypto"
	"math/big"
)

var (
	OTABalanceStorageAddr = common.BytesToAddress(crypto.Keccak256([]byte(string("OTA balance storage address"))))
)

var (
	ErrInvalidOTAArgs = errors.New("Invalid arguments to persist OTAs")
)

func GetOTASet(db StateDB, otaAX []byte, otaQty int) (otaWanAddress [][]byte, balance *big.Int, err error) {
	if db == nil || otaAX == nil || len(otaAX) != common.HashLength {
		return nil, nil, nil
	}
	return nil, nil, nil
}

func AddOTAIfNotExist(db StateDB, balance *big.Int, otaWanAddr []byte) (bool, error) {
	if db == nil || balance == nil || otaWanAddr == nil || len(otaWanAddr) != common.WAddressLength {
		return false, ErrInvalidOTAArgs
	}

	otaAddrKey := common.BytesToHash(otaWanAddr[1 : 1+common.HashLength])
	exist, _, err := CheckOTAExist(db, otaAddrKey[:])
	if err != nil {
		return false, err
	}

	if exist {
		return false, nil
	}

	err = SetOTA(db, balance, otaWanAddr)
	if err != nil {
		return false, err
	}

	return true, nil

}

func CheckOTAExist(db StateDB, otaAX []byte) (status bool, balance *big.Int, err error) {
	if db == nil || otaAX == nil || len(otaAX) < common.HashLength {
		return false, nil, ErrInvalidOTAArgs
	}

	otaAddrKey := common.BytesToHash(otaAX)
	balance, err = GetOTABalanceFromAX(db, otaAddrKey[:])
	if err != nil {
		return false, nil, err
	} else if balance.Cmp(common.Big0) == 0 {
		return false, nil, nil
	}

	mptAddr := common.HexToAddress(balance.String())
	fmt.Println("mptAddr:")
	fmt.Printf("mptAddr: %s\n", mptAddr)
	fmt.Println("mptAddr:")

	otaValue := db.GetStateByteArray(mptAddr, otaAddrKey)
	fmt.Printf("\nOTA VALUE: %v\n", otaValue)
	if otaValue != nil && len(otaValue) != 0 {
		return true, balance, nil
	}

	return false, nil, nil
}

func SetOTA(db StateDB, balance *big.Int, otaWanAddr []byte) error {
	if db == nil || balance == nil || otaWanAddr == nil || len(otaWanAddr) != common.WAddressLength {
		return ErrInvalidOTAArgs
	}

	otaAX := otaWanAddr[1 : 1+common.HashLength]
	balanceOld, err := GetOTABalanceFromAX(db, otaAX)
	if err != nil {
		return err
	}

	if balanceOld != nil && balanceOld.Cmp(common.Big0) != 0 {
		return errors.New("SetOTA, ota balance is not 0! old balance: " + balanceOld.String())
	}

	mptAddr := common.HexToAddress(balance.String())
	db.SetStateByteArray(mptAddr, common.BytesToHash(otaAX), otaWanAddr)
	return SetOTABalanceToAX(db, otaAX, balance)
}

func SetOTABalanceToAX(db StateDB, otaAX []byte, balance *big.Int) error {
	if db == nil || otaAX == nil || len(otaAX) != common.HashLength || balance == nil {
		return errors.New("SetOTABalanceToAX. Invalid input params!")
	}

	db.SetStateByteArray(OTABalanceStorageAddr, common.BytesToHash(otaAX), balance.Bytes())
	return nil
}

func GetOTABalanceFromAX(db StateDB, otaAX []byte) (*big.Int, error) {
	if db == nil || otaAX == nil || len(otaAX) != common.HashLength {
		return nil, errors.New("GetOTABalanceFromAX Err: invalid input params")
	}

	balance := db.GetStateByteArray(OTABalanceStorageAddr, common.BytesToHash(otaAX))
	if balance == nil || len(balance) == 0 {
		return common.Big0, nil
	}

	return new(big.Int).SetBytes(balance), nil
}
