package dpos

import (
	"github.com/ethereum/go-ethereum/common"
)

type DposConfig struct {
	//初始化成员列表，共计21人
	Validators []common.Address `json:"validators"`
}

func (d *DposConfig) String() string {
	return "dpos"
}
