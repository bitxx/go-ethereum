package context

import (
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/ethdb"
	"github.com/ethereum/go-ethereum/rlp"
	"golang.org/x/crypto/sha3"
)

//此模块是hash层面对dpos相关内容对读取
//TODO 能否将其去掉？合并到DposContext中？

type DposContextProto struct {
	EpochHash     common.Hash `json:"epochRoot"        gencodec:"required"`
	DelegateHash  common.Hash `json:"delegateRoot"     gencodec:"required"`
	CandidateHash common.Hash `json:"candidateRoot"    gencodec:"required"`
	VoteHash      common.Hash `json:"voteRoot"         gencodec:"required"`
	MintCntHash   common.Hash `json:"mintCntRoot"      gencodec:"required"`
}

func NewDposContextFromProto(db ethdb.Database, ctxProto *DposContextProto) (*DposContext, error) {
	epochTrie, err := NewEpochTrie(ctxProto.EpochHash, db)
	if err != nil {
		return nil, err
	}
	delegateTrie, err := NewDelegateTrie(ctxProto.DelegateHash, db)
	if err != nil {
		return nil, err
	}
	voteTrie, err := NewVoteTrie(ctxProto.VoteHash, db)
	if err != nil {
		return nil, err
	}
	candidateTrie, err := NewCandidateTrie(ctxProto.CandidateHash, db)
	if err != nil {
		return nil, err
	}
	mintCntTrie, err := NewMintCntTrie(ctxProto.MintCntHash, db)
	if err != nil {
		return nil, err
	}
	return &DposContext{
		EpochTrie:     epochTrie,
		DelegateTrie:  delegateTrie,
		VoteTrie:      voteTrie,
		CandidateTrie: candidateTrie,
		MintCntTrie:   mintCntTrie,
		db:            db,
	}, nil
}

func (p *DposContextProto) Root() (hash common.Hash) {
	hasher := sha3.NewLegacyKeccak256()
	rlp.Encode(hasher, []interface{}{
		p.EpochHash,
		p.DelegateHash,
		p.CandidateHash,
		p.VoteHash,
		p.MintCntHash,
	})

	hasher.Sum(hash[:0])
	return hash
}
