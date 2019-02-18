package context

import (
	"bytes"
	"errors"
	"fmt"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/ethdb"
	"github.com/ethereum/go-ethereum/rlp"
	"github.com/ethereum/go-ethereum/trie"
	"golang.org/x/crypto/sha3"
)

//此模块的作用是对dpos相关trie的操作

var (
	epochPrefix     = []byte("epoch-")
	delegatePrefix  = []byte("delegate-")
	votePrefix      = []byte("vote-")
	candidatePrefix = []byte("candidate-")
	mintCntPrefix   = []byte("mintCnt-")
)

func NewEpochTrie(root common.Hash, db ethdb.Database) (*trie.Trie, error) {
	return trie.NewTrieWithPrefix(root, epochPrefix, db)
}

func NewDelegateTrie(root common.Hash, db ethdb.Database) (*trie.Trie, error) {
	return trie.NewTrieWithPrefix(root, delegatePrefix, db)
}

func NewVoteTrie(root common.Hash, db ethdb.Database) (*trie.Trie, error) {
	return trie.NewTrieWithPrefix(root, votePrefix, db)
}

func NewCandidateTrie(root common.Hash, db ethdb.Database) (*trie.Trie, error) {
	return trie.NewTrieWithPrefix(root, candidatePrefix, db)
}

func NewMintCntTrie(root common.Hash, db ethdb.Database) (*trie.Trie, error) {
	return trie.NewTrieWithPrefix(root, mintCntPrefix, db)
}

type DposContext struct {
	EpochTrie     *trie.Trie //记录每个周期的验证人列表
	DelegateTrie  *trie.Trie //记录候选人->投票人
	VoteTrie      *trie.Trie //记录投票人->候选人
	CandidateTrie *trie.Trie //记录候选人列表
	MintCntTrie   *trie.Trie //记录验证人在周期内的出块数目

	db ethdb.Database
}

func NewDposContext(db ethdb.Database) (*DposContext, error) {
	epochTrie, err := NewEpochTrie(common.Hash{}, db)
	if err != nil {
		return nil, err
	}
	delegateTrie, err := NewDelegateTrie(common.Hash{}, db)
	if err != nil {
		return nil, err
	}
	voteTrie, err := NewVoteTrie(common.Hash{}, db)
	if err != nil {
		return nil, err
	}
	candidateTrie, err := NewCandidateTrie(common.Hash{}, db)
	if err != nil {
		return nil, err
	}
	mintCntTrie, err := NewMintCntTrie(common.Hash{}, db)
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

func (d *DposContext) Copy() *DposContext {
	epochTrie := *d.EpochTrie
	delegateTrie := *d.DelegateTrie
	voteTrie := *d.VoteTrie
	candidateTrie := *d.CandidateTrie
	mintCntTrie := *d.MintCntTrie
	return &DposContext{
		EpochTrie:     &epochTrie,
		DelegateTrie:  &delegateTrie,
		VoteTrie:      &voteTrie,
		CandidateTrie: &candidateTrie,
		MintCntTrie:   &mintCntTrie,
	}
}

func (d *DposContext) Root() (hash common.Hash) {
	hasher := sha3.NewLegacyKeccak256()
	rlp.Encode(hasher, []interface{}{
		d.EpochTrie.Hash(),
		d.DelegateTrie.Hash(),
		d.CandidateTrie.Hash(),
		d.VoteTrie.Hash(),
		d.MintCntTrie.Hash(),
	})
	hasher.Sum(hash[:0])
	return hash
}

//快照
func (d *DposContext) Snapshot() *DposContext {
	return d.Copy()
}

//将快照信息读取出来
func (d *DposContext) RevertToSnapShot(snapshot *DposContext) {
	d.EpochTrie = snapshot.EpochTrie
	d.DelegateTrie = snapshot.DelegateTrie
	d.CandidateTrie = snapshot.CandidateTrie
	d.VoteTrie = snapshot.VoteTrie
	d.MintCntTrie = snapshot.MintCntTrie
}

//将地址转换为trie
func (d *DposContext) FromProto(dcp *DposContextProto) error {
	var err error
	d.EpochTrie, err = NewEpochTrie(dcp.EpochHash, d.db)
	if err != nil {
		return err
	}
	d.DelegateTrie, err = NewDelegateTrie(dcp.DelegateHash, d.db)
	if err != nil {
		return err
	}
	d.CandidateTrie, err = NewCandidateTrie(dcp.CandidateHash, d.db)
	if err != nil {
		return err
	}
	d.VoteTrie, err = NewVoteTrie(dcp.VoteHash, d.db)
	if err != nil {
		return err
	}
	d.MintCntTrie, err = NewMintCntTrie(dcp.MintCntHash, d.db)
	return err
}

//将trie转换为hash
func (d *DposContext) ToProto() *DposContextProto {
	return &DposContextProto{
		EpochHash:     d.EpochTrie.Hash(),
		DelegateHash:  d.DelegateTrie.Hash(),
		CandidateHash: d.CandidateTrie.Hash(),
		VoteHash:      d.VoteTrie.Hash(),
		MintCntHash:   d.MintCntTrie.Hash(),
	}
}

//踢掉某个候选人
//该方法只有在踢出验证人的时候有效
//需要实现：
// 删除候选人对应的投票人
// 删除投票人对应的候选人
func (d *DposContext) KickoutCandidate(candidateAddr common.Address) error {
	candidate := candidateAddr.Bytes()
	err := d.CandidateTrie.TryDeleteWithPrefix(candidate)
	if err != nil {
		if _, ok := err.(*trie.MissingNodeError); !ok {
			return err
		}
	}
	//候选人对应的投票人，
	iter := trie.NewIterator(d.DelegateTrie.PrefixIterator(candidate))
	for iter.Next() {
		delegator := iter.Value
		key := append(candidate, delegator...)
		//相当于是要删除满足这样条件的数据：delegate-candidate-投票人
		err = d.DelegateTrie.TryDeleteWithPrefix(key)
		if err != nil {
			if _, ok := err.(*trie.MissingNodeError); !ok {
				return err
			}
		}
		//获取投票人对应的验证人，就是说每一轮一个投票人只能投一张票给一个候选人
		//需要注意的是，候选人拥有的投票人，和投票人对应的候选人，是不同的概念
		v, err := d.VoteTrie.TryGetWithPrefix(delegator)
		if err != nil {
			if _, ok := err.(*trie.MissingNodeError); !ok {
				return err
			}
		}
		if err == nil && bytes.Equal(v, candidate) {
			err = d.VoteTrie.TryDeleteWithPrefix(delegator)
			if err != nil {
				if _, ok := err.(*trie.MissingNodeError); !ok {
					return err
				}
			}
		}
	}
	return nil
}

//成为候选人
func (d *DposContext) BecomeCandidate(candidateAddr common.Address) error {
	candidate := candidateAddr.Bytes()
	return d.CandidateTrie.TryUpdateWithPrefix(candidate, candidate)
}

//为候选人投票
//每轮投票，一投票人只能给一个候选人投票
func (d *DposContext) Delegate(delegatorAddr, candidateAddr common.Address) error {
	delegator, candidate := delegatorAddr.Bytes(), candidateAddr.Bytes()

	//先要确保trie中有该候选人
	candidateInTrie, err := d.CandidateTrie.TryGetWithPrefix(candidate)
	if err != nil {
		return err
	}
	if candidateInTrie == nil {
		return errors.New("invalid candidate to delegate")
	}

	//若投票人已经有投票记录，则先删除旧的投票记录
	oldCandidate, err := d.VoteTrie.TryGetWithPrefix(delegator)
	if err != nil {
		if _, ok := err.(*trie.MissingNodeError); !ok {
			return err
		}
	}
	if oldCandidate != nil {
		d.DelegateTrie.Delete(append(oldCandidate, delegator...))
	}

	//记录候选热对应的投票人
	//候选人可以有不同的投票人
	//从这里也可以看出Delegator中有共同的前缀。而key格式为：Delegate-candidateAddr-不同用户
	if err = d.DelegateTrie.TryUpdateWithPrefix(append(candidate, delegator...), delegator); err != nil {
		return err
	}
	//记录投票人对应的验证人
	return d.VoteTrie.TryUpdateWithPrefix(delegator, candidate)
}

//取消对候选人的投票
func (d *DposContext) UnDelegate(delegatorAddr, candidateAddr common.Address) error {
	delegator, candidate := delegatorAddr.Bytes(), candidateAddr.Bytes()

	//判断是否有候选人
	//candidateInTrie和candidate一样
	candidateInTrie, err := d.CandidateTrie.TryGetWithPrefix(candidate)
	if err != nil {
		return err
	}
	if candidateInTrie == nil {
		return errors.New("invalid candidate to undelegate")
	}

	//判断投票人是否已经投过票，以及给谁投的票
	oldCandidate, err := d.VoteTrie.TryGetWithPrefix(delegator)
	if err != nil {
		return err
	}

	//投票人不是给候选人candidate投的票，则不可以做取消操作
	if !bytes.Equal(candidate, oldCandidate) {
		return errors.New("mismatch candidate to undelegate")
	}

	//将候选人对应投票人删除
	if err = d.DelegateTrie.TryDeleteWithPrefix(append(candidate, delegator...)); err != nil {
		return err
	}

	//将投票人对应候选人删除
	return d.VoteTrie.TryDeleteWithPrefix(delegator)
}

func (d *DposContext) CommitTo(onleaf trie.LeafCallback) (*DposContextProto, error) {
	epochRoot, err := d.EpochTrie.Commit(onleaf)
	if err != nil {
		return nil, err
	}
	delegateRoot, err := d.DelegateTrie.Commit(onleaf)
	if err != nil {
		return nil, err
	}
	voteRoot, err := d.VoteTrie.Commit(onleaf)
	if err != nil {
		return nil, err
	}
	candidateRoot, err := d.CandidateTrie.Commit(onleaf)
	if err != nil {
		return nil, err
	}
	mintCntRoot, err := d.MintCntTrie.Commit(onleaf)
	if err != nil {
		return nil, err
	}
	return &DposContextProto{
		EpochHash:     epochRoot,
		DelegateHash:  delegateRoot,
		VoteHash:      voteRoot,
		CandidateHash: candidateRoot,
		MintCntHash:   mintCntRoot,
	}, nil
}

func (d *DposContext) GetValidators() ([]common.Address, error) {
	var validators []common.Address
	key := []byte("validator")
	validatorsRLP := d.EpochTrie.GetWithPrefix(key)
	if err := rlp.DecodeBytes(validatorsRLP, &validators); err != nil {
		return nil, fmt.Errorf("failed to decode validators:%s", err)
	}
	return validators, nil
}

func (d *DposContext) SetValidators(validators []common.Address) error {
	key := []byte("validator")
	validatorsRLP, err := rlp.EncodeToBytes(validators)
	if err != nil {
		return fmt.Errorf("failed to encode validators to rlp bytes:%s", err)
	}
	d.EpochTrie.TryUpdateWithPrefix(key, validatorsRLP)
	return nil
}

//基础数据管理
func (d *DposContext) GetCandidateTrie() *trie.Trie      { return d.CandidateTrie }
func (d *DposContext) GetDelegateTrie() *trie.Trie       { return d.DelegateTrie }
func (d *DposContext) GetVoteTrie() *trie.Trie           { return d.VoteTrie }
func (d *DposContext) GetEpochTrie() *trie.Trie          { return d.EpochTrie }
func (d *DposContext) GetMintCntTrie() *trie.Trie        { return d.MintCntTrie }
func (d *DposContext) DB() ethdb.Database                { return d.db }
func (d *DposContext) SetEpoch(epoch *trie.Trie)         { d.EpochTrie = epoch }
func (d *DposContext) SetDelegate(delegate *trie.Trie)   { d.DelegateTrie = delegate }
func (d *DposContext) SetVote(vote *trie.Trie)           { d.VoteTrie = vote }
func (d *DposContext) SetCandidate(candidate *trie.Trie) { d.CandidateTrie = candidate }
func (d *DposContext) SetMintCnt(mintCnt *trie.Trie)     { d.MintCntTrie = mintCnt }
