package dpos

import (
	"encoding/binary"
	"errors"
	"fmt"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/consensus/dpos/context"
	"github.com/ethereum/go-ethereum/core/state"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/log"
	"github.com/ethereum/go-ethereum/trie"
	"math/big"
	"math/rand"
	"sort"
)

type EpochContext struct {
	TimeStamp   int64
	DposContext *context.DposContext
	Statedb     *state.StateDB
}

//投票数统计，返回候选人及其对应的积分
//TODO 根据投票人的eth来计算积分？
//TODO 候选人数量需要有限制
func (ec *EpochContext) CountVotes() (votes map[common.Address]*big.Int, err error) {
	votes = map[common.Address]*big.Int{}
	delegateTrie := ec.DposContext.GetDelegateTrie()   //候选人对应的投票人,多个
	candidateTrie := ec.DposContext.GetCandidateTrie() //所有候选人
	statedb := ec.Statedb

	iterCandidate := trie.NewIterator(candidateTrie.NodeIterator(nil))
	existCandidate := iterCandidate.Next()
	if !existCandidate {
		return votes, errors.New("no candidates")
	}

	for existCandidate {
		candidate := iterCandidate.Value
		candidateAddr := common.BytesToAddress(candidate)                            //候选人
		delegateIterator := trie.NewIterator(delegateTrie.PrefixIterator(candidate)) //一个候选人对应多个投票人
		existDelegator := delegateIterator.Next()
		if !existDelegator { //当前候选人没有票
			votes[candidateAddr] = new(big.Int) //候选人票数为0
			existCandidate = iterCandidate.Next()
			continue
		}
		for existDelegator { //TODO 当前候选人有投票,要是拥有很多投票人，这种计算方式会很慢(没有限制候选人数)
			delegator := delegateIterator.Value
			score, ok := votes[candidateAddr]
			if !ok {
				score = new(big.Int)
			}
			delegatorAddr := common.BytesToAddress(delegator)
			weight := statedb.GetBalance(delegatorAddr) //根据投票人的eth来计算积分？
			score.Add(score, weight)
			votes[candidateAddr] = score
			existDelegator = delegateIterator.Next()
		}
		existCandidate = iterCandidate.Next()
	}
	return votes, nil
}

//将验证人踢出
//epoch表示第几轮
func (ec *EpochContext) KickoutValidator(epoch int64) error {
	validators, err := ec.DposContext.GetValidators()
	if err != nil {
		return fmt.Errorf("failed to get validator:%s", err)
	}
	if len(validators) == 0 {
		return errors.New("no validator could be kickout")
	}

	epochDuration := epochInterval //默认24小时

	//主要是针对第一个块的产生
	//当前周期（轮）还没有结束，但所有验证人都产生了足够的块
	//TODO timeOfFirstBlock表示的是第一个块的时间，此处处理只会对创世第一轮有影响，不知道为什么要这么做？
	if ec.TimeStamp-timeOfFirstBlock < epochInterval {
		epochDuration = ec.TimeStamp - timeOfFirstBlock
	}

	needKickoutValidators := sortableAddresses{} //存放待踢出的验证人
	for _, validator := range validators {
		key := make([]byte, 8)
		binary.BigEndian.PutUint64(key, uint64(epoch)) //uint64转化成[]byte
		key = append(key, validator.Bytes()...)        //验证人前缀
		cnt := int64(0)
		//获取某验证人的出块数
		if cntBytes := ec.DposContext.MintCntTrie.Get(key); cntBytes != nil {
			cnt = int64(binary.BigEndian.Uint64(cntBytes)) //出块数
		}
		//验证人不合格
		if cnt < epochDuration/blockInterval/maxValidatorSize/2 { //一轮出块周期中，该验证人出块若不积极，则将其加入待踢出队列
			needKickoutValidators = append(needKickoutValidators, &sortableAddress{validator, big.NewInt(cnt)})
		}
	}

	needKickoutValidatorCnt := len(needKickoutValidators)
	if needKickoutValidatorCnt <= 0 {
		return nil
	}
	sort.Sort(sort.Reverse(needKickoutValidators))
	candidateCount := 0
	//遍历候选人队列，确保候选人人数足够多
	iter := trie.NewIterator(ec.DposContext.GetCandidateTrie().NodeIteratorWithPrefix(nil))
	for iter.Next() {
		candidateCount++
		if candidateCount >= needKickoutValidatorCnt+safeSize { //确保候选人数量满足这么多
			break
		}
	}

	//踢出不合格的验证人
	for i, validator := range needKickoutValidators {
		//如果小于某个安全阈值，则不删除验证人
		if candidateCount <= safeSize {
			log.Info("No more candidate can be kickout", "prevEpochID", epoch, "candidateCount", candidateCount, "needKickoutCount", len(needKickoutValidators)-i)
			return nil
		}
		if err := ec.DposContext.KickoutCandidate(validator.address); err != nil {
			return err
		}
		candidateCount--
		log.Info("Kickout candidate", "prevEpochID", epoch, "candidate", validator.address.String(), "mintCnt", validator.weight.String())
	}
	return nil
}

//确定一个验证人
//now为当前时间，单位秒
//此处相当于根据当前时间来判断选择哪个验证人
func (ec *EpochContext) LookupValidator(now int64) (validator common.Address, err error) {
	validator = common.Address{}
	offset := now % epochInterval  //offset表示当前偏移时间
	if offset%blockInterval != 0 { //也就是offset不能被blockInterval整除，则不产生新的验证人
		return common.Address{}, ErrInvalidMintBlockTime
	}
	offset /= blockInterval

	validators, err := ec.DposContext.GetValidators()
	if err != nil {
		return common.Address{}, err
	}

	validatorSize := len(validators)
	if validatorSize == 0 {
		return common.Address{}, errors.New("failed to lookup validator")
	}
	offset %= int64(validatorSize) //这个结果可以判断出offset范围在0～validatorSize-1之间
	return validators[offset], nil
}

func (ec *EpochContext) tryElect(genesis, parent *types.Header) error {
	genesisEpoch := genesis.Time.Int64() / epochInterval //创世块起始轮数
	prevEpoch := parent.Time.Int64() / epochInterval     //父块起始轮数
	currentEpoch := ec.TimeStamp / epochInterval         //当前块起始轮数
	prevEpochIsGenesis := prevEpoch == genesisEpoch      //说明是创世块
	//将创世周期明确定义为当前周期的上一周期，鲁棒性
	if prevEpochIsGenesis && prevEpoch < currentEpoch {
		prevEpoch = currentEpoch - 1 //prevEpoch表示上一轮选举
	}
	prevEpochBytes := make([]byte, 8)
	binary.BigEndian.PutUint64(prevEpochBytes, uint64(prevEpoch))

	//获取上一周期的验证人及其对应的出块数
	iter := trie.NewIterator(ec.DposContext.GetMintCntTrie().PrefixIterator(prevEpochBytes))

	//如果prevEpoch和currentEpoch相同，则表明是在同一周期内，不用触发选举
	//否则触发
	//TODO 其实for最多也就执行一次，因为中间只隔着一轮
	for i := prevEpoch; i < currentEpoch; i++ {
		iter.Next()
		//若不是创世周期，而且有多个验证人
		//TODO 这里只是判断有多个验证人，则踢出当前轮不合格验证人，最多踢到安全阈值为止
		if !prevEpochIsGenesis && iter.Next() {
			if err := ec.KickoutValidator(prevEpoch); err != nil {
				return err
			}
		}

		//针对创世周期进行处理

		votes, err := ec.CountVotes()
		if err != nil {
			return err
		}
		//候选人及其对应的分数
		candidates := sortableAddresses{}
		for candidate, cnt := range votes {
			candidates = append(candidates, &sortableAddress{candidate, cnt})
		}
		if len(candidates) < safeSize {
			return errors.New("too few candidates")
		}
		sort.Sort(candidates) //票数高的在前面
		//选前21个作为出块验证人，票数最高的前21个
		if len(candidates) > maxValidatorSize {
			candidates = candidates[:maxValidatorSize]
		}

		//打乱验证人出块顺序
		//根据上一个块的hash作为种子
		//TODO 这种伪随机数，若有心人愿意，还是可以找出规律的，但细想一下，这种规律即便找到，也很难改变结果，还是靠谱的
		seed := int64(binary.LittleEndian.Uint32(crypto.Keccak512(parent.Hash().Bytes()))) + i
		r := rand.New(rand.NewSource(seed))
		for i := len(candidates) - 1; i > 0; i-- {
			j := int(r.Int31n(int32(i + 1)))
			//随机切换位置，即使j重复也没关系，不信但演算一下
			candidates[i], candidates[j] = candidates[j], candidates[i]
		}
		sortedValidators := make([]common.Address, 0)
		for _, candidate := range candidates {
			sortedValidators = append(sortedValidators, candidate.address)
		}

		epochTrie, _ := context.NewEpochTrie(common.Hash{}, ec.DposContext.DB())
		ec.DposContext.SetEpoch(epochTrie) //必须先加入trie
		ec.DposContext.SetValidators(sortedValidators)
		log.Info("Come to new epoch", "prevEpoch", i, "nextEpoch", i+1)
	}
	return nil
}

//地址排序
type sortableAddress struct {
	address common.Address
	weight  *big.Int
}
type sortableAddresses []*sortableAddress

func (p sortableAddresses) Swap(i, j int) { p[i], p[j] = p[j], p[i] }
func (p sortableAddresses) Len() int      { return len(p) }
func (p sortableAddresses) Less(i, j int) bool {
	if p[i].weight.Cmp(p[j].weight) < 0 {
		return false
	} else if p[i].weight.Cmp(p[j].weight) > 0 {
		return true
	} else {
		return p[i].address.String() < p[j].address.String()
	}
}
