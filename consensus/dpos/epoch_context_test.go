package dpos

import (
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/consensus/dpos/context"
	"github.com/ethereum/go-ethereum/core/state"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/ethdb"
	"github.com/ethereum/go-ethereum/trie"
	"github.com/stretchr/testify/assert"
	"math/big"
	"strconv"
	"strings"
	"testing"
)

var validators = []common.Address{
	common.HexToAddress("0x0000000000000000000000000000000000000001"),
	common.HexToAddress("0x0000000000000000000000000000000000000002"),
	common.HexToAddress("0x0000000000000000000000000000000000000003"),
	common.HexToAddress("0x0000000000000000000000000000000000000004"),
	common.HexToAddress("0x0000000000000000000000000000000000000005"),
	common.HexToAddress("0x0000000000000000000000000000000000000006"),
	common.HexToAddress("0x0000000000000000000000000000000000000007"),
	common.HexToAddress("0x0000000000000000000000000000000000000008"),
	common.HexToAddress("0x0000000000000000000000000000000000000009"),
	common.HexToAddress("0x0000000000000000000000000000000000000010"),
	common.HexToAddress("0x0000000000000000000000000000000000000011"),
	common.HexToAddress("0x0000000000000000000000000000000000000012"),
	common.HexToAddress("0x0000000000000000000000000000000000000013"),
	common.HexToAddress("0x0000000000000000000000000000000000000014"),
	common.HexToAddress("0x0000000000000000000000000000000000000015"),
	common.HexToAddress("0x0000000000000000000000000000000000000016"),
	common.HexToAddress("0x0000000000000000000000000000000000000017"),
	common.HexToAddress("0x0000000000000000000000000000000000000018"),
	common.HexToAddress("0x0000000000000000000000000000000000000019"),
	common.HexToAddress("0x0000000000000000000000000000000000000020"),
	common.HexToAddress("0x0000000000000000000000000000000000000021"),
}

func TestEpochContextCountVotes(t *testing.T) {
	//一个候选人对应多个投票人
	//总共4个投票人
	voteMap := map[common.Address][]common.Address{
		common.HexToAddress("0x44d1ce0b7cb3588bca96151fe1bc05af38f91b6e"): {
			common.HexToAddress("0xb040353ec0f2c113d5639444f7253681aecda1f8"),
		},
		common.HexToAddress("0xa60a3886b552ff9992cfcd208ec1152079e046c2"): {
			common.HexToAddress("0x14432e15f21237013017fa6ee90fc99433dec82c"),
			common.HexToAddress("0x9f30d0e5c9c88cade54cd1adecf6bc2c7e0e5af6"),
		},
		common.HexToAddress("0x4e080e49f62694554871e669aeb4ebe17c4a9670"): {
			common.HexToAddress("0xd83b44a3719720ec54cdb9f54c0202de68f1ebcb"),
			common.HexToAddress("0x56cc452e450551b7b9cffe25084a069e8c1e9441"),
			common.HexToAddress("0xbcfcb3fa8250be4f2bf2b1e70e1da500c668377b"),
		},
		common.HexToAddress("0x9d9667c71bb09d6ca7c3ed12bfe5e7be24e2ffe1"): {},
	}
	balance := int64(5)
	db := ethdb.NewMemDatabase()
	stateDB, _ := state.New(common.Hash{}, state.NewDatabase(db))
	dposContext, err := context.NewDposContext(db)
	assert.Nil(t, err)
	epochContext := &EpochContext{
		DposContext: dposContext,
		Statedb:     stateDB,
	}
	_, err = epochContext.CountVotes() //此时投票其实为空
	assert.NotNil(t, err)
	for candidate, electors := range voteMap {
		assert.Nil(t, dposContext.BecomeCandidate(candidate))
		for _, elector := range electors {
			stateDB.SetBalance(elector, big.NewInt(balance))
			assert.Nil(t, dposContext.Delegate(elector, candidate))
		}
	}
	result, err := epochContext.CountVotes()
	assert.Nil(t, err)
	assert.Equal(t, len(voteMap), len(result))
	//查看投票数
	for candidate, electors := range voteMap {
		voteCount, ok := result[candidate]
		assert.True(t, ok)
		assert.Equal(t, balance*int64(len(electors)), voteCount.Int64())
	}
}

func TestLookupValidator(t *testing.T) {
	db := ethdb.NewMemDatabase()
	dposCtx, _ := context.NewDposContext(db)
	mockEpochContext := &EpochContext{
		DposContext: dposCtx,
	}
	validators := []common.Address{
		common.HexToAddress("0x0000000000000000000000000000000000000001"),
		common.HexToAddress("0x0000000000000000000000000000000000000002"),
		common.HexToAddress("0x0000000000000000000000000000000000000003"),
	}
	mockEpochContext.DposContext.SetValidators(validators)
	for i, expected := range validators {
		got, _ := mockEpochContext.LookupValidator(int64(i) * blockInterval) //获取每个间隔对应的验证人
		if got != expected {
			t.Errorf("Failed to test lookup validator, %s was expected but got %s", expected.String(), got.String())
		}
	}
}

//测试踢出验证人
func TestEpochContextKickoutValidator(t *testing.T) {

	//测试：搜是合格的验证人
	db := ethdb.NewMemDatabase()
	stateDB, _ := state.New(common.Hash{}, state.NewDatabase(db))
	dposContext, err := context.NewDposContext(db)
	assert.Nil(t, err)
	epochContext := &EpochContext{
		TimeStamp:   epochInterval,
		DposContext: dposContext,
		Statedb:     stateDB,
	}
	//每个验证人最少要挖的块数
	atLeastMintCnt := epochInterval / blockInterval / maxValidatorSize / 2
	testEpoch := int64(1)

	//为每个验证人设置足够的挖块数
	for i := 0; i < maxValidatorSize; i++ {
		assert.Nil(t, dposContext.BecomeCandidate(validators[i]))
		setTestMintCnt(dposContext, testEpoch, validators[i], atLeastMintCnt)
	}
	//设置验证人
	assert.Nil(t, dposContext.SetValidators(validators))
	//成为候选人,新添加一个候选人
	assert.Nil(t, dposContext.BecomeCandidate(common.HexToAddress("0x0000000000000000000000000000000000000022")))
	//某轮踢出某个不合格,此时validator中都是合格的，因此这里其实并没有踢出不合格的人
	assert.Nil(t, epochContext.KickoutValidator(testEpoch))
	candidateMap := getCandidates(dposContext.GetCandidateTrie())
	assert.Equal(t, maxValidatorSize+1, len(candidateMap))

	//测试：在安全阈值范围内的测试
	dposContext, err = context.NewDposContext(db)
	assert.Nil(t, err)
	epochContext = &EpochContext{
		TimeStamp:   epochInterval,
		DposContext: dposContext,
		Statedb:     stateDB,
	}
	for i := 0; i < maxValidatorSize; i++ {
		assert.Nil(t, dposContext.BecomeCandidate(validators[i]))
		setTestMintCnt(dposContext, testEpoch, validators[i], atLeastMintCnt-int64(i)-1)
	}
	assert.Nil(t, dposContext.SetValidators(validators))
	assert.Nil(t, epochContext.KickoutValidator(testEpoch))
	candidateMap = getCandidates(dposContext.GetCandidateTrie())
	assert.Equal(t, safeSize, len(candidateMap))
	for i := maxValidatorSize - 1; i >= safeSize; i-- {
		assert.False(t, candidateMap[validators[i]])
	}

	//测试：新加入21个候选人，而当前所有验证人都不合格，全部踢了，候选人还剩21个
	dposContext, err = context.NewDposContext(db)
	assert.Nil(t, err)
	epochContext = &EpochContext{
		TimeStamp:   epochInterval,
		DposContext: dposContext,
		Statedb:     stateDB,
	}
	for i := 0; i < maxValidatorSize; i++ {
		assert.Nil(t, dposContext.BecomeCandidate(validators[i]))
		setTestMintCnt(dposContext, testEpoch, validators[i], atLeastMintCnt-int64(i)-1)
	}
	for i := maxValidatorSize; i < maxValidatorSize*2; i++ {
		assert.Nil(t, dposContext.BecomeCandidate(common.HexToAddress("0x00000000000000000000000000000000000000"+strconv.Itoa(i+1))))
	}
	candidateMap = getCandidates(dposContext.GetCandidateTrie())
	assert.Nil(t, dposContext.SetValidators(validators))
	assert.Nil(t, epochContext.KickoutValidator(testEpoch))
	candidateMap = getCandidates(dposContext.GetCandidateTrie())
	assert.Equal(t, maxValidatorSize, len(candidateMap))

	//测试：只有一个验证人不合格
	dposContext, err = context.NewDposContext(db)
	assert.Nil(t, err)
	epochContext = &EpochContext{
		TimeStamp:   epochInterval,
		DposContext: dposContext,
		Statedb:     stateDB,
	}
	for i := 0; i < maxValidatorSize; i++ {
		assert.Nil(t, dposContext.BecomeCandidate(validators[i]))
		if i == 0 {
			setTestMintCnt(dposContext, testEpoch, validators[i], atLeastMintCnt-1)
		} else {
			setTestMintCnt(dposContext, testEpoch, validators[i], atLeastMintCnt)
		}
	}
	assert.Nil(t, dposContext.BecomeCandidate(common.HexToAddress("0x0000000000000000000000000000000000000050"))) //新增了一个候选人
	assert.Nil(t, dposContext.SetValidators(validators))
	assert.Nil(t, epochContext.KickoutValidator(testEpoch)) //此时会踢掉一个不合格的候选人
	candidateMap = getCandidates(dposContext.GetCandidateTrie())
	assert.Equal(t, maxValidatorSize, len(candidateMap))
	assert.False(t, candidateMap[validators[0]])

	//不到一轮时间，每个验证人都产生了足够的块，
	//TODO 此时发现的问题是，这个只是针对创世周期
	dposContext, err = context.NewDposContext(db)
	assert.Nil(t, err)
	epochContext = &EpochContext{
		TimeStamp:   epochInterval / 2,
		DposContext: dposContext,
		Statedb:     stateDB,
	}
	for i := 0; i < maxValidatorSize; i++ {
		assert.Nil(t, dposContext.BecomeCandidate(validators[i]))
		setTestMintCnt(dposContext, testEpoch, validators[i], atLeastMintCnt/2)
	}
	for i := maxValidatorSize; i < maxValidatorSize*2; i++ {
		assert.Nil(t, dposContext.BecomeCandidate(common.HexToAddress("0x00000000000000000000000000000000000000"+strconv.Itoa(i+1))))
	}
	assert.Nil(t, dposContext.SetValidators(validators))
	assert.Nil(t, epochContext.KickoutValidator(testEpoch))
	candidateMap = getCandidates(dposContext.GetCandidateTrie())
	assert.Equal(t, maxValidatorSize*2, len(candidateMap))

	//测试：不到一轮时间，每个验证人也没有产生足够的块,会踢掉一轮验证人
	dposContext, err = context.NewDposContext(db)
	assert.Nil(t, err)
	epochContext = &EpochContext{
		TimeStamp:   epochInterval / 2,
		DposContext: dposContext,
		Statedb:     stateDB,
	}
	for i := 0; i < maxValidatorSize; i++ {
		assert.Nil(t, dposContext.BecomeCandidate(validators[i]))
		setTestMintCnt(dposContext, testEpoch, validators[i], atLeastMintCnt/2-1)
	}
	for i := maxValidatorSize; i < maxValidatorSize*2; i++ {
		assert.Nil(t, dposContext.BecomeCandidate(common.HexToAddress("0x00000000000000000000000000000000000000"+strconv.Itoa(i+1))))
	}
	assert.Nil(t, dposContext.SetValidators(validators))
	assert.Nil(t, epochContext.KickoutValidator(testEpoch))
	candidateMap = getCandidates(dposContext.GetCandidateTrie())
	assert.Equal(t, maxValidatorSize, len(candidateMap))

	//测试：不到一轮时间，直接踢人验证人（踢空的，此时原本一个候选人都没有）
	dposContext, err = context.NewDposContext(db)
	assert.Nil(t, err)
	epochContext = &EpochContext{
		TimeStamp:   epochInterval / 2,
		DposContext: dposContext,
		Statedb:     stateDB,
	}
	assert.NotNil(t, epochContext.KickoutValidator(testEpoch))
	dposContext.SetValidators([]common.Address{})
	assert.NotNil(t, epochContext.KickoutValidator(testEpoch))

}

//count表示出块数，每一个块，则加1，由updateMintCnt执行
func setTestMintCnt(dposContext *context.DposContext, epoch int64, validator common.Address, count int64) {
	for i := int64(0); i < count; i++ {
		updateMintCnt(epoch*epochInterval, epoch*epochInterval+blockInterval, validator, dposContext)
	}
}

func getCandidates(candidateTrie *trie.Trie) map[common.Address]bool {
	candidateMap := map[common.Address]bool{}
	iter := trie.NewIterator(candidateTrie.NodeIterator(nil))
	for iter.Next() {
		candidateMap[common.BytesToAddress(iter.Value)] = true
	}
	return candidateMap
}

//测试选举
func TestEpochContextTryElect(t *testing.T) {
	db := ethdb.NewMemDatabase()
	stateDB, _ := state.New(common.Hash{}, state.NewDatabase(db))
	dposContext, err := context.NewDposContext(db)
	assert.Nil(t, err)
	epochContext := &EpochContext{
		TimeStamp:   epochInterval,
		DposContext: dposContext,
		Statedb:     stateDB,
	}
	atLeastMintCnt := epochInterval / blockInterval / maxValidatorSize / 2
	testEpoch := int64(1)
	for i := 0; i < maxValidatorSize; i++ {
		assert.Nil(t, dposContext.BecomeCandidate(validators[i]))
		assert.Nil(t, dposContext.Delegate(validators[i], validators[i]))       //每个人为自己投一票
		stateDB.SetBalance(validators[i], big.NewInt(1))                        //每个验证人1wei
		setTestMintCnt(dposContext, testEpoch, validators[i], atLeastMintCnt-1) //所有验证人产块都不满足最低要求
	}
	dposContext.BecomeCandidate(common.HexToAddress("0x0000000000000000000000000000000000000022"))
	assert.Nil(t, dposContext.SetValidators(validators))

	//创世周期内，不踢人
	genesis := &types.Header{
		Time: big.NewInt(0),
	}
	parent := &types.Header{
		Time: big.NewInt(epochInterval - blockInterval),
	}
	oldHash := dposContext.GetEpochTrie().Hash()
	assert.Nil(t, epochContext.tryElect(genesis, parent)) //发生选举,选举出21个验证人
	result, err := dposContext.GetValidators()
	assert.Nil(t, err)
	assert.Equal(t, maxValidatorSize, len(result))
	assert.NotEqual(t, oldHash, dposContext.GetEpochTrie().Hash())

	//如果不是创世周期，
	genesis = &types.Header{
		Time: big.NewInt(-epochInterval),
	}
	parent = &types.Header{
		Difficulty: big.NewInt(1),
		Time:       big.NewInt(epochInterval - blockInterval),
	}
	epochContext.TimeStamp = epochInterval
	oldHash = dposContext.GetEpochTrie().Hash()
	assert.Nil(t, epochContext.tryElect(genesis, parent))
	result, err = dposContext.GetValidators()
	assert.Nil(t, err)
	assert.Equal(t, maxValidatorSize, len(result))
	assert.NotEqual(t, oldHash, dposContext.GetEpochTrie().Hash())

	//非创世周期，则正常踢出
	genesis = &types.Header{
		Time: big.NewInt(0),
	}
	parent = &types.Header{
		Time: big.NewInt(epochInterval*2 - blockInterval),
	}
	epochContext.TimeStamp = epochInterval * 2
	oldHash = dposContext.GetEpochTrie().Hash()
	assert.Nil(t, epochContext.tryElect(genesis, parent))
	result, err = dposContext.GetValidators()
	assert.Nil(t, err)
	assert.Equal(t, safeSize, len(result))
	moreCnt := 0
	for _, validator := range result {
		if strings.Contains(validator.String(), "0x0000000000000000000000000000000000000022") {
			moreCnt++
		}
	}
	assert.Equal(t, 1, moreCnt)
	assert.NotEqual(t, oldHash, dposContext.GetEpochTrie().Hash())

	// 父块和当前块属于同一周期，则不触发选举
	genesis = &types.Header{
		Time: big.NewInt(0),
	}
	parent = &types.Header{
		Time: big.NewInt(epochInterval),
	}
	epochContext.TimeStamp = epochInterval + blockInterval
	oldHash = dposContext.GetEpochTrie().Hash()
	assert.Nil(t, epochContext.tryElect(genesis, parent))
	result, err = dposContext.GetValidators()
	assert.Nil(t, err)
	assert.Equal(t, safeSize, len(result))
	assert.Equal(t, oldHash, dposContext.GetEpochTrie().Hash())
}
