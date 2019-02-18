package dpos

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"github.com/ethereum/go-ethereum/accounts"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/consensus"
	"github.com/ethereum/go-ethereum/consensus/dpos/context"
	"github.com/ethereum/go-ethereum/consensus/misc"
	"github.com/ethereum/go-ethereum/core/state"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/ethdb"
	"github.com/ethereum/go-ethereum/log"
	"github.com/ethereum/go-ethereum/params"
	"github.com/ethereum/go-ethereum/rlp"
	"github.com/ethereum/go-ethereum/rpc"
	"github.com/ethereum/go-ethereum/trie"
	"github.com/hashicorp/golang-lru"
	"golang.org/x/crypto/sha3"
	"math/big"
	"sync"
	"time"
)

//DPOS：这样理解会更好，将其理解成是一个民主的大选机构，如何设置让这个机构更加公平合理是核心

const (
	inmemorySignatures = 4096 //最近块签名数
	extraVanity        = 32   //签名的基本长度
	extraSeal          = 65   //65字节的secp256k1签名

	blockInterval    = int64(10)    //上下块之间不能相差10s
	epochInterval    = int64(86400) //一轮是一天，秒，
	maxValidatorSize = 21
	safeSize         = maxValidatorSize*2/3 + 1
	consensusSize    = maxValidatorSize*2/3 + 1
)

var (
	frontierBlockReward  = big.NewInt(5e+18)
	byzantiumBlockReward = big.NewInt(3e+18)

	timeOfFirstBlock   = int64(0)
	confirmedBlockHead = []byte("confirmed-block-head")
)

var (
	errUnknownBlock = errors.New("unknown block")

	errMissingVanity = errors.New("extra-data 32 byte vanity prefix missing")

	ErrWaitForPrevBlock = errors.New("wait for last block arrived")

	ErrMintFutureBlock = errors.New("mint the future block")

	//需要包含签名信息
	errMissingSignature = errors.New("extra-data 65 byte suffix signature missing")

	errInvalidMixDigest = errors.New("non-zero mix digest")

	errInvalidDifficulty = errors.New("invalid difficulty")

	errInvalidUncleHash = errors.New("non empty uncle hash")

	ErrInvalidTimestamp = errors.New("invalid timestamp")

	ErrInvalidBlockValidator = errors.New("invalid block validator")

	ErrInvalidMintBlockTime = errors.New("invalid time to mint the block")

	ErrMismatchSignerAndValidator = errors.New("mismatch block signer and validator")

	ErrNilBlockHeader = errors.New("nil block header returned")
)

var (
	uncleHash = types.CalcUncleHash(nil) //叔块空时的判断
)

type SignerFn func(accounts.Account, []byte) ([]byte, error)

type Dpos struct {
	config *DposConfig
	db     ethdb.Database //存储验证人相关信息

	signer common.Address //打包人
	signFn SignerFn

	//ARCCache是一个线程安全的固定大小的自适应替换缓存工具。
	//ARC是对标准LRU缓存的一种改进，它跟踪使用的频率和最近情况。
	//这样就避免了对新条目的突然访问，无法将经常使用的旧条目逐出。
	//它为标准的LRU缓存增加了一些额外的跟踪开销，计算上它大约是成本的2倍，并且额外的内存开销与缓存的大小成线性关系。
	//ARC已获得IBM专利，但类似于需要设置参数的TwoQueueCache（2Q,双队列缓存).
	signatures           *lru.ARCCache //等待验签的块
	confirmedBlockHeader *types.Header //被确认了的块头部

	mu   sync.RWMutex
	stop chan bool
}

func New(config *DposConfig, db ethdb.Database) *Dpos {
	signatures, _ := lru.NewARC(inmemorySignatures)
	return &Dpos{
		config:     config,
		db:         db,
		signatures: signatures,
	}
}

func (d *Dpos) Coinbase(header *types.Header) (common.Address, error) {
	return header.Coinbase, nil
}

func (d *Dpos) Author(header *types.Header) (common.Address, error) {
	return header.Validator, nil
}

func (d *Dpos) VerifyHeader(chain consensus.ChainReader, header *types.Header, seal bool) error {
	return d.verifyHeader(chain, header, nil)
}

func (d *Dpos) verifyHeader(chain consensus.ChainReader, header *types.Header, parents []*types.Header) error {
	if header.Number == nil {
		return errUnknownBlock
	}

	number := header.Number.Uint64()
	if header.Time.Cmp(big.NewInt(time.Now().Unix())) > 0 {
		return consensus.ErrFutureBlock
	}
	if len(header.Extra) < extraVanity {
		return errMissingVanity
	}
	if len(header.Extra) < extraVanity+extraSeal {
		return errMissingSignature
	}

	if header.MixDigest != (common.Hash{}) {
		return errInvalidMixDigest
	}

	if header.Difficulty.Uint64() != 1 {
		return errInvalidDifficulty
	}

	if header.UncleHash != uncleHash {
		return errInvalidUncleHash
	}

	//验证符合网络硬叉的块是否具有正确的哈希值，以避免客户端在不同的链上运行。
	if err := misc.VerifyForkHashes(chain.Config(), header, false); err != nil {
		return err
	}

	var parent *types.Header
	if len(parents) > 0 {
		parent = parents[len(parents)-1]
	} else {
		parent = chain.GetHeader(header.ParentHash, number-1)
	}
	if parent == nil || parent.Number.Uint64() != number-1 || parent.Hash() != header.ParentHash {
		return consensus.ErrUnknownAncestor
	}

	if parent.Time.Uint64()+uint64(blockInterval) > header.Time.Uint64() {
		return ErrInvalidTimestamp
	}
	return nil

}

func (d *Dpos) VerifyHeaders(chain consensus.ChainReader, headers []*types.Header, seals []bool) (chan<- struct{}, <-chan error) {
	abort := make(chan struct{})
	results := make(chan error, len(headers))

	go func() {
		for i, header := range headers {
			err := d.verifyHeader(chain, header, headers[:i])
			select {
			case <-abort:
				return
			case results <- err:
			}
		}
	}()
	return abort, results
}

func (d *Dpos) VerifyUncles(chain consensus.ChainReader, block *types.Block) error {
	if len(block.Uncles()) > 0 {
		return errors.New("uncles not allowed")
	}
	return nil
}

func (d *Dpos) VerifySeal(chain consensus.ChainReader, header *types.Header) error {
	return d.verifySeal(chain, header, nil)
}

func (d *Dpos) verifySeal(chain consensus.ChainReader, header *types.Header, parents []*types.Header) error {
	number := header.Number.Uint64()
	if number == 0 { //创世块不能验证
		return errUnknownBlock
	}
	var parent *types.Header
	if len(parents) > 0 {
		parent = parents[len(parents)-1]
	} else {
		parent = chain.GetHeader(header.ParentHash, number-1)
	}

	dposContext, err := context.NewDposContextFromProto(d.db, parent.DposContext)
	if err != nil {
		return err
	}
	epochContext := &EpochContext{DposContext: dposContext}
	//验证人队列中，获取当前验证人
	validator, err := epochContext.LookupValidator(header.Time.Int64())
	if err != nil {
		return err
	}
	if err := d.verifyBlockSigner(validator, header); err != nil {
		return err
	}
	//TODO 这个是不是可以直接返回nil?
	return d.updateConfirmedBlockHeader(chain)
}

//块验签
func (d *Dpos) verifyBlockSigner(validator common.Address, header *types.Header) error {
	//从块头部获取签名人，也就是出块人
	signer, err := ecrecover(d, header, d.signatures)
	if err != nil {
		return err
	}
	//检查validator是否为块头部签名中记录的出块人
	if bytes.Compare(signer.Bytes(), validator.Bytes()) != 0 {
		return ErrInvalidBlockValidator
	}
	//检查签名人和块头部记录的挖矿人是否匹配
	if bytes.Compare(signer.Bytes(), header.Validator.Bytes()) != 0 {
		return ErrMismatchSignerAndValidator
	}
	return nil
}

//TODO 此处确认块的方式暂时没搞明白，最后连着的21个块能够确认上一轮的就行？
//TODO 设定一个被确认的位置就行？
func (d *Dpos) updateConfirmedBlockHeader(chain consensus.ChainReader) error {
	if d.confirmedBlockHeader == nil {
		header, err := d.loadConfirmedBlockHeader(chain)
		if err != nil { //如果获取不到块头部，则使用创世块的头部
			header = chain.GetHeaderByNumber(0)
			if header == nil {
				return err
			}
		}
		d.confirmedBlockHeader = header //待确认的块不一定是最新的块
	}
	curHeader := chain.CurrentHeader() //当前本地最新的一个块
	//epoch := int64(-1)
	validatorMap := make(map[common.Address]bool) //表示已经验证的
	for d.confirmedBlockHeader.Hash() != curHeader.Hash() && d.confirmedBlockHeader.Number.Uint64() < curHeader.Number.Uint64() {
		//TODO 貌似下面5行代码多余了
		/*curEpoch := curHeader.Time.Int64() / epochInterval
		if curEpoch != epoch {
			epoch = curEpoch //当前轮数
			validatorMap = make(map[common.Address]bool)
		}*/

		//块少于2/3的验证人，则不需要验证了
		//TODO 这块不懂
		if curHeader.Number.Int64()-d.confirmedBlockHeader.Number.Int64() < int64(consensusSize-len(validatorMap)) {
			log.Debug("Dpos fast return", "current", curHeader.Number.String(), "confirmed", d.confirmedBlockHeader.Number.String(), "witnessCount", len(validatorMap))
			return nil
		}
		validatorMap[curHeader.Validator] = true
		if len(validatorMap) > consensusSize {
			d.confirmedBlockHeader = curHeader
			if err := d.storeConfirmedBlockHeader(d.db); err != nil {
				return err
			}
			log.Debug("dpos set confirmed block header success", "currentHeader", curHeader.Number.String())
			return nil
		}
		curHeader = chain.GetHeaderByHash(curHeader.ParentHash)
		if curHeader == nil {
			return ErrNilBlockHeader
		}
	}
	return nil
}

func (d *Dpos) loadConfirmedBlockHeader(chain consensus.ChainReader) (*types.Header, error) {
	key, err := d.db.Get(confirmedBlockHead)
	if err != nil {
		return nil, err
	}
	header := chain.GetHeaderByHash(common.BytesToHash(key))
	if header == nil {
		return nil, ErrNilBlockHeader
	}
	return header, nil
}

//把确认的块保存
func (d *Dpos) storeConfirmedBlockHeader(db ethdb.Database) error {
	return db.Put(confirmedBlockHead, d.confirmedBlockHeader.Hash().Bytes())
}

func (d *Dpos) Prepare(chain consensus.ChainReader, header *types.Header) error {
	header.Nonce = types.BlockNonce{}
	number := header.Number.Uint64()
	if len(header.Extra) < extraVanity {
		header.Extra = append(header.Extra, bytes.Repeat([]byte{0x00}, extraVanity-len(header.Extra))...)
	}
	header.Extra = header.Extra[:extraVanity]
	header.Extra = append(header.Extra, make([]byte, extraSeal)...) //加入签名扩展
	parent := chain.GetHeader(header.ParentHash, number-1)
	if parent == nil {
		return consensus.ErrUnknownAncestor
	}
	header.Difficulty = d.CalcDifficulty(chain, header.Time.Uint64(), parent)
	header.Validator = d.signer
	return nil

}

//当前轮结束，分发奖励，进行下一轮选举
func (d *Dpos) Finalize(chain consensus.ChainReader, header *types.Header, state *state.StateDB, txs []*types.Transaction,
	uncles []*types.Header, receipts []*types.Receipt, dposContext *context.DposContext) (*types.Block, error) {
	AccumulateRewards(chain.Config(), state, header, uncles)
	header.Root = state.IntermediateRoot(chain.Config().IsEIP158(header.Number))

	parent := chain.GetHeaderByHash(header.ParentHash)
	epochContext := &EpochContext{
		Statedb:     state,
		DposContext: dposContext,
		TimeStamp:   header.Time.Int64(),
	}
	if timeOfFirstBlock == 0 {
		if firstBlockHeader := chain.GetHeaderByNumber(1); firstBlockHeader != nil {
			timeOfFirstBlock = firstBlockHeader.Time.Int64()
		}
	}
	genesis := chain.GetHeaderByNumber(0)
	err := epochContext.tryElect(genesis, parent)
	if err != nil {
		return nil, fmt.Errorf("got error when elect next epoch, err: %s", err)
	}

	updateMintCnt(parent.Time.Int64(), header.Time.Int64(), header.Validator, dposContext)
	header.DposContext = dposContext.ToProto()
	return types.NewBlock(header, txs, uncles, receipts), nil

}

//相当于是打包一个块
func (d *Dpos) Seal(chain consensus.ChainReader, block *types.Block, results chan<- *types.Block, stop <-chan struct{}) error {
	header := block.Header()
	number := header.Number.Uint64()
	if number == 0 {
		return errUnknownBlock
	}
	now := time.Now().Unix()
	delay := NextSlot(now) - now
	if delay > 0 {
		select {
		case <-stop:
			return nil
		case <-time.After(time.Duration(delay) * time.Second):
		}
	}

	block.Header().Time.SetInt64(time.Now().Unix())

	sighash, err := d.signFn(accounts.Account{Address: d.signer}, d.SealHash(header).Bytes())
	if err != nil {
		return err
	}
	copy(header.Extra[len(header.Extra)-extraSeal:], sighash) //加入签名信息
	return nil
}

func (d *Dpos) Authorize(signer common.Address, signFn SignerFn) {
	d.mu.Lock()
	d.signer = signer
	d.signFn = signFn
	d.mu.Unlock()
}

func (d *Dpos) SealHash(header *types.Header) (hash common.Hash) {
	hasher := sha3.NewLegacyKeccak256()
	rlp.Encode(hasher, []interface{}{
		header.ParentHash,
		header.UncleHash,
		header.Validator,
		header.Coinbase,
		header.Root,
		header.TxHash,
		header.ReceiptHash,
		header.Bloom,
		header.Difficulty,
		header.Number,
		header.GasLimit,
		header.GasUsed,
		header.Time,
		header.Extra[:len(header.Extra)-65], // Yes, this will panic if extra is too short
		header.MixDigest,
		header.Nonce,
		header.DposContext.Root(),
	})
	hasher.Sum(hash[:0])
	return hash
}

//难度为1
func (d *Dpos) CalcDifficulty(chain consensus.ChainReader, time uint64, parent *types.Header) *big.Int {
	return big.NewInt(1)
}

func (d *Dpos) APIs(chain consensus.ChainReader) []rpc.API {
	return []rpc.API{
		{
			Namespace: "dpos",
			Version:   "1.0",
			Service:   &API{chain: chain, dpos: d},
			Public:    true,
		},
	}
}

func (d *Dpos) Close() error {
	//Dpos本身没有channel，不需要close
	return nil
}

func (d *Dpos) CheckValidator(lastBlock *types.Block, now int64) error {
	if err := d.checkDeadline(lastBlock, now); err != nil {
		return err
	}
	dposContext, err := context.NewDposContextFromProto(d.db, lastBlock.Header().DposContext)
	if err != nil {
		return err
	}
	epochContext := &EpochContext{DposContext: dposContext}
	validator, err := epochContext.LookupValidator(now)
	if err != nil {
		return err
	}
	if (validator == common.Address{}) || bytes.Compare(validator.Bytes(), d.signer.Bytes()) != 0 {
		return ErrInvalidBlockValidator
	}
	return nil
}

//检查每个块产生时间
func (d *Dpos) checkDeadline(lastBlock *types.Block, now int64) error {
	prevSlot := PrevSlot(now)
	nextSlot := NextSlot(now)
	//当前块比最新可产块的时间都要长，则报错
	if lastBlock.Time().Int64() >= nextSlot {
		return ErrMintFutureBlock
	}

	//最新块时间和上一次出块时间一致或者下一个出块时间和当前时间相差1秒，则任务可出块
	if lastBlock.Time().Int64() == prevSlot || nextSlot-now <= 1 {
		return nil
	}
	return ErrWaitForPrevBlock
}

//上一次出块时间
func PrevSlot(now int64) int64 {
	return int64((now-1)/blockInterval) * blockInterval
}

//下一次出块时间
func NextSlot(now int64) int64 {
	return int64((now+blockInterval-1)/blockInterval) * blockInterval
}

//为当前验证人新增一个块
func updateMintCnt(parentBlockTime, currentBlockTime int64, validator common.Address, dposContext *context.DposContext) {
	currentMintCntTrie := dposContext.GetMintCntTrie()
	currentEpoch := parentBlockTime / epochInterval
	currentEpochBytes := make([]byte, 8)
	binary.BigEndian.PutUint64(currentEpochBytes, uint64(currentEpoch))
	cnt := int64(1)
	newEpoch := currentBlockTime / epochInterval
	if currentEpoch == newEpoch {
		iter := trie.NewIterator(currentMintCntTrie.NodeIterator(currentEpochBytes))
		if iter.Next() {
			//当前验证人在这一轮的挖块数
			cntBytes := currentMintCntTrie.Get(append(currentEpochBytes, validator.Bytes()...))
			if cntBytes != nil {
				cnt = int64(binary.BigEndian.Uint64(cntBytes)) + 1 //当前验证人，新增一个块
			}
		}
	}

	newCntBytes := make([]byte, 8)
	newEpochBytes := make([]byte, 8)
	binary.BigEndian.PutUint64(newEpochBytes, uint64(newEpoch))
	binary.BigEndian.PutUint64(newCntBytes, uint64(cnt))
	dposContext.MintCntTrie.TryUpdateWithPrefix(append(newEpochBytes, validator.Bytes()...), newCntBytes)
}

//块分发奖励，
func AccumulateRewards(config *params.ChainConfig, state *state.StateDB, header *types.Header, uncles []*types.Header) {
	blockReward := frontierBlockReward
	if config.IsByzantium(header.Number) {
		blockReward = byzantiumBlockReward
	}
	reward := new(big.Int).Set(blockReward)
	state.AddBalance(header.Coinbase, reward)

}

func ecrecover(d *Dpos, header *types.Header, sigcache *lru.ARCCache) (common.Address, error) {
	hash := header.Hash()
	//如果已经加入了缓存，则直接返回结果
	if address, known := sigcache.Get(hash); known {
		return address.(common.Address), nil
	}
	//说明该块没有签名信息
	if len(header.Extra) < extraSeal {
		return common.Address{}, errMissingSignature
	}
	signature := header.Extra[len(header.Extra)-extraSeal:] //获取65字节的签名

	//从签名中获取公钥
	pubkey, err := crypto.Ecrecover(d.SealHash(header).Bytes(), signature)
	if err != nil {
		return common.Address{}, err
	}
	var signer common.Address
	//crypto.Keccak256(pubkey[1:])[12:]是一个以太坊地址，相当于公钥转地址
	copy(signer[:], crypto.Keccak256(pubkey[1:])[12:])
	sigcache.Add(hash, signer)
	return signer, nil
}
