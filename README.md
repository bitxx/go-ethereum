## Go Ethereum
本项目参考自：[美图](https://github.com/meitu/go-ethereum)
目前只是参考实现了dpos算法，具体对接还未实现

项目改造中...

### 说明
1. core->types->block.go中，结构体Header中加入：
```go
	Validator   common.Address           `json:"validator"        gencodec:"required"`
	DposContext *params.DposContextProto `json:"dposContext"      gencodec:"required"`
```

2. trie模块中，加入新的文件prefix_trie.go
主要用户生成带有dpos相关前缀的trie

3. trie模块中，加入新的文件prefix_trie_iterator.go
主要用于dpos相关trie的遍历


3. trie->trie.go中，Tire结构体加入如下内容：
用于标识前缀
```go
prefix       []byte
```

4. 共识引擎接口中，Finalize需要加一个参数：
```go
Finalize(chain ChainReader, header *types.Header, state *state.StateDB, txs []*types.Transaction,
		uncles []*types.Header, receipts []*types.Receipt, dposContext *dpos.DposContext) (*types.Block, error)
```