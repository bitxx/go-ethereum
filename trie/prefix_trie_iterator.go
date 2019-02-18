package trie

import (
	"bytes"
	"github.com/ethereum/go-ethereum/common"
)

type prefixIterator struct {
	prefix       []byte
	nodeIterator NodeIterator
}

func newPrefixIterator(trie *Trie, prefix []byte) NodeIterator {
	if trie.Hash() == emptyState {
		return new(prefixIterator)
	}
	nodeIt := newNodeIterator(trie, prefix)
	prefix = keybytesToHex(prefix)
	return &prefixIterator{
		nodeIterator: nodeIt,
		prefix:       prefix[:len(prefix)-1],
	}
}

func (it *prefixIterator) hasPrefix() bool {
	return bytes.HasPrefix(it.nodeIterator.Path(), it.prefix)
}

func (it *prefixIterator) Next(descend bool) bool {
	if it.nodeIterator.Next(descend) {
		if it.hasPrefix() {
			return true
		}
	}
	return false
}

func (it *prefixIterator) Error() error {
	return it.nodeIterator.Error()
}

func (it *prefixIterator) Hash() common.Hash {
	if it.hasPrefix() {
		return it.nodeIterator.Hash()
	}
	return common.Hash{}
}

func (it *prefixIterator) Parent() common.Hash {
	if it.hasPrefix() {
		it.nodeIterator.Parent()
	}
	return common.Hash{}
}

func (it *prefixIterator) Path() []byte {
	if it.hasPrefix() {
		return it.nodeIterator.Path()
	}
	return nil
}

func (it *prefixIterator) Leaf() bool {
	if it.hasPrefix() {
		return it.nodeIterator.Leaf()
	}
	return false
}

func (it *prefixIterator) LeafKey() []byte {
	if it.hasPrefix() {
		return it.nodeIterator.LeafKey()
	}
	return nil
}

func (it *prefixIterator) LeafBlob() []byte {
	if it.hasPrefix() {
		return it.nodeIterator.LeafBlob()
	}
	return nil
}

func (it *prefixIterator) LeafProof() [][]byte {
	//TODO 该方法暂时未用到
	panic("implement me")
}
