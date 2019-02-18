package trie

import (
	"fmt"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/ethdb"
	"github.com/ethereum/go-ethereum/log"
)

func NewTrieWithPrefix(root common.Hash, prefix []byte, db ethdb.Database) (*Trie, error) {
	trie, err := New(root, NewDatabase(db))
	if err != nil {
		return nil, err
	}
	trie.prefix = prefix
	return trie, nil
}

func (t *Trie) NodeIteratorWithPrefix(start []byte) NodeIterator {
	if t.prefix != nil {
		start = append(t.prefix, start...)
	}
	return newNodeIterator(t, start)
}

func (t *Trie) PrefixIterator(prefix []byte) NodeIterator {
	if t.prefix != nil {
		prefix = append(t.prefix, prefix...)
	}
	return newPrefixIterator(t, prefix)
}

func (t *Trie) UpdateWithPrefix(key, value []byte) {
	if err := t.TryUpdateWithPrefix(key, value); err != nil {
		log.Error(fmt.Sprintf("Unhandled trie error: %v", err))
	}
}

func (t *Trie) TryUpdateWithPrefix(key, value []byte) error {
	if t.prefix != nil {
		key = append(t.prefix, key...)
	}
	k := keybytesToHex(key)
	if len(value) != 0 {
		_, n, err := t.insert(t.root, nil, k, valueNode(value))
		if err != nil {
			return err
		}
		t.root = n
	} else {
		_, n, err := t.delete(t.root, nil, k)
		if err != nil {
			return err
		}
		t.root = n
	}
	return nil
}

func (t *Trie) GetWithPrefix(key []byte) []byte {
	res, err := t.TryGetWithPrefix(key)
	if err != nil {
		log.Error(fmt.Sprintf("Unhandled trie error: %v", err))
	}
	return res
}

func (t *Trie) TryGetWithPrefix(key []byte) ([]byte, error) {
	if t.prefix != nil {
		key = append(t.prefix, key...)
	}
	key = keybytesToHex(key)
	value, newroot, didResolve, err := t.tryGet(t.root, key, 0)
	if err == nil && didResolve {
		t.root = newroot
	}
	return value, err
}

func (t *Trie) TryDeleteWithPrefix(key []byte) error {
	if t.prefix != nil {
		key = append(t.prefix, key...)
	}
	k := keybytesToHex(key)
	_, n, err := t.delete(t.root, nil, k)
	if err != nil {
		return err
	}
	t.root = n
	return nil
}
