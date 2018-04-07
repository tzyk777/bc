from typing import NamedTuple, Iterable, Tuple
from functools import lru_cache
from utils import sha256d, chunks


class MerkleNode(NamedTuple):
    val: str
    children: Iterable = None


@lru_cache(maxsize=1024)
def get_merkle_root(*leaves: Tuple(str)) -> MerkleNode:
    """Builds a Merkle tree and returns the root given some leaves"""
    if len(leaves) % 2 == 1:
        leaves = leaves + (leaves[-1],)

    def find_root(nodes):
        newlevel = [
            MerkleNode(sha256d(i1.val + i2.val), children=[i1, i2])
            for [i1, i2] in chunks(nodes, 2)
        ]

        return find_root(newlevel) if len(newlevel) > 1 else newlevel[0]

    return find_root([MerkleNode(sha256d(l)) for l in leaves])


def get_merkle_root_of_txns(txns):
    return get_merkle_root(*[t.id for t in txns])