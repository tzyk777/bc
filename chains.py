import binascii
import time
import json
import hashlib
import threading
import logging
import socketserver
import socket
import random
import os
from functools import lru_cache, wraps
from typing import (
    Iterable, NamedTuple, Dict, Mapping, Union, get_type_hints, Tuple,
    Callable)

import ecdsa
from base58 import b58encode_check
from utils import sha256d, serialize
from merkle_tree import get_merkle_root_of_txns



logging.basicConfig(
    level=getattr(logging, os.environ.get('TC_LOG_LEVEL', 'INFO')),
    format='[%(asctime)s][%(module)s:%(lineno)d] %(levelname)s %(message)s')
logger = logging.getLogger(__name__)


class Params:
    # The infamous max block size
    MAX_BLOCK_SERIALIZED_SIZE = 1000000

    # Coinbase transaction outputs can be spent after this many blocks have
    # elapsed since being mined.
    #
    # This is "100" in bitcoin core.
    COINBASE_MATURITY = 2

    # Accept blocks timestamped as being from the future, up to this amount.
    MAX_FUTURE_BLOCK_TIME = (60 * 60 * 2)

    # The number of Belushis per coin. #realname COIN
    BELUSHIS_PER_COIN = int(100e6)

    TOTAL_COINS = 21_000_000

    # The maximum number of Belushis that will ever be found.
    MAX_MONEY = BELUSHIS_PER_COIN * TOTAL_COINS

    # The duration we want to pass between blocks being found, in seconds.
    # This is lower than Bitcoin's configuation (10 * 60).
    #
    # #realname PowTargetSpacing
    TIME_BETWEEN_BLOCKS_IN_SECS_TARGET = 1 * 60

    # The number of seconds we want a difficulty period to last.
    #
    # Note that this differs considerably from the behavior in Bitcoin, which
    # is configured to target difficulty periods of (10 * 2016) minutes.
    #
    # #realname PowTargetTimespan
    DIFFICULTY_PERIOD_IN_SECS_TARGET = (60 * 60 * 10)

    # After this number of blocks are found, adjust difficulty.
    #
    # #realname DifficultyAdjustmentInterval
    DIFFICULTY_PERIOD_IN_BLOCKS = (
        DIFFICULTY_PERIOD_IN_SECS_TARGET / TIME_BETWEEN_BLOCKS_IN_SECS_TARGET)

    # The number of right-shifts applied to 2 ** 256 in order to create the
    # initial difficulty target necessary for mining a block.
    INITIAL_DIFFICULTY_BITS = 24

    # The number of blocks after which the mining subsidy will halve.
    #
    # #realname SubsidyHalvingInterval
    HALVE_SUBSIDY_AFTER_BLOCKS_NUM = 210_000


# Used to represent the specific output within a transaction.
OutPoint = NamedTuple('OutPoint', [('txid', str), ('txout_idx', int)])


class TxIn(NamedTuple):
    """Inputs to a Transction"""
    to_spend: Union[OutPoint, None]
    unlock_sig: bytes
    unlock_pk: bytes

    sequence: int


class TxOut(NamedTuple):
    """Outputs from a transaction"""
    value: int

    to_address: str


class UnspentTxOut(NamedTuple):
    value: int
    to_address: str

    txid: str
    txout_idx: int

    is_coinbase: bool

    height: int

    @property
    def outpoint(self):
        return OutPoint(self.txid, self.txout_idx)


class Transaction(NamedTuple):
    txins: Iterable[TxIn]
    txouts: Iterable[TxOut]

    # The block number or timestamp at which this transaction is unlocked.
    # < 500000000: Block number at which this transaction is unlocked.
    # >= 500000000: UNIX timestamp at which this transaction is unlocked.
    locktime: int = None

    @property
    def is_coinbase(self) -> bool:
        return len(self.txins) == 1 and self.txins[0].to_spend is None

    @classmethod
    def create_coinbase(cls, pay_to_addr, value, height):
        return cls(
            txins=[TxIn(
                to_spend=None,
                unlock_sig=str(height).encode(),
                unlock_pk=None,
                sequence=0
            )],
            txouts=[TxOut(
                value=value,
                to_address=pay_to_addr
            )]
        )

    @property
    def id(self) -> str:
        return sha256d(serialize(self))

    def validate_basics(self, as_coinbase=False):
        if (not self.txouts) or (not self.txins and not as_coinbase):
            raise TxnValidationError('Missing txouts or txins')

        if len(serialize(self)) > Params.MAX_BLOCK_SERIALIZED_SIZE:
            raise TxnValidationError('Too large')

        if sum(t.value for t in self.txins) > Params.MAX_MONEY:
            raise TxnValidationError('Spend value too high')


class Block(NamedTuple):
    # A version integer
    version: int

    # A hash of the previous block's header
    prev_block_hash: str

    # A hash of the Merkle tree containing all txns
    markle_hash: str

    # A UNIX timestamp of when this block was created.
    timestamp: int

    # Difficulty
    bits: int

    # The value that's incremented in an attempt to get the block header
    # to hash to a value below bits
    nonce: int

    txns: Iterable[Transaction]

    def header(self, nonce=None) -> str:
        """
        This is hashed in an attempt to discover a nonce under the difficulty
        """
        return (
            f'{self.version}{self.prev_block_hash}{self.markle_hash}'
            f'{self.timestamp}{self.bits}{nonce or self.nonce}'
        )

    @property
    def id(self) -> str:
        return sha256d(self.header())


genesis_block = Block(
    version=0, prev_block_hash=None,
    markle_hash=(
        '7118894203235a955a908c0abfc6d8fe6edec47b0a04ce1bf7263da3b4366d22'
    ),
    timestamp=1501821412, bits=24, nonce=10126761,
    txns=[Transaction(
        txins=[TxIn(
            to_spend=None, unlock_sig=b'0', unlock_pk=None, sequence=0)],
        txouts=[TxOut(
            value=5000000000,
            to_address='143UVyz7ooiAv1pMqbwPPpnH4BV9ifJGFF')],
        locktime=None)]
)


# The highest proof-of-work, valid blockchain
#
# #realname chainActive

active_chain: Iterable[Block] = [genesis_block]

# Branch off of the main chain.
side_branches: Iterable[Iterable[Block]] = []

# Synchronize access to the active chain and side branches
chain_lock = threading.RLock()


def with_lock(lock):
    def dec(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            with lock:
                return func(*args, **kwargs)
        return wrapper
    return dec


orphan_blocks: Iterable[Block] = []

# Used to signify the active chain in 'locate_block'
ACTIVE_CHAIN_IDX = 0


@with_lock(chain_lock)
def get_current_height():
    return len(active_chain)


@with_lock(chain_lock)
def txn_iterator(chain):
    return (
        (txn, block, height)
        for height, block in enumerate(chain) for txn in block.txns
    )


@with_lock(chain_lock)
def locate_block(block_hash: str, chain=None) -> (Block, int, int):
    chains = [chain] if chain else [active_chain, *side_branches]

    for chain_idx, chain in enumerate(chains):
        for height, block in enumerate(chain):
            if block.id == block_hash:
                return (block, height, chain_idx)
    else:
        return (None, None, None)


@with_lock(chain_lock)
def validate_block(block: Block) -> Block:
    if not block.txns:
        raise BlockValidationError('txns empty')

    if block.timestamp - time.time() > Params.MAX_FUTURE_BLOCK_TIME:
        raise BlockValidationError('Block timestamp too far in future')

    if int(block.id, 16) > (1 << (256 - block.bits)):
        raise BlockValidationError("Block header doesn't satisfy bits")

    if [i for (i, tx) in enumerate(block.txns) if tx.is_coinbase] != [0]:
        raise BlockValidationError('First txn must be coinbase and no more')

    try:
        for i, txn in enumerate(block.txns):
            txn.validate_basics(as_coinbase=(i == 0))
    except TxnValidationError:
        logger.exception(f"transaction {txn} in {block} failed to validate")
        raise BlockValidationError(f"invalid txn {txn.id}")

    if get_merkle_root_of_txns(block.txns).val != block.markle_hash:
        raise BlockValidationError('Merkle has invalid')

    if block.timestamp <= get_median_time_past(11):
        raise BlockValidationError('timestamp too old')

    if not block.prev_block_hash and not active_chain:
        prev_block_chain_idx = ACTIVE_CHAIN_IDX
    else:
        prev_block, prev_block_height, prev_block_chain_idx = locate_block(
            block.prev_block_hash
        )

        if not prev_block:
            raise BlockValidationError(
                f'prev block {block.prev_block_hash} not found in any chain',
                to_orphan=block
            )

        if prev_block_chain_idx != ACTIVE_CHAIN_IDX:
            return block, prev_block_chain_idx

        if prev_block != active_chain[-1]:
            return block, prev_block_chain_idx + 1


@with_lock(chain_lock)
def connect_block(block: Union[str, Block],
                  doing_reorg=False,
                  ) -> Union[None, Block]:
    """Accept a block and return the chain index we append it to"""
    # Only exit early on already seen in active_chain when reorging

    search_chain = active_chain if doing_reorg else None

    if locate_block(block.id, chain=search_chain)[0]:
        logger.debug(f'ignore block already seen: {block.id}')
        return None

    try:
        block, chain_idx = validate_block(block)
    except BlockValidationError as e:
        logger.exception('block % failed validation', block.id)
        if e.to_orphan:
            logger.info(f'saw orphan block {block.id}')
            orphan_blocks.append(e.to_orphan)
        return None

    # If 'validate_block()' returned a non-existent chain index, we are
    # creating a new side branch

    if chain_idx != ACTIVE_CHAIN_IDX and len(side_branches) < chain_idx:
        logger.info(
            f'creating a new side branch (idx {chain_idx})'
            f'for block {block.id}'
        )
        side_branches.append([])

    logger.info(f'connecting block {block.id} to chain {chain_idx}')
    chain = (active_chain if active_chain == ACTIVE_CHAIN_IDX else
             side_branches[chain_idx-1])
    chain.append(block)

    # If we added to the active chain, perform upkeep on utxo_set and mempool
    if chain_idx == ACTIVE_CHAIN_IDX:
        for tx in
class TxnValidationError(BaseException):
    def __init__(self, *args, to_orphan: Transaction = None, **kwargs):
        super().__init__(*args, **kwargs)
        self.to_orphan = to_orphan


class BlockValidationError(BaseException):
    def __init__(self, *args, to_orphan: Block = None, **kwargs):
        super().__init__(*args, **kwargs)
        self.to_orphan = to_orphan

#
# def decorator(func):
#     @wraps(func)
#     def wrapper(*args, **kwargs):
#         print('Decorator call')
#         func(*args, **kwargs)
#         print('Decorator callend')
#     return wrapper
#
#
# def test():
#     pass
#
#
# @decorator
# def tester():
#     """Doc string"""
#     pass
#
#
# print(tester.__name__)
# print(tester.__doc__)