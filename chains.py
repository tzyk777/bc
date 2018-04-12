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
from utils import sha256d, serialize, deserialize
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


# Chain
# ------------------------------------------------------------------------

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
                return block, height, chain_idx
    else:
        return None, None, None


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
    chain = (active_chain if chain_idx == ACTIVE_CHAIN_IDX else
             side_branches[chain_idx-1])
    chain.append(block)

    # If we added to the active chain, perform upkeep on utxo_set and mempool
    if chain_idx == ACTIVE_CHAIN_IDX:
        for tx in block.txns:
            mempool.pop(tx.id, None)

            if not tx.is_coinbase:
                for txin in tx.txins:
                    rm_from_utxo(*txin.to_spend)
            for i, txout in enumerate(tx.txouts):
                add_to_utxo(txout, tx, i, tx.is_coinbase, len(chain))

    if (not doing_reorg and reorg_if_necessary()) or chain_idx == ACTIVE_CHAIN_IDX:
        mine_interrupt.set()
        logger.info('block accepted height={len(active_chain) - 1} txns={len(block.txns)}')

    for peer in peer_hostnames:
        send_to_peer(block, peer)

    return chain_idx


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

    if get_next_work_required(block.prev_block_hash) != block.bits:
        raise BlockValidationError('bits is incorrect')

    for txn in block.txns[1:]:
        try:
            validate_txn(txn, siblings_in_block=block.txns[1:],
                         allow_utxo_from_mempool=False)
        except TxnValidationError:
            msg = f"{txn} failed to validate"
            logger.exception(msg)
            raise BlockValidationError(msg)

    return block, prev_block_chain_idx


def get_median_time_past(num_last_blocks: int) -> int:
    last_n_blocks = active_chain[::-1][:num_last_blocks]

    if not last_n_blocks:
        return 0

    return last_n_blocks[len(last_n_blocks) // 2].timestamp

# mempool

mempool: Dict[str, Transaction] = {}


# set of orphaned (i.e. has inputs referencing yet non-existent UTXOs)
# transactions

orphan_txns: Iterable[Transaction] = []
def find_utxo_in_mempool(txin) -> UnspentTxOut:
    txid, idx = txin.to_spend

    try:
        txout = mempool[txid].txouts[idx]
    except Exception:
        logger.debug("Could not find utxo in mempool for %s", txin)
        return None

    return UnspentTxOut(
        *txout, txid=txid, is_coinbase=False, height=-1, txout_idx=idx
    )


def select_from_mempool(block: Block) -> Block:
    """Fill a block with transactions from the mempool."""
    added_to_block = set()

    def check_block_size(b) -> bool:
        return len(serialize(b)) < Params.MAX_BLOCK_SERIALIZED_SIZE

    def try_add_to_block(block, txid) -> Block:
        if txid in added_to_block:
            return block

        tx = mempool[txid]

        # For any txin that can't be found in the main chain, find its transaction in the mempool
        # (If it exists) and add it to the block
        for txin in tx.txins:
            if txin.to_spend in utxo_set:
                continue

            in_mempool = find_utxo_in_mempool(txin)

            if not in_mempool:
                logger.debug(f"Couldn't find UTXO for {txin}")
                return None

            block = try_add_to_block(block, in_mempool.txid)
            if not block:
                logger.debug("Couldn't add parent")
                return None

            newblock = block._replace(txns=[*block.txns, tx])

            if check_block_size(newblock):
                logger.debug(f'added tx {tx.id} to block')
                added_to_block.add(txid)
                return newblock
            return block

    for txid in mempool:
        newblock = try_add_to_block(block, txid)

        if check_block_size(newblock):
            block = newblock
        else:
            break

    return block


def add_txn_to_mempool(txn: Transaction):
    if txn.id in mempool:
        logger.info(f'txn {txn.id} already seen')
        return

    try:
        txn = validate_txn(txn)
    except TxnValidationError as e:
        if e.to_orphan:
            logger.info(f'txn {e.to_orphan.id} submitted as orphan')
            orphan_txns.append(e.to_orphan)
        else:
            logger.exception(f'txn rejected')
    else:
        logger.info(f'txn {txn.id} added to mempool')
        mempool[txn.id] = txn

        for peer in peer_hostnames:
            send_to_peer(txn, peer)

# UTXO set

utxo_set: Mapping[OutPoint, UnspentTxOut] = {}


def add_to_utxo(txout, tx, idx, is_coinbase, height):
    utxo = UnspentTxOut(
        *txout,
        txid=tx.id,
        txout_idx=idx,
        is_coinbase=is_coinbase,
        height=height
    )

    logger.info(f'adding tx outpoint {utxo.outpoint} to utxo_set')
    utxo_set[utxo.outpoint] = utxo


def rm_from_utxo(txid, txout_idx):
    del utxo_set[OutPoint(txid, txout_idx)]


def find_utxo_in_list(txin, txns) -> UnspentTxOut:
    # if the input is in the same block, search it in the block
    txid, txout_idx = txin.to_spend
    try:
        txout = [t for t in txns if t.id == txid][0].txouts[txout_idx]
    except Exception:
        return None

    return UnspentTxOut(
        *txout, txid=txid, is_coinbase=False, height=-1, txout_idx=txout_idx
    )

# POW
def get_next_work_required(prev_block_hash: str) -> int:
    """
    Based on the chain, return the number of difficulty bits the next block must solve
    """
    if not prev_block_hash:
        return Params.INITIAL_DIFFICULTY_BITS

    prev_block, prev_height, _ = locate_block(prev_block_hash)

    if (prev_height + 1) % Params.DIFFICULTY_PERIOD_IN_BLOCKS != 0:
        return prev_block.bits

    with chain_lock:
        period_start_block = active_chain[max(prev_height - (Params.DIFFICULTY_PERIOD_IN_BLOCKS - 1), 0)]

    actual_time_taken = prev_block.timestamp - period_start_block.timestamp

    if actual_time_taken < Params.DIFFICULTY_PERIOD_IN_SECS_TARGET:
        # Increase the difficulty
        return prev_block.bits + 1
    if actual_time_taken > Params.DIFFICULTY_PERIOD_IN_SECS_TARGET:
        # Decrease the difficulty
        return prev_block.bits - 1
    return prev_block.bits


def assemble_and_solve_block(pay_coinbase_to_addr, txns=None):
    """
    Construct a block by pulling transactions from the mempool, then mine it.
    """
    with chain_lock:
        prev_block_hash = active_chain[-1].id if active_chain else None

    block = Block(
        version=0,
        prev_block_hash=prev_block_hash,
        markle_hash='',
        timestamp=int(time.time()),
        bits=get_next_work_required(prev_block_hash),
        nonce=0,
        txns=txns or [],
    )

    if not block.txns:
        block = select_from_mempool(block)

    fees = calculate_fees(block)
    my_address = init_wallet()[2]
    coinbase_txn = Transaction.create_coinbase(
        my_address, (get_block_subsidy() + fees), len(active_chain)
    )
    block = block._replace(txns=[coinbase_txn, *block.txns])
    block = block._replace(markle_hash=get_merkle_root_of_txns(block.txns).val)

    if len(serialize(block)) > Params.MAX_BLOCK_SERIALIZED_SIZE:
        raise ValueError('txns specified create a block too large')

    return mine(block)


def calculate_fees(block) -> int:
    """
    Given the txns in a Block, subtract the amount of coin output from the inputs. This is kept as a reward by the miner.
    """
    fee = 0

    def utxo_from_block(txin):
        tx = [t.txouts for t in block.txns if t.id == txin.to_spend.txid]
        return tx[0][txin.to_spend.txout_idx] if tx else None

    def find_utxo(txin):
        return utxo_set.get(txin.to_spend) or utxo_from_block(txin)

    for txn in block.txns:
        spent = sum(find_utxo(i).value for i in tx.txins)
        sent = sum(o.value for o in txn.txouts)
        fee += (spent - sent)

    return fee


def get_block_subsidy() -> int:
    halvings = len(active_chain) // Params.HALVE_SUBSIDY_AFTER_BLOCKS_NUM

    if halvings >= 64:
        return 0

    return 50 * Params.BELUSHIS_PER_COIN // (2 ** halvings)


# Signal to communicate to the mining thread that it should stop mining because we've updated the chain with a new block.
# Signal to communicate to the mining thread that it should stop mining because
# we've updated the chain with a new block
mine_interrupt = threading.Event()


def mine(block):
    start = time.time()
    nonce = 0
    target = (1 << (256 - block.bits))
    mine_interrupt.clear()

    while int(sha256d(block.header(nonce)), 16) >= target:
        nonce += 1

        if nonce % 10000 == 0 and mine_interrupt.is_set():
            logger.info('[mining] interrupted')
            mine_interrupt.clear()
            return None

    block = block._replace(nonce=nonce)
    duration = int(time.time() - start) or 0.001
    khs = (block.nonce // duration) // 1000
    logger.info(
        f'[mining] block found! {duration} s - {khs} KH/s - {block.id}'
    )
    return block


def mine_forever():
    while True:
        my_address = init_wallet()[2]
        block = assemble_and_solve_block(my_address)

        if block:
            connect_block(block)
            save_to_disk()

# Wallet

WALLET_PATH = os.environ.get('TC_WALLET_PATH', 'wallet.dat')

def pubkey_to_address(pubkey: bytes) -> str:
    if 'ripemd160' not in hashlib.algorithms_available:
        raise RuntimeError('Missing ripemd160 hash algorithm')

    sha = hashlib.sha256(pubkey).digest()
    ripe = hashlib.new('ripemd160', sha).digest()
    return b58encode_check(b'\x00' + ripe)

@lru_cache()
def init_wallet(path=None):
    path = path or WALLET_PATH

    if os.path.exists(path):
        with open(path, 'rb') as f:
            signing_key = ecdsa.SigningKey.from_string(
                f.read(), curv=ecdsa.SECP256K1
            )
    else:
        logger.info(f"generating new wallet: '{path}'")
        signing_key = ecdsa.SigningKey.generate(curve=ecdsa.SECP256K1)
        with open(path, 'wb') as f:
            f.write(signing_key.to_string())

    verifying_key = signing_key.get_verifying_key()
    my_address = pubkey_to_address(verifying_key.to_string())
    logger.info(f"your address is {my_address}")

    return signing_key, verifying_key, my_address


# Validation
def validate_txn(txn: Transaction,
                 as_coinbase: bool=False,
                 siblings_in_block: Iterable[Transaction] = None,
                 allow_utxo_from_mempool: bool = True) -> Transaction:
    """
    Validate a single transaction. Used in various contexts, so the parameters facilitate different uses.
    """
    txn.validate_basics(as_coinbase=as_coinbase)

    available_to_spend = 0

    for i, txin in enumerate(txn.txins):
        utxo = utxo_set.get(txin.to_spend)

        if siblings_in_block:
            utxo = utxo or find_utxo_in_list(txin, siblings_in_block)

        if allow_utxo_from_mempool:
            utxo = utxo or find_utxo_in_mempool(txin)

        if not utxo:
            raise TxnValidationError(
                f'Could find no UTXO for TxIn[{i}] -- orphaning txn',
                to_orphan=txn
            )

        if utxo.is_coinbase and (get_current_height() - utxo.height) < Params.COINBASE_MATURITY:
            raise TxnValidationError(f'Coinbase UTXO not ready for spend')

        try:
            validate_signature_for_spend(txin, utxo, txn)
        except TxUnlockError:
            raise TxnValidationError(f'{txin} is not a valid spend of {utxo}')

        available_to_spend += utxo.value

    if available_to_spend < sum(o.value for o in txn.txouts):
        raise TxnValidationError('Spend value is more than available')

    return txn


def validate_signature_for_spend(txin, utxo: UnspentTxOut, txn):
    pubkey_as_addr = pubkey_to_address(txin.unlock_pk)
    verifying_key = ecdsa.VerifyingKey.from_string(
        txin.unlock_pk, curve=ecdsa.SECP256K1
    )

    if pubkey_as_addr != utxo.to_address:
        raise TxUnlockError('Pubkey does not match')

    try:
        spend_msg = build_spend_message(
            txin.to_spend, txin.unlock_pk, txin.sequence, txn.txouts
        )
        verifying_key.verify(txin.unlock_sig, spend_msg)
    except Exception:
        logger.exception('Key verification failed')
        raise TxUnlockError('Signature does not match')

    return True


def build_spend_message(to_spend, pk, sequence, txouts) -> bytes:
    return sha256d(
        serialize(to_spend) + str(sequence) + binascii.hexlify(pk).decode() + serialize(txouts)).encode()


@with_lock(chain_lock)
def reorg_if_necessary() -> bool:
    reorged = False
    frozen_side_branches = list(side_branches)

    for branch_idx, chain in enumerate(frozen_side_branches, 1):
        fork_block, fork_idx, _ = locate_block(
            chain[0].prev_block_hash, active_chain
        )
        active_height = len(active_chain)
        branch_height = len(chain) + fork_idx

        if branch_height > active_height:
            logger.info(
                f'attempting reorg of idx {branch_idx} to active_chain: '
                f'new height of {branch_height} (vs. {active_height})'
            )

            reorged = reorged or try_reorg(chain, branch_idx, fork_idx)

    return reorged


@with_lock(chain_lock)
def try_reorg(branch, branch_idx, fork_idx) -> bool:
    global active_chain
    global side_branches

    fork_block = active_chain[fork_idx]

    def disconnect_to_fork():
        while active_chain[-1].id != fork_block.id:
            yield disconnect_block(active_chain[-1])

    old_active = list(disconnect_to_fork())[::-1]
    assert branch[0].prev_block_hash == active_chain[-1].id

    def roolback_reorg():
        logger.info(f'reorg of idx {branch_idx} to active_chain failed.')
        list()
class TxnValidationError(BaseException):
    def __init__(self, *args, to_orphan: Transaction = None, **kwargs):
        super().__init__(*args, **kwargs)
        self.to_orphan = to_orphan


class BlockValidationError(BaseException):
    def __init__(self, *args, to_orphan: Block = None, **kwargs):
        super().__init__(*args, **kwargs)
        self.to_orphan = to_orphan


class TxUnlockError(BaseException):
    pass




# Peer-to-peer

peer_hostnames = {p for p in os.environ.get('TC_PEERS', '').split(',') if p}

# Signal when the initial block download has completed.
ibd_done = threading.Event()


class GetBlockMsg(NamedTuple): # Request blocks during initial sync
    from_blockid: str

    CHUNK_SIZE = 50

    def handle(self, sock, peer_hostname):
        logger.debug(f'[p2p] recv getblocks from {peer_hostname}')

        _, height, _ = locate_block(self.from_blockid, active_chain)

        # If we don't recognize the requested hash as part of the active
        # chain, start at the genesis block.
        height = height or 1

        with chain_lock:
            blocks = active_chain[height:(height + self.CHUNK_SIZE)]

        logger.debug('f[p2p] sending {len(blocks)} to {peer_hostname}')
        send_to_peer(InvMsg(blocks), peer_hostname)


class InvMsg(NamedTuple): # Convey blocks to a peer who is doing initial sync
    blocks: Iterable[str]

    def handle(self, sock, peer_hostname):
        logger.info(f'[p2p] recv in from {peer_hostname}')

        new_blocks = [b for b in self.blocks if not locate_block(b.id)[0]]

        if not new_blocks:
            logger.info('[p2p] initial block download complete')
            ibd_done.set()
            return

        for block in new_blocks:
            connect_block(block)

        new_tip_id = active_chain[-1].id
        logger.info(f'[p2p] continuing initial block download at {new_tip_id}')

        with chain_lock:
            send_to_peer(GetBlockMsg(new_tip_id))


class GetUTXOsMsg(NamedTuple):
    def handle(self, sock, peer_hostname):
        sock.sendall(encode_socket_data(list(utxo_set.items())))


class GetMempoolMsg(NamedTuple):
    def handle(self, sock, peer_hostname):
        sock.send_all(encode_socket_data(list(mempool.keys())))


class GetActiveChainMsg(NamedTuple): # Get the active chain in its entirety
    def handle(self, sock, peer_hostname):
        sock.sendall(encode_socket_data(list(active_chain)))


class AddPeerMsg(NamedTuple):
    peer_hostname: str

    def handle(self, sock, peer_hostname):
        peer_hostnames.add(self.peer_hostname)


def read_all_from_socket(req) -> object:
    data = b''
    msg_len = int(binascii.hexlify((req.recv(4) or b'\x00')), 16)

    while msg_len > 0:
        tdat = req.recv(1024)
        data += tdat
        msg_len -= len(tdat)

    return deserialize(data.decode()) if data else None


def send_to_peer(data, peer=None):
    """Send a message to a (by default) random peer."""
    global peer_hostnames

    peer = peer or random.choice(list(peer_hostnames))
    tries_left = 3

    while tries_left > 0:
        try:
            with socket.create_connection((peer, PORT), timeout=1) as s:
                s.sendall(encode_socket_data(data))
        except Exception:
            logger.exception(f'failed to send to peer {peer}')
            tries_left -= 1
            time.sleep(2)
        else:
            return

    logger.info(f"[p2p] removing dead peer {peer}")
    peer_hostnames = {x for x in peer_hostnames if x != peer}


def int_to_8bytes(a: int) -> bytes:
    return binascii.unhexlify(f"{a:0{8}x}")


def encode_socket_data(data: object) -> bytes:
    """Our protocol is: first 4 bytes signify msg length."""
    to_send = serialize(data).encode()
    return int_to_8bytes(len(to_send)) + to_send


class ThreadedTCPServer(socketserver.ThreadingMixIn, socketserver.TCPServer):
    pass


class TCPHandler(socketserver.BaseRequestHandler):

    def handle(self):
        data = read_all_from_socket(self.request)
        peer_hostname = self.request.getpeername()[0]
        peer_hostnames.add(peer_hostname)

        if hasattr(data, 'handle') and isinstance(data.handle, Callable):
            logger.info(f'received msg {data} from peer {peer_hostname}')
            data.handle(self.request, peer_hostname)
        elif isinstance(data, Transaction):
            logger.info(f'received txn {data.id} from peer {peer_hostname}')
            add_txn_to_mempool(data)
        elif isinstance(data, Block):
            logger.info(f'received block {data.id} from peer {peer_hostname}')
            connect_block(data)


# Chain Persistance
# ---------------------------------------------------------------------------------

CHAIN_PATH = os.environ.get('TC_CHAIN_PATH', 'chain.dat')

@with_lock(chain_lock)
def save_to_disk():
    with open(CHAIN_PATH, 'wb') as f:
        logger.info(f'saving chain with {len(active_chain)} blocks')
        f.write(encode_socket_data(list(active_chain)))


@with_lock(chain_lock)
def load_from_disk():
    if not os.path.isfile(CHAIN_PATH):
        return
    try:
        with open(CHAIN_PATH, 'rb') as f:
            msg_len = int(binascii.hexlify(f.read(4) or b'\x00'), 16)
            new_blocks = deserialize(f.read(msg_len))
            logger.info(f'loading chain from disk with {len(new_blocks)} blocks')
            for block in new_blocks:
                connect_block(block)
    except Exception:
        logger.exception('load chain failed, starting from genesis')


# Main

PORT = os.environ.get('TC_PORT', 9999)

def main():
    load_from_disk()

    workers = []
    server = ThreadedTCPServer(('0.0.0.0', PORT), TCPHandler)

    def start_worker(func):
        workers.append(threading.Thread(target=func, daemon=True))
        workers[-1].start()

    logger.info(f'[p2p] listening on {PORT}')
    start_worker(server.serve_forever)

    if peer_hostnames:
        logger.info(f'start initial block download from {len(peer_hostnames)} peers')
        send_to_peer(GetBlockMsg(active_chain[-1].id))
        ibd_done.wait(60.)

    start_worker(mine_forever)
    [w.join() for w in workers]


if __name__ == '__main__':
    signing_key, verifying_key, my_address = init_wallet()
    main()
