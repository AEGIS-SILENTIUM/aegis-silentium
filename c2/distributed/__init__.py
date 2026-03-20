"""
c2/distributed/__init__.py
AEGIS-SILENTIUM v12 — Distributed Systems Module

Public API for all distributed systems primitives.

Quick import::

    from c2.distributed import (
        HybridLogicalClock, HLCTimestamp,
        MerkleTree,
        WriteAheadLog, WALStateMachine,
        GCounter, PNCounter, ORSet, LWWRegister, VectorClock,
        GossipProtocol, Member, MemberState,
        FencingTokenManager, StaleEpochError,
        MVCCStore,
        QuorumManager, ConsistencyLevel,
        AntiEntropyScheduler,
        TwoPCCoordinator, Mutation,
        LeaseCache, SpeculativeReadBuffer,
        StateVerifier,
        Redlock, ReadWriteLock, NamedLockPool,
        ConsistentHashRing, BloomFilter, PriorityTaskQueue, PriorityTask,
        DeadLetterQueue, AdaptiveLoadBalancer, Backend,
        ChaosRunner, ChaosExperiment, build_standard_experiments,
    )
"""

from .hlc           import HybridLogicalClock, HLCTimestamp
from .merkle        import MerkleTree
from .wal           import WriteAheadLog, WALStateMachine, WALEntry
from .crdt          import GCounter, PNCounter, ORSet, LWWRegister, VectorClock
from .gossip        import GossipProtocol, Member, MemberState
from .fencing       import FencingTokenManager, StaleEpochError
from .mvcc          import MVCCStore
from .quorum        import QuorumManager, ConsistencyLevel, QuorumError
from .anti_entropy  import AntiEntropyScheduler
from .two_phase_commit import TwoPCCoordinator, Mutation, Transaction, TxnState
from .lease         import LeaseCache, SpeculativeReadBuffer
from .state_verifier import StateVerifier
from .lock_manager  import Redlock, ReadWriteLock, NamedLockPool, RedlockAcquireError
from .consistent_hash import ConsistentHashRing, BloomFilter, PriorityTaskQueue, PriorityTask
from .dead_letter   import DeadLetterQueue, AdaptiveLoadBalancer, Backend
from .chaos         import ChaosRunner, ChaosExperiment, ChaosResult, build_standard_experiments

__all__ = [
    # HLC
    "HybridLogicalClock", "HLCTimestamp",
    # Merkle
    "MerkleTree",
    # WAL
    "WriteAheadLog", "WALStateMachine", "WALEntry",
    # CRDTs
    "GCounter", "PNCounter", "ORSet", "LWWRegister", "VectorClock",
    # Gossip
    "GossipProtocol", "Member", "MemberState",
    # Fencing
    "FencingTokenManager", "StaleEpochError",
    # MVCC
    "MVCCStore",
    # Quorum
    "QuorumManager", "ConsistencyLevel", "QuorumError",
    # Anti-entropy
    "AntiEntropyScheduler",
    # 2PC
    "TwoPCCoordinator", "Mutation", "Transaction", "TxnState",
    # Lease + Speculative
    "LeaseCache", "SpeculativeReadBuffer",
    # State Verifier
    "StateVerifier",
    # Locks
    "Redlock", "ReadWriteLock", "NamedLockPool", "RedlockAcquireError",
    # Routing / DS
    "ConsistentHashRing", "BloomFilter", "PriorityTaskQueue", "PriorityTask",
    # DLQ + LB
    "DeadLetterQueue", "AdaptiveLoadBalancer", "Backend",
    # Chaos
    "ChaosRunner", "ChaosExperiment", "ChaosResult", "build_standard_experiments",
]

# v11 additions
from .saga import SagaOrchestrator, SagaDefinition, SagaState, SagaStep
from .service_registry import ServiceRegistry, ServiceInstance, ServiceState

__all__ = [
    # v10 exports (existing)
    "HybridLogicalClock", "HLCTimestamp",
    "MerkleTree", "MerkleNode",
    "WriteAheadLog", "WALStateMachine", "WALEntry",
    "VectorClock", "GCounter", "PNCounter", "ORSet", "LWWRegister",
    "GossipProtocol", "Member", "MemberState",
    "FencingTokenManager", "StaleEpochError",
    "MVCCStore",
    "QuorumManager", "ConsistencyLevel",
    "AntiEntropyScheduler",
    "TwoPCCoordinator",
    "LeaseCache",
    "StateVerifier",
    "Redlock", "ReadWriteLock", "NamedLockPool",
    "ConsistentHashRing", "BloomFilter", "PriorityTaskQueue",
    "DeadLetterQueue", "AdaptiveLoadBalancer",
    "ChaosRunner", "ChaosExperiment",
    # v11 additions
    "SagaOrchestrator", "SagaDefinition", "SagaState", "SagaStep",
    "ServiceRegistry", "ServiceInstance", "ServiceState",
    "EpochRecord", "EpochExpiredError",
    "WALSyncMode", "WALEntryType",
]
