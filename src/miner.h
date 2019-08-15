// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2016 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_MINER_H
#define BITCOIN_MINER_H

#include <primitives/block.h>
#include <txmempool.h>

#include <boost/multi_index/ordered_index.hpp>
#include <boost/multi_index_container.hpp>

#include <cstdint>
#include <memory>

class CBlockIndex;
class CChainParams;
class Config;
class CScript;

namespace Consensus {
struct Params;
}

static const bool DEFAULT_PRINTPRIORITY = false;

struct CBlockTemplateEntry {
    CTransactionRef tx;
    //!< Total real fees paid by the transaction and cached to avoid parent
    //!< lookup
    Amount txFee;
    //!< Cached total size of the transaction to avoid reserializing transaction
    size_t txSize;
    //!< Cached total number of SigOps
    uint64_t txSigOps;

    CBlockTemplateEntry(CTransactionRef _tx, Amount _fees, uint64_t _size,
                        int64_t _sigOps)
        : tx(_tx), txFee(_fees), txSize(_size), txSigOps(_sigOps) {}
};

struct CBlockTemplate {
    CBlock block;

    std::vector<CBlockTemplateEntry> entries;
};

// A comparator that sorts transactions based on number of ancestors.
// This is sufficient to sort an ancestor package in an order that is valid
// to appear in a block.
struct CompareTxIterByAncestorCount {
    bool operator()(const CTxMemPool::txiter &a,
                    const CTxMemPool::txiter &b) const {
        if (a->GetCountWithAncestors() != b->GetCountWithAncestors()) {
            return a->GetCountWithAncestors() < b->GetCountWithAncestors();
        }
        return CTxMemPool::CompareIteratorByHash()(a, b);
    }
};

/** Generate a new block, without valid proof-of-work */
class BlockAssembler {
private:
    // The constructed block template
    std::unique_ptr<CBlockTemplate> pblocktemplate;
    // A convenience pointer that always refers to the CBlock in pblocktemplate
    CBlock *pblock;

    // Configuration parameters for the block size
    uint64_t nMaxGeneratedBlockSize;
    CFeeRate blockMinFeeRate;

    // Information on the current status of the block
    uint64_t nBlockSize;
    uint64_t nBlockTx;
    uint64_t nBlockSigOps;
    Amount nFees;
    CTxMemPool::setEntries inBlock;

    // Chain context for the block
    int nHeight;
    int64_t nLockTimeCutoff;
    int64_t nMedianTimePast;
    const CChainParams &chainparams;
    uint8_t nBlockPriorityPercentage;

    const CTxMemPool *mempool;

    // Variables used for addPriorityTxs
    int lastFewTxs;

public:
    struct Options {
        Options();
        uint64_t nExcessiveBlockSize;
        uint64_t nMaxGeneratedBlockSize;
        CFeeRate blockMinFeeRate;
        uint8_t nBlockPriorityPercentage;
    };

    BlockAssembler(const Config &config, const CTxMemPool &_mempool);
    BlockAssembler(const CChainParams &params, const CTxMemPool &_mempool,
                   const Options &options);

    /** Construct a new block template with coinbase to scriptPubKeyIn */
    std::unique_ptr<CBlockTemplate>
    CreateNewBlock(const CScript &scriptPubKeyIn);

    uint64_t GetMaxGeneratedBlockSize() const { return nMaxGeneratedBlockSize; }

private:
    // utility functions
    /** Clear the block's state and prepare for assembling a new block */
    void resetBlock();
    /** Add a tx to the block */
    void AddToBlock(CTxMemPool::txiter iter);

    // Methods for how to add transactions to a block.
    /** Add transactions based on tx "priority" */
    void addPriorityTxs() EXCLUSIVE_LOCKS_REQUIRED(mempool->cs);
    /**
     * Add transactions based on feerate including unconfirmed ancestors.
     * Increments nPackagesSelected / nDescendantsUpdated with corresponding
     * statistics from the package selection (for logging statistics).
     */
    void addPackageTxs(int &nPackagesSelected, int &nDescendantsUpdated)
        EXCLUSIVE_LOCKS_REQUIRED(mempool->cs);

    /** Enum for the results from TestForBlock */
    enum class TestForBlockResult : uint8_t {
        TXFits = 0,
        TXCantFit = 1,
        BlockFinished = 3,
    };

    // helper function for addPriorityTxs
    /** Test if tx will still "fit" in the block */
    TestForBlockResult TestForBlock(CTxMemPool::txiter iter);
    /** Test if tx still has unconfirmed parents not yet in block */
    bool isStillDependent(CTxMemPool::txiter iter)
        EXCLUSIVE_LOCKS_REQUIRED(mempool->cs);

    // helper functions for addPackageTxs()
    /** Test if a new package would "fit" in the block */
    bool TestPackage(uint64_t packageSize, int64_t packageSigOps) const;
    /** Test if a set of transactions are all final */
    bool TestPackageFinality(const CTxMemPool::setEntries &package);
    /** Sort the package in an order that is valid to appear in a block */
    void SortForBlock(const CTxMemPool::setEntries &package,
                      std::vector<CTxMemPool::txiter> &sortedEntries);
};

/** Modify the extranonce in a block */
void IncrementExtraNonce(CBlock *pblock, const CBlockIndex *pindexPrev,
                         uint64_t nExcessiveBlockSize,
                         unsigned int &nExtraNonce);
int64_t UpdateTime(CBlockHeader *pblock, const Consensus::Params &params,
                   const CBlockIndex *pindexPrev);
#endif // BITCOIN_MINER_H
