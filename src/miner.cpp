// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2016 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <miner.h>

#include <amount.h>
#include <chain.h>
#include <chainparams.h>
#include <coins.h>
#include <config.h>
#include <consensus/activation.h>
#include <consensus/consensus.h>
#include <consensus/merkle.h>
#include <consensus/tx_verify.h>
#include <consensus/validation.h>
#include <hash.h>
#include <net.h>
#include <policy/policy.h>
#include <pow.h>
#include <primitives/transaction.h>
#include <script/standard.h>
#include <timedata.h>
#include <txmempool.h>
#include <util/moneystr.h>
#include <util/system.h>
#include <validation.h>
#include <validationinterface.h>

#include <algorithm>
#include <queue>
#include <utility>

// Unconfirmed transactions in the memory pool often depend on other
// transactions in the memory pool. When we select transactions from the
// pool, we select by highest priority or fee rate, so we might consider
// transactions that depend on transactions that aren't yet in the block.

uint64_t nLastBlockTx = 0;
uint64_t nLastBlockSize = 0;

int64_t UpdateTime(CBlockHeader *pblock, const Consensus::Params &params,
                   const CBlockIndex *pindexPrev) {
    int64_t nOldTime = pblock->nTime;
    int64_t nNewTime =
        std::max(pindexPrev->GetMedianTimePast() + 1, GetAdjustedTime());

    if (nOldTime < nNewTime) {
        pblock->nTime = nNewTime;
    }

    // Updating time can change work required on testnet:
    if (params.fPowAllowMinDifficultyBlocks) {
        pblock->nBits = GetNextWorkRequired(pindexPrev, pblock, params);
    }

    return nNewTime - nOldTime;
}

BlockAssembler::Options::Options()
    : nExcessiveBlockSize(DEFAULT_MAX_BLOCK_SIZE),
      nMaxGeneratedBlockSize(DEFAULT_MAX_GENERATED_BLOCK_SIZE),
      blockMinFeeRate(DEFAULT_BLOCK_MIN_TX_FEE_PER_KB),
      nBlockPriorityPercentage(DEFAULT_BLOCK_PRIORITY_PERCENTAGE) {}

BlockAssembler::BlockAssembler(const CChainParams &params,
                               const CTxMemPool &_mempool,
                               const Options &options)
    : chainparams(params), mempool(&_mempool) {
    blockMinFeeRate = options.blockMinFeeRate;
    // Limit size to between 1K and options.nExcessiveBlockSize -1K for sanity:
    nMaxGeneratedBlockSize = std::max<uint64_t>(
        1000, std::min<uint64_t>(options.nExcessiveBlockSize - 1000,
                                 options.nMaxGeneratedBlockSize));
    // Reserve a portion of the block for high priority transactions.
    nBlockPriorityPercentage = options.nBlockPriorityPercentage;
}

static BlockAssembler::Options DefaultOptions(const Config &config) {
    // Block resource limits
    // If -blockmaxsize is not given, limit to DEFAULT_MAX_GENERATED_BLOCK_SIZE
    // If only one is given, only restrict the specified resource.
    // If both are given, restrict both.
    BlockAssembler::Options options;

    options.nExcessiveBlockSize = config.GetMaxBlockSize();

    if (gArgs.IsArgSet("-blockmaxsize")) {
        options.nMaxGeneratedBlockSize =
            gArgs.GetArg("-blockmaxsize", DEFAULT_MAX_GENERATED_BLOCK_SIZE);
    }

    if (gArgs.IsArgSet("-blockmintxfee")) {
        Amount n = Amount::zero();
        ParseMoney(gArgs.GetArg("-blockmintxfee", ""), n);
        options.blockMinFeeRate = CFeeRate(n);
    }

    options.nBlockPriorityPercentage = config.GetBlockPriorityPercentage();

    return options;
}

BlockAssembler::BlockAssembler(const Config &config, const CTxMemPool &_mempool)
    : BlockAssembler(config.GetChainParams(), _mempool,
                     DefaultOptions(config)) {}

void BlockAssembler::resetBlock() {
    inBlock.clear();

    // Reserve space for coinbase tx.
    nBlockSize = 1000;
    nBlockSigOps = 100;

    // These counters do not include coinbase tx.
    nBlockTx = 0;
    nFees = Amount::zero();

    lastFewTxs = 0;
}

std::unique_ptr<CBlockTemplate>
BlockAssembler::CreateNewBlock(const CScript &scriptPubKeyIn) {
    int64_t nTimeStart = GetTimeMicros();

    resetBlock();

    pblocktemplate.reset(new CBlockTemplate());
    if (!pblocktemplate.get()) {
        return nullptr;
    }

    // Pointer for convenience.
    pblock = &pblocktemplate->block;

    // Add dummy coinbase tx as first transaction.  It is updated at the end.
    pblocktemplate->entries.emplace_back(CTransactionRef(), -SATOSHI, 0, -1);

    LOCK2(cs_main, mempool->cs);
    CBlockIndex *pindexPrev = chainActive.Tip();
    assert(pindexPrev != nullptr);
    nHeight = pindexPrev->nHeight + 1;

    pblock->nVersion =
        ComputeBlockVersion(pindexPrev, chainparams.GetConsensus());
    // -regtest only: allow overriding block.nVersion with
    // -blockversion=N to test forking scenarios
    if (chainparams.MineBlocksOnDemand()) {
        pblock->nVersion = gArgs.GetArg("-blockversion", pblock->nVersion);
    }

    pblock->nTime = GetAdjustedTime();
    nMedianTimePast = pindexPrev->GetMedianTimePast();
    nLockTimeCutoff =
        (STANDARD_LOCKTIME_VERIFY_FLAGS & LOCKTIME_MEDIAN_TIME_PAST)
            ? nMedianTimePast
            : pblock->GetBlockTime();

    addPriorityTxs();
    int nPackagesSelected = 0;
    int nDescendantsUpdated = 0;
    addPackageTxs(nPackagesSelected, nDescendantsUpdated);

    if (IsMagneticAnomalyEnabled(chainparams.GetConsensus(), pindexPrev)) {
        // If magnetic anomaly is enabled, we make sure transaction are
        // canonically ordered.
        // FIXME: Use a zipped list. See T479
        std::sort(std::begin(pblocktemplate->entries) + 1,
                  std::end(pblocktemplate->entries),
                  [](const CBlockTemplateEntry &a, const CBlockTemplateEntry &b)
                      -> bool { return a.tx->GetId() < b.tx->GetId(); });
    }

    int64_t nTime1 = GetTimeMicros();

    nLastBlockTx = nBlockTx;
    nLastBlockSize = nBlockSize;

    // Create coinbase transaction.
    CMutableTransaction coinbaseTx;
    coinbaseTx.vin.resize(1);
    coinbaseTx.vin[0].prevout = COutPoint();
    coinbaseTx.vout.resize(1);
    coinbaseTx.vout[0].scriptPubKey = scriptPubKeyIn;
    coinbaseTx.vout[0].nValue =
        nFees + GetBlockSubsidy(nHeight, chainparams.GetConsensus());
    coinbaseTx.vin[0].scriptSig = CScript() << nHeight << OP_0;

    // Make sure the coinbase is big enough.
    uint64_t coinbaseSize =
        ::GetSerializeSize(coinbaseTx, SER_NETWORK, PROTOCOL_VERSION);
    if (coinbaseSize < MIN_TX_SIZE) {
        coinbaseTx.vin[0].scriptSig
            << std::vector<uint8_t>(MIN_TX_SIZE - coinbaseSize - 1);
    }

    pblocktemplate->entries[0].tx = MakeTransactionRef(coinbaseTx);
    // Note: For the Coinbase, the template entry fields aside from the `tx` are
    // not used anywhere at the time of writing.  The mining rpc throws out the
    // entire transaction in fact. The tx itself is only used during regtest
    // mode.
    pblocktemplate->entries[0].txFee = -1 * nFees;

    uint64_t nSerializeSize =
        GetSerializeSize(*pblock, SER_NETWORK, PROTOCOL_VERSION);

    LogPrintf("CreateNewBlock(): total size: %u txs: %u fees: %ld sigops %d\n",
              nSerializeSize, nBlockTx, nFees, nBlockSigOps);

    // Fill in header.
    pblock->hashPrevBlock = pindexPrev->GetBlockHash();
    UpdateTime(pblock, chainparams.GetConsensus(), pindexPrev);
    pblock->nBits =
        GetNextWorkRequired(pindexPrev, pblock, chainparams.GetConsensus());
    pblock->nNonce = 0;
    pblocktemplate->entries[0].txSigOps = GetSigOpCountWithoutP2SH(
        *pblocktemplate->entries[0].tx, STANDARD_SCRIPT_VERIFY_FLAGS);

    // Copy all the transactions into the block
    // FIXME: This should be removed as it is significant overhead.
    // See T479
    for (const CBlockTemplateEntry &tx : pblocktemplate->entries) {
        pblock->vtx.push_back(tx.tx);
    }

    CValidationState state;
    if (!TestBlockValidity(state, chainparams, *pblock, pindexPrev,
                           BlockValidationOptions(nMaxGeneratedBlockSize)
                               .withCheckPoW(false)
                               .withCheckMerkleRoot(false))) {
        throw std::runtime_error(strprintf("%s: TestBlockValidity failed: %s",
                                           __func__,
                                           FormatStateMessage(state)));
    }
    int64_t nTime2 = GetTimeMicros();

    LogPrint(BCLog::BENCH,
             "CreateNewBlock() packages: %.2fms (%d packages, %d updated "
             "descendants), validity: %.2fms (total %.2fms)\n",
             0.001 * (nTime1 - nTimeStart), nPackagesSelected,
             nDescendantsUpdated, 0.001 * (nTime2 - nTime1),
             0.001 * (nTime2 - nTimeStart));

    return std::move(pblocktemplate);
}

bool BlockAssembler::isStillDependent(CTxMemPool::txiter iter) {
    for (CTxMemPool::txiter parent : mempool->GetMemPoolParents(iter)) {
        if (!inBlock.count(parent)) {
            return true;
        }
    }
    return false;
}

bool BlockAssembler::TestPackage(uint64_t packageSize,
                                 int64_t packageSigOps) const
{
    auto blockSizeWithPackage = nBlockSize + packageSize;
    if (blockSizeWithPackage >= nMaxGeneratedBlockSize) {
        return false;
    }

    if (nBlockSigOps + packageSigOps >=
        GetMaxBlockSigOpsCount(blockSizeWithPackage)) {
        return false;
    }

    return true;
}
bool BlockAssembler::TestPackageFinality(const CTxMemPool::setEntries &package)
{
    for (const CTxMemPool::txiter it : package)
    {
        if (!IsFinalTx(it->GetTx(), nHeight, nLockTimeCutoff))
            return false;
    }
    return true;
}

BlockAssembler::TestForBlockResult
BlockAssembler::TestForBlock(CTxMemPool::txiter it) {
    auto blockSizeWithTx =
        nBlockSize +
        ::GetSerializeSize(it->GetTx(), SER_NETWORK, PROTOCOL_VERSION);
    if (blockSizeWithTx >= nMaxGeneratedBlockSize) {
        if (nBlockSize > nMaxGeneratedBlockSize - 100 || lastFewTxs > 50) {
            return TestForBlockResult::BlockFinished;
        }

        if (nBlockSize > nMaxGeneratedBlockSize - 1000) {
            lastFewTxs++;
        }

        return TestForBlockResult::TXCantFit;
    }

    auto maxBlockSigOps = GetMaxBlockSigOpsCount(blockSizeWithTx);
    if (nBlockSigOps + it->GetSigOpCount() >= maxBlockSigOps) {
        // If the block has room for no more sig ops then flag that the block is
        // finished.
        // TODO: We should consider adding another transaction that isn't very
        // dense in sigops instead of bailing out so easily.
        if (nBlockSigOps > maxBlockSigOps - 2) {
            return TestForBlockResult::BlockFinished;
        }

        // Otherwise attempt to find another tx with fewer sigops to put in the
        // block.
        return TestForBlockResult::TXCantFit;
    }

    // Must check that lock times are still valid. This can be removed once MTP
    // is always enforced as long as reorgs keep the mempool consistent.
    CValidationState state;
    if (!ContextualCheckTransaction(chainparams.GetConsensus(), it->GetTx(),
                                    state, nHeight, nLockTimeCutoff,
                                    nMedianTimePast)) {
        return TestForBlockResult::TXCantFit;
    }

    return TestForBlockResult::TXFits;
}

void BlockAssembler::AddToBlock(CTxMemPool::txiter iter) {
    pblocktemplate->entries.emplace_back(iter->GetSharedTx(), iter->GetFee(),
                                         iter->GetTxSize(),
                                         iter->GetSigOpCount());
    nBlockSize += iter->GetTxSize();
    ++nBlockTx;
    nBlockSigOps += iter->GetSigOpCount();
    nFees += iter->GetFee();
    inBlock.insert(iter);

    bool fPrintPriority =
        gArgs.GetBoolArg("-printpriority", DEFAULT_PRINTPRIORITY);
    if (fPrintPriority) {
        double dPriority = iter->GetPriority(nHeight);
        Amount dummy;
        mempool->ApplyDeltas(iter->GetTx().GetId(), dPriority, dummy);
        LogPrintf(
            "priority %.1f fee %s txid %s\n", dPriority,
            CFeeRate(iter->GetModifiedFee(), iter->GetTxSize()).ToString(),
            iter->GetTx().GetId().ToString());
    }
}

void BlockAssembler::SortForBlock(
    const CTxMemPool::setEntries &package,
    std::vector<CTxMemPool::txiter> &sortedEntries) {
    // Sort package by ancestor count. If a transaction A depends on transaction
    // B, then A's ancestor count must be greater than B's. So this is
    // sufficient to validly order the transactions for block inclusion.
    sortedEntries.clear();
    sortedEntries.insert(sortedEntries.begin(), package.begin(), package.end());
    std::sort(sortedEntries.begin(), sortedEntries.end(),
              CompareTxIterByAncestorCount());
}

// This transaction selection algorithm orders the mempool based
// on feerate of a transaction including all unconfirmed ancestors.
//
// This is accomplished by considering a group of ancestors as a single transaction. We can call these
// transations, Ancestor Grouped Transactions (AGT). This approach to grouping allows us to process
// packages orders of magnitude faster than other methods of package mining since we no longer have
// to continuously update the descendant state as we mine part of an unconfirmed chain.
//
// There is a theorical flaw in this approach which could happen when a block is almost full. We
// could for instance end up including a lower fee transaction as part of an ancestor group when
// in fact it would be better, in terms of fees, to include some other single transaction. This
// would result in slightly less fees (perhaps a few hundred satoshis) rewarded to the miner. However,
// this situation is not likely to be seen for two reasons. One, long unconfirmed chains are typically
// having transactions with all the same fees and Two, the typical child pays for parent scenario has only
// two transactions with the child having the higher fee. And neither of these two types of packages could
// cause any loss of fees with this mining algorithm, when the block is nearly full.
//
// The mining algorithm is surprisingly simple and centers around parsing though the mempools ancestor_score
// index and adding the AGT's into the new block. There is however a pathological case which has to be
// accounted for where a child transaction has less fees per KB than its parent which causes child transactions
// to show up later as we parse though the ancestor index. In this case we then have to recalculate the
// ancestor sigops and package size which can be time consuming given we have to parse through the ancestor
// tree each time. However we get around that by shortcutting the process by parsing through only the portion
// of the tree that is currently not in the block. This shortcutting happens in _CalculateMempoolAncestors()
// where we pass in the inBlock vector of already added transactions. Even so, if we didn't do this shortcutting
// the current algo is still much better than the older method which needed to update calculations for the
// entire descendant tree after each package was added to the block.
void BlockAssembler::addPackageTxs(int &nPackagesSelected,
                                   int &nDescendantsUpdated)
{
    CTxMemPool::indexed_transaction_set::index<ancestor_score>::type::iterator mi =
        g_mempool.mapTx.get<ancestor_score>().begin();
    CTxMemPool::txiter iter;

    uint64_t nPackageFailures = 0;
    while (mi != g_mempool.mapTx.get<ancestor_score>().end())
    {
        iter = g_mempool.mapTx.project<0>(mi);
        ++mi;

        uint64_t packageSize = iter->GetSizeWithAncestors();
        Amount packageFees = iter->GetModFeesWithAncestors();
        unsigned int packageSigOps = iter->GetSigOpCountWithAncestors();

        // Skip txns we know are in the block
        if (inBlock.count(iter))
        {
            continue;
        }

        // Get any unconfirmed ancestors of this txn
        CTxMemPool::setEntries ancestors;
        uint64_t nNoLimit = std::numeric_limits<uint64_t>::max();
        std::string dummy;
        g_mempool.CalculateMemPoolAncestors(
            *iter, ancestors, nNoLimit, nNoLimit, nNoLimit, nNoLimit, dummy, &inBlock, false);

        // Include in the package the current txn we're working with
        ancestors.insert(iter);

        // Recalculate sigops and package size, only if there were txns already in the block for
        // this set of ancestors
        if (iter->GetCountWithAncestors() > ancestors.size())
        {
            packageSize = 0;
            packageSigOps = 0;
            for (auto &it : ancestors)
            {
                packageSize += it->GetTxSize();
                packageSigOps += it->GetSigOpCount();
            }
        }

        static uint64_t nBlockPrioritySize = nMaxGeneratedBlockSize * nBlockPriorityPercentage / 100;
        if (packageFees <  blockMinFeeRate.GetFee(packageSize) && nBlockSize >= nBlockPrioritySize)
        {
            // Everything else we might consider has a lower fee rate so no need to continue
            return;
        }

        // Test if package fits in the block
        if (!TestPackage(packageSize, packageSigOps))
        {
            if (nBlockSize > nMaxGeneratedBlockSize * .50)
            {
                nPackageFailures++;
            }

            // If we keep failing then the block must be almost full so bail out here.
            if (nPackageFailures >= 5)
                return;
            else
                continue;
        }

        // Test if all tx's are Final
        if (!TestPackageFinality(ancestors))
        {
            continue;
        }

        // Package can be added.
        for (auto &it : ancestors)
        {
            AddToBlock(it);
        }
    }
}

void BlockAssembler::addPriorityTxs() {
    // How much of the block should be dedicated to high-priority transactions,
    // included regardless of the fees they pay.
    if (nBlockPriorityPercentage == 0) {
        return;
    }

    uint64_t nBlockPrioritySize =
        nMaxGeneratedBlockSize * nBlockPriorityPercentage / 100;

    // This vector will be sorted into a priority queue:
    std::vector<TxCoinAgePriority> vecPriority;
    TxCoinAgePriorityCompare pricomparer;
    std::map<CTxMemPool::txiter, double, CTxMemPool::CompareIteratorByHash>
        waitPriMap;
    typedef std::map<CTxMemPool::txiter, double,
                     CTxMemPool::CompareIteratorByHash>::iterator waitPriIter;
    double actualPriority = -1;

    vecPriority.reserve(mempool->mapTx.size());
    for (CTxMemPool::indexed_transaction_set::iterator mi =
             mempool->mapTx.begin();
         mi != mempool->mapTx.end(); ++mi) {
        double dPriority = mi->GetPriority(nHeight);
        Amount dummy;
        mempool->ApplyDeltas(mi->GetTx().GetId(), dPriority, dummy);
        vecPriority.push_back(TxCoinAgePriority(dPriority, mi));
    }
    std::make_heap(vecPriority.begin(), vecPriority.end(), pricomparer);

    CTxMemPool::txiter iter;

    // Add a tx from priority queue to fill the part of block reserved to
    // priority transactions.
    while (!vecPriority.empty()) {
        iter = vecPriority.front().second;
        actualPriority = vecPriority.front().first;
        std::pop_heap(vecPriority.begin(), vecPriority.end(), pricomparer);
        vecPriority.pop_back();

        // If tx already in block, skip.
        if (inBlock.count(iter)) {
            // Shouldn't happen for priority txs.
            assert(false);
            continue;
        }

        // If tx is dependent on other mempool txs which haven't yet been
        // included then put it in the waitSet.
        if (isStillDependent(iter)) {
            waitPriMap.insert(std::make_pair(iter, actualPriority));
            continue;
        }

        TestForBlockResult testResult = TestForBlock(iter);
        // Break if the block is completed
        if (testResult == TestForBlockResult::BlockFinished) {
            break;
        }

        // If this tx does not fit in the block, skip to next transaction.
        if (testResult != TestForBlockResult::TXFits) {
            continue;
        }

        AddToBlock(iter);

        // If now that this txs is added we've surpassed our desired priority
        // size, then we're done adding priority transactions.
        if (nBlockSize >= nBlockPrioritySize) {
            break;
        }

        // if we have dropped below the AllowFreeThreshold, then we're done
        // adding priority transactions.
        if (!AllowFree(actualPriority)) {
            break;
        }

        // This tx was successfully added, so add transactions that depend
        // on this one to the priority queue to try again.
        for (CTxMemPool::txiter child : mempool->GetMemPoolChildren(iter)) {
            waitPriIter wpiter = waitPriMap.find(child);
            if (wpiter == waitPriMap.end()) {
                continue;
            }

            vecPriority.push_back(TxCoinAgePriority(wpiter->second, child));
            std::push_heap(vecPriority.begin(), vecPriority.end(), pricomparer);
            waitPriMap.erase(wpiter);
        }
    }
}

static const std::vector<uint8_t>
getExcessiveBlockSizeSig(uint64_t nExcessiveBlockSize) {
    std::string cbmsg = "/EB" + getSubVersionEB(nExcessiveBlockSize) + "/";
    std::vector<uint8_t> vec(cbmsg.begin(), cbmsg.end());
    return vec;
}

void IncrementExtraNonce(CBlock *pblock, const CBlockIndex *pindexPrev,
                         uint64_t nExcessiveBlockSize,
                         unsigned int &nExtraNonce) {
    // Update nExtraNonce
    static uint256 hashPrevBlock;
    if (hashPrevBlock != pblock->hashPrevBlock) {
        nExtraNonce = 0;
        hashPrevBlock = pblock->hashPrevBlock;
    }

    ++nExtraNonce;
    // Height first in coinbase required for block.version=2
    unsigned int nHeight = pindexPrev->nHeight + 1;
    CMutableTransaction txCoinbase(*pblock->vtx[0]);
    txCoinbase.vin[0].scriptSig =
        (CScript() << nHeight << CScriptNum(nExtraNonce)
                   << getExcessiveBlockSizeSig(nExcessiveBlockSize)) +
        COINBASE_FLAGS;

    // Make sure the coinbase is big enough.
    uint64_t coinbaseSize =
        ::GetSerializeSize(txCoinbase, SER_NETWORK, PROTOCOL_VERSION);
    if (coinbaseSize < MIN_TX_SIZE) {
        txCoinbase.vin[0].scriptSig
            << std::vector<uint8_t>(MIN_TX_SIZE - coinbaseSize - 1);
    }

    assert(txCoinbase.vin[0].scriptSig.size() <= MAX_COINBASE_SCRIPTSIG_SIZE);
    assert(::GetSerializeSize(txCoinbase, SER_NETWORK, PROTOCOL_VERSION) >=
           MIN_TX_SIZE);

    pblock->vtx[0] = MakeTransactionRef(std::move(txCoinbase));
    pblock->hashMerkleRoot = BlockMerkleRoot(*pblock);
}
