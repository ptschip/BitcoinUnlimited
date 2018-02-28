// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2015 The Bitcoin Core developers
// Copyright (c) 2015-2018 The Bitcoin Unlimited developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "blockdb_leveldb.h"

#include "blockdb_sequential.h"
#include "chain.h"
#include "chainparams.h"
#include "hash.h"
#include "main.h"
#include "pow.h"
#include "ui_interface.h"
#include "uint256.h"
#include "validationinterface.h"

#include <stdint.h>

CFullBlockDB *pblockfull = NULL;


/**
  * Config param to determine what DB type we are using
  */
BlockDBMode DEFAULT_BLOCK_DB_MODE = LEVELDB_BLOCK_STORAGE;
BlockDBMode BLOCK_DB_MODE = DEFAULT_BLOCK_DB_MODE;


bool WriteBlockToDisk(const CBlock &block, CDiskBlockPos &pos, const CMessageHeader::MessageStartChars &messageStart)
{
    if(BLOCK_DB_MODE == SEQUENTIAL_BLOCK_FILES)
    {
        // Open history file to append
        CAutoFile fileout(OpenBlockFile(pos), SER_DISK, CLIENT_VERSION);
        if (fileout.IsNull())
            return error("WriteBlockToDisk: OpenBlockFile failed");

        // Write index header
        unsigned int nSize = GetSerializeSize(fileout, block);
        fileout << FLATDATA(messageStart) << nSize;

        // Write block
        long fileOutPos = ftell(fileout.Get());
        if (fileOutPos < 0)
            return error("WriteBlockToDisk: ftell failed");
        pos.nPos = (unsigned int)fileOutPos;
        fileout << block;
    }
    else if(BLOCK_DB_MODE == LEVELDB_BLOCK_STORAGE)
    {
        BlockDBValue value(block);
        return pblockfull->Write(block.GetHash(), value);
    }
    else if(BLOCK_DB_MODE == LEVELDB_AND_SEQUENTIAL)
    {
        // Open history file to append
        CAutoFile fileout(OpenBlockFile(pos), SER_DISK, CLIENT_VERSION);
        if (fileout.IsNull())
            return error("WriteBlockToDisk: OpenBlockFile failed");

        // Write index header
        unsigned int nSize = GetSerializeSize(fileout, block);
        fileout << FLATDATA(messageStart) << nSize;

        // Write block
        long fileOutPos = ftell(fileout.Get());
        if (fileOutPos < 0)
            return error("WriteBlockToDisk: ftell failed");
        pos.nPos = (unsigned int)fileOutPos;
        fileout << block;

        BlockDBValue value(block);
        return pblockfull->Write(block.GetHash(), value);
    }

    return true;
}

bool ReadBlockFromDisk(CBlock &block, const CDiskBlockPos &pos, const Consensus::Params &consensusParams)
{
    block.SetNull();
    // Open history file to read
    CAutoFile filein(OpenBlockFile(pos, true), SER_DISK, CLIENT_VERSION);
    if (filein.IsNull())
    {
        return error("ReadBlockFromDisk: OpenBlockFile failed for %s", pos.ToString());
    }

    // Read block
    try
    {
        filein >> block;
    }
    catch (const std::exception &e)
    {
        return error("%s: Deserialize or I/O error - %s at %s", __func__, e.what(), pos.ToString());
    }

    // Check the header
    if (!CheckProofOfWork(block.GetHash(), block.nBits, consensusParams))
    {
        return error("ReadBlockFromDisk: Errors in block header at %s", pos.ToString());
    }
    return true;
}

bool ReadBlockFromDisk(CBlock &block, const CBlockIndex *pindex, const Consensus::Params &consensusParams)
{
    if(BLOCK_DB_MODE == SEQUENTIAL_BLOCK_FILES)
    {
        if (!ReadBlockFromDisk(block, pindex->GetBlockPos(), consensusParams))
        {
            return false;
        }
        if (block.GetHash() != pindex->GetBlockHash())
        {
            return error("ReadBlockFromDisk(CBlock&, CBlockIndex*): GetHash() doesn't match index for %s at %s", pindex->ToString(), pindex->GetBlockPos().ToString());
        }
    }
    else if (BLOCK_DB_MODE == LEVELDB_BLOCK_STORAGE)
    {
        block.SetNull();
        BlockDBValue value;
        if(!pblockfull->ReadBlock(pindex->GetBlockHash(), value))
        {
            return false;
        }
        if(value.block.GetHash() != pindex->GetBlockHash())
        {
            return error("ReadBlockFromDisk(CBlock&, CBlockIndex*): GetHash() doesn't match index for %s at %s", pindex->ToString(), pindex->GetBlockPos().ToString());
        }
        block = value.block;
    }
    else if (BLOCK_DB_MODE == LEVELDB_AND_SEQUENTIAL)
    {
        /// run both to verify both databases match, we will only return
        if (!ReadBlockFromDisk(block, pindex->GetBlockPos(), consensusParams))
        {
            return false;
        }
        if (block.GetHash() != pindex->GetBlockHash())
        {
            return error("ReadBlockFromDisk(CBlock&, CBlockIndex*): GetHash() doesn't match index for %s at %s", pindex->ToString(), pindex->GetBlockPos().ToString());
        }
        BlockDBValue value;
        if(!pblockfull->ReadBlock(pindex->GetBlockHash(), value))
        {
            return false;
        }
        if(value.block.GetHash() != pindex->GetBlockHash())
        {
            return error("ReadBlockFromDisk(CBlock&, CBlockIndex*): GetHash() doesn't match index for %s at %s", pindex->ToString(), pindex->GetBlockPos().ToString());
        }
        if(block.GetHash() != value.block.GetHash())
        {
            return error("ReadBlockFromDisk(CBlock&, CBlockIndex*): GetHash() doesn't match for both database types. THERE IS A CRITICAL ERROR SOMEWHERE \n");
        }
    }
    return true;
}


CFullBlockDB::CFullBlockDB(size_t nCacheSize, bool fMemory, bool fWipe) : CDBWrapper(GetDataDir() / "blocks" / "blocks", nCacheSize, fMemory, fWipe)
{
}

// Writes a whole array of blocks, at some point a rename of this method should be considered
bool CFullBlockDB::WriteBatchSync(const std::vector<CBlock> &blocks)
{
    CDBBatch batch(*this);
    for (std::vector<CBlock>::const_iterator it = blocks.begin(); it != blocks.end(); it++)
    {
        batch.Write(it->GetHash(), BlockDBValue(*it));
    }
    return WriteBatch(batch, true);
}

// hash is key, value is {version, height, block}
bool CFullBlockDB::ReadBlock(const uint256 &hash, BlockDBValue &value)
{
    return Read(hash, value);
}

bool CFullBlockDB::WriteBlock(const uint256 &hash, const BlockDBValue &value)
{
    return Write(hash, value);
}

bool CFullBlockDB::EraseBlock(const uint256 &hash)
{
    return Erase(hash);
}
