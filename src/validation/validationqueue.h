// Copyright (c) 2012-2015 The Bitcoin Core developers
// Copyright (c) 2015-2018 The Bitcoin Unlimited developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
#ifndef BITCOIN_VALIDATIONQUEUE_H
#define BITCOIN_VALIDATIONQUEUE_H

#include "validation/validation.h"
#include <algorithm>
#include <atomic>
#include <vector>

#include <boost/thread/condition_variable.hpp>
#include <boost/thread/locks.hpp>
#include <boost/thread/mutex.hpp>

//void RunValidation(std::shared_ptr<CRunValidationThread> pData);
struct CRunValidationThread
{
    // Initialized here on construction but will be modified
    // and used locally only.
    std::shared_ptr<CCoinsViewCache> pView;
    CBlockIndex *pindex;
    const CBlock *block;
    CCheckQueueControl<CScriptCheck> *control_scriptchecks;
    boost::thread::id main_thread_id;
    uint32_t flags = 0;
    int nLockTimeFlags = 0;
    uint32_t nBeginIndex = 0;
    uint32_t nEndIndex = 0;
    bool fJustCheck = false;
    bool fParallel = true;
    bool fScriptChecks = true;
    bool fSuccess = true;

    // Return values
    std::shared_ptr<CBlockUndo> pBlockUndo;
    std::shared_ptr<ValidationResourceTracker> pResourceTracker;
    std::shared_ptr<CValidationState> pState;

    // These are set here and used locally but need
    // to be returned to the main thread to be summed.
    int nFees = 0;
    int nUnVerifiedChecked = 0;
    int nChecked = 0;
    unsigned int nInputs = 0;
};
bool RunValidation(std::shared_ptr<CRunValidationThread> pData, std::vector<int> &vIndex);

//template <typename T>
class CValidationQueueControl;

/**
 * Queue for verifications that have to be performed.
  * The verifications are represented by a type T, which must provide an
  * operator(), returning a bool.
  *
  * One thread (the master) is assumed to push batches of verifications
  * onto the queue, where they are processed by N-1 worker threads. When
  * the master is done adding work, it temporarily joins the worker pool
  * as an N'th worker, until all jobs are done.
  */
class CValidationQueue
{
private:
    //! Mutex to protect the inner state
    boost::mutex mutex;

    //! Worker threads block on this when out of work
    boost::condition_variable condWorker;

    //! Master thread blocks on this when out of work
    boost::condition_variable condMaster;

    //! The queue of elements to be processed.
    //! As the order of booleans doesn't matter, it is used as a LIFO (stack)
    std::vector<int> queue;

    //! The number of workers (including the master) that are idle.
    int nIdle;

    //! The total number of workers (including the master).
    int nTotal;

    //! The temporary evaluation result.
    bool fAllOk;

    /**
     * Number of verifications that haven't completed yet.
     * This includes elements that are no longer queued, but still in the
     * worker's own batches.
     */
    unsigned int nTodo;

    //! Whether we're shutting down this round of parallel validation
    std::atomic<bool> fQuit;

    //! Exit this thread
    std::atomic<bool> fExit;

    //! The maximum number of elements to be processed in one batch
    unsigned int nBatchSize;

    //! A shared point to data that is passed in and also used to return data to the main thread
    std::shared_ptr<CRunValidationThread> pData;
    uint32_t nBeginIndex;
    uint32_t nEndIndex;

    /** Internal function that does bulk of the verification work. */
    bool Loop(bool fMaster = false)
    {
        boost::condition_variable &cond = fMaster ? condMaster : condWorker;
        std::vector<int> vChecks;
        vChecks.reserve(nBatchSize);
        unsigned int nNow = 0;
        bool fOk = true;
        do
        {
            {
                boost::unique_lock<boost::mutex> lock(mutex);
                // first do the clean-up of the previous loop run (allowing us to do it in the same critsect)
                if (nNow)
                {
                    fAllOk &= fOk;
                    if (nTodo >= nNow)
                        nTodo -= nNow;
                    if (nTodo == 0 && !fMaster)
                    {
printf("notify master\n");
                        // We processed the last element; inform the master it can exit and return the result
                        queue.clear();
                        condMaster.notify_one();
                    }
                    if (fQuit && !fMaster)
                    {
                        nTodo -= queue.size();
                        queue.clear();
                        condMaster.notify_one();
                    }
                }
                else
                {
                    // first iteration
                    nTotal++;
                }
                // logically, the do loop starts here
                while (queue.empty())
                {
                    if (fExit)
                        return fAllOk;
                    if ((fMaster) && nTodo == 0)
                    {
                        if (fAllOk)
                        {
                          // Flush the view to the lower level
          //                 printf("flushing data %ld\n",pData->nChecked);
          //                 pData->pView->Flush();
                        }

                        nTotal--;
                        bool fRet = fAllOk;
                        // reset the status for new work later
                        if (fMaster)
                            fAllOk = true;
                        // return the current status
                        fQuit = false; // reset the flag before returning
                        return fRet;
                    }
                    nIdle++;
                    cond.wait(lock); // wait
                    nIdle--;
                }
                // Decide how many work units to process now.
                // * Do not try to do everything at once, but aim for increasingly smaller batches so
                //   all workers finish approximately simultaneously.
                // * Try to account for idle jobs which will instantly start helping.
                // * Don't do batches smaller than 1 (duh), or larger than nBatchSize.
                nNow = std::max(1U, std::min(nBatchSize, (unsigned int)queue.size() / (nTotal + nIdle + 1)));
nNow = 1;
                vChecks.resize(nNow);
printf("nNow is %d queue is %lu\n", nNow, queue.size());
                for (unsigned int i = 0; i < nNow; i++)
                {
                    // We want the lock on the mutex to be as short as possible, so swap jobs from the global
                    // queue to the local batch vector instead of copying.
                    vChecks.push_back(queue.back());
                    queue.pop_back();
                }


                // Check whether we need to do work at all
                fOk = fAllOk;
            }
            // execute work
            if (fOk)
            {
printf("running validation checks\n");
                fOk = RunValidation(pData, vChecks);
//fOk=true;
                vChecks.clear();
printf("done validation checks size of queue is %lu fOK is %d\n", queue.size(), fOk);
queue.clear();
nTodo = 0;
            }

        } while (true);
    }

public:
    //! Create a new check queue
    CValidationQueue(unsigned int nBatchSizeIn)
        : nIdle(0), nTotal(0), fAllOk(true), nTodo(0), fQuit(false), fExit(false), nBatchSize(nBatchSizeIn)
    {
    }

    //! Worker thread
    void Thread() { Loop(); }
    //! Wait until execution finishes, and return whether all evaluations were successful.
    bool Wait() { return Loop(true); }
    //! Quit execution of any remaining checks.
    void Quit(bool flag = true) { fQuit = flag; }
    //! All threads exit
    void Shutdown()
    {
        fExit = true;
        condWorker.notify_all();
        condMaster.notify_all();
    }
    //! Add a batch of checks to the queue
/*
    void Add(std::vector<T> &vChecks)
    {
        boost::unique_lock<boost::mutex> lock(mutex);
        for (T &check : vChecks)
        {
            queue.push_back(T());
            check.swap(queue.back());
        }
        nTodo += vChecks.size();
        if (vChecks.size() == 1)
            condWorker.notify_one();
        else if (vChecks.size() > 1)
            condWorker.notify_all();
    }
*/
    void SetValidationData(std::shared_ptr<CRunValidationThread> _pData)
    {
        boost::unique_lock<boost::mutex> lock(mutex);
        pData = _pData;

        for (size_t i = 0; i < pData->block->vtx.size(); i++)
        {
            queue.push_back(i);
        }

        nTodo += queue.size();
printf("ntodo %d\n", nTodo);
        if (nTodo == 1)
            condWorker.notify_one();
        else if (nTodo > 1)
            condWorker.notify_all();
    }

    void ClearThreadData() { pData.reset(); }

    ~CValidationQueue() {}
    bool IsIdle()
    {
        boost::unique_lock<boost::mutex> lock(mutex);
printf("ntotal %d nidle %d ntodo %d fallok %d\n", nTotal, nIdle, nTodo, fAllOk);
        return (nTotal == nIdle && nTodo == 0 && fAllOk == true);
    }
};

/**
 * RAII-style controller object for a CCheckQueue that guarantees the passed
 * queue is finished before continuing.
 */
//template <typename T>
class CValidationQueueControl
{
private:
    CValidationQueue *pqueue;
    bool fDone;

public:
    CValidationQueueControl() {}
    CValidationQueueControl(CValidationQueue *pqueueIn) : pqueue(pqueueIn), fDone(false)
    {
        // passed queue is supposed to be unused, or nullptr
        if (pqueue != nullptr)
        {
            bool isIdle = pqueue->IsIdle();
            assert(isIdle);
        }
    }

    void Queue(CValidationQueue *pqueueIn)
    {
        pqueue = pqueueIn;
        // passed queue is supposed to be unused, or nullptr
        if (pqueue != nullptr)
        {
            bool isIdle = pqueue->IsIdle();
            assert(isIdle);
            fDone = false;
        }
    }

    bool Wait()
    {
        if (fDone)
            return true;
        else if (pqueue == nullptr)
            return true;
        bool fRet = pqueue->Wait();
        fDone = true;
        return fRet;
    }
/*
    void Add(std::vector<T> &vChecks)
    {
        if (pqueue != nullptr)
            pqueue->Add(vChecks);
    }
*/

    ~CValidationQueueControl()
    {
        if (!fDone)
            Wait();
    }
};

#endif // BITCOIN_VALIDATIONQUEUE_H
