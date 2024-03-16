// Aleth: Ethereum C++ client, tools and libraries.
// Copyright 2014-2019 Aleth Authors.
// Licensed under the GNU General Public License, Version 3.

#include "node/Singleton.h"
#include "HyperChain/HyperChainSpace.h"

#include "BlockQueue.h"
#include <thread>
#include <sstream>
#include <libdevcore/Log.h>
#include <libethcore/Exceptions.h>
#include <libethcore/BlockHeader.h>
#include "BlockChain.h"
#include "VerifiedBlock.h"
#include "State.h"

#include "util/threadname.h"

using namespace std;
using namespace dev;
using namespace dev::eth;

constexpr size_t c_maxKnownCount = 2000; // 100000;
constexpr size_t c_maxKnownSize = 128 * 1024 * 1024;
constexpr size_t c_maxUnknownCount = 100000;
constexpr size_t c_maxUnknownSize = 512 * 1024 * 1024;  // Block size can be ~50kb

extern std::string currentTimeStr();

BlockQueue::BlockQueue()
{
    // Allow some room for other activity
    unsigned verifierThreads = std::max(thread::hardware_concurrency(), 3U) - 2U;
    for (unsigned i = 0; i < verifierThreads; ++i)
        m_verifiers.emplace_back([=](){
            string name = "verifier" + toString(i);
            setThreadName(name);
            hc::SetThreadName(-1, name.c_str());
            this->verifierBody();
        });
}

BlockQueue::~BlockQueue()
{
    stop();
}

void BlockQueue::stop()
{
    DEV_GUARDED(m_verification)
        m_deleting = true;

    m_moreToVerify.notify_all();
    for (auto& i: m_verifiers)
        i.join();
    m_verifiers.clear();
}

void BlockQueue::clear()
{
    WriteGuard l(m_lock);
    DEV_INVARIANT_CHECK;
    Guard l2(m_verification);

    //if (m_verified.size() > 0 || m_unverified.size() > 0) {
    //    cwarn << "BlockQueue clear(): "
    //        << " verified:" << m_verified.size()
    //        << " readySet:" << m_readySet.size()
    //        << " unverified:" << m_unverified.size()
    //        << " verifying:" << m_verifying.size();
    //}

    m_readySet.clear();
    m_drainingSet.clear();
    m_verified.clear();
    m_unverified.clear();
    m_verifying.clear();
    m_unknownSet.clear();
    m_unknown.clear();
    m_future.clear();
    m_futureSet.clear();
    m_difficulty = 0;
    m_drainingDifficulty = 0;
}

void BlockQueue::verifierBody()
{
    while (!m_deleting)
    {
        UnverifiedBlock work;

        {
            unique_lock<Mutex> l(m_verification);
            m_moreToVerify.wait(l, [&](){ return !m_unverified.isEmpty() || m_deleting; });
            if (m_deleting)
                return;
            work = m_unverified.dequeue();

            BlockHeader bi;
            bi.setSha3Uncles(work.hash);
            bi.setParentHash(work.parentHash);
            m_verifying.enqueue(move(bi));
        }

        auto fnexcep = [this, &work](Exception const& _ex, bool invalidh) {

            // bad block.
            // has to be this order as that's how invariants() assumes.
            WriteGuard l2(m_lock);
            m_knownBad.insert(work.hash);
            updateBad_WITH_LOCK(work.hash);

            //HC: bad block due to invalid hyper block, which is temporary 
            if (invalidh) {
                auto hid = boost::get_error_info<errinfo_hID>(_ex);
                if(hid)
                    m_knownBadInvalidHBlock.insert(*hid);
            }

            //cerr << std::this_thread::get_id() << ": Unexpected exception when verifying block: " << _ex.what()
            //    << " ********, remove from verifying" << endl;
        };

        VerifiedBlock res;
        swap(work.blockData, res.blockData);
        try {
            res.verified = m_bc->verifyBlock(&res.blockData, m_onBad, ImportRequirements::OutOfOrderChecks);

            //HCE: Remove the element from m_knownBad which has verified in the past
            if (m_knownBad.count(res.verified.info.hash())) {
                m_knownBad.erase(res.verified.info.hash());
            }
        }
        catch (InvalidHyperBlock const& _ex) {
            fnexcep(_ex, true);
            continue;
        }
        catch (Exception const& _ex) {
            fnexcep(_ex, false);
            continue;
        }

        bool ready = false;
        {
            WriteGuard l2(m_lock);
            unique_lock<Mutex> l(m_verification);
            if (!m_verifying.isEmpty() && m_verifying.nextHash() == work.hash)
            {
                // we're next!
                m_verifying.dequeue();
                if (m_knownBad.count(res.verified.info.parentHash()))
                {
                    m_readySet.erase(res.verified.info.hash());
                    m_knownBad.insert(res.verified.info.hash());
                }
                else
                    m_verified.enqueue(move(res));

                //cout << std::this_thread::get_id() << " " << currentTimeStr() << " BlockQueue will be ready, block height is " << res.verified.info.number()
                //    << " hash:" << res.verified.info.hash()
                //    << " prevHID:" << res.verified.info.prevHID()
                //    << " prevHHash:" << res.verified.info.prevHyperBlkHash()
                //    << endl;
                drainVerified_WITH_BOTH_LOCKS();
                ready = true;
            }
            else
            {
               if (!m_verifying.replace(work.hash, move(res)))
                    cwarn << "BlockQueue missing our job: was there a GM?";
                //cerr << std::this_thread::get_id() << " " << currentTimeStr() << " BlockQueue missing our job, ready is false, block height is "
                //    << res.verified.info.number() 
                //    << " hash:" << res.verified.info.hash()
                //    << endl;
            }
        }
        if (ready)
            m_onReady();
    }
}

void BlockQueue::onLatestHyperBlockChanged(uint32_t hid, const h256& hhash)
{
    LOG(m_logger) << "onLatestHyperBlockChanged " << hid << " hyper block reached";

    WriteGuard l2(m_lock);

    //HC: 新超块到达，部分无效块变成有效，这里简单处理，清空所有的无效块
    if (m_knownBadInvalidHBlock.count(hid)) {
        m_knownBadInvalidHBlock.erase(hid);
        m_knownBad.clear();
    }
}


void BlockQueue::drainVerified_WITH_BOTH_LOCKS()
{
    while (!m_verifying.isEmpty() && !m_verifying.next().blockData.empty())
    {
        VerifiedBlock block = m_verifying.dequeue();
        if (m_knownBad.count(block.verified.info.parentHash()))
        {
            m_readySet.erase(block.verified.info.hash());
            m_knownBad.insert(block.verified.info.hash());
        }
        else
            m_verified.enqueue(move(block));
    }
}

ImportResult BlockQueue::import(bytesConstRef _block, bool _isOurs)
{
    // Check if we already know this block.
    h256 h = BlockHeader::headerHashFromBlock(_block);

    LOG(m_loggerDetail) << "Queuing block " << h.hex() << " for import...";

    UpgradableGuard l(m_lock);

    if (contains(m_readySet, h) || contains(m_drainingSet, h) || contains(m_unknownSet, h) ||
        contains(m_knownBad, h) || contains(m_futureSet, h))
    {
        // Already know about this one.
        LOG(m_loggerDetail) << "Already known. Is it in m_knownBad? " << contains(m_knownBad, h);
        return ImportResult::AlreadyKnown;
    }

    BlockHeader bi;
    try
    {
        // TODO: quick verification of seal - will require BlockQueue to be templated on SealEngine
        // VERIFY: populates from the block and checks the block is internally coherent.
        bi = m_bc->verifyBlock(_block, m_onBad, ImportRequirements::PostGenesis).info;
    }
    catch (Exception const& _e)
    {
        cwarn << "Ignoring malformed block: " << diagnostic_information(_e);
        return ImportResult::Malformed;
    }

    LOG(m_loggerDetail) << "Block " << h << " is " << bi.number() << " parent is " << bi.parentHash();

    // Check block doesn't already exist first!
    if (m_bc->isKnown(h))
    {
        LOG(m_logger) << "Already known in chain.";
        return ImportResult::AlreadyInChain;
    }

    UpgradeGuard ul(l);
    DEV_INVARIANT_CHECK;

    // Check it's not in the future
    if (bi.timestamp() > utcTime() && !_isOurs)
    {
        m_future.insert(static_cast<time_t>(bi.timestamp()), h, _block.toBytes());
        m_futureSet.insert(h);
        char buf[24];
        time_t bit = static_cast<time_t>(bi.timestamp());
        if (strftime(buf, 24, "%X", localtime(&bit)) == 0)
            buf[0] = '\0'; // empty if case strftime fails
        LOG(m_loggerDetail) << "OK - queued for future [" << bi.timestamp() << " vs " << utcTime()
                         << "] - will wait until " << buf;
        m_difficulty += bi.difficulty();
        h256 const parentHash = bi.parentHash();
        bool const unknown = !contains(m_readySet, parentHash) &&
                             !contains(m_drainingSet, parentHash) &&
                             !contains(m_futureSet, parentHash) && !m_bc->isKnown(parentHash);
        return unknown ? ImportResult::FutureTimeUnknown : ImportResult::FutureTimeKnown;
    }
    else
    {
        // We now know it.
        if (m_knownBad.count(bi.parentHash()))
        {
            m_knownBad.insert(bi.hash());
            updateBad_WITH_LOCK(bi.hash());
            // bad parent; this is bad too, note it as such
            return ImportResult::BadChain;
        }
        else if (!m_readySet.count(bi.parentHash()) && !m_drainingSet.count(bi.parentHash()) && !m_bc->isKnown(bi.parentHash()))
        {
            // We don't know the parent (yet) - queue it up for later. It'll get resent to us if we find out about its ancestry later on.
            LOG(m_loggerDetail) << "OK - queued as unknown parent: " << bi.parentHash();
            m_unknown.insert(bi.parentHash(), h, _block.toBytes());
            m_unknownSet.insert(h);
            m_difficulty += bi.difficulty();

            return ImportResult::UnknownParent;
        }
        else
        {
            // If valid, append to blocks.
            LOG(m_loggerDetail) << "OK - ready for chain insertion.";
            DEV_GUARDED(m_verification)
                m_unverified.enqueue(UnverifiedBlock { h, bi.parentHash(), _block.toBytes() });
            m_moreToVerify.notify_one();
            m_readySet.insert(h);
            m_difficulty += bi.difficulty();

            noteReady_WITH_LOCK(h);

            return ImportResult::Success;
        }
    }
}

void BlockQueue::updateBad_WITH_LOCK(h256 const& _bad)
{
    DEV_INVARIANT_CHECK;
    DEV_GUARDED(m_verification)
    {
        collectUnknownBad_WITH_BOTH_LOCKS(_bad);
        bool moreBad = true;
        while (moreBad)
        {
            moreBad = false;
            std::vector<VerifiedBlock> badVerified = m_verified.removeIf([this](VerifiedBlock const& _b) -> bool
            {
                return m_knownBad.count(_b.verified.info.parentHash()) || m_knownBad.count(_b.verified.info.hash());
                //bool b1 = m_knownBad.count(_b.verified.info.parentHash());
                //bool b2 = m_knownBad.count(_b.verified.info.hash());
                //if(b1)
                //    cout << "removeIf badVerified parentHash:" << _b.verified.info.parentHash() 
                //    << " hash:" << _b.verified.info.hash() << " number:" << _b.verified.info.number()
                //    << endl;
                //if(b2)
                //    cout << "removeIf badVerified:" << _b.verified.info.hash() << " number:" << _b.verified.info.number()
                //        << endl;
                //return b1 || b2;
            });

            for (auto& b : badVerified)
            {
                if (!m_knownBad.count(b.verified.info.hash())) {
                    //cout << "m_knownBad haven't:" << b.verified.info.hash() << " number:" << b.verified.info.number()
                    //    << endl;
                }
                m_knownBad.insert(b.verified.info.hash());
                m_readySet.erase(b.verified.info.hash());
                collectUnknownBad_WITH_BOTH_LOCKS(b.verified.info.hash());
                //cout << "removed badVerified:" << b.verified.info.hash() << " number:" << b.verified.info.number()
                //    << endl;
                moreBad = true;
            }

            std::vector<UnverifiedBlock> badUnverified = m_unverified.removeIf([this](UnverifiedBlock const& _b)
            {
                return m_knownBad.count(_b.parentHash) || m_knownBad.count(_b.hash);
            });
            for (auto& b: badUnverified)
            {
                m_knownBad.insert(b.hash);
                m_readySet.erase(b.hash);
                collectUnknownBad_WITH_BOTH_LOCKS(b.hash);
                //cout << "removed badUnverified:" << b.hash << endl;
                moreBad = true;
            }

            std::vector<VerifiedBlock> badVerifying = m_verifying.removeIf([this](VerifiedBlock const& _b)
            {
                return m_knownBad.count(_b.verified.info.parentHash()) || m_knownBad.count(_b.verified.info.sha3Uncles());
            });

            for (auto& b: badVerifying)
            {
                h256 const& h = b.blockData.size() != 0 ? b.verified.info.hash() : b.verified.info.sha3Uncles();
                m_knownBad.insert(h);
                m_readySet.erase(h);
                collectUnknownBad_WITH_BOTH_LOCKS(h);
                //cout << "removed badVerifying:" << h << endl;
                moreBad = true;
            }

            //std::stringstream s;
            //s << "updateBad_WITH_LOCK internal:  m_knownBad: " << m_knownBad.size()
            //    << " badVerified: " << badVerified.size() << " moreBad:" << moreBad 
            //    << " " << m_readySet.size()
            //    << " " << m_verified.count() << " " << m_verified.size()
            //    << " " << m_verifying.count()
            //    << " " << m_unverified.count()
            //    << endl << endl;
            //cout << s.str();
        }
    }
}

void BlockQueue::collectUnknownBad_WITH_BOTH_LOCKS(h256 const& _bad)
{
    list<h256> badQueue(1, _bad);
    while (!badQueue.empty())
    {
        vector<pair<h256, bytes>> const removed = m_unknown.removeByKeyEqual(badQueue.front());
        badQueue.pop_front();
        for (auto& newBad: removed)
        {
            m_unknownSet.erase(newBad.first);
            m_knownBad.insert(newBad.first);
            badQueue.push_back(newBad.first);
        }
    }
}

bool BlockQueue::doneDrain(h256s const& _bad)
{
    WriteGuard l(m_lock);
    DEV_INVARIANT_CHECK;
    m_drainingSet.clear();
    m_difficulty -= m_drainingDifficulty;
    m_drainingDifficulty = 0;
    if (_bad.size())
    {
        // at least one of them was bad.
        //m_knownBad += _bad;
        //cout << "bad size:" << _bad.size() << endl;

        for (h256 const& b : _bad) {

            //std::stringstream s;
            //s << "updateBad_WITH_LOCK: BlockQueue invariant: m_readySet: " << m_readySet.size()
            //    << " m_verified: " << m_verified.count() << " m_unverified: " << m_unverified.count() << " m_verifying: " << m_verifying.count()
            //    << endl;
            //cout << s.str();

            updateBad_WITH_LOCK(b);
            //cout << std::this_thread::get_id() << " " << "updateBad_WITH_LOCK: " << b << " ***************" << endl;
        }
    }
    return !m_readySet.empty();
}

void BlockQueue::tick()
{
    vector<pair<h256, bytes>> todo;
    {
        UpgradableGuard l(m_lock);
        if (m_future.isEmpty())
            return;

        LOG(m_logger) << "Checking past-future blocks...";

        time_t t = utcTime();
        if (t < m_future.firstKey())
            return;

        LOG(m_logger) << "Past-future blocks ready.";

        {
            UpgradeGuard l2(l);
            DEV_INVARIANT_CHECK;
            todo = m_future.removeByKeyNotGreater(t);
            for (auto const& hash : todo)
                m_futureSet.erase(hash.first);
        }
    }
    LOG(m_logger) << "Importing " << todo.size() << " past-future blocks.";

    for (auto const& b: todo)
        import(&b.second);
}

BlockQueueStatus BlockQueue::status() const
{
    ReadGuard l(m_lock);
    Guard l2(m_verification);
    return BlockQueueStatus{ m_drainingSet.size(), m_verified.count(), m_verifying.count(), m_unverified.count(),
        m_future.count(), m_unknown.count(), m_knownBad.size() };
}

BlockQueueStatus BlockQueue::status(size_t& readySet) const
{
    ReadGuard l(m_lock);
    Guard l2(m_verification);
    readySet = m_readySet.size();
    return BlockQueueStatus{ m_drainingSet.size(), m_verified.count(), m_verifying.count(), m_unverified.count(),
        m_future.count(), m_unknown.count(), m_knownBad.size() };
}



QueueStatus BlockQueue::blockStatus(h256 const& _h) const
{
    ReadGuard l(m_lock);
    return
        m_readySet.count(_h) ?
            QueueStatus::Ready :
        m_drainingSet.count(_h) ?
            QueueStatus::Importing :
        m_unknownSet.count(_h) ?
            QueueStatus::UnknownParent :
        m_knownBad.count(_h) ?
            QueueStatus::Bad :
            QueueStatus::Unknown;
}

bool BlockQueue::knownFull() const
{
    Guard l(m_verification);
    return knownSize() > c_maxKnownSize || knownCount() > c_maxKnownCount;
}

std::size_t BlockQueue::knownSize() const
{
    return m_verified.size() + m_unverified.size() + m_verifying.size();
}

std::size_t BlockQueue::knownCount() const
{
    return m_verified.count() + m_unverified.count() + m_verifying.count();
}

bool BlockQueue::unknownFull() const
{
    ReadGuard l(m_lock);
    return unknownSize() > c_maxUnknownSize || unknownCount() > c_maxUnknownCount;
}

std::size_t BlockQueue::unknownSize() const
{
    return m_future.size() + m_unknown.size();
}

std::size_t BlockQueue::unknownCount() const
{
    return m_future.count() + m_unknown.count();
}

void BlockQueue::drain(VerifiedBlocks& o_out, unsigned _max)
{
    DEV_WRITE_GUARDED(m_lock)
    {
        DEV_INVARIANT_CHECK;
        if (m_drainingSet.empty())
        {
            m_drainingDifficulty = 0;
            DEV_GUARDED(m_verification)
                o_out = m_verified.dequeueMultiple(min<unsigned>(_max, m_verified.count()));

            for (auto const& bs: o_out)
            {
                // TODO: @optimise use map<h256, bytes> rather than vector<bytes> & set<h256>.
                auto h = bs.verified.info.hash();
                m_drainingSet.insert(h);
                m_drainingDifficulty += bs.verified.info.difficulty();
                m_readySet.erase(h);
            }
        }
    }
    m_onBlocksDrained();
}

bool BlockQueue::invariants() const
{
    Guard l(m_verification);
    if (m_readySet.size() != knownCount())
    {
        std::stringstream s;
        s << "Failed BlockQueue invariant: m_readySet: " << m_readySet.size() << " m_verified: " << m_verified.count() << " m_unverified: " << m_unverified.count() << " m_verifying" << m_verifying.count();
        BOOST_THROW_EXCEPTION(FailedInvariant() << errinfo_comment(s.str()));
    }
    //else {
    //    std::stringstream s;
    //    s << "BlockQueue invariant: m_readySet: " << m_readySet.size() << " m_verified: " << m_verified.count() << " m_unverified: " << m_unverified.count() << " m_verifying" << m_verifying.count();
    //    cout << s.str() << endl;
    //}
    return true;
}

void BlockQueue::noteReady_WITH_LOCK(h256 const& _good)
{
    DEV_INVARIANT_CHECK;
    list<h256> goodQueue(1, _good);
    bool notify = false;
    while (!goodQueue.empty())
    {
        h256 const parent = goodQueue.front();
        vector<pair<h256, bytes>> const removed = m_unknown.removeByKeyEqual(parent);
        goodQueue.pop_front();
        for (auto& newReady: removed)
        {
            DEV_GUARDED(m_verification)
                m_unverified.enqueue(UnverifiedBlock { newReady.first, parent, move(newReady.second) });
            m_unknownSet.erase(newReady.first);
            m_readySet.insert(newReady.first);
            goodQueue.push_back(newReady.first);
            notify = true;
        }
    }
    if (notify)
        m_moreToVerify.notify_all();
}

void BlockQueue::retryAllUnknown()
{
    WriteGuard l(m_lock);
    DEV_INVARIANT_CHECK;
    while (!m_unknown.isEmpty())
    {
        h256 parent = m_unknown.firstKey();
        vector<pair<h256, bytes>> removed = m_unknown.removeByKeyEqual(parent);
        for (auto& newReady: removed)
        {
            DEV_GUARDED(m_verification)
                m_unverified.enqueue(UnverifiedBlock{ newReady.first, parent, move(newReady.second) });
            m_unknownSet.erase(newReady.first);
            m_readySet.insert(newReady.first);
            m_moreToVerify.notify_one();
        }
    }
    m_moreToVerify.notify_all();
}

boost::log::formatting_ostream& dev::eth::operator<<(
    boost::log::formatting_ostream& _out, BlockQueueStatus const& _bqs)
{
    _out << "importing: " << _bqs.importing << endl;
    _out << "verified: " << _bqs.verified << endl;
    _out << "verifying: " << _bqs.verifying << endl;
    _out << "unverified: " << _bqs.unverified << endl;
    _out << "future: " << _bqs.future << endl;
    _out << "unknown: " << _bqs.unknown << endl;
    _out << "bad: " << _bqs.bad << endl;

    return _out;
}

u256 BlockQueue::difficulty() const
{
    UpgradableGuard l(m_lock);
    return m_difficulty;
}

bool BlockQueue::isActive() const
{
    UpgradableGuard l(m_lock);
    if (m_readySet.empty() && m_drainingSet.empty())
        DEV_GUARDED(m_verification)
            if (m_verified.isEmpty() && m_verifying.isEmpty() && m_unverified.isEmpty())
                return false;
    return true;
}

std::ostream& dev::eth::operator<< (std::ostream& os, QueueStatus const& obj)
{
   os << static_cast<std::underlying_type<QueueStatus>::type>(obj);
   return os;
}

std::ostream& dev::eth::operator<<(std::ostream& _out, BlockQueueStatus const& obj)
{
    _out << "BlockQueue importing: " << obj.importing << endl;
    _out << "verified: " << obj.verified << endl;
    _out << "verifying: " << obj.verifying << endl;
    _out << "unverified: " << obj.unverified << endl;
    _out << "future: " << obj.future << endl;
    _out << "unknown: " << obj.unknown << endl;
    _out << "bad: " << obj.bad << endl;
    return _out;
}

