/*Copyright 2016-2024 hyperchain.net (Hyperchain)

Distributed under the MIT software license, see the accompanying
file COPYING or?https://opensource.org/licenses/MIT.

Permission is hereby granted, free of charge, to any person obtaining a copy of this?
software and associated documentation files (the "Software"), to deal in the Software
without restriction, including without limitation the rights to use, copy, modify, merge,
publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons
to whom the Software is furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all copies or
substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED,?
INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR
PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE
FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR
OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
DEALINGS IN THE SOFTWARE.
*/
#include "globalconfig.h"
#include "headers.h"
#include "plshared.h"
#include "dllmain.h"


extern bool ResolveBlock(CBlock& block, const char* payload, size_t payloadlen);

extern "C" BOOST_SYMBOL_EXPORT
bool GetParaBlockHash(const unsigned char* blockdata, int blockdatalen, unsigned char hash[32])
{
    CBlock block;
    if (ResolveBlock(block, (const char*)blockdata, blockdatalen)) {
        uint256 h = block.GetHash();
        memcpy(hash, h.begin(), 32);
        return true;
    }
    return false;
}

extern "C" BOOST_SYMBOL_EXPORT
int GetParaBlockHeader(const unsigned char* blockdata, int blockdatalen, unsigned char header[300])
{
    CBlock block;
    if (ResolveBlock(block, (const char*)blockdata, blockdatalen)) {

        CDataStream datastream(SER_BLOCKHEADERONLY);
        try {
            datastream << block;
            int len = datastream.size();
            datastream.read((char*)header, len);
            return len;
        }
        catch (const std::ios_base::failure& e) {
            //ERROR_FL("Error: Cannot extract block data, %s\n", e.what());
        }

    }
    return 0;
}

extern "C" BOOST_SYMBOL_EXPORT
bool GetParaBlockHashByHeader(const unsigned char* blockheaderdata, int blockheaderdatalen, unsigned char hash[32])
{
    CBlock block;

    CDataStream datastream((const char*)blockheaderdata, (const char*)blockheaderdata + blockheaderdatalen, SER_BLOCKHEADERONLY);
    try {
        datastream >> block;
        uint256 h = block.GetHash();
        memcpy(hash, h.begin(), 32);
    }
    catch (const std::ios_base::failure& e) {
        return ERROR_FL("Error: Cannot resolve block data, %s\n", e.what());
    }
    return true;
}

//The following codes might provide to light nodes in the future
//static bool isstopmining = false;
//
//typedef struct tagMiningSession {
//
//    enum class MS : char {
//        unknown,
//        opened,
//        mining,
//        closing,
//        closed,
//    };
//    MS status = MS::unknown;
////public:
////    tagMiningSession(bool isOpened) : opened(isOpened) {
////
////    }
//
//} MiningSession;
//
//static std::map<int, MiningSession> mapSession;
//static int nMaxSessionID = 0;
//static std::mutex mutx_mining;
//
//extern "C" BOOST_SYMBOL_EXPORT
//int LightNodeOpenMiningSession()
//{
//    std::lock_guard<std::mutex> guard(mutx_mining);
//    for (auto & sess : mapSession) {
//        if (sess.second.status == MiningSession::MS::closed) {
//            return sess.first;
//        }
//        //HCE: only one session can run at the same time, so close the other sessions
//        mapSession[sess.first].status = MiningSession::MS::closing;
//    }
//
//    nMaxSessionID = nMaxSessionID++;
//    int sessionid = nMaxSessionID;
//    mapSession.insert({ sessionid , MiningSession() });
//    mapSession[sessionid].status = MiningSession::MS::opened;
//    return sessionid;
//}
//
//extern "C" BOOST_SYMBOL_EXPORT
//void LightNodeCloseMiningSession(int sessionid)
//{
//    std::lock_guard<std::mutex> guard(mutx_mining);
//    if (mapSession.count(sessionid)) {
//        mapSession[sessionid].status = MiningSession::MS::closing;
//    }
//}
//
//
//extern "C" BOOST_SYMBOL_EXPORT
//bool LightNodeDoMining(int sessionid, int blockheight, int highnonce, int lownonce,
//    const unsigned char* pstrheaderhash,
//    const unsigned char* pstrtarget,
//    //bool (*CBFnStopMining)(void*),
//    //void* param,
//    int timeout,
//    unsigned char nonce[8], //HCE: if found, return mining result
//    unsigned char mixhash[32])
//{
//    std::unique_lock<std::mutex> uguard(mutx_mining);
//    if (!mapSession.count(sessionid)) {
//        uguard.unlock();
//        return false;
//    }
//
//    auto& session = mapSession[sessionid];
//
//    if (session.status != MiningSession::MS::opened) {
//        uguard.unlock();
//        return false; //HCE: firstly you should open the session by calling LightNodeOpenMiningSession
//    }
//    uguard.unlock();
//
//    session.status = MiningSession::MS::mining;
//
//    ethash::hash256 header_hash;
//    std::copy(BEGIN(pstrheaderhash), END(pstrheaderhash), header_hash.bytes);
//
//    ethash::hash256 target;
//    std::copy(BEGIN(pstrtarget), END(pstrtarget), target.bytes);
//
//    //isstopmining = false;
//
//    uint64_t start_nonce = ((uint64_t)highnonce) << 32 + lownonce;
//    uint32_t epoch = ethash::get_epoch_number(blockheight);
//    ethash_epoch_context epoch_ctx = ethash::get_global_epoch_context(epoch);
//
//    uint64_t nMaxTries = 1000000;
//    int64 nStart = GetTime();
//    progpow::search_result searchresult = progpow::search_light(epoch_ctx, blockheight, header_hash, target, start_nonce, nMaxTries,
//        [&nStart, timeout, &session]() {
//            //HCE: Return true means stop mining.
//            //if (isstopmining)
//            //    return true;
//            if (GetTime() - nStart >= timeout) {
//                return true;
//            }
//            std::lock_guard<std::mutex> guard(mutx_mining);
//            if (session.status == MiningSession::MS::closing) {
//                return true;
//            }
//            return false;
//        });
//    if (searchresult.solution_found) {
//        //found, set nonce & mix hash
//        memcpy(nonce, &searchresult.nonce, 8);
//        memcpy(mixhash, searchresult.mix_hash.bytes, 32);
//
//        std::lock_guard<std::mutex> guard(mutx_mining);
//        session.status = MiningSession::MS::closed;
//        return true;
//    }
//
//    std::lock_guard<std::mutex> guard(mutx_mining);
//    session.status = MiningSession::MS::closed;
//    return false;
//}
//
//
////extern "C" BOOST_SYMBOL_EXPORT
////void LightNodeStopMining()
////{
////    isstopmining = true;
////}
