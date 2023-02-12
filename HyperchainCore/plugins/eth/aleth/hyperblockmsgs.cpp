
#include "hyperblockmsgs.h"

#include <libdevcore/Common.h>
#include <libdevcore/Guards.h>
#include <libwebthree/WebThree.h>

#include <libethereum/hyperchaininfo.h>
#include "blocktriaddr.h"
#include "cryptoethcurrency.h"
#include "alethapi.h"
#include "node/defer.h"


using namespace dev;
using namespace dev::eth;


HyperBlockMsgs hyperblockMsgs;
extern dev::WebThreeDirect *g_ptrWeb3;
extern Logger g_logger;

extern bool SwitchChainTo(const BlockHeader& pindexBlock);
extern bool LatestBlockIndexOnChained(const BlockHeader& header, BlockHeader& onchainedblkheader);

string ToString(ImportResult IR)
{
    switch (IR)
    {
    case ImportResult::Success:
        return "Success";
    case ImportResult::Malformed:
        return "Malformed";
    case ImportResult::BadChain:
        return "BadChain";
    case ImportResult::FutureTimeKnown:
        return "FutureTimeKnown";
    case ImportResult::AlreadyInChain:
        return "AlreadyInChain";
    case ImportResult::AlreadyKnown:
        return "AlreadyKnown";
    case ImportResult::FutureTimeUnknown:
        return "FuturenTimeUnknown";
    case ImportResult::UnknownParent:
        return "UnknownParent";
    case ImportResult::OverbidGasPrice:
        return "OverbidGasPrice";
    case ImportResult::ZeroSignature:
        return "ZeroSignature";
    }
    return "Unknown";
}

bool AcceptBlocks(vector<T_PAYLOADADDR>& vecPA, const T_SHA256& hhash, bool isLatest)
{
    if (vecPA.size() == 0 || !g_ptrWeb3) {
        return false;
    }

    eth::Client *cli = g_ptrWeb3->ethereum();

    vector<bytes> vecBlock;
    vector<BLOCKTRIPLEADDRESS> vecBlockAddr;
    for (auto b : vecPA) {
        bytes block(b.payload.begin(), b.payload.end());

        vecBlock.push_back(std::move(block));
        BLOCKTRIPLEADDRESS btriaddr(b.addr);
        btriaddr.hhash = hhash;
        vecBlockAddr.push_back(btriaddr);
    }

    bool isNeedSync = false;
    for (size_t i = 0; i < vecBlock.size(); i++) {

        bytes blk = CryptoEthCurrency::ExtractBlock(string(vecBlock[i].begin(), vecBlock[i].end()));
        BlockHeader header(blk);
        ImportResult ret = cli->injectBlock(blk);
        if (ret == ImportResult::Success) {
            LOG(g_logger) << StringFormat("AcceptBlocks() : %d(%s) is accepted\n\n", header.number(), header.hash().hex());
        } else {
            if (ret == ImportResult::UnknownParent)
                isNeedSync = true;
            LOG(g_logger) << StringFormat("AcceptBlocks() : %d(%s) is rejected for %s\n\n", header.number(), header.hash().hex(), ToString(ret));
        }

        //if (ProcessBlockWithTriaddr(nullptr, &vecBlock[i], &vecBlockAddr[i])) {
        //    uint256 hash = vecBlock[i].GetHash();
        //    TRACE_FL("AcceptBlocks() : (%s) %s is accepted\n\n", vecPA[i].addr.tostring().c_str(),
        //        hash.ToString().substr(0, 20).c_str());
        //} else {
        //    WARNING_FL("(%s) cannot be accepted\n", vecPA[i].addr.tostring().c_str());
        //}
    }

    if (isNeedSync) {
        cli->SyncfromPeers();
    }

    return true;
}


bool ProcessChainCb(map<T_APPTYPE, vector<T_PAYLOADADDR>>& mapPayload, uint32_t& hidFork, uint32_t& hid, T_SHA256& thhash, bool isLatest)
{
    //CSpentTime spentt;
    //defer {
    //    cout << strprintf("Para ProcessChainCb spent million seconds : %ld\n", spentt.Elapse());
    //};
    if (!g_ptrWeb3) {
        return false;
    }

    eth::Client* cli = g_ptrWeb3->ethereum();
    const BlockChain& bc = g_ptrWeb3->ethereum()->blockChain();

    LOG(g_logger) << StringFormat("ProcessChainCb: hyper block has changed, [%d %s] %d",
        hid, thhash.toHexString(), isLatest);

    defer{
        if (isLatest) {
            //HC: 最新超块改变，必须更新working block
            //HCE: In case the latest Hyperblock changes, working block must be updated.
            cli->completeSync();
            cli->resetWorking();
        }
    };

    //FIBER_SWITCH_CRITICAL_BLOCK_T_MAIN(50)
    {
        LatestHyperBlock::CompareAndUpdate(hid, thhash, isLatest);

        T_APPTYPE meApp(APPTYPE::ethereum, g_cryptoEthCurrency.GetHID(),
            g_cryptoEthCurrency.GetChainNum(),
            g_cryptoEthCurrency.GetLocalID());
        if (mapPayload.count(meApp)) {
            vector<T_PAYLOADADDR>& vecPA = mapPayload[meApp];
            AcceptBlocks(vecPA, thhash, isLatest);

            BlockHeader pindexBest = bc.info();

            BlockHeader onchainedheader;
            if (!LatestBlockIndexOnChained(pindexBest, onchainedheader)) {
                cli->suspendSealing();
                LOG(g_logger) << StringFormat("ProcessChainCb: Failed to LatestBlockIndexOnChained %d and suspend sealing", pindexBest.number());

                return false;
            }
            cli->resumeSealing();

            if (onchainedheader != pindexBest) {
                SwitchChainTo(onchainedheader);
                LOG(g_logger) << StringFormat("ProcessChainCb: SwitchChainTo %d(%s) because hyper block has changed",
                    onchainedheader.number(), onchainedheader.hash().hex());
            }
            else {
                LOG(g_logger) << StringFormat("ProcessChainCb: best block is ok! %d(%s) ",
                    onchainedheader.number(), onchainedheader.hash().hex());
            }

            return true;
        }

        if (isLatest) {
            BlockHeader pStart = bc.info();
            while (pStart && pStart.prevHID() >= hidFork) {
                pStart = bc.pprev(pStart);
            }

            if (!pStart) {
                pStart = bc.genesis();
            }

            pStart = bc.pnext(pStart);
            if (!pStart) {
                return true;
            }

            h256 hhash(thhash.toHexString());
            BlockHeader pEnd = pStart;
            while (pEnd && pEnd.prevHID() == hid && pEnd.prevHyperBlkHash() == hhash) {
                pEnd = bc.pnext(pEnd);
            }

            if (pEnd) {
                auto spprev = bc.pprev(pEnd);
                if (spprev) {
                    SwitchChainTo(spprev);
                }
            }
            cli->resumeSealing();
        }
    }

    return true;
}


void HyperBlockMsgs::insert(CHAINCBDATA&& cb)
{
    std::lock_guard<boost::fibers::mutex> l(m_cs_list);
    m_list.push_back(std::move(cb));
}

void HyperBlockMsgs::process()
{
    std::lock_guard<boost::fibers::mutex> l(m_cs_list);
    auto it = m_list.begin();
    for (; it != m_list.end(); ) {
        ProcessChainCb(it->m_mapPayload, it->m_hidFork, it->m_hid, it->m_thhash, it->m_isLatest);
        m_list.erase(it++);
    }
}

size_t HyperBlockMsgs::size()
{
    std::lock_guard<boost::fibers::mutex> l(m_cs_list);
    return m_list.size();
}
