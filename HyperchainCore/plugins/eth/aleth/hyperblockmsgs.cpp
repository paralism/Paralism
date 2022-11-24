
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
extern void LatestBlockIndexOnChained(BlockHeader& onchainedblkheader);

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

    for (size_t i = 0; i < vecBlock.size(); i++) {

        bytes blk = CryptoEthCurrency::ExtractBlock(string(vecBlock[i].begin(), vecBlock[i].end()));
        if (cli->injectBlock(blk) == ImportResult::Success) {
            BlockHeader header(blk);
            LOG(g_logger) << StringFormat("AcceptBlocks() : %d(%s) is accepted\n\n", header.number(), header.hash().hex());
        }
        //if (ProcessBlockWithTriaddr(nullptr, &vecBlock[i], &vecBlockAddr[i])) {
        //    uint256 hash = vecBlock[i].GetHash();
        //    TRACE_FL("AcceptBlocks() : (%s) %s is accepted\n\n", vecPA[i].addr.tostring().c_str(),
        //        hash.ToString().substr(0, 20).c_str());
        //} else {
        //    WARNING_FL("(%s) cannot be accepted\n", vecPA[i].addr.tostring().c_str());
        //}
    }

    //HC: cannot use ethereum block in latest hyper block as unique standard of choosing best chain
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
        //HC: reset work block, avoid to stop mining
        if (isLatest)
            cli->resetWorking();
    };


    //HC: Called by consensus MQ service, switching in case cannot retrieve the cs_main
    //FIBER_SWITCH_CRITICAL_BLOCK_T_MAIN(50)
    {
        LatestHyperBlock::CompareAndUpdate(hid, thhash, isLatest);

        T_APPTYPE meApp(APPTYPE::ethereum, g_cryptoEthCurrency.GetHID(),
            g_cryptoEthCurrency.GetChainNum(),
            g_cryptoEthCurrency.GetLocalID());
        if (mapPayload.count(meApp)) {
            vector<T_PAYLOADADDR>& vecPA = mapPayload[meApp];
            AcceptBlocks(vecPA, thhash, isLatest);

            //HC: 检查链头是否正确，如果不对，需要切换
            BlockHeader onchainedheader;
            LatestBlockIndexOnChained(onchainedheader);
            BlockHeader pindexBest = bc.info();

            if (onchainedheader != pindexBest) {
                SwitchChainTo(onchainedheader);
                LOG(g_logger) << StringFormat("ProcessChainCb: SwitchChainTo %d(%s) because hyper block has changed",
                    onchainedheader.number(), onchainedheader.hash().hex());
            }

            return true;
        }

        //HC: 超块里无最新以太坊子块，但是最新超块发生了变化，因子链与超块链的锁定关系，分析是否子链要回退
        if (isLatest) {
            //HC: 链切换过程中，需要回退到分叉超块
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

            //HC: Forward to block matched
            //HC: Sometimes ethereum has already done mining on base of hid, so continue forwarding to latest ethereum block
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
