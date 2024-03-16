/*Copyright 2016-2024 hyperchain.net (Hyperchain)

Distributed under the MIT software license, see the accompanying
file COPYING or?https://opensource.org/licenses/MIT.

Permission is hereby granted, free of charge, to any person obtaining a copy of
this? software and associated documentation files (the "Software"), to deal in
the Software without restriction, including without limitation the rights to
use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of
the Software, and to permit persons to whom the Software is furnished to do so,
subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED,? INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
*/
#include <libethcore/TransactionBase.h>
#include <libethcore/BlockHeader.h>

#ifdef ALETH

#include "cryptoethcurrency.h"
#include "../AppPlugins.h"

using namespace std;

extern void RSyncRemotePullHyperBlock(uint32_t hid, string nodeid = "");
extern void RSyncRemotePullHyperBlock(uint32_t starthid, uint32_t endhid, string nodeid = "");

Logger cc_loggerDebug{ createLogger(VerbosityDebug, "crosschaintx") };
Logger cc_loggerWarn{ createLogger(VerbosityWarning, "crosschaintx") };
Logger cc_loggerInfo{ createLogger(VerbosityInfo, "crosschaintx") };

void verifyParaTxOfCrossChainParaToEth(dev::eth::TransactionBase const& _t, dev::eth::BlockHeader const& _header)
{
    //HC: 从附加信息里提取对应的Para交易地址和hash信息
    int hid;
    int chainid;
    int localid;

    LOG(cc_loggerDebug) << "Verifiing ParaTxOfCrossChainParaToEth, block height of eth: " << _header.number();

    string paratxhash = _t.parseCrossChainData(hid, chainid, localid);

    uint32_t genesishid = g_cryptoEthCurrency.GetHID();
    uint16_t genesischainid = g_cryptoEthCurrency.GetChainNum();
    uint16_t genesislocalid = g_cryptoEthCurrency.GetLocalID();
    auto genesishash = g_cryptoEthCurrency.GetHashGenesisBlock();


    bool paraapploaded = false;
    ConsensusEngine* consensuseng = Singleton<ConsensusEngine>::getInstance();
    if (consensuseng && consensuseng->IsParaAppLoaded()) {
        paraapploaded = true; //App of Para is started
    }

    CHyperChainSpace* hyperchainspace = Singleton<CHyperChainSpace, string>::getInstance();
    T_LOCALBLOCK localblock;
    T_LOCALBLOCKADDRESS addr;
    addr.set(hid, chainid, localid);

    //HC: 读取交易所在子块
    bool foundLocalblock = hyperchainspace->GetLocalBlock(addr, localblock);

    ostringstream oss;
    oss << _t.value();
    string strAmount = UnitConversionToPara(oss.str());

    //HC: 提取公钥
    auto pk = recover(_t.signature(), _t.sha3(WithoutSignature));

    //HC：验证对应的Para交易的合法性
    string strerr;
    if (!AppPlugins::callFunction<bool>("paracoin",
        "VerifyTx",
        localblock.GetPayLoad(),
        paraapploaded,
        paratxhash,
        genesishid, genesischainid, genesislocalid,
        genesishash.hex(),
        pk.hex(),
        _t.receiveAddress().hex(),
        //pk.GetHexNoReverse(),
        strAmount,
        strerr)) {

        //HC: To do： 由于Tp交易三元组可能会发生变化，所以失败了也不能完全确认交易就不合法，
        //HC: 需要异步向拥有Para链的邻居询问Para交易的所在地址
        if (!foundLocalblock) {
            //下载超块,等待重试

            std::string msg = StringFormat("Failed to verify eth cross-chain-tx(block height: %d) because %s and missing local block: [%d %d %d]",
                _header.number(),
                strerr,
                hid, chainid, localid);

            LOG(cc_loggerInfo) << msg;

            RSyncRemotePullHyperBlock((uint32_t)hid);

            BOOST_THROW_EXCEPTION(InvalidHyperBlock() << errinfo_hID(hid));
        }

        std::string msg = StringFormat("Failed to verify eth cross-chain-tx(block height: %d) because %s, local block: [%d %d %d]",
            _header.number(),
            strerr,
            hid, chainid, localid);
        LOG(cc_loggerWarn) << msg;

        BOOST_THROW_EXCEPTION(IllegalCrossChainTransaction() << errinfo_comment(strerr));
    }

    LOG(cc_loggerDebug) << "Verified ParaTxOfCrossChainParaToEth, block height of eth: " << _header.number()
        << " hash: " << _t.sha3().hex();
}


#else

void verifyParaTxOfCrossChainParaToEth(dev::eth::TransactionBase const& _t, dev::eth::BlockHeader const& _header)
{
}

#endif
