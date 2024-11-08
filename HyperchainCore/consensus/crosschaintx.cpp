/*Copyright 2016-2022 hyperchain.net (Hyperchain)

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

#include <iostream>
#include <map>

#include "../node/defer.h"
#include "util/hex.hpp"
#include "crosschaintx.h"
#include "AppPlugins.h"

using namespace std;

namespace crosschain {


const char* MODULE_PARA = "paracoin";
const char* MODULE_ALETH = "aleth";


void CrossChainExecutorBase::doAction() {
    StateBase::TXSTATE txstate;
    if (m_isDoing) {
        return;
    }
    m_isDoing = true;
    defer{
        m_isDoing = false;
    };
    m_state->handle(this, txstate);
}


bool StartState::handle(CrossChainExecutorBase* context, TXSTATE& txstate)
{
    ParaToEthExecutor* ctx = reinterpret_cast<ParaToEthExecutor*>(context);

    vector<uint8_t> privatekey;
    vector<uint8_t> senderaddr;

    m_state = StringFormat("%s Sending to chain: creating a Para outgoing transaction\n", 
        toReadableTime(time(nullptr)));
    try {
        //Generate a swapping key pair
        AppPlugins::callFunction<void>(MODULE_ALETH, "makeswapkey", privatekey, senderaddr);

        //HC: 2. 创建Para转账交易，目标地址带上密钥对
        map<string, string>& mapparams = context->getMapParams();

        mapparams["chainaddress"] = ctx->m_chainaddress;
        mapparams["amount"] = ctx->m_amount;
        mapparams["senderprikey"] = ToHexString(privatekey);  //以太坊收款交易的发送者私钥
        mapparams["senderaddress"] = ToHexString(senderaddr); //以太坊收款交易的发送者
        mapparams["fromaccount"] = ctx->m_fromaccount;

        //HC: Para交易的目标地址里带上Aleth交易的发送者地址，同时aleth交易带上Para交易的hash，这样二者相互锁定形成一对一的对应关系
        if (ctx->m_accountaddrtargetchain.empty()) {
            string toaddress;
            AppPlugins::callFunction<void>(MODULE_ALETH, "getrewarddistributeaddress", toaddress);
            mapparams["to"] = toaddress;
        } else {
            mapparams["to"] = ctx->m_accountaddrtargetchain; //HC: account address of target chain
        }

        string txhash;
        string strerr;
        bool ret = AppPlugins::callFunction<bool>(MODULE_PARA, "sendtochain", mapparams, txhash, strerr);
        if (!ret)
            ctx->setState(new ExceptionState(shared_from_this(), StringFormat("sendtochain: %s\n", strerr)));
        else {
            mapparams["paratxhash"] = txhash;
            ctx->setState(new ParaTxCreatedState(shared_from_this(), txhash));
            return true;
        }
    }
    catch (std::exception& e) {
        ctx->setState(new ExceptionState(shared_from_this(), StringFormat("%s: %s\n", __FUNCTION__, e.what())));
    }
    return false;
}

std::string StartState::toString()
{
    return m_state;
}

bool ImportStartState::handle(CrossChainExecutorBase* context, TXSTATE& txstate)
{
    ParaToEthExecutor* ctx = reinterpret_cast<ParaToEthExecutor*>(context);

    string strerr;
    map<string, string>& mapparams = context->getMapParams();


    bool ret = AppPlugins::callFunction<bool>(MODULE_PARA, "GetTxDetails", m_paratxhash, mapparams, strerr);
    if (!ret)
        ctx->setState(new ExceptionState(shared_from_this(), StringFormat("GetTxDetails: %s\n", strerr)));
    else {
        ctx->m_paratxhash = m_paratxhash;
        mapparams["paratxhash"] = m_paratxhash;
        ctx->initEnv("",
            mapparams.at("chainaddress"),
            mapparams.at("to"),
            mapparams.at("amount") );
        ctx->setState(new ParaTxCreatedState(nullptr, m_paratxhash));
        return true;
    }
    return false;
}

std::string ImportStartState::toString()
{
    return StringFormat("ImportStartState: %s\n", m_paratxhash);
}


bool TxCreatedState::handle(CrossChainExecutorBase* context, TXSTATE& txstate) {

    string desc;
    string strerr;

    m_hyperId = -1;
    int64_t blocktm;
    try {
        bool ret = AppPlugins::callFunction<bool>(m_txModule, "GetTxState",
            m_txhash, m_blocknum, blocktm, m_blockmaturity,
            m_hyperId, m_chainId, m_localId,
            desc, strerr);
        if (!ret) {
            txstate = TXSTATE::notfound;
            return false;
        }
    }
    catch (std::exception& e) {
        context->setState(new ExceptionState(shared_from_this(), StringFormat("%s: %s\n", __FUNCTION__, e.what())));
        txstate = TXSTATE::cannotgetstate;
        return false;
    }


    //HC: Check if the transaction has matured
    if (m_blocknum < 0 || m_blockmaturity < m_maturity_threshold || m_hyperId < 0) {
        txstate = TXSTATE::immaturity;
        return false;
    }
    
    CHyperChainSpace* sp = Singleton<CHyperChainSpace, string>::getInstance();
    if (sp->GetMaxBlockID() < m_hyperId + m_hyperblock_maturity_threshold) {
        txstate = TXSTATE::immaturity;
        return false;
    }

    txstate = TXSTATE::maturity;
    return true;
}


std::string TxCreatedState::toString()
{
    string comment = StringFormat("if maturity > %d and hyperblock maturity > %d, then transaction is mature",
        m_maturity_threshold, m_hyperblock_maturity_threshold);

    CHyperChainSpace* HSpce = Singleton<CHyperChainSpace, string>::getInstance();

    uint64 latest_hid;
    T_SHA256 thhash;
    uint64 ctm;
    HSpce->GetLatestHyperBlockIDAndHash(latest_hid, thhash, ctm);

    string message;
    if (m_prevState)
        message = m_prevState->toString();
    message +=
        StringFormat("The transaction created on %s chain:\n"
            "hash:     %s\n"
            "blocknum: %d\n"
            "maturity: %s\n"
            "block triple address: [%d %d %d]\n"
            "mature:  %s\n"
            "%s\n\n",
            m_chainname,
            m_txhash, m_blocknum,

            (m_blockmaturity >= m_maturity_threshold ?
                StringFormat(">=%d", m_blockmaturity) : StringFormat("%d", m_blockmaturity)),

            m_hyperId, m_chainId, m_localId,

            ((m_blockmaturity >= m_maturity_threshold && 
                (m_hyperId > 0 && m_hyperId + m_hyperblock_maturity_threshold < latest_hid)) ? "Yes" : "No"),
            comment);
    return message;
}


ParaTxCreatedState::ParaTxCreatedState(SPState prevstate, const string& txhash) : TxCreatedState(prevstate, txhash)
{
    m_chainname = "para";
    m_txModule = "paracoin";

    //HC: 开发时此值设置的小，上线后需要调整，同样还有 COINBASE_MATURITY(block.h)
    m_maturity_threshold = 30;
}


bool ParaTxCreatedState::handle(CrossChainExecutorBase* context, TXSTATE& txstate)
{
    TxCreatedState::handle(context, txstate);
    if (txstate == TXSTATE::maturity) {
        map<string, string>& mapparams = context->getMapParams();
        mapparams["para_tx_hid"] = StringFormat("%d", m_hyperId);
        mapparams["para_tx_chainid"] = StringFormat("%d", m_chainId);
        mapparams["para_tx_localid"] = StringFormat("%d", m_localId);

        string strerr;
        string txhash;
        bool ret = AppPlugins::callFunction<bool>(MODULE_ALETH, "recvfromchain", context->getMapParams(), txhash, strerr);
        if (!ret) {
            context->setState(new ExceptionState(shared_from_this(), strerr));
            return false;
        }

        //HC: 进入eth已创建并逐步成熟阶段
        context->setState(new EthTxCreatedState(shared_from_this(), txhash));
        return true;
    } else if (txstate == TXSTATE::notfound) {
        //HC: 交易无法找到，跨链交易失败
        map<string, string>& mapparams = context->getMapParams();
        context->setState(new ExceptionState(shared_from_this(), 
            StringFormat("%s: Tx %s can not be found\n", __FUNCTION__, mapparams["paratxhash"])));
    }

    return false;
}

EthTxCreatedState::EthTxCreatedState(SPState prevstate, const string& txhash) : TxCreatedState(prevstate, txhash)
{
    m_chainname = "aleth";
    m_txModule = "aleth";

    //HC: 开发时此值设置的小，上线后需要调整，同样还有 COINBASE_MATURITY(block.h)
    m_maturity_threshold = 30;
}

bool EthTxCreatedState::handle(CrossChainExecutorBase* context, TXSTATE& txstate)
{
    TxCreatedState::handle(context, txstate);
    if (txstate == TXSTATE::maturity) {

        //HC: 进入eth已成熟, 跨链交易完成状态
        context->setState(new CompletedState(shared_from_this()));
        return true;
    } else if (txstate == TXSTATE::notfound) {
        //HC: 交易无法找到，跨链交易失败
        //map<string, string>& mapparams = context->getMapParams();
        //context->setState(this->getPreviouState().get());

        context->setState(new ExceptionState(shared_from_this(),
            StringFormat("%s: Tx %s can not be found\n", __FUNCTION__, m_txhash)));

    }

    return false;
}


//////////////////////////////////////////////////////////////////////////

bool SettlementStartState::handle(CrossChainExecutorBase* context, TXSTATE& txstate)
{
    map<string, string> &mapparams = context->getMapParams();

    EthToParaExecutor* ctx = reinterpret_cast<EthToParaExecutor*>(context);
    mapparams["from"] = ctx->m_fromaddress;        //HC: 转出地址

    m_state = StringFormat("%s Sending to chain: creating an Ethereum outgoing transaction\n", 
        toReadableTime(time(nullptr)));
    string strerr;
    try {
        bool ret = AppPlugins::callFunction<bool>(MODULE_PARA, "GetScriptPubKeyFromDestination",
            ctx->m_paraaddress, ctx->m_scriptpubkey, strerr);
        if (!ret) {
            ctx->setState(new ExceptionState(shared_from_this(), StringFormat("GetScriptPubKeyFromDestination: %s\n", strerr)));
            //*m_ostream << StringFormat("destinationscriptpubKey: %s\n", strerr);
            return false;
        }

        mapparams["para_recv_script"] = ctx->m_scriptpubkey; //HC: Para交易收款脚本
        mapparams["amount"] = ctx->m_amount;

        //HC: 创建ethereum转出交易
        uint32_t hid = 0;
        uint16_t chainid = 0;
        uint16_t localid = 0;

        ret = AppPlugins::callFunction<bool>(MODULE_ALETH, "sendtochain", mapparams,
            ctx->m_ethtxhash,
            ctx->m_publickey,
            hid, chainid, localid,
            ctx->m_genesisblockhash, strerr);
        if (!ret) {
            ctx->setState(new ExceptionState(shared_from_this(), StringFormat("sendtochain: %s\n", strerr)));
            return false;
        }

        mapparams["eth_tx_hash"] = ctx->m_ethtxhash;
        mapparams["eth_tx_publickey"] = ctx->m_publickey;
        mapparams["genesis_block_hid"] = StringFormat("%d", hid);
        mapparams["genesis_block_chainid"] = StringFormat("%d", chainid);
        mapparams["genesis_block_localid"] = StringFormat("%d", localid);
        mapparams["genesis_block_hash"] = ctx->m_genesisblockhash;


        ctx->setState(new SettlementEthTxCreatedState(shared_from_this(), ctx->m_ethtxhash));
        return true;
    }
    catch (std::exception& e) {
        ctx->setState(new ExceptionState(shared_from_this(), StringFormat("%s: %s\n", __FUNCTION__, e.what())));
    }
    return false;
}

std::string SettlementStartState::toString()
{
    return m_state;
}

bool SettlementEthTxCreatedState::handle(CrossChainExecutorBase* context, TXSTATE& txstate)
{
    string desc;
    string strerr;

    EthToParaExecutor* ctx = reinterpret_cast<EthToParaExecutor*>(context);

    try {

        TxCreatedState::handle(context, txstate);
        if (txstate == TXSTATE::maturity) {
            map<string, string>& mapparams = context->getMapParams();
            mapparams["eth_tx_hid"] = StringFormat("%d", m_hyperId);
            mapparams["eth_tx_chainid"] = StringFormat("%d", m_chainId);
            mapparams["eth_tx_localid"] = StringFormat("%d", m_localId);

            //HC: 完成上链并成熟才能创建Para收款交易
            bool ret = AppPlugins::callFunction<bool>(MODULE_PARA, "recvfromchain", context->getMapParams(), ctx->m_paratxhash, strerr);
            if (!ret) {
                ctx->setState(new ExceptionState(shared_from_this(), StringFormat("recvfromchain: %s\n", strerr)));
                return false;
            }
            ctx->setState(new SettlementParaTxCreatedState(shared_from_this(), ctx->m_paratxhash));
            return true;
        } else if (txstate == TXSTATE::notfound) {
            //HC: 交易无法找到，跨链交易失败
            map<string, string>& mapparams = context->getMapParams();
            context->setState(new ExceptionState(shared_from_this(),
                StringFormat("%s: Tx %s can not be found\n", __FUNCTION__, ctx->m_ethtxhash)));
        }
    }
    catch (std::exception& e) {
        ctx->setState(new ExceptionState(shared_from_this(), StringFormat("%s: %s\n", __FUNCTION__, e.what())));
    }
    return false;
}


//////////////////////////////////////////////////////////////////////////
bool SettlementParaTxCreatedState::handle(CrossChainExecutorBase* context, TXSTATE& txstate)
{
    TxCreatedState::handle(context, txstate);
    if (txstate == TXSTATE::maturity) {
        context->setState(new CompletedState(shared_from_this()));
        return true;
    } else if (txstate == TXSTATE::notfound) {
        //map<string, string>& mapparams = context->getMapParams();
        //context->setState(this->getPreviouState().get());

        context->setState(new ExceptionState(shared_from_this(),
            StringFormat("%s: Tx %s can not be found\n", __FUNCTION__, m_txhash)));
    }

    return false;
}


//////////////////////////////////////////////////////////////////////////
bool CompletedState::handle(CrossChainExecutorBase* context, TXSTATE& txstate)
{
    UNUSED(context);
    UNUSED(txstate);
    return true;
}


std::string CompletedState::toString()
{
    return m_prevState->toString() +
        "The cross-chain transaction has already completed\n";
}


//int main() {
//    Context* context = new Context();
//    context->request();
//    context->setState(new ConcreteStateB());
//    context->request();
//    return 0;
//}


bool SettlementImportStartState::handle(CrossChainExecutorBase* context, TXSTATE& txstate)
{
    EthToParaExecutor* ctx = reinterpret_cast<EthToParaExecutor*>(context);

    string strerr;
    map<string, string>& mapparams = context->getMapParams();


    bool ret = AppPlugins::callFunction<bool>(MODULE_ALETH, "GetTxDetails", m_ethtxhash, mapparams, strerr);
    if (!ret) {
        ctx->setState(new ExceptionState(shared_from_this(), StringFormat("GetTxDetails: %s\n", strerr)));
    } else {
        ctx->m_ethtxhash = m_ethtxhash;

        mapparams["eth_tx_hash"] = ctx->m_ethtxhash;

        string paraaddress;
        ret = AppPlugins::callFunction<bool>(MODULE_PARA, "GetDestinationFromScriptPubKey", mapparams["para_recv_script"], paraaddress, strerr);
        if (!ret) {
            ctx->setState(new ExceptionState(shared_from_this(), StringFormat("GetDestinationFromScriptPubKey: %s\n", strerr)));
            return false;
        }

        ctx->initEnv(mapparams.at("from"),
            paraaddress,
            mapparams.at("amount"));
        ctx->setState(new SettlementEthTxCreatedState(nullptr, m_ethtxhash));
        return true;
    }
    return false;
}

std::string SettlementImportStartState::toString()
{
    return StringFormat("SettlementImportStartState: %s\n", m_ethtxhash);
}

}
