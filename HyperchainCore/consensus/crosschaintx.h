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

#pragma once


#include <string>
#include <list>
#include <memory>

#include "headers/inter_public.h"

extern string toReadableTime(time_t t);

namespace crosschain {

class StateBase;
using SPState = std::shared_ptr<StateBase>;

class CrossChainExecutorBase;

class StateBase : public std::enable_shared_from_this<StateBase> {
public:
    enum class TXSTATE : char {
        maturity,
        immaturity,
        notfound,
        cannotgetstate,

    };

    StateBase(SPState prevstate) : m_prevState(prevstate)
    { }

    virtual bool handle(CrossChainExecutorBase* context, TXSTATE& txstate) = 0;
    virtual std::string toString() = 0;

    bool isCompleted() {
        return m_isCompleted;
    }
    
    std::shared_ptr<StateBase> getPreviouState()
    {
        return m_prevState;
    }

protected:
    std::shared_ptr<StateBase> m_prevState;
    bool m_isCompleted = false;
    string m_state;
};

class TxCreatedState : public StateBase {
public:

    TxCreatedState(SPState prevstate, const string& txhash) : StateBase(prevstate), m_txhash(txhash)
    { }

    bool handle(CrossChainExecutorBase* context, TXSTATE& txstate) override;

    std::string toString() override;

    string m_chainname;
    string m_txhash;
    int m_blocknum = -1;
    int m_blockmaturity = -1;

    int64_t m_hyperId = -1;
    int64_t m_chainId = 0;
    int64_t m_localId = 0;


    string m_txModule;
    int m_maturity_threshold = 0;
    int m_hyperblock_maturity_threshold = 5;
};

class EthTxCreatedState;
class ParaTxCreatedState : public TxCreatedState {

public:
    ParaTxCreatedState(SPState prevstate, const string& txhash);
    bool handle(CrossChainExecutorBase* context, TXSTATE& txstate) override;
};


class EthTxCreatedState : public TxCreatedState {

public:
    EthTxCreatedState(SPState prevstate, const string& txhash);
    bool handle(CrossChainExecutorBase* context, TXSTATE& txstate) override;
};


class ExceptionState : public StateBase {
public:
    ExceptionState(SPState prevstate, const std::string& desc) : StateBase(prevstate), m_desc(desc) {
        m_isCompleted = true;
    }

    bool handle(CrossChainExecutorBase* context, TXSTATE& txstate) override
    {
        UNUSED(context);
        UNUSED(txstate);
        return true;
    }

    std::string toString() {
        return m_prevState->toString() +
            StringFormat("Abort for exception %s", m_desc);
    };
private:
    std::string m_desc;
};

class CompletedState : public StateBase {
public:
    CompletedState(SPState prevstate) : StateBase(prevstate) {
        m_isCompleted = true;
    }
    bool handle(CrossChainExecutorBase* context, TXSTATE& txstate) override;
    std::string toString() override;
};

class CrossChainExecutorBase {

public:
    string m_name;
    int64_t m_createdtime;  //HC: 交易发起时间

    string m_amount;        //HC: 转账数
    string m_ethtxhash;
    string m_paratxhash;

    std::shared_ptr<StateBase> m_state;  //HC: 交易状态
    std::ostream* m_ostream;

    std::list<std::string> m_params;
    std::map<std::string, std::string> m_mapparams;

    bool m_isImported = false; //是否是导入
    bool m_isDoing = false;

public:
    CrossChainExecutorBase(const std::string& name) :
        m_name(name),
        m_createdtime(time(nullptr))
    {
    }

    void setState(StateBase* s) {
        if (!s->weak_from_this().expired()) {
            m_state = s->shared_from_this();
        }
        else {
            m_state = std::shared_ptr<StateBase>(s);
        }
    }

    void doAction();
    
    std::string currentState() {
        return StringFormat("Cross chain transaction status:\n%s", m_state->toString());
    }

    bool isCompleted() {
        return m_state->isCompleted();
    }

    std::list<std::string>& getParams()
    {
        return m_params;
    }

    std::map<std::string, std::string> & getMapParams() {
        return m_mapparams;
    }

    virtual ::string details() = 0;

};


//////////////////////////////////////////////////////////////////////////
//
//HC: 跨链交易的结算交易，以太坊转出到Para
//
//////////////////////////////////////////////////////////////////////////

class SettlementStartState : public StateBase {
public:
    using StateBase::StateBase;
    bool handle(CrossChainExecutorBase* context, TXSTATE& txstate) override;
    std::string toString() override;
};

//HC: 结算跨链导入存在的
class SettlementImportStartState : public StateBase {
public:
    using StateBase::StateBase;
    SettlementImportStartState(const string& ethtxhash) : StateBase(nullptr), m_ethtxhash(ethtxhash) {

    }

    bool handle(CrossChainExecutorBase* context, TXSTATE& txstate) override;
    std::string toString() override;
public:
    string m_ethtxhash;
};


class SettlementEthTxCreatedState : public EthTxCreatedState {
public:
    SettlementEthTxCreatedState(SPState prevstate, const string& txhash) : EthTxCreatedState(prevstate, txhash)
    { }

    bool handle(CrossChainExecutorBase* context, TXSTATE& txstate) override;
};

class SettlementParaTxCreatedState : public ParaTxCreatedState {
public:
    SettlementParaTxCreatedState(SPState prevstate, const string& txhash) : ParaTxCreatedState(prevstate, txhash) { }

    bool handle(CrossChainExecutorBase* context, TXSTATE& txstate) override;
};


//////////////////////////////////////////////////////////////////////////
/*
// HC: Para to Eth跨链交易状态变化过程：StartState -> ParaTxCreatedState -> EthTxCreatedState -> CompletedState，
// HC: 如果中间出现异常那么进入ExceptionState状态
// HC: 另外也可以从ImportStartState开始

+------------------ +
| ImportStartState  | --------- +
+------------------ +           |
                                |
                                |
                                V
    +-------------- +      +--------------------+      +------------------ +      +---------------- +
    | StartState    | -- > | ParaTxCreatedState | -- > | EthTxCreatedState | -- > | CompletedState  |
    +-------------- +      +--------------------+      +------------------ +      +---------------- +
        |                           |                           |                           |
        |                           |                           |                           |
        |                           |                           |                           |
        |                           |                           |                           |
        v                           v                           v                           v
       +------------------+ +----------------+ +---------------- + +-------------------------+
       |                               ExceptionState                                        |
       +------------------+ +----------------+ +---------------- + +-------------------------+
*/
//////////////////////////////////////////////////////////////////////////

class StartState : public StateBase {
public:
    using StateBase::StateBase;
    bool handle(CrossChainExecutorBase* context, TXSTATE& txstate) override;
    std::string toString() override;
};

//HC:  导入存在的 Para发起的跨链
class ImportStartState : public StateBase {
public:
    using StateBase::StateBase;
    ImportStartState(const string& paratxhash) : StateBase(nullptr), m_paratxhash(paratxhash) {

    }

    bool handle(CrossChainExecutorBase* context, TXSTATE& txstate) override;
    std::string toString() override;
public:
    string m_paratxhash;
};



class ParaToEthExecutor : public CrossChainExecutorBase {

public:
    string m_fromaccount;
    string m_chainaddress;
    string m_accountaddrtargetchain;

public:
    ParaToEthExecutor(const std::string& name) : CrossChainExecutorBase(name)
    {
        setState(new StartState(nullptr));
    }

    ParaToEthExecutor(ImportStartState *imp_state) :
        CrossChainExecutorBase(StringFormat("imported-%s", imp_state->m_paratxhash.substr(0, 10)))
    {
        setState(imp_state);
        m_isImported = true;
    }

    void initEnv(const string& fromacc,
        const string& chainaddress, const string& toaddress, const string& amount) {
        m_fromaccount = fromacc;
        m_chainaddress = chainaddress;
        m_accountaddrtargetchain = toaddress;
        m_amount = amount;
    }

    std::string details() override
    {
        return StringFormat("\nCross chain transaction(Para to Eth) details:\n"
            "From:         %s\n"
            "Target chain: %s\n"
            "To:           %s\n"
            "Fund amount:  %s\n"
            "Name:         %s\n"
            "%s time: %s\n",
            (m_fromaccount.empty() ? "\"\"" : m_fromaccount),
            m_chainaddress,
            m_accountaddrtargetchain, m_amount, m_name,
            (m_isImported ? "Imported" : "Created"),
            toReadableTime(m_createdtime));
    }
};


//HC: eth to Para 交易
class EthToParaExecutor : public CrossChainExecutorBase {

public:
    string m_fromaddress;
    string m_paraaddress;


    string m_scriptpubkey;
    string m_signature;
    string m_publickey;
    string m_genesisblockhash;  //HC: eth genesis block

public:
    EthToParaExecutor(const std::string& name) : CrossChainExecutorBase(name)
    {
        setState(new SettlementStartState(nullptr));
    }

    EthToParaExecutor(SettlementImportStartState* imp_state) :
        CrossChainExecutorBase(StringFormat("imported-%s", imp_state->m_ethtxhash.substr(0, 10)))
    {
        setState(imp_state);
        m_isImported = true;
    }


    void initEnv(const string& fromaddress, const string& paraaddress, const string& amount) {
        m_fromaddress = fromaddress;
        m_paraaddress = paraaddress;
        m_amount = amount;
    }

    std::string details() override
    {
        return StringFormat("\nCross chain transaction(Eth to Para) details:\n"
        "From:         %s\n"
        "To:           %s\n"
        "Fund amount:  %s\n"
        "Name:         %s\n"
        "Created time: %s\n",
        m_fromaddress, m_paraaddress, m_amount, m_name, toReadableTime(m_createdtime));
    }

    bool isCompleted() {
        return m_state->isCompleted();
    }
};

}
