// Aleth: Ethereum C++ client, tools and libraries.
// Copyright 2015-2019 Aleth Authors.
// Licensed under the GNU General Public License, Version 3.

#include <libdevcore/vector_ref.h>
#include <libdevcore/Log.h>
#include <libdevcrypto/Common.h>
#include <libethcore/Exceptions.h>
#include "TransactionBase.h"
#include "EVMSchedule.h"

using namespace std;
using namespace dev;
using namespace dev::eth;

TransactionBase::TransactionBase(TransactionSkeleton const& _ts, Secret const& _s):
    m_type(_ts.creation ? Type::ContractCreation : Type::MessageCall),
    m_nonce(_ts.nonce),
    m_value(_ts.value),
    m_receiveAddress(_ts.to),
    m_gasPrice(_ts.gasPrice),
    m_gas(_ts.gas),
    m_data(_ts.data),
    m_sender(_ts.from)
{
    if (_ts.crosschain_recv) {
        m_type = Type::CrossChainPara2Eth;
    }

    if (_ts.crosschain_send) {
        m_type = Type::CrossChainEth2Para;
    }

    if (_s)
        sign(_s);
}

TransactionBase::TransactionBase(bytesConstRef _rlpData, CheckTransaction _checkSig)
{
    RLP rlp(_rlpData);
    try
    {
        //HC: 交易格式按照 EIP-2718 进行了改造，并且支持传统交易格式
        bool TxIsEIP2718 = false;
        if (rlp.isString()) {
            //格式为EIP-2718, 带交易类型
            bytesConstRef txData = rlp.toBytesConstRef(); //提取交易数据部分
            m_type = (Type)(txData[0]);
            rlp = RLP(txData.cropped(1));               //不含交易类型的交易数据

            TxIsEIP2718 = true;

        } else if (!rlp.isList())
            BOOST_THROW_EXCEPTION(InvalidTransactionFormat() << errinfo_comment("transaction RLP must be a list or string"));

        m_nonce = rlp[0].toInt<u256>();
        m_gasPrice = rlp[1].toInt<u256>();
        m_gas = rlp[2].toInt<u256>();
        if (!rlp[3].isData())
            BOOST_THROW_EXCEPTION(InvalidTransactionFormat()
                                  << errinfo_comment("recepient RLP must be a byte array"));

        if(!TxIsEIP2718)
            m_type = rlp[3].isEmpty() ? Type::ContractCreation : Type::MessageCall;

        m_receiveAddress = rlp[3].isEmpty() ? Address() : rlp[3].toHash<Address>(RLP::VeryStrict);

        m_value = rlp[4].toInt<u256>();

        if (!rlp[5].isData())
            BOOST_THROW_EXCEPTION(InvalidTransactionFormat()
                                  << errinfo_comment("transaction data RLP must be a byte array"));

        m_data = rlp[5].toBytes();

        u256 const v = rlp[6].toInt<u256>();
        h256 const r = rlp[7].toInt<u256>();
        h256 const s = rlp[8].toInt<u256>();

        if (isZeroSignature(r, s))
        {
            m_chainId = static_cast<uint64_t>(v);
            m_vrs = SignatureStruct{r, s, 0};
        }
        else
        {
            if (v > 36)
            {
                auto const chainId = (v - 35) / 2;
                if (chainId > std::numeric_limits<uint64_t>::max())
                    BOOST_THROW_EXCEPTION(InvalidSignature());
                m_chainId = static_cast<uint64_t>(chainId);
            }
            // only values 27 and 28 are allowed for non-replay protected transactions
            else if (v != 27 && v != 28)
                BOOST_THROW_EXCEPTION(InvalidSignature());

            auto const recoveryID =
                m_chainId.has_value() ? uint8_t{v - (u256{*m_chainId} * 2 + 35)} : uint8_t{v - 27};
            m_vrs = SignatureStruct{r, s, recoveryID};

            if (_checkSig >= CheckTransaction::Cheap && !m_vrs->isValid())
                BOOST_THROW_EXCEPTION(InvalidSignature());
        }

        //HC: get sender
        if (_checkSig == CheckTransaction::Everything)
            m_sender = sender();

        //HC: To cross chain transaction, first byte of address of sender is 1, more see function 'makeswapkey'
        //if (m_sender && m_sender->data()[0] == 1) {
        if(m_type == Type::CrossChainPara2Eth) {
            if (m_nonce != 0) {
                BOOST_THROW_EXCEPTION(InvalidNonce() << errinfo_comment("nonce shoule be zero for cross-chain transaction"));
            }
        }

        if (rlp.itemCount() > 9)
            BOOST_THROW_EXCEPTION(InvalidTransactionFormat() << errinfo_comment("too many fields in the transaction RLP"));
    }
    catch (Exception& _e)
    {
        _e << errinfo_name("invalid transaction format: " + toString(rlp) + " RLP: " + toHex(rlp.data()));
        throw;
    }
}

Address const& TransactionBase::safeSender() const noexcept
{
    try
    {
        return sender();
    }
    catch (...)
    {
        return ZeroAddress;
    }
}

//HC: 从v r s 中计算交易发送者账户地址
Address const& TransactionBase::sender() const
{
    if (!m_sender.is_initialized())
    {
        if (hasZeroSignature())
            m_sender = MaxAddress;
        else
        {
            if (!m_vrs)
                BOOST_THROW_EXCEPTION(TransactionIsUnsigned());

            auto p = recover(*m_vrs, sha3(WithoutSignature));
            if (!p)
                BOOST_THROW_EXCEPTION(InvalidSignature());
            m_sender = right160(dev::sha3(bytesConstRef(p.data(), sizeof(p))));
        }
    }
    return *m_sender;
}

SignatureStruct const& TransactionBase::signature() const
{
    if (!m_vrs)
        BOOST_THROW_EXCEPTION(TransactionIsUnsigned());

    return *m_vrs;
}

u256 TransactionBase::rawV() const
{
    if (!m_vrs)
        BOOST_THROW_EXCEPTION(TransactionIsUnsigned());

    int const vOffset = m_chainId.has_value() ? *m_chainId * 2 + 35 : 27;
    return m_vrs->v + vOffset;
}


void TransactionBase::sign(Secret const& _priv)
{
    auto sig = dev::sign(_priv, sha3(WithoutSignature));
    SignatureStruct sigStruct = *(SignatureStruct const*)&sig;
    if (sigStruct.isValid())
        m_vrs = sigStruct;
}

void TransactionBase::streamRLP(RLPStream& _s, IncludeSignature _sig, bool _forEip155hash, bool _forsha3) const
{
    if (m_type == Type::NullTransaction)
        return;

    RLPStream _s_legacy;

    _s_legacy.appendList((_sig || _forEip155hash ? 3 : 0) + 6);
    _s_legacy << m_nonce << m_gasPrice << m_gas;

    if (m_type == Type::MessageCall || m_type == Type::CrossChainPara2Eth || m_type == Type::CrossChainEth2Para)
        _s_legacy << m_receiveAddress;
    else
        _s_legacy << "";

    _s_legacy << m_value;
    if (!_forsha3) {
        _s_legacy << m_data;
    }
    else {
        //HC: 如果用于计算hash，需要区分交易类型
        if (m_type != TransactionBase::Type::CrossChainPara2Eth) {
            _s_legacy << m_data;
        }
        else {
            //HC: push only hash into RLP stream
            string paratxhash = parseCrossChainData();
            _s_legacy << toHex(paratxhash);
        }
    }

    if (_sig)
    {
        if (!m_vrs)
            BOOST_THROW_EXCEPTION(TransactionIsUnsigned());

        if (hasZeroSignature())
            _s_legacy << *m_chainId;
        else
            _s_legacy << rawV();

        _s_legacy << (u256)m_vrs->r << (u256)m_vrs->s;
    }
    else if (_forEip155hash)
        _s_legacy << *m_chainId << 0 << 0;

    if (m_type != Type::MessageCall && m_type != Type::ContractCreation) {
        const bytes &legacytx = _s_legacy.out();
        bytes rawtx;
        rawtx.push_back((char)m_type);
        rawtx.insert(rawtx.end(), legacytx.begin(), legacytx.end());
        _s.append(rawtx);
    }
    else {
        //It is legacy transaction
        bytes ret(_s_legacy.invalidate());
        _s.swapOut(ret);
    }
}

static const u256 c_secp256k1n("115792089237316195423570985008687907852837564279074904382605163141518161494337");

void TransactionBase::checkLowS() const
{
    if (!m_vrs)
        BOOST_THROW_EXCEPTION(TransactionIsUnsigned());

    if (m_vrs->s > c_secp256k1n / 2)
        BOOST_THROW_EXCEPTION(InvalidSignature());
}

void TransactionBase::checkChainId(uint64_t _chainId) const
{
    if (m_chainId.has_value() && *m_chainId != _chainId)
        BOOST_THROW_EXCEPTION(InvalidSignature());
}

int64_t TransactionBase::baseGasRequired(bool _contractCreation, bytesConstRef _data, EVMSchedule const& _es)
{
    int64_t g = _contractCreation ? _es.txCreateGas : _es.txGas;

    // Calculate the cost of input data.
    // No risk of overflow by using int64 as long as txDataNonZeroGas is quite small
    // (the value not in billions).
    for (auto i: _data)
        g += i ? _es.txDataNonZeroGas : _es.txDataZeroGas;
    return g;
}

h256 TransactionBase::sha3(IncludeSignature _sig) const
{
    if (_sig == WithSignature && m_hashWith)
        return m_hashWith;

    RLPStream s;
    streamRLP(s, _sig, isReplayProtected() && _sig == WithoutSignature, true);

    auto ret = dev::sha3(s.out());
    if (_sig == WithSignature)
        m_hashWith = ret;
    return ret;
}

std::string TransactionBase::parseCrossChainData() const
{
    int hid;
    int chainid;
    int localid;

    string paratxhash = parseCrossChainData(hid, chainid, localid);
    return paratxhash;
}


std::string TransactionBase::parseCrossChainData(int& hid, int& chainid, int& localid) const
{
    hid = -1;
    chainid = -1;
    localid = -1;
    if (!isCrossChainParaToEth()) {
        return "";
    }

    RLP rlp(data());
    if (!rlp.isList())
        BOOST_THROW_EXCEPTION(RLPException());

    string paratxhash = rlp[0].toString();  //HC: 与Eth交易对应的Para交易hash
    hid = rlp[1].toInt();                   //HC: Para交易所在超块号
    chainid = rlp[2].toInt();
    localid = rlp[3].toInt();
    return paratxhash;
}

std::string TransactionBase::parseCrossChainData(string& triaddr) const
{
    int hid;
    int chainid;
    int localid;

    string paratxhash = parseCrossChainData(hid, chainid, localid);

    std::stringstream stream;
    stream << "[" << hid << " " << chainid << " " << localid << "]";
    triaddr = stream.str();

    return paratxhash;
}
