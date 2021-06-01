/*Copyright 2016-2021 hyperchain.net (Hyperchain)

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

//////////////////////////////////////////////////////////////////////////
//all plugin module share
//////////////////////////////////////////////////////////////////////////
#include "headers.h"

#include "plshared.h"
#include "block.h"
#include "wallet.h"

extern CWallet* pwalletMain;

Array toArray(const list<string>& cmdlist)
{
    Array arr;
    auto cmd = cmdlist.begin();
    for (; cmd != cmdlist.end(); ++cmd)
        arr.push_back(*cmd);
    return arr;
}


std::string PrKey2WIF(const CPrivKey& prikey, bool isCompressed)
{
    std::vector<unsigned char> ret;
    auto pos = prikey.begin();
    std::advance(pos, 9);

    ret.push_back(0x80);
    std::copy(pos, pos + 32, std::back_inserter(ret));

    if (isCompressed) {
        ret.push_back(1);
    }

    return EncodeBase58Check(ret);
}

bool WIF2PrKey(const string& strprivkey, bool isCompressed, std::vector<unsigned char>& vchPriKey)
{


    if (!DecodeBase58Check(strprivkey, vchPriKey))
        return false;

    if (isCompressed) {
        //remove 01 (flag for compressed)
        auto pos = vchPriKey.end();
        if (*(--pos) != 1) {
            return false;
        }
        vchPriKey.erase(pos);
    }
    return true;
}

int impwalletkey(const string& strprivkey, string& msg)
{
    std::vector<unsigned char> vchPriKey;

    bool isWIFOK = true;
    size_t nSize = strprivkey.size();
    if (nSize == 52 && (strprivkey[0] == 'K' || strprivkey[0] == 'L')) {

        isWIFOK = WIF2PrKey(strprivkey, true, vchPriKey);
    }
    else if (nSize == 51 && strprivkey[0] == '5') {

        isWIFOK = WIF2PrKey(strprivkey, false, vchPriKey);
    }
    else {

        vchPriKey = ParseHex(strprivkey);
    }

    msg = "Incorrect private key";
    if (vchPriKey.size() == 0) {
        return -1;
    }

    if (vchPriKey[0] == 0x80 && vchPriKey.size() == 0x21) {
        vchPriKey.erase(vchPriKey.begin());
    }

    CPrivKey privkey;
    privkey.insert(privkey.end(), vchPriKey.begin(), vchPriKey.end());

    CKey keyPair;
    if (vchPriKey.size() != 0x20 || !isWIFOK || !keyPair.SetSecret(privkey)) {
        return -1;
    }

    likely_wallet_locked

    int ret = 0;
    CRITICAL_BLOCK(pwalletMain->cs_wallet)
    {
        CBitcoinAddress coinaddress = CBitcoinAddress(keyPair.GetPubKey());
        if (pwalletMain->HaveKey(coinaddress)) {
            msg = StringFormat("Key pair has already been in wallet, which address is %s", coinaddress.ToString());
            ret = 0;
        }
        else if (pwalletMain->AddKey(keyPair)) {
            pwalletMain->SetAddressBookName(coinaddress, "");
            msg = StringFormat("Key pair has imported successfully, which address is %s", coinaddress.ToString());
            ret = 1;
        }
        else {
            msg = "Failed to import key pair";
            ret = -1;
        }
    }
    return ret;
}

Value impwalletkeysfromfile(const Array& params, bool fHelp)
{
    if (fHelp || params.size() < 1) {
        throw runtime_error(COMMANDPREFIX " ikpf <filename> : import private keys from <filename>");
    }

    likely_wallet_locked

    string ret;
    const string& filename = params[0].get_str();
    ifstream ff(filename);
    if (!ff) {
        return (StringFormat("%s cannot be opened\n", filename));
    }

    string strLine;
    char pstrPriKey[128];
    int nImportedCount = 0;
    int nSkipCount = 0;
    int nLineNum = 0;

    CommadLineProgress progress;
    progress.Start();

    while (true) {
        std::getline(ff, strLine);
        if (!ff.good()) {
            break;
        }
        nLineNum++;
        if (std::sscanf(strLine.c_str(), "%*s %*s %s", pstrPriKey) != 1) {
            progress.PrintStatus(1, StringFormat("Invalid line:%d, stopped", nLineNum));
            break;
        }

        string msg;
        int r = impwalletkey(pstrPriKey, msg);

        progress.PrintStatus(1, "******");

        if (r < 0) {
            return StringFormat("%s : %s\n", msg, pstrPriKey);
        }
        r == 1 ? nImportedCount++ : nSkipCount++;
    }

    return StringFormat("Key imported: %d, Key existed : %d", nImportedCount, nSkipCount);
}

Value expwalletkeystofile(const Array& params, bool fHelp)
{
    if (fHelp || params.size() < 1) {
        throw runtime_error(COMMANDPREFIX " ekpf <filename> [WIF|WIFC] : export private keys(WIF|WIFC) to <filename>");
    }

    likely_wallet_locked

    Array ret;
    const string& filename = params[0].get_str();

    ofstream ff(filename);
    ff.exceptions(std::ofstream::failbit | std::ofstream::badbit);
    if (!ff) {
        ret.push_back(StringFormat("%s cannot be opened\n", filename));
        return ret;
    }

    CommadLineProgress progress;
    progress.Start();

    int64_t nCount = 0;

    bool isCompressed = true;
    if (params.size() > 1 && params[1].get_str() == "WIF") {
        isCompressed = false;
    }
    bool r = pwalletMain->AllOfKeys([&ff, &nCount, &progress, isCompressed](const CKey& keyPair) ->bool {

        CBitcoinAddress bitcoinaddr;
        bitcoinaddr.SetPubKey(keyPair.GetPubKey());

        CPrivKey pr = keyPair.GetPrivKey();

        ff << StringFormat("%s %s %s", bitcoinaddr.ToString(),
            ToHexString(keyPair.GetPubKey()),
            PrKey2WIF(pr, isCompressed)) << endl;
        nCount++;

        progress.PrintStatus(1, "******");
        return true;
    });

    if (!r) {
        ret.push_back("Failed to export wallet keys, maybe wallet unlock timeout");
        return ret;
    }

    ff.flush();

    return Value::null;
}

Value setdefaultkey(const Array& params, bool fHelp)
{
    if (fHelp || params.size() < 1) {
        throw runtime_error(COMMANDPREFIX " dkp <address> : specify the key pair whose address is <address> as default key");
    }

    likely_wallet_locked

    Array ret;
    CKey keyPair;
    CRITICAL_BLOCK(pwalletMain->cs_wallet)
    {
        CBitcoinAddress coinaddress = CBitcoinAddress(params[0].get_str());
        if (!pwalletMain->GetKey(coinaddress, keyPair)) {
            ret.push_back("Failed to find the key pair in wallet, maybe address is invalid");
            return ret;
        }
        pwalletMain->SetDefaultKey(keyPair.GetPubKey());
        pwalletMain->SetAddressBookName(coinaddress, "");

    }

    return Value::null;
}
