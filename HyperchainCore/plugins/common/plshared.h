/*Copyright 2016-2022 hyperchain.net (Hyperchain)

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

#pragma once


#include "json/json_spirit_reader_template.h"
#include "json/json_spirit_writer_template.h"
#include "json/json_spirit_utils.h"
#include "json/json_spirit_value.h"
#include "util.h"
#include "key.h"

using namespace json_spirit;

extern CWallet* pwalletMain;

#define likely_wallet_locked \
{ \
   if (pwalletMain->IsLocked()) { \
       throw runtime_error("Wallet is already locked, please use 'wpass' to unlock firstly"); \
   } \
}

Array toArray(const list<string>& cmdlist);

template<typename F, typename... Args>
Value CallWithLock(bool uselock, F f, Args&&... args)
{
    int nTry = 150;
    CCriticalBlockT<pcstName> criticalblock(cs_main, __FILE__, __LINE__);
    while (nTry-- > 0) {
        if (uselock && !criticalblock.TryEnter(__FILE__, __LINE__)) {
            boost::this_thread::sleep_for(boost::chrono::milliseconds(100));
        }
        else {
            Value result;
            try {
                CTryCriticalBlock cs(pwalletMain->cs_wallet, "cs_wallet", __FILE__, __LINE__);
                if (!cs.Entered()) {
                    goto busying;
                }
                result = f(std::forward<Args>(args)...);
            }
            catch (std::exception& e) {
                return e.what();
            }
            catch (Object& objError) {
                result = objError;
            }

            return result;
        }
    }
busying:
    Object error;
    error.push_back(Pair("cs_wallet", "The operator cannot be executed for internal busying(maybe mining for coin)"));
    return error;
}

template<typename F>
string doAction(F f, const list<string>& cmdlist, bool fhelp = false, bool uselock = true, std::function<Array(const list<string>&)> funca = toArray)
{
    Value ret;
    Array arr;
    if (fhelp) {
        Value result;
        try {
            ret = f(arr, true);
            return write_string(ret, true);
        }
        catch (std::exception& e) {
            return e.what();
        }
        catch (Object& objError) {
            result = objError;
        }
    }

    arr = funca(cmdlist);

    ret = CallWithLock(uselock, f, arr, false);
    if (ret.is_null()) {
        return "ok!";
    }

    if (ret.type() == str_type) {
        return ret.get_str();
    }

    return write_string(ret, true);
}


std::string PrKey2WIF(const CPrivKey& prikey, bool isCompressed);
bool WIF2PrKey(const string& strprivkey, bool& isCompressed, std::vector<unsigned char>& vchPriKey);
int impwalletkey(const string& strprivkey, const string& strlabel, string& msg);
Value impwalletkeysfromfile(const Array& params, bool fHelp);

Value expwalletkey(const Array& params, bool fHelp);
Value expwalletkeystofile(const Array& params, bool fHelp);

Value setdefaultkey(const Array& params, bool fHelp);

string MakeNewKeyPair();




