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
#include "globalconfig.h"
#include "headers.h"
#include "plshared.h"
#include "db/dbmgr.h"
#include "../dllmain.h"
#include "../../node/defer.h"

//2021-2-19 17:56:37
//when issue a new chain as Para, we need put all public-private-key pairs in old wallet into new wallet
//
//Usage:
//E:\workspace\git\buildwin64\bin\Debug>walletmerge -datadir=C:\hc -model=informal -oldwallet=wallet1.dat -newwallet=wallet.dat
//This upper command will read all public-private-key pairs in C:\hc\informal\wallet1.dat, and write them into C:\hc\informal\wallet.dat

class CDelTxWallet : public CWalletDB
{
public:
    CDelTxWallet(const string& sWalletFile) : CWalletDB(sWalletFile, "r+")
    {}

    bool exec()
    {
        CommadLineProgress progress;
        progress.Start();

        int nTotalCount = 0;

        try {
            for (;;) {
                int nCount = 0;
                //HC: A time of transaction operation, we only delete 10000 for Berkeley db lock limit which can also set by dbenv
                deleteTx(progress, nCount, 10000);
                nTotalCount += nCount;
                if (nCount < 10000) {
                    break;
                }
            }
            cout << strprintf("\n Deleted('tx') : %d\n", nTotalCount);
        } catch (DbException& dbe) {
            if (dbe.get_errno() == DB_NOTFOUND) {
                cout << " CDelTxWallet : " << dbe.what() << endl;
                return true;
            }
            cerr << " CDelTxWallet error: " << dbe.what() << endl;
            return false;
        }
    }

private:

    bool deleteTx(CommadLineProgress& progress, int& nDeletedCount, int nLimit)
    {
        std::string key = "tx";
        uint256 hash = 0;
        if (!TxnBegin())
            ThrowException(-1, "DB_ENV->txn_begin");

        Dbc* pcursor = GetCursor(GetTxn());
        if (!pcursor)
            ThrowException(-1, "DB->cursor");

        std::shared_ptr<Dbc*> sp(&pcursor, [this](Dbc** pCur) {
            if (*pCur != NULL)
                (*pCur)->close();
        });

        int nAdd = 0;

        unsigned int fFlags = DB_SET_RANGE;
        for (; !fShutdown;) {
            // Read next record
            CDataStream ssKey;
            if (fFlags == DB_SET_RANGE)
                ssKey << make_pair(key, hash);
            CDataStream ssValue;
            int ret = ReadAtCursor(pcursor, ssKey, ssValue, fFlags);
            fFlags = DB_NEXT;
            if (ret != 0)
                ThrowException(&pcursor, ret, "ReadAtCursor");

            // Unserialize
            string strType;
            uint256 hash;
            ssKey >> strType;

            if (strType == key) {
                ret = pcursor->del(0);
                if (0 != ret) {
                    ThrowException(&pcursor, ret, "cursor->del");
                }
                nDeletedCount++;
                nAdd++;

                if (nDeletedCount > nLimit) {
                    break;
                }
            }
            else {
                break;
            }

            if (nAdd > 1000) {
                uint256 h;
                ssKey >> h;
                progress.PrintStatus(nAdd, h.ToPreViewString().c_str());
                nAdd = 0;
            }
        }
        pcursor->close();
        pcursor = nullptr;
        TxnCommit();
        return true;
    }
};

class CMigrWallet : public CWalletDB
{
public:

    using CWalletDB::CWalletDB;

    CMigrWallet(const string &srcWalletFile, const string &dstWalletFile) :
        _srcWalletFile(srcWalletFile),
        _dstWalletFile(dstWalletFile),
        CWalletDB(dstWalletFile, "cr+")
    {}

    void Import()
    {
        CWallet dstWallet(_dstWalletFile);
        int nLoadWalletRet = LoadWallet(&dstWallet);
        if (nLoadWalletRet != DB_LOAD_OK) {
            cout << strprintf("Load %s error", _dstWalletFile.c_str());
            return;
        }

        cout << "Start wallet data import...\n";

        CMigrWallet srcW(_srcWalletFile, "r");

        if (!srcW.BulkImpWalletUser(this)) {
            throw runtime_error("CMigrWallet : can't import wallet users");
        }

        if (!srcW.BulkImpWalletKey(&dstWallet))
            throw runtime_error("CMigrWallet : can't import wallet key");

        if (!srcW.BulkImpWalletWKey(&dstWallet))
            throw runtime_error("CMigrWallet : can't import wallet wkey");

        if (!srcW.BulkImpWalletMKey(&dstWallet))
            throw runtime_error("CMigrWallet : can't import wallet mkey");

        if (!srcW.BulkImpWalletCKey(&dstWallet))
            throw runtime_error("CMigrWallet : can't import wallet ckey");

        if (!srcW.ReadDefaultKey(dstWallet.vchDefaultKey)) {
            throw runtime_error("CMigrWallet : can't import wallet default key");
        }
        if (!WriteDefaultKey(dstWallet.vchDefaultKey)) {
            throw runtime_error("CMigrWallet : can't import wallet default key");
        }

        //srcW.BulkLoadWalletPool(&dstWallet); //unused key, so not need to import
        if (!srcW.BulkImpWalletSettings(this)) {
            throw runtime_error("CMigrWallet : can't import wallet settings");
        }
    }

private:

    bool impKey(CWallet* pwallet, CDataStream& ssKeySecond, CDataStream& ssValue, std::vector<unsigned char>& vchPubKey)
    {
        ssKeySecond >> vchPubKey;
        vector<unsigned char> vchPrivKey;
        ssValue >> vchPrivKey;

        CPrivKey privkey;
        privkey.resize(vchPrivKey.size());
        std::copy(vchPrivKey.begin(), vchPrivKey.end(), privkey.begin());

        CKey keyPair;
        if (!keyPair.SetPrivKey(privkey)) {
            return "Incorrect private key\n";
        }

        CBitcoinAddress coinaddress = CBitcoinAddress(keyPair.GetPubKey());
        if (pwallet->HaveKey(coinaddress)) {
            //"Key pair has already been in wallet\n";
            return true;
        }
        else if (pwallet->AddKey(vchPubKey, keyPair)) {
            return true;
        }

        return false;
    }

    bool BulkImpWalletUser(CWalletDB* pDstWalletdb)
    {
        std::function<bool(CDataStream&, CDataStream&, string&)> fn = [this, pDstWalletdb](CDataStream& ssKeySecond,
            CDataStream& ssValue, string& strAddress) ->bool {

            ssKeySecond >> strAddress;
            string strname;
            ssValue >> strname;
            pDstWalletdb->WriteName(strAddress, strname);
            return true;
        };

        std::function<CDataStream(const string&, string&)> fnNext = [](const string& nextT,
            string& msgstatus) ->CDataStream {

            CDataStream ssNxtKey;
            ssNxtKey << make_pair(string("name"), nextT);
            msgstatus = strprintf("name : %s", nextT.c_str());  //HC: status message
            return ssNxtKey;
        };

        CDataStream ssKey;
        ssKey << make_pair(string("name"), string(""));

        if (!BulkLoad("name", ssKey, fn, fnNext)) {
            return false;
        }
        return true;
    }

    bool BulkImpWalletKey(CWallet* pwallet)
    {
        std::function<bool(CDataStream&, CDataStream&, std::vector<unsigned char>&)> fn =
            std::bind(&CMigrWallet::impKey, this, pwallet, std::placeholders::_1, std::placeholders::_2, std::placeholders::_3);

        std::function<CDataStream(const std::vector<unsigned char>&, string&)> fnNext = [](const std::vector<unsigned char>& nextT,
            string& msgstatus) ->CDataStream {

            CDataStream ssNxtKey;
            ssNxtKey << make_pair(string("key"), nextT);
            msgstatus = "key : ******";  //HC: status message
            return ssNxtKey;
        };

        CDataStream ssKey;
        std::vector<unsigned char> veckey;
        ssKey << make_pair(string("key"), veckey);

        if (!BulkLoad("key", ssKey, fn, fnNext)) {
            return false;
        }
        return true;
    }

    bool BulkImpWalletWKey(CWallet* pwallet)
    {
        std::function<bool(CDataStream&, CDataStream&, std::vector<unsigned char>&)> fn =
            std::bind(&CMigrWallet::impKey, this, pwallet, std::placeholders::_1, std::placeholders::_2, std::placeholders::_3);

        std::function<CDataStream(const std::vector<unsigned char>&, string&)> fnNext = [](const std::vector<unsigned char>& nextT,
            string& msgstatus) ->CDataStream {

            CDataStream ssNxtKey;
            ssNxtKey << make_pair(string("wkey"), nextT);
            msgstatus = "wallet key : ******";  //HC: status message
            return ssNxtKey;
        };

        CDataStream ssKey;
        std::vector<unsigned char> veckey;
        ssKey << make_pair(string("wkey"), veckey);

        if (!BulkLoad("wkey", ssKey, fn, fnNext)) {
            return false;
        }
        return true;
    }

    //HC: Encrypt bitcoin's key pair using vMasterkey
    //HC: vMasterkey is plain text, kMasterKey contains cipher text
    //HC: crypter.Encrypt(vMasterKey, kMasterKey.vchCryptedKey), see CWallet::EncryptWallet(const string& strWalletPassphrase)
    bool BulkImpWalletMKey(CWallet* pwallet)
    {
        std::function<bool(CDataStream&, CDataStream&, unsigned int&)> fn = [pwallet](CDataStream& ssKeySecond,
            CDataStream& ssValue, unsigned int& nID) ->bool {

            ssKeySecond >> nID;
            CMasterKey kMasterKey;
            ssValue >> kMasterKey;
            if (pwallet->mapMasterKeys.count(nID) != 0)
                return false; //DB_CORRUPT;
            pwallet->mapMasterKeys[nID] = kMasterKey;
            if (pwallet->nMasterKeyMaxID < nID)
                pwallet->nMasterKeyMaxID = nID;
            return true;
        };

        std::function<CDataStream(const unsigned int&, string&)> fnNext = [](const unsigned int& nextT,
            string& msgstatus) ->CDataStream {

            CDataStream ssNxtKey;
            ssNxtKey << make_pair(string("mkey"), nextT);
            msgstatus = "mkey : ******";  //HC: status message
            return ssNxtKey;
        };

        CDataStream ssKey;
        ssKey << make_pair(string("mkey"), 0);
        if (!BulkLoad("mkey", ssKey, fn, fnNext)) {
            return false;
        }
        return true;
    }

    //HC: crypt keys
    bool BulkImpWalletCKey(CWallet* pwallet)
    {
        std::function<bool(CDataStream&, CDataStream&, std::vector<unsigned char>&)> fn =
            std::bind(&CMigrWallet::impKey, this, pwallet, std::placeholders::_1, std::placeholders::_2, std::placeholders::_3);

        std::function<CDataStream(const std::vector<unsigned char>&, string&)> fnNext = [](const std::vector<unsigned char>& nextT,
            string& msgstatus) ->CDataStream {

            CDataStream ssNxtKey;
            ssNxtKey << make_pair(string("ckey"), nextT);
            msgstatus = "ckey : ******";  //HC: status message
            return ssNxtKey;
        };

        CDataStream ssKey;
        std::vector<unsigned char> veckey;
        ssKey << make_pair(string("ckey"), veckey);

        if (!BulkLoad("ckey", ssKey, fn, fnNext)) {
            return false;
        }
        return true;
    }

    bool BulkImpWalletSettings(CWalletDB *pDstWalletdb)
    {
        std::function<bool(CDataStream&, CDataStream&, string&)> fn = [this, pDstWalletdb](CDataStream& ssKeySecond,
            CDataStream& ssValue, string& strKey) ->bool {

            //HC: read all unused key pairs
            ssKeySecond >> strKey;

            // Options
            int nValue = 0;

            if (strKey == "fGenerateBitcoins" ||
                strKey == "nTransactionFee" ||
                strKey == "fLimitProcessors" ||
                strKey == "nLimitProcessors" ||
                strKey == "fMinimizeToTray" ||
                strKey == "fMinimizeOnClose" ||
                strKey == "fUseProxy" ||
                strKey == "addrProxy" ||
                strKey == "fUseUPnP" ) {
                ssValue >> nValue;
                pDstWalletdb->WriteSetting(strKey, nValue);
            }

            return true;
        };

        std::function<CDataStream(const string&, string&)> fnNext = [](const string& nextT,
            string& msgstatus) ->CDataStream {

            CDataStream ssNxtKey;
            ssNxtKey << make_pair(string("setting"), nextT);
            msgstatus = "setting : ******";  //HC: status message
            return ssNxtKey;
        };

        CDataStream ssKey;
        ssKey << make_pair(string("setting"), string(""));
        if (!BulkLoad("setting", ssKey, fn, fnNext)) {
            return false;
        }
        return true;
    }

private:
    string _srcWalletFile;
    string _dstWalletFile;
};


void exportWalletKeystoFile(const string &walletfile, const string &exportfile, bool isCompressed)
{
    std::unique_ptr<CWallet> pwalletM(new CWallet(walletfile));

    int nLoadWalletRet = CWalletDB(walletfile, "r+").LoadWallet(pwalletM.get());

    string strErrors;
    if (nLoadWalletRet != DB_LOAD_OK) {
        if (nLoadWalletRet == DB_CORRUPT)
            strErrors = _("Error loading wallet.dat: Wallet corrupted");
        else if (nLoadWalletRet == DB_TOO_NEW)
            strErrors = _("Error loading wallet.dat: Wallet requires newer version");
        else
            strErrors = _("Error loading wallet.dat");
        throw runtime_error(strErrors);
    }

    if (pwalletM->IsLocked()) {
        string spass;
        cout << "The wallet has encrypted, please input passphrase: ";
        getline(std::istream(cin.rdbuf()), spass);
        if (!pwalletM->Unlock(spass)) {
            throw runtime_error("Error: The wallet passphrase entered was incorrect.");
        }
    }

    ofstream ff(exportfile);
    ff.exceptions(std::ofstream::failbit | std::ofstream::badbit);
    if (!ff) {
        throw runtime_error(StringFormat("%s cannot be opened", exportfile));
    }

    CommadLineProgress progress;
    progress.Start();

    int64_t nCount = 0;
    bool r = pwalletM->AllOfKeys([&ff, &nCount, &progress, isCompressed](const CKey& keyPair) ->bool {
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
        throw runtime_error("Failed to export wallet keys");
    }

    ff.flush();
}


void ShowUsage()
{
    cout << "\nSelect command:\n";
    cout << "Press '?' or 'help' for help" << endl;
    cout << "Press 'm' to merge wallets" << endl;
    cout << "Input 'del' to delete all tx in wallet" << endl;
    cout << "Input 'exp' to export all key pairs" << endl;
    cout << "Press 'q' for exit" << endl;
}

//"walletmgr -datadir=path -model=[informal|sandbox|formal]\n";
//"For example : walletmgr -datadir=C:\\hc -model=informal\n";
int main(int argc, char* argv[])
{
    SoftwareInfo();
    AppParseParameters(argc, argv);

    string strDataDir = GetDataDir();

    cout <<
        strprintf("This program merges/exports key pairs, default key, users, settings of two wallets for Paracoin\n"
            "Please put wallet files into %s ", strDataDir.c_str()) << endl;

    ShowUsage();

    while (true) {

        cout << "WM $ ";
        string sInput;
        getline(std::istream(cin.rdbuf()), sInput);

        if (sInput == "?" || sInput == "help") {
            ShowUsage();
            continue;
        }

        if (sInput == "q") {
            break;
        }

        if (sInput == "exp") {
            cout << strprintf("Work directory is %s\n", strDataDir.c_str());

            string sWalletFile;
            cout << "Please input wallet short file name: ";
            getline(std::istream(cin.rdbuf()), sWalletFile);

            string sexportfile;
            cout << "Please input file name saving keys: ";
            getline(std::istream(cin.rdbuf()), sexportfile);
            sexportfile.insert(0, "/");
            sexportfile.insert(0, strDataDir);

            try {
                bool isCompressed = true;
                exportWalletKeystoFile(sWalletFile, sexportfile, isCompressed);
            }
            catch (std::exception& e) {
                cout << e.what() << endl;
                continue;
            }
            cout << "Exported successfully\n";
        }

        if (sInput == "del") {

            cout << strprintf("Work directory is %s\n", strDataDir.c_str());
            cout << "Warning: All 'tx' data will be deleted in wallet file and cannot restore\n";

            string sWalletFile;
            cout << "Please input wallet short file name: ";
            getline(std::istream(cin.rdbuf()), sWalletFile);

            try {
                CDelTxWallet w(sWalletFile);
                if (!w.exec()) {
                    cout << "Error occurred\n";
                    continue;
                }
            }
            catch (std::exception& e) {
                cout << e.what() << endl;
                continue;
            }
            cout << "Wallet has cleaned 'tx' data successfully\n";
        }

        if (sInput == "m") {

            cout << strprintf("Work directory is %s\n", strDataDir.c_str());

            string srcWalletFile;
            cout << "Please input source wallet short file name: ";
            getline(std::istream(cin.rdbuf()), srcWalletFile);

            string dstWalletFile;
            cout << "Please input destination wallet short file name(will create if not exist): ";
            getline(std::istream(cin.rdbuf()), dstWalletFile);

            CMigrWallet migr(srcWalletFile, dstWalletFile);

            cout << "Start wallet import...";
            try {
                migr.Import();
            } catch (std::exception &e) {
                cout << e.what() << endl;
                continue;
            }
            cout << "Wallet has imported successfully\n";
        }
    }

    DBFlush(true); //HC: remove archive log
    return 0;
}