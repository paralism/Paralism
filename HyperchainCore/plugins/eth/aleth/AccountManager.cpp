// Aleth: Ethereum C++ client, tools and libraries.
// Copyright 2016-2019 Aleth Authors.
// Licensed under the GNU General Public License, Version 3.

#include <libdevcore/SHA3.h>
#include <libdevcore/FileSystem.h>
#include <libdevcore/CommonIO.h>
#include <libethcore/KeyManager.h>
#include "AccountManager.h"
using namespace std;
using namespace dev;
using namespace dev::eth;

void AccountManager::streamAccountHelp(ostream& _out, const string& lineprefix)
{
    _out << lineprefix << "   account list                                List all keys available in wallet\n"
         << lineprefix << "   account new                                 Create a new key and add it to wallet\n"
         << lineprefix << "   account update [<uuid>|<address> , ... ]    Decrypt and re-encrypt keys\n"
         << lineprefix << "   account import [<uuid>|<file>|<secret-hex>] Import keys from given source and "
            "place in wallet\n";
}

void AccountManager::streamWalletHelp(ostream& _out, const string& lineprefix)
{
    _out << lineprefix << "   wallet import <file>                        Import a presale wallet\n\n";
}

bool AccountManager::contain(const h160& acc)
{
    if (!openWallet())
        return false;
    for (auto const& a : m_keyManager->accounts())
        if (a == acc)
        {
            return true;
        }
    return false;
}

std::list<dev::h160> AccountManager::addresses()
{
    std::list<dev::h160> alladdress;

    openWallet();
    if (!m_keyManager->store().keys().empty()) {
        //"No keys found.\n";
        //vector<u128> bare;
        AddressHash got;
        for (auto const& u : m_keyManager->store().keys())
        {
            if (Address a = m_keyManager->address(u))
            {
                got.insert(a);
                alladdress.push_back(a);
            }
            //else
            //    bare.push_back(u);
        }
        for (auto const& a : m_keyManager->accounts())
            if (!got.count(a)) {
                alladdress.push_back(a);
            }

        //for (auto const& u : bare)
        //{
        //    cout << "Account #" << k << ": " << toUUID(u) << " (Bare)\n";
        //    k++;
        //}
    }

    return alladdress;
}

bool AccountManager::execute(int argc, const char** argv)
{
	if (string(argv[1]) == "wallet")
	{
		if (3 < argc && string(argv[2]) == "import")
		{
			if (!openWallet())
				return false;
			string file = argv[3];
			string name = "presale wallet";
			string pw;
			try
			{
				KeyPair k = m_keyManager->presaleSecret(
					contentsString(file),
					[&](bool){ return (pw = getPassword("Enter the passphrase for the presale key: "));}
				);
				m_keyManager->import(k.secret(), name, pw, "Same passphrase as used for presale key");
				cout << "  Address: {" << k.address().hex() << "}\n";
			}
			catch (Exception const& _e)
			{
				if (auto err = boost::get_error_info<errinfo_comment>(_e))
					cout << "  Decryption failed: " << *err << "\n";
				else
					cout << "  Decryption failed: Unknown reason.\n";
				return false;
			}
		}
		else
			streamWalletHelp(cout);
		return true;
	}
	else if (string(argv[1]) == "account")
	{
		if (argc < 3 || string(argv[2]) == "list")
		{
			openWallet();
			if (m_keyManager->store().keys().empty())
				cout << "No keys found.\n";
			else
			{
				vector<u128> bare;
				AddressHash got;
				int k = 0;
				for (auto const& u: m_keyManager->store().keys())
				{
					if (Address a = m_keyManager->address(u))
					{
						got.insert(a);
						cout << "Account #" << k << ": {" << a.hex() << "}\n";
						k++;
					}
					else
						bare.push_back(u);
				}
				for (auto const& a: m_keyManager->accounts())
					if (!got.count(a))
					{
						cout << "Account #" << k << ": {" << a.hex() << "}" << " (Brain)\n";
						k++;
					}
				for (auto const& u: bare)
				{
					cout << "Account #" << k << ": " << toUUID(u) << " (Bare)\n";
					k++;
				}
			}
		}
		else if (2 < argc && string(argv[2]) == "new")
		{
			openWallet();
			string name;
			string lock;
			string lockHint;
			lock = createPassword("Enter a passphrase with which to secure this account:");
			auto k = makeKey();
			h128 u = m_keyManager->import(k.secret(), name, lock, lockHint);
			cout << "Created key " << toUUID(u) << "\n";
			cout << "  Address: " << k.address().hex() << "\n";
		}
		else if (3 < argc && string(argv[2]) == "import")
		{
			openWallet();
			h128 u = m_keyManager->store().importKey(argv[3]);
			if (!u)
			{
				cerr << "Error: reading key file failed\n";
				return false;
			}
			string pw;
			bytesSec s = m_keyManager->store().secret(u, [&](){ return (pw = getPassword("Enter the passphrase for the key: ")); });
			if (s.empty())
			{
				cerr << "Error: couldn't decode key or invalid secret size.\n";
				return false;
			}
			else
			{
				string lockHint;
				string name;
				m_keyManager->importExisting(u, name, pw, lockHint);
				auto a = m_keyManager->address(u);
				cout << "Imported key " << toUUID(u) << "\n";
				cout << "  Address: " << a.hex() << "\n";
			}
		}
		else if (3 < argc && string(argv[2]) == "update")
		{
			openWallet();
			for (int k = 3; k < argc; k++)
			{
				string i = argv[k];
				h128 u = fromUUID(i);
				if (isHex(i) || u != h128())
				{
					string newP = createPassword("Enter the new passphrase for the account " + i + ": ");
					auto oldP = [&](){ return getPassword("Enter the current passphrase for the account " + i + ": "); };
					bool recoded = false;
					if (isHex(i))
					{
						recoded = m_keyManager->store().recode(
							Address(i),
							newP,
							oldP,
							dev::KDF::Scrypt
						);
					}
					else if (u != h128())
					{
						recoded = m_keyManager->store().recode(
							u,
							newP,
							oldP,
							dev::KDF::Scrypt
						);
					}
					if (recoded)
						cerr << "Re-encoded " << i << "\n";
					else
						cerr << "Couldn't re-encode " << i << "; key does not exist, corrupt or incorrect passphrase supplied." << "\n";
				}
				else
					cerr << "Couldn't re-encode " << i << "; does not represent an address or uuid." << "\n";
			}
		}
		else
			streamAccountHelp(cout);
		return true;
	}
	else
		return false;
}

string AccountManager::createPassword(string const& _prompt) const
{
	string ret;
	while (true)
	{
		ret = getPassword(_prompt);
		string confirm = getPassword("Please confirm the passphrase by entering it again: ");
		if (ret == confirm)
			break;
		cout << "Passwords were different. Try again." << "\n";
	}
	return ret;
}

//HCE: generate key use as swapping, whose address value of first byte is equal to 1
extern "C" BOOST_SYMBOL_EXPORT void makeswapkey(vector<uint8_t>& key, vector<uint8_t>& addr) {
    bool icap = true;
    KeyPair k(Secret::random());
    while (icap && k.address()[0] != 1)
        k = KeyPair(Secret(sha3(k.secret().ref())));

    Secret s = k.secret();
    Address a = k.address();

    auto r = s.ref();
    std::copy(r.begin(), r.end(), std::back_inserter(key));
    std::copy(a.begin(), a.end(), std::back_inserter(addr));
}

extern "C" BOOST_SYMBOL_EXPORT bool validateswapkey(const string &secret, const string &pub) {
    bool icap = true;

    Secret s(fromHex(secret));
    
    KeyPair k(s);
    Public x(fromHex(pub));

    if (k.pub() == x) {
        return true;
    }
    return false;
}


KeyPair AccountManager::makeKey() const
{
	bool icap = true;
	KeyPair k(Secret::random());
	while (icap && k.address()[0])
		k = KeyPair(Secret(sha3(k.secret().ref())));
	return k;
}

bool AccountManager::openWallet()
{
	if (!m_keyManager)
	{
		m_keyManager.reset(new KeyManager());
		if (m_keyManager->exists())
		{
			if (m_keyManager->load(std::string()) || m_keyManager->load(getPassword("Please enter your MASTER passphrase: ")))
				return true;
			else
			{
				cerr << "Couldn't open wallet. Please check passphrase." << "\n";
				return false;
			}
		}
		else
		{
			cerr << "Couldn't open wallet. Does it exist?" << "\n";
			return false;
		}
	}
	return true;
}
