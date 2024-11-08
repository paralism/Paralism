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
// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2011 The Bitcoin developers
// Distributed under the MIT/X11 software license, see the accompanying
// file license.txt or http://www.opensource.org/licenses/mit-license.php.

#ifndef __cplusplus
# error This header can only be compiled as C++.
#endif

#ifndef __INCLUDED_PROTOCOL_H__
#define __INCLUDED_PROTOCOL_H__

#include "serialize.h"
#include <string>
#include "uint256.h"

#include <boost/functional/hash.hpp>

extern bool fTestNet;
static inline unsigned short GetDefaultPort(const bool testnet = fTestNet)
{
    return testnet ? 18115 : 8115;
    return testnet ? 18333 : 8333;
}

//
// Message header
//  (4) message start
//  (12) command
//  (4) size
//  (4) checksum

extern unsigned char pchMessageStart[4];

class CMessageHeader
{
    public:
        CMessageHeader();
        CMessageHeader(const char* pszCommand, unsigned int nMessageSizeIn);

        std::string GetCommand() const;
        bool IsValid() const;

        IMPLEMENT_SERIALIZE
            (
             READWRITE(FLATDATA(pchMessageStart));
             READWRITE(FLATDATA(pchCommand));
             READWRITE(nMessageSize);
             if (nVersion >= 209)
             READWRITE(nChecksum);
            )

    // TODO: make private (improves encapsulation)
    public:
        enum { COMMAND_SIZE=12 };
        char pchMessageStart[sizeof(::pchMessageStart)];
        char pchCommand[COMMAND_SIZE];
        unsigned int nMessageSize;
        unsigned int nChecksum;
};

enum
{
    NODE_NETWORK = (1 << 0),
};

class CAddress
{
    public:
        CAddress();
        CAddress(unsigned int ipIn, unsigned short portIn=0, uint64 nServicesIn=NODE_NETWORK);
        explicit CAddress(const struct sockaddr_in& sockaddr, uint64 nServicesIn=NODE_NETWORK);
        explicit CAddress(const char* pszIn, int portIn, bool fNameLookup = false, uint64 nServicesIn=NODE_NETWORK);
        explicit CAddress(const char* pszIn, bool fNameLookup = false, uint64 nServicesIn=NODE_NETWORK);
        explicit CAddress(std::string strIn, int portIn, bool fNameLookup = false, uint64 nServicesIn=NODE_NETWORK);
        explicit CAddress(std::string strIn, bool fNameLookup = false, uint64 nServicesIn=NODE_NETWORK);

        void Init();

        IMPLEMENT_SERIALIZE
            (
             if (fRead)
             const_cast<CAddress*>(this)->Init();
             if (nType & SER_DISK)
             READWRITE(nVersion);
             //if ((nType & SER_DISK) || (nVersion >= 31402 && !(nType & SER_GETHASH)))
             READWRITE(nTime);
             READWRITE(nServices);
             READWRITE(FLATDATA(pchReserved)); // for IPv6
             READWRITE(ip);
             READWRITE(port);
            )

        friend bool operator==(const CAddress& a, const CAddress& b);
        friend bool operator!=(const CAddress& a, const CAddress& b);
        friend bool operator<(const CAddress& a, const CAddress& b);

        std::vector<unsigned char> GetKey() const;
        struct sockaddr_in GetSockAddr() const;
        bool IsIPv4() const;
        bool IsRFC1918() const;
        bool IsRFC3927() const;
        bool IsLocal() const;
        bool IsRoutable() const;
        bool IsValid() const;
        unsigned char GetByte(int n) const;
        std::string ToStringIPPort() const;
        std::string ToStringIP() const;
        std::string ToStringPort() const;
        std::string ToString() const;
        void print() const;

    // TODO: make private (improves encapsulation)
    public:
        uint64 nServices;
        unsigned char pchReserved[12];
        unsigned int ip;
        unsigned short port;

        // disk and network only
        unsigned int nTime;

        // memory only
        unsigned int nLastTry;
};

class CInv
{
    public:
        CInv();
        CInv(int typeIn, const uint256& hashIn);
        CInv(const std::string& strType, const uint256& hashIn);

        IMPLEMENT_SERIALIZE
        (
            READWRITE(type);
            READWRITE(hash);

            //HCE:
            if (type == 3 || type == 4) { //MSG_BLOCKEX MSG_BLOCKEX_R
                READWRITE(height);
            }
        )

        friend bool operator<(const CInv& a, const CInv& b);
        friend bool operator==(const CInv& a, const CInv& b);


        bool IsKnownType() const;
        const char* GetCommand() const;
        std::string ToString() const;
        void print() const;

        void SetNull() {
            height = 0;
            hash = 0;
        }


    // TODO: make private (improves encapsulation)
    public:
        int type;
        uint256 hash;
        int height = 0; //HCE:
};

//namespace boost {
        inline std::size_t hash_value(CInv const &s) {
            size_t seed = 0;
            for(int i = 0; i < 8; i++)
                boost::hash_combine(seed, s.hash[i]);
            boost::hash_combine(seed, s.height);
            return seed;
        }
//}

#endif // __INCLUDED_PROTOCOL_H__
