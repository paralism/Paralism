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

#pragma once

#include "UInt128.h"
#include "IAccessPoint.h"
#include "ObjectFactory.hpp"
#include "headers/commonstruct.h"

#include <list>
#include <memory>
#include <algorithm>
using namespace std;

class CUInt128;


typedef struct tagLocalChainInformation {
    int hId;        //HCE: Hyper Block Id
    int chainId;
    int localId;
    T_SHA256 hhash; //HCE: hash of hyper block
    string modulename;

    string serialize();

} LocalChainInformation, *PLocalChainInformation;

using SPLocalChainList = list <std::shared_ptr<LocalChainInformation>>;


class HCNode {
public:
    using APList = list <std::shared_ptr<IAccessPoint>>;

    HCNode() : _nodeid() {};

    HCNode(const HCNode& node);
    HCNode(HCNode&& node);

    HCNode(const CUInt128& nodeid);
    HCNode(CUInt128&& nodeid);

    HCNode& operator=(const HCNode& node);

    bool operator<(const HCNode & other) const
    {
        return _nodeid < other._nodeid;
    }


    static string generateNodeId();

    template<typename T, typename = typename std::enable_if<std::is_same<T, std::string>::value>::type>
    const string getNodeId() const
    {
        return string(_nodeid.ToHexString());
    }

    template<typename T, typename = typename std::enable_if<std::is_same<T, CUInt128>::value>::type>
    const CUInt128& getNodeId() const {
        return _nodeid;
    }

    template<typename T, typename = typename std::enable_if<std::is_same<T, CUInt128*>::value>::type>
    const CUInt128* getNodeId() const {
        return &_nodeid;
    }

    void getNodeId(uint8_t b[CUInt128::value]) const {
        _nodeid.ToByteArray(b);
    }

    bool isValid() {
        return !_nodeid.IsZero();
    }

    APList& getAPList() {
        return _aplist;
    }

    void setNodeId(const string& id) {
        _nodeid.SetHexString(id);
    }

    bool getUDPAP(string& ip, int& nport) const;

    int send(const string& msgbuf) const;

    string serialize();
    static void parse(const string& nodeinfo, HCNode& node);

    string serializeAP() const;
    void parseAP(const string& aps);

    string serializeLocalChains() const;
    void parseLocalChains(const string& lcs);

    void updateLocalChains(const std::map<string, T_APPTYPE>& nodeApps);

    void addAP(std::shared_ptr<IAccessPoint> ap) {
        _aplist.push_back(ap);
    }

    void removeAPs() {
        _aplist.clear();
    }

    void updateAP(std::shared_ptr<IAccessPoint> ap) {

        auto result = std::find_if(_aplist.begin(), _aplist.end(), [&](std::shared_ptr<IAccessPoint>& apCurr) {
            if (typeid(*(apCurr.get())) == typeid(*(ap.get()))) {
                apCurr = std::move(ap);
                return true;
            }
            return false;
        });

        if (result == _aplist.end()) {
            _aplist.push_front(ap);
        }
    }

private:
    void registerType();

private:

    CUInt128 _nodeid;
    APList _aplist;
    SPLocalChainList _localchainlist;

    //HCE: Access point object factory
    objectFactory _apFactory;
    bool _isReg = false;


};

using HCNodeSH = std::shared_ptr<HCNode>;
using HCNodeList = std::list<HCNode>;
