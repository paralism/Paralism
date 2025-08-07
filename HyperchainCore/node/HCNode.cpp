/*Copyright 2016-2024 hyperchain.net (Hyperchain)

Distributed under the MIT software license, see the accompanying
file COPYING or https://opensource.org/licenses/MIT.

Permission is hereby granted, free of charge, to any person obtaining a copy of this
software and associated documentation files (the "Software"), to deal in the Software
without restriction, including without limitation the rights to use, copy, modify, merge,
publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons
to whom the Software is furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all copies or
substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED,
INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR
PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE
FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR
OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
DEALINGS IN THE SOFTWARE.
*/

#include <iostream>
#include <random>
#include <sstream>
#include <iomanip>
using namespace std;

#include "../newLog.h"
#include "UdpAccessPoint.hpp"
#include "TcpAccessPoint.hpp"
#include "UInt128.h"
#include "NodeManager.h"
#include "../util/common.h"
#include "../headers/commonstruct.h"
#include "HCNode.h"

#include <cpprest/json.h>
#include <boost/uuid/uuid.hpp>
#include <boost/uuid/uuid_io.hpp>
#include <boost/uuid/uuid_generators.hpp>
using namespace web;

/**
 * CNode implementation
 */

utility::string_t UdpAccessPoint::CLASSNAME_U = _XPLATSTR("UdpAP");
std::string UdpAccessPoint::CLASSNAME = "UdpAP";;
utility::string_t TcpAccessPoint::CLASSNAME_U = _XPLATSTR("TcpAP");
std::string TcpAccessPoint::CLASSNAME = "TcpAP";

static const utility::string_t LocalChainJsonKey = _XPLATSTR("chains");

string LocalChainInformation::serialize()
{
    json::value obj;
    obj[_XPLATSTR("hid")] = json::value::number(hId);
    obj[_XPLATSTR("chainid")] = json::value::number(chainId);
    obj[_XPLATSTR("localid")] = json::value::number(localId);
    //obj[_XPLATSTR("hhash")] = json::value::string(s2t(hhash.toHexString()));
    obj[_XPLATSTR("module")] = json::value::string(s2t(modulename));

    std::stringstream oss;
    obj.serialize(oss);
    return oss.str();
}


HCNode::HCNode(const CUInt128 & nodeid) : _nodeid(nodeid)
{
}

HCNode::HCNode(CUInt128 && nodeid) : _nodeid(std::move(nodeid))
{
}

HCNode::HCNode(HCNode && node) : _nodeid(std::move(node._nodeid)), 
    _aplist(std::move(node._aplist)), 
    _localchainlist(std::move(node._localchainlist))
{
}

HCNode::HCNode(const HCNode & node) : _nodeid(node._nodeid)
{
    _aplist.clear();
    for (auto &ap : node._aplist) {
        _aplist.push_back(ap);
    }

    _localchainlist.clear();
    for (auto &ap : node._localchainlist) {
        _localchainlist.push_back(ap);
    }
}

void HCNode::registerType()
{
    if (_isReg) {
        return;
    }
    _apFactory.RegisterType<IAccessPoint, UdpAccessPoint, string>(UdpAccessPoint::CLASSNAME);
    _apFactory.RegisterType<IAccessPoint, TcpAccessPoint, string>(TcpAccessPoint::CLASSNAME);
    _isReg = true;
}

string HCNode::generateNodeId()
{
    return CCommonStruct::generateNodeId();
}

HCNode & HCNode::operator=(const HCNode & node)
{
    _nodeid = node._nodeid;
    _aplist.clear();
    for (auto &ap : node._aplist) {
        _aplist.push_back(ap);
    }

    _localchainlist.clear();
    for (auto &ap : node._localchainlist) {
        _localchainlist.push_back(ap);
    }
    return *this;
}

bool HCNode::getUDPAP(string& ip, int& nport) const
{
    if (_aplist.size() > 0) {
        UdpAccessPoint* ap = reinterpret_cast<UdpAccessPoint*>(_aplist.begin()->get());
        if (ap) {
            ip = ap->ip();
            nport = ap->port();
            return true;
        }
    }
    return false;
}

int HCNode::send(const string &msgbuf) const
{
    //HC: Choose the first access point to send.
    //HC: TODO: improve performance
    for (auto &ap : _aplist) {
        return ap->write(msgbuf.c_str(), msgbuf.size());
    }
    return 0;
}


string HCNode::serialize()
{
    json::value objAP = json::value::array(_aplist.size());

    int i = 0;
    for (auto &ap : _aplist) {
        objAP[i++] = json::value::parse(s2t(ap->serialize()));
    }

    json::value obj;
    obj[_XPLATSTR("ap")] = objAP;
    obj[_XPLATSTR("id")] = json::value::string(s2t(_nodeid.ToHexString()));


    json::value objlocalchain = json::value::array(_localchainlist.size());

    i = 0;
    for (auto& chain : _localchainlist) {
        objlocalchain[i++] = json::value::parse(s2t(chain->serialize()));
    }
    obj[LocalChainJsonKey] = objlocalchain;

    std::stringstream oss;
    obj.serialize(oss);
    return oss.str();
}

void HCNode::parse(const string &nodeinfo, HCNode &node)
{
    json::value obj = json::value::parse(s2t(nodeinfo));

    if (!obj.has_field(_XPLATSTR("id"))) {
        throw std::invalid_argument("Invalid CNode type");
    }

    string id = t2s(obj[_XPLATSTR("id")].as_string());
    node.setNodeId(id);

    string aplist = t2s(obj[_XPLATSTR("ap")].serialize());
    node.parseAP(aplist);

    if (obj.has_field(LocalChainJsonKey)) {
        string localchaininfo = t2s(obj[LocalChainJsonKey].serialize());
        node.parseLocalChains(localchaininfo);
    }
}


string HCNode::serializeAP() const
{
    json::value obj = json::value::array(_aplist.size());

    int i = 0;
    for (auto &ap : _aplist) {
        obj[i] = json::value::parse(s2t(ap->serialize()));
        ++i;
    }
    std::stringstream oss;
    obj.serialize(oss);
    return oss.str();
}


void HCNode::parseAP(const string &aps)
{
    json::value obj = json::value::parse(s2t(aps));
    assert(obj.is_array());

    _aplist.clear();
    registerType();
    size_t num = obj.size();
    for (size_t i = 0; i < num; i++) {
        if (!obj[i].has_field(_XPLATSTR("typename"))) {
            throw std::invalid_argument("Invalid access point type");
        }

        string tn = t2s(obj[i][_XPLATSTR("typename")].as_string());
        string objstr = t2s(obj[i].serialize());
        shared_ptr<IAccessPoint> ap = _apFactory.CreateShared<IAccessPoint>(tn, objstr);
        if (!ap) {
            throw std::invalid_argument("Failed to create access point");
        }
        _aplist.push_back(ap);
    }
}


std::string HCNode::serializeLocalChains() const
{
    json::value obj = json::value::array(_localchainlist.size());

    int i = 0;
    for (auto& chain : _localchainlist) {
        obj[i] = json::value::parse(s2t(chain->serialize()));
        ++i;
    }

    json::value lcsjson = json::value::object();
    lcsjson[LocalChainJsonKey] = obj;

    std::stringstream oss;
    lcsjson.serialize(oss);
    return oss.str();
}



void HCNode::updateLocalChains(const std::map<string, T_APPTYPE>& nodeApps)
{
    json::value obj = json::value::array();
    int i = 0;
    for (auto& app : nodeApps) {
        json::value appjson = json::value::object();
        uint32_t hid = 0;
        uint16 chainnum = 0;
        uint16 localid = 0;

        app.second.get(hid, chainnum, localid);
        if (hid >= 0 && chainnum > 0 && localid > 0) {
            appjson[_XPLATSTR("hid")] = hid;
            appjson[_XPLATSTR("chainid")] = chainnum;
            appjson[_XPLATSTR("localid")] = localid;
            //appjson[L"hhash"] = ;
            appjson[_XPLATSTR("module")] = json::value::string(s2t(app.first));
            obj[i++] = appjson;
        }
    }
    json::value lcsjson = json::value::object();
    lcsjson[LocalChainJsonKey] = obj;
    parseLocalChains(t2s(lcsjson.serialize()));

}

void HCNode::parseLocalChains(const string& lcs)
{
    json::value objtop = json::value::parse(s2t(lcs));

    if (!objtop.has_field(LocalChainJsonKey)) {
        return;
    }

    json::value obj = objtop[LocalChainJsonKey];
    _localchainlist.clear();
    size_t num = obj.size();
    for (size_t i = 0; i < num; i++) {
        shared_ptr<LocalChainInformation> lci = make_shared<LocalChainInformation>();

        lci->hId = obj[i][_XPLATSTR("hid")].as_integer();
        lci->chainId = obj[i][_XPLATSTR("chainid")].as_integer();
        lci->localId = obj[i][_XPLATSTR("localid")].as_integer();
        //lci->hhash = CCommonStruct::StrToHash256(t2s(obj[i][_XPLATSTR("hhash")].as_string()));

        lci->modulename = t2s(obj[i][_XPLATSTR("module")].as_string());

        _localchainlist.push_back(lci);
    }
}

