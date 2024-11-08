/*Copyright 2016-2022 hyperchain.net (Hyperchain)

Distributed under the MIT software license, see the accompanying
file COPYING or https://opensource.org/licenses/MIT.

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

#ifndef __INTER_PUBLIC_H__
#define __INTER_PUBLIC_H__

#include <inttypes.h>

#include<iostream>
#include<vector>
#include <cstdio>
#ifdef WIN32
#include <time.h>
#else
#include <sys/time.h>
#include <iconv.h>
#endif

#include<stdio.h>
#include<stdlib.h>
#include <string.h>
#include <stdint.h>
#include "gen_int.h"
#include "includeComm.h"
#include "shastruct.h"


//HC: max seconds
#define MAX_SECS_COUNTER (9999999999)
#define MAX_SECS_COUNTER (9999999999)
#define MAX_SEND_NAT_TRAVERSAL_NODE_NUM (2)
#define MAX_SEND_PEERLIST_RSP_PERIOD	(5*60)
#define MAX_SAVE_PEERLIST_PERIOD		(30*60)
#define MAX_SEND_CHAIN_STATE_RSP_PERIOD	(5*60)
#define MAX_RECV_UDP_BUF_LEN			(64*1024)
#define	MAX_NATTRAVERSAL_PERIOD					(10*60)
#define RANDTIME						(60)

#define LOCALBUDDYTIME                  (2*60)
#define GLOBALBUDDYTIME                 (4*60)
#define NEXTBUDDYTIME					(5*60)
/*
//更紧凑的周期
#define NEXTBUDDYTIME                   (3*60)
#define LOCALBUDDYTIME                  (75)
#define GLOBALBUDDYTIME                 (140)
*/

#define LIST_BUDDY_RSP_NUM				(3)
#define BUDDYSCRIPT						("buddy_script")
#define AUTHKEY							("auth_key")
#define FILESIZES						(256)
#define FILESIZEL						(512)
#define BUFFERLEN						(1024)
#define PORT							(8111)
#define MAGICNUMBER						(116444736000000000)
#define SECONDLEN						(10000000)
#define TEST_SERVER1					("http://192.168.0.2/api/nodeinfo?node=")
#define TEST_SERVER2					("http://192.168.0.3/api/nodeinfo?node=")
#define ONE_SECOND						(1000)
#define ONE_MIN						    (60*ONE_SECOND)
#define INIT_TIME						(10)
#define ONE_KILO						(1024)
#define FIVE_MINI						(5*60)
#define ONE_HOUR						(60*60)
#define UNICODE_POS					    (2)
#define DIVIDEND_NUM					(2)
#define MAX_NUM_LEN						(256)
#define ONE_LOCAL_BLOCK				    (1)
#define NOT_START_BUDDY_NUM				(2)
#define LEAST_START_GLOBAL_BUDDY_NUM    (2)
#define HYPERBLOCK_SYNC_TIMES			(2)
#define REQUEST_ID_LEN					(32)
#define MATURITY_TIME					(10 * 60)

#define UNUSED(x)                       (void)(x)


enum _ePoeReqState
{
    DEFAULT_REGISREQ_STATE = 0,
    RECV,													//HC: 已接收
    SEND,													//HC: 已发送
    STOP,													//HC: 中止
    CONFIRMING,												//HC: 待确认
    CONFIRMED,												//HC: 已确认
    REJECTED,												//HC: 已拒绝
//	OTHERREFUSEME,											//HC: 被拒绝
//	ALLCONFIRMED,											//HC: 累计已确认
//	ALLOTHERREFUSEME,										//HC: 累计被拒绝
//	ALLMYREFUSEOTHER										//HC: 累计已拒绝
};

enum _eblocktype
{
    HYPER_BLOCK = 1,
    LOCAL_BLOCK
};

enum _eNodeState
{
    DEFAULT_NODE_STATE = 0,
    SYNC_DATA_STATE,		//HC: 正在同步数据
    IDLE_STATE,				//HC: 空闲状态
    LOCAL_BUDDY_STATE,		//HC: 局部共识
    GLOBAL_BUDDY_STATE,		//HC: 全局共识
    ON_CHAIN_SUCCESS,		//HC: 上链成功
    ON_CHAIN_FAILED,		//HC: 上链失败
    NODE_MALICE				//HC: 恶意节点
};


enum _eChainState
{
    CHAIN_DEFAULT_STATE = 0,
    CHAIN_CONFIRMING,				//HC: 链中所有block全部确认（UI中对应的绿色）
    CHAIN_CONFIRMED					//HC: 链中有未确认的block（UI中对应的黄色）
};

inline
char const* StringConvertToCharBuf(const std::string& cpp)
{
    return cpp.c_str();
}

template <typename T>
T StringConvertToCharBuf(const T& t)
{
    return t;
}

template<class... Args>
std::string StringFormat(const char* fmt, Args&&... args)
{
    size_t expandedlen = std::snprintf(nullptr, 0, fmt, StringConvertToCharBuf(args)...);

    std::string buf(expandedlen + 1, 0);
    std::snprintf(&buf[0], buf.size(), fmt, StringConvertToCharBuf(args)...);

    //HC: remove '\0'
    buf.pop_back();

    return buf;
}

#pragma pack(push,1)





typedef struct _tLocalChain
{
    uint16	iId;							//HC: 链标识
    uint64	iAllChainNodeNum;				//HC: 链中节点数量
    _eChainState	eState;					//HC: 链的状态

    void Set(uint16 id, uint64 allChainNodeNum, _eChainState state);

    uint16 GetID()const;

    uint64 GetChainNodesNum()const;

    _eChainState GetChainState()const;

}TGETFRIENDCHAININFO, *P_TGETFRIENDCHAININFO;

//HC: 一个存证文件信息
typedef struct _tPoeInfo
{
    string				cFileName;			//HC: 文件名
    string				cCustomInfo;		//HC: 自定义信息
    string				cRightOwner;		//HC: 文件所有者
    string				cFileHash;			//HC: 文件hash
    int16				iFileState;			//HC: 文件状态
    uint64				tRegisTime;			//HC: 存证时间
    uint64				iFileSize;			//HC: 文件大小
    uint64				iBlocknum;			//HC: 块号

    _tPoeInfo()
    {
        cFileName = "";
        cCustomInfo = "";
        cRightOwner = "";
        cFileHash = "";
        iFileSize = 0;
        iFileState = DEFAULT_REGISREQ_STATE;
        tRegisTime = 0;
        iBlocknum = 0;
    }

    void Set(string fileName, string customInfo, string rightOwner, string fileHash,
        int16 fileState, uint64 regisTime, uint64 fileSize, uint64 blockNum);

    string GetFileName()const;
    string GetFileHash()const;
    int16 GetFileState()const;
    string GetBlockNum()const;
    uint64 GetFileSize()const;
    string GetRightOwner()const;
    uint64 GetRegisTime()const;
    string GetCustomInfo()const;



}TEVIDENCEINFO, *P_TEVIDENCEINFO;

//HC: 浏览器显示信息
typedef struct _tChainQueryStru
{
    uint64		iBlockNo;								//HC: 块号
    uint64		iJoinedNodeNum;							//HC: 参与节点数
    uint64		iLocalBlockNum;							//HC: 数据块个数
    uint16		iLocalChainNum;							//HC: 数据链条
    //uint16		iLongestChain;						//HC: 最长链
    uint64		tTimeStamp;								//HC: 时间戳
    _tPoeInfo tPoeRecordInfo;

    _tChainQueryStru()
    {
        iBlockNo = 0;
        iLocalChainNum = 0;
        iLocalBlockNum = 0;
        iJoinedNodeNum = 0;
        //iLongestChain = 0;
        tTimeStamp = 0;
    }

    void Set(uint64 blockNo, uint64 joinedNodeNum, uint64 localBlockNum, uint16 localChainNum, uint64 timeStamp,
        _tPoeInfo poeRecordInfo);

    uint64 GetBlockNo()const;

    uint64 GetJoinedNodeNum()const;

    uint64 GetLocalBlockNum()const;

    uint16 GetLocalChainNUm()const;

    uint64 GetTimeStamp()const;

    _tPoeInfo GetPoeRecordInfo()const;

}TBROWSERSHOWINFO, *P_TBROWSERSHOWINFO;
#pragma pack(pop)

//HC: by:changhua
typedef struct _tUpqueue
{
    uint64 uiID;
    string strHash;
    uint64 uiTime;
}TUPQUEUE, *P_TUPQUEUE;

typedef struct _tlocalblockaddress
{
    uint64 hid = 0;            //HC: hyper block id
    uint16 chainnum = 0;
    uint16 id = 0;
    string ns;                  //HC: namespace

    void set(uint64 uihid, uint16 chain, uint16 uiid, string nspace ="") {
        hid = uihid;
        chainnum = chain;
        id = uiid;
        ns = nspace;
    }

    bool isValid() const {
        return id > (uint16)0 && id < 10000 &&
            chainnum > (uint16)0 && chainnum < 5000;
    }

    string tostring() const {
        return StringFormat("[%lld,%d,%d]", hid, chainnum, id);
    }

    bool fromstring(const string& addr)
    {
        //HC: Use PRId64 : (Don't forget to include <inttypes.h>)
        //return (std::sscanf(addr.c_str(),"[%lld,%d,%d]",&hid,&chainnum,&id) !=3);
        return (std::sscanf(addr.c_str(),"[%" PRId64 ",%hd,%hd]", &hid, &chainnum, &id) !=3);
    }

    bool operator <(const _tlocalblockaddress &addr) const
    {
        if (hid < addr.hid) {
            return true;
        } else if (hid > addr.hid) {
            return false;
        }

        if (chainnum < addr.chainnum) {
            return true;
        } else if (chainnum > addr.chainnum) {
            return false;
        }

        if (id < addr.id) {
            return true;
        } else if (id > addr.id) {
            return false;
        }
        return false;
    }

    bool operator >=(const _tlocalblockaddress &addr) const
    {
        if (hid > addr.hid) {
            return true;
        } else if (hid < addr.hid) {
            return false;
        }

        if (chainnum > addr.chainnum) {
            return true;
        } else if (chainnum < addr.chainnum) {
            return false;
        }

        if (id > addr.id) {
            return true;
        } else if (id < addr.id) {
            return false;
        }
        return true;
    }

    friend bool operator==(const _tlocalblockaddress& a, const _tlocalblockaddress& b)
    {
        return a.hid == b.hid && a.chainnum == b.chainnum && a.id == b.id && a.ns == b.ns;
    }

    friend bool operator!=(const _tlocalblockaddress& a, const _tlocalblockaddress& b)
    {
        return !(a == b);
    }


    friend class boost::serialization::access;
    template <typename Archive>
    void serialize(Archive &ar, const unsigned int version)
    {
        ar & hid;
        ar & chainnum;
        ar & id;
        ar & ns;
    }

}T_LOCALBLOCKADDRESS, *P_TLOCALBLOCKADDRESS;



//HC: 每一个块信息
typedef struct _tBlockInfo
{
    uint64 iBlockNo;
    uint64 iCreatTime;
    _tPoeInfo tPoeRecordInfo;

    void Set(uint64 blockNo, uint64 createTime, _tPoeInfo poeRecordInfo);

    uint64 GetBlockNo()const;

    uint64 GetCreateTime()const;

    _tPoeInfo GetPoeRecordInfo()const;

}TBLOCKINFO, *P_TBLOCKINFO;

typedef struct _tHBlockDlgInfo
{
    uint64 iBlockNo;
    uint64 iCreatTime;
    uint64 iLocalBlockNum;
    string strHHash;
    string strVersion;

    void Set(uint64 blockNo, uint64 createTime, uint64 localBlockNum, string HHash, string version);

    uint64 GetBlockNo()const;

    uint64 GetCreateTime()const;

    uint64 GetLocalBlockNum()const;

    string GetParentHash()const;

}THBLOCKDLGINFO, *P_THBLOCKDLGINFO;

typedef struct _tNodeInfo
{
    uint64 uiNodeState;
    string strNodeIp;

    _tNodeInfo() {};
    _tNodeInfo(uint64 nodeState, string nodeIp);
    void Set(uint64 nodeState, string nodeIp);

    uint64 GetNodeState()const;

    string GetNodeIp()const;

}TNODEINFO, *P_TNODEINFO;




//HC: Linux下静态库(如：hyperchainspace)中定义的全局变量，当libparacoin.so libaleth.so等动态库被hc进程加载后会被重新初始化
//HC：导致不同模块中全局变量不同
//HC: 即使已经把hyperchainspace在Linux下调整为动态库了，保险起见，仍然改为下面方式
class MainProgramArgs {

public:

using MAPARGS = std::map<std::string, std::string>;
using MAPMULTIARGS = std::map<std::string, std::vector<std::string>>;

    MainProgramArgs() {}

    MainProgramArgs(const MainProgramArgs&) = delete;
    MainProgramArgs& operator=(const MainProgramArgs&) = delete;

    ~MainProgramArgs() {}

    MAPARGS& hcArgs() {
        return mapHCArgs;
    };

    MAPMULTIARGS& hcMultiArgs()
    {
        return mapHCMultiArgs;
    }

private:
    MAPARGS mapHCArgs;
    MAPMULTIARGS mapHCMultiArgs;
};


#define HC_MAIN_PROGRAM_ARGS    \
    MainProgramArgs* mpargs = Singleton<MainProgramArgs>::instance();\
    auto &mapHCArgs = mpargs->hcArgs();\
    auto &mapHCMultiArgs = mpargs->hcMultiArgs(); \
    UNUSED(mapHCArgs); UNUSED(mapHCMultiArgs);



#endif
