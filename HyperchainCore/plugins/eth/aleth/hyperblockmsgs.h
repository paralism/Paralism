
#pragma once

#include "headers/commonstruct.h"

#include <boost/fiber/all.hpp>

#include <map>
#include <list>
#include <mutex>

typedef std::map<T_APPTYPE, std::vector<T_PAYLOADADDR>> M_APP_PAYLOADADDR;
typedef struct tagCHAINCBDATA
{
    tagCHAINCBDATA(const M_APP_PAYLOADADDR& m, uint32_t hidFork, uint32_t hid, const T_SHA256& thhash, bool isLatest) :
        m_mapPayload(m), m_hidFork(hidFork), m_hid(hid), m_thhash(thhash), m_isLatest(isLatest)
    {
    }

    M_APP_PAYLOADADDR m_mapPayload;
    uint32_t m_hidFork;
    uint32_t m_hid;
    T_SHA256 m_thhash;
    bool m_isLatest;
} CHAINCBDATA;

//HC:
//HC: 超块消息类
//HC: 接收并处理新超块到达或变更通知

//HCE:
//HCE: @brief The Hyperblock notification message class
//HCE: Receive and process notifications of new Hyperblock arrivals or changes
//HCE:
class HyperBlockMsgs
{
public:
    void insert(CHAINCBDATA&& cb);  //HCE: insert a new notification
    void process();                 //HCE: Process notifications
    size_t size();
private:
    boost::fibers::mutex m_cs_list;
    std::list<CHAINCBDATA> m_list;
};

extern HyperBlockMsgs hyperblockMsgs;
