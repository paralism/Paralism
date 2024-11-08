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
#ifndef ELAPSED_TIME_H

#define ELAPSED_TIME_H

#include "headers/inter_public.h"

#include <iostream>
#include <sstream>
#include <map>
#include <string>
#include <string_view>
#include <chrono>
using namespace std::chrono;

class ElapsedTime
{
public:
	ElapsedTime();
	~ElapsedTime();

	void Start();
	void End();
	long GetYears()const;
	long GetMonths()const;
	long GetDays()const;
	long GetHours()const;
	long GetMinutes()const;
	long GetSeconds()const;

private:
	uint64_t m_start, m_end;

};

//HC: 支持二种类型的action（整数和字符串类型） 统计
class CActionCostStatistics
{
public:
    typedef struct _Cost
    {
        int32_t nExecCount = 0;
        int32_t nMinCost = 0;
        int32_t nMaxCost = 0;
        int64_t nSumCost = 0;
        std::string sActionDesc;
    } COST;

    typedef std::map<int32_t, COST> ACTIONCOST;
    typedef std::map<std::string, COST> STRACTIONCOST; //Key is action name

    class StatisticsOnce
    {
    public:
        StatisticsOnce() {}
        StatisticsOnce(CActionCostStatistics* pACObj, int32_t action)
        {
            ACTIONCOST& ac = pACObj->m_acstatt;
            auto& actioncost = ac[action];
            _actioncost = &actioncost;
            _tpStarting = system_clock::now();
        }

        StatisticsOnce(CActionCostStatistics* pACObj, std::string action)
        {
            _isnameaction = true;
            _actionname = action;

            auto &ac = pACObj->m_stracstatt;
            auto& actioncost = ac[action];
            _actioncost = &actioncost;
            _tpStarting = system_clock::now();
        }

        ~StatisticsOnce()
        {
            if (_actioncost && !_isleaved) {
                leave();
            }
        }

    private:
        void leave();

    private:
        COST* _actioncost = nullptr;
        system_clock::time_point _tpStarting;
        bool _isleaved = false;
        bool _isnameaction = false;
        std::string _actionname;
    };

    CActionCostStatistics()
    {}

    void AddAction(int32_t nAction, std::string actiondesc)
    {
        COST cost;
        cost.sActionDesc = actiondesc;
        m_acstatt[nAction] = cost;
    }

    void AddAction(std::string action)
    {
        COST cost;
        m_stracstatt[action] = cost;
    }

    StatisticsOnce NewStatt(int32_t action)
    {
        return StatisticsOnce(this, action);
    }

    StatisticsOnce NewStatt(std::string action)
    {
        return StatisticsOnce(this, action);
    }


    std::string Statistics(const std::string_view& header = "") const;

 private:
    ACTIONCOST m_acstatt;
    STRACTIONCOST m_stracstatt;
};

#endif
