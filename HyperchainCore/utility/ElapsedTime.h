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

    class StatisticsOnce
    {
    public:
        StatisticsOnce(CActionCostStatistics* pACObj, int32_t action)
        {
            _action = action;
            ACTIONCOST& ac = pACObj->m_acstatt;
            auto& actioncost = ac[action];
            _actioncost = &actioncost;
            _tpStarting = system_clock::now();
        }

        ~StatisticsOnce()
        {
            if (!_isleaved) {
                leave();
            }
        }

        void reenter()
        {
            _tpStarting = system_clock::now();
        }

        void leave()
        {
            milliseconds diff = duration_cast<milliseconds>(system_clock::now() - _tpStarting);
            int32_t tmdiff = diff.count();

            _actioncost->nExecCount++;
            _actioncost->nSumCost += tmdiff;

            _isleaved = true;
            if (tmdiff > _actioncost->nMaxCost) {
                _actioncost->nMaxCost = tmdiff;
                return;
            }

            if (_actioncost->nMinCost == 0) {
                _actioncost->nMinCost = tmdiff;
                return;
            }

            if (tmdiff < _actioncost->nMinCost) {
                _actioncost->nMinCost = tmdiff;
                return;
            }
        }

    private:
        COST* _actioncost;
        int32_t _action;
        system_clock::time_point _tpStarting;
        bool _isleaved = false;
    };

    CActionCostStatistics()
    {}

    void AddAction(int32_t nAction, std::string actiondesc)
    {
        COST cost;
        cost.sActionDesc = actiondesc;
        m_acstatt[nAction] = cost;
    }

    StatisticsOnce NewStatt(int32_t action)
    {
        return StatisticsOnce(this, action);
    }

    std::string Statistics(const std::string_view & header = "")
    {
        ostringstream oss;
        oss << header << endl;
        for (auto& elm : m_acstatt) {
            COST& cost = elm.second;
            oss << StringFormat("\t%d(%8s.)\texec:%d min:%d(ms) max:%d(ms) avg:%d(ms) sum:%d(ms)\n",
                elm.first,
                cost.sActionDesc.substr(0,8),
                cost.nExecCount,
                cost.nMinCost,
                cost.nMaxCost,
                cost.nExecCount ? cost.nSumCost / cost.nExecCount : 0,
                cost.nSumCost);
        }
        return oss.str();
    }

private:
    ACTIONCOST m_acstatt;
};

#endif