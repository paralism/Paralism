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

#include <chrono>
#include <string>

#define HAS_MEMBER(member)\
template<typename T, typename... Args>struct has_member_##member\
{\
private:\
        template<typename U> static auto Check(int) -> decltype(std::declval<U>().member(std::declval<Args>()...), std::true_type()); \
    template<typename U> static std::false_type Check(...);\
public:\
    enum{value = std::is_same<decltype(Check<T>(0)), std::true_type>::value};\
};\

HAS_MEMBER(Foo)
HAS_MEMBER(Before)
HAS_MEMBER(After)


class NonCopyableBase
{
public:
    NonCopyableBase(const NonCopyableBase&) = delete;
    NonCopyableBase& operator = (const NonCopyableBase&) = delete;
    NonCopyableBase() = default;
};


template<typename Func, typename... Args>
struct Aspect : NonCopyableBase
{
    Aspect(Func&& f) : m_func(std::forward<Func>(f))
    { }

    template<typename T>
    typename std::enable_if<has_member_Before<T, Args...>::value&& has_member_After<T, Args...>::value>::type Invoke(Args&&... args, T&& aspect)
    {
        aspect.Before(std::forward<Args>(args)...); //核心逻辑之前的切面逻辑
        m_func(std::forward<Args>(args)...);        //核心逻辑
        aspect.After(std::forward<Args>(args)...);  //核心逻辑之后的切面逻辑
    }

    template<typename T>
    typename std::enable_if<has_member_Before<T, Args...>::value && !has_member_After<T, Args...>::value>::type Invoke(Args&&... args, T&& aspect)
    {
        aspect.Before(std::forward<Args>(args)...); //核心逻辑之前的切面逻辑
        m_func(std::forward<Args>(args)...);        //核心逻辑
    }

    template<typename T>
    typename std::enable_if<!has_member_Before<T, Args...>::value&& has_member_After<T, Args...>::value>::type Invoke(Args&&... args, T&& aspect)
    {
        m_func(std::forward<Args>(args)...);        //核心逻辑
        aspect.After(std::forward<Args>(args)...);  //核心逻辑之后的切面逻辑
    }

    template<typename Head, typename... Tail>
    void Invoke(Args&&... args, Head&& headAspect, Tail&&... tailAspect)
    {
        headAspect.Before(std::forward<Args>(args)...);
        Invoke(std::forward<Args>(args)..., std::forward<Tail>(tailAspect)...);
        headAspect.After(std::forward<Args>(args)...);
    }

private:
    Func m_func;
};

template<typename T> using identity_t = T;

//AOP help
template<typename... AP, typename... Args, typename Func, typename FuncAfter>
void AOPInvoke(FuncAfter&& fAfter, Func&& f, Args&&... args)
{
    Aspect<Func, Args...> asp(std::forward<Func>(f));
    asp.Invoke(std::forward<Args>(args)..., identity_t<AP>()...);
}


class CSpentTime
{
public:
    CSpentTime();
    uint64_t Elapse();
    void Reset();
    std::string ToString();
private:
    std::chrono::system_clock::time_point  _StartTimePoint;
};

template<typename CBFN, typename Func, typename... Args>
class CSpentTimeAOP : public CSpentTime
{
    typedef Func func_type;
public:
    CSpentTimeAOP(CBFN&& fn) : m_func(std::forward<CBFN>(fn))
    { }

    void Before(Args&&... args)
    {
        m_spent.Reset();
    }

    void After(Args&&... args)
    {
        m_func(typeid(func_type).name(), m_spent.Elapse());
    }

private:
    CSpentTime m_spent;
    CBFN m_func;
};

template<typename... Args, typename Func, typename FuncAfter>
void AOPInvokeCost(FuncAfter&& fAfter, Func&& f, Args&&... args)
{
    Aspect<Func, Args...> asp(std::forward<Func>(f));
    CSpentTimeAOP<FuncAfter, Func, Args...> ap_time(std::forward<FuncAfter>(fAfter));
    asp.Invoke(std::forward<Args>(args)..., ap_time);
}


//HCE: two ways for display the progress: percent and already handled
class CommadLineProgress
{
public:
    //Way 1:
    void Update(double newProgress);
    void PrintPercent();

    //Way 2:
    void Start();
    void PrintStatus(uint32_t nAddCount, const std::string& msg = "");

    uint64_t GetCount() {
        return _ncount;
    }


private:
    std::string firstPartOfpBar = "[", //Change these at will (that is why I made them public)
        lastPartOfpBar = "]",
        pBarFiller = "|",
        pBarUpdater = "/-\\|";

    int amountOfFiller,
        pBarLength = 50,        //I would recommend NOT changing this
        currUpdateVal = 0;      //Do not change
    double currentProgress = 0, //Do not change
        neededProgress = 100;   //I would recommend NOT changing this

    CSpentTime _spentt;
    uint64_t _ncount;
};


std::string strprintf(const char* fmt, ...);
