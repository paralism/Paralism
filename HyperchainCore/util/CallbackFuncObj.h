﻿/*Copyright 2016-2022 hyperchain.net (Hyperchain)

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
//callbackfuncobj.h
#ifndef __CALLBACK_FUNCTION_BOJ_H__
#define __CALLBACK_FUNCTION_BOJ_H__


#include <stdio.h>
#include <iostream>

template<typename pCallbackFunc>
class TCallbackFuncObj
{
public:
	TCallbackFuncObj();
	TCallbackFuncObj(pCallbackFunc pCF, void* pCParam);
	~TCallbackFuncObj();

	inline void Set(pCallbackFunc pCF, void* pCParam);
	inline pCallbackFunc GetCallbackFunc();
	inline void* GetCallbackParam();

private:
	TCallbackFuncObj(const TCallbackFuncObj& crs);
	TCallbackFuncObj& operator=(const TCallbackFuncObj& crs );

private:
	pCallbackFunc	m_pCF;
	void* 			m_pCParam;
};

//定义
template<typename pCallbackFunc>
TCallbackFuncObj<pCallbackFunc>::TCallbackFuncObj() : m_pCF(NULL)
, m_pCParam(NULL)
{
}

template<typename pCallbackFunc>
TCallbackFuncObj<pCallbackFunc>::TCallbackFuncObj(pCallbackFunc pCF, void* pCParam) : m_pCF(pCF)
, m_pCParam(pCParam)
{
}

template<typename pCallbackFunc>
TCallbackFuncObj<pCallbackFunc>::~TCallbackFuncObj()
{
}

template<typename pCallbackFunc>
void TCallbackFuncObj<pCallbackFunc>::Set(pCallbackFunc pCF, void* pCParam)
{
	m_pCF = pCF;
	m_pCParam = pCParam;
}

template<typename pCallbackFunc>
pCallbackFunc TCallbackFuncObj<pCallbackFunc>::GetCallbackFunc()
{
	return m_pCF;
}

template<typename pCallbackFunc>
void* TCallbackFuncObj<pCallbackFunc>::GetCallbackParam()
{
	return m_pCParam;
}

template<typename pCallbackFunc>
TCallbackFuncObj<pCallbackFunc>::TCallbackFuncObj(const TCallbackFuncObj& crs)
{
	m_pCF = crs.m_pCF;
	m_pCParam = crs.m_pCParam;
}

template<typename pCallbackFunc>
TCallbackFuncObj<pCallbackFunc>& TCallbackFuncObj<pCallbackFunc>::operator=(const TCallbackFuncObj& crs)
{
	if (&crs == this)
		return *this;

	m_pCF = crs.m_pCF;
	m_pCParam = crs.m_pCParam;
	return *this;
}





#endif   //__CALLBACK_FUNCTION_BOJ_H__
