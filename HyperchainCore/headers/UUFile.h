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
#ifndef _UUFILE_H
#define _UUFILE_H


#ifndef _WIN32
#include <unistd.h>
#include <netdb.h>
#include <net/if.h>
#include <arpa/inet.h>
#include <sys/ioctl.h>
#include <limits.h>
#define SOCKET_ERROR (-1)
#define LPHOSTENT hostent*

#else
#include <winsock2.h>
#pragma comment(lib,"IPHLPAPI.lib")
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <iostream>
#include <iphlpapi.h>
#include <stdio.h>
#include <stdlib.h>
#include<WS2tcpip.h>
//#include <Ws2tcpip.h>
#pragma comment(lib,"IPHLPAPI.lib")
using namespace std;
#endif

#include <string.h>
//#include <io.h>
//#include <direct.h>
#include <string>
#include <vector>
#include "../Log.h"
using namespace std;

#define WORKING_BUFFER_SIZE 15000
#define MAX_TRIES 3

//#include "includeComm.h"
#define MAX_SIZE 1024
class UUFile
{
public:
	UUFile()
	{
	}
	~UUFile()
	{}

	int getlocalip(char* outip)
	{
#ifndef WIN32
		int i = 0;
		int sockfd;
		struct ifconf ifconf;
		char buf[512];
		struct ifreq *ifreq;
		char* ip;
		//HC: 初始化ifconf
		ifconf.ifc_len = 512;
		ifconf.ifc_buf = buf;
		strcpy(outip, "127.0.0.1");
		if ((sockfd = socket(AF_INET, SOCK_DGRAM, 0))<0)
		{
			return -1;
		}
		ioctl(sockfd, SIOCGIFCONF, &ifconf);    //HC: 获取所有接口信息
		close(sockfd);
		//HC: 接下来一个一个的获取IP地址
		ifreq = (struct ifreq*)buf;
		for (i = (ifconf.ifc_len / sizeof(struct ifreq)); i>0; i--)
		{
			ip = inet_ntoa(((struct sockaddr_in*)&(ifreq->ifr_addr))->sin_addr);


			if (strcmp(ip, "127.0.0.1") == 0)  //HC: 排除127.0.0.1，继续下一个
			{
				ifreq++;
				continue;
			}
		}
		strcpy(outip, ip);
		return 0;
#else
		PIP_ADAPTER_ADDRESSES pAddresses = NULL;
		IP_ADAPTER_DNS_SERVER_ADDRESS *pDnServer = NULL;
		ULONG outBufLen = 0;
		DWORD dwRetVal = 0;
		char buff[100];
		DWORD bufflen = 100;
		int i;
		char bufTemp[256] = {0};

		GetAdaptersAddresses(AF_UNSPEC, 0, NULL, pAddresses, &outBufLen);

		pAddresses = (IP_ADAPTER_ADDRESSES*)malloc(outBufLen);

		if ((dwRetVal = GetAdaptersAddresses(AF_INET, GAA_FLAG_SKIP_ANYCAST, NULL, pAddresses, &outBufLen)) == NO_ERROR)
		{
			while (pAddresses)
			{
				PIP_ADAPTER_UNICAST_ADDRESS pUnicast = pAddresses->FirstUnicastAddress;
				pDnServer = pAddresses->FirstDnsServerAddress;

				if (pDnServer)
				{
					sockaddr_in *sa_in = (sockaddr_in *)pDnServer->Address.lpSockaddr;
					sprintf(bufTemp, "DNS:%s\n", inet_ntop(AF_INET, &(sa_in->sin_addr), buff, bufflen));
				}
				if (pAddresses->OperStatus == IfOperStatusUp)
				{
					printf("Status: active\n");
				}
				else
				{
					printf("Status: deactive\n");
					pAddresses = pAddresses->Next;
					continue;
				}

				for (i = 0; pUnicast != NULL; i++)
				{
					if (pUnicast->Address.lpSockaddr->sa_family == AF_INET)
					{
						sockaddr_in *sa_in = (sockaddr_in *)pUnicast->Address.lpSockaddr;
						sprintf(bufTemp, "%s", inet_ntop(AF_INET, &(sa_in->sin_addr), buff, bufflen));
						wchar_t *ptr = pAddresses->FriendlyName;
						if (pAddresses->IfType == 71 || pAddresses->IfType == MIB_IF_TYPE_ETHERNET)
						{
							if ((0 != strcmp(bufTemp, "127.0.0.1")) && (NULL == wcsstr(ptr, L"Network")))
							{
								strcpy(outip, bufTemp);
								//log_info(g_pLogHelper, "IP IS %s, name %s\n", outip, ptr);
								//	break;
							}
						}
					}
					/*else if (pUnicast->Address.lpSockaddr->sa_family == AF_INET6)
					{
						sockaddr_in6 *sa_in6 = (sockaddr_in6 *)pUnicast->Address.lpSockaddr;
						sprintf(bufTemp, "IPV6:%s\n", inet_ntop(AF_INET6, &(sa_in6->sin6_addr), buff, bufflen));
					}
					else
					{
						printf("\tUNSPEC");
					}*/
					pUnicast = pUnicast->Next;
				}
				//printf("Number of Unicast Addresses: %d\n", i);
				pAddresses = pAddresses->Next;
			}
		}
		/*else {
			LPVOID lpMsgBuf;
			printf("Call to GetAdaptersAddresses failed.\n");
			if (FormatMessage(
				FORMAT_MESSAGE_ALLOCATE_BUFFER |
				FORMAT_MESSAGE_FROM_SYSTEM |
				FORMAT_MESSAGE_IGNORE_INSERTS,
				NULL,
				dwRetVal,
				MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
				(LPTSTR)&lpMsgBuf,
				0,
				NULL)) {
				printf("\tError: %s", lpMsgBuf);
			}
			LocalFree(lpMsgBuf);
		}*/
		free(pAddresses);

		return 0;

#endif
	}

	void ReplaceAll(string& str,const string& old_value,const string& new_value)
	{
		if (old_value.empty())
			return;

		size_t Pos = 0;
		while ((Pos = str.find(old_value, Pos)) != string::npos) {
			str.erase(Pos, old_value.size());
			str.insert(Pos, new_value);
			Pos += new_value.size();
		}
	}

	void ReplaceAllSelect(string& str,const string& old_value,const string& new_value)
	{
		if (old_value.empty())
			return;

		size_t Pos = 8;
		while ((Pos = str.find(old_value, Pos)) != string::npos) {
			str.erase(Pos, old_value.size());
			str.insert(Pos, new_value);
			Pos += new_value.size();
		}
	}

	void ReparePath(string& astrPath)
	{
	#ifdef WIN32
		ReplaceAll(astrPath, "/", "\\");
	#else
		ReplaceAll(astrPath, "\\", "/");
	#endif
	}

	bool mkdirEx(const char *Path)
	{
		/*
		string pathname = Path;
		//    if(pathname.Right(1) != "\\")
		//	     pathname += "\\" ;

		int end = pathname.rfind('\\');
		int pt = pathname.find('\\');
		if (pathname[pt-1] == ':')
		pt = pathname.find('\\', pt+1);

		string path;

		while(pt != -1 && pt<=end)
		{
		path = pathname.substr(0, pt+1);
		if(_access(path.c_str(), 0) == -1)
		_mkdir(path.c_str());
		pt = pathname.find('\\', pt+1);
		}
		*/
		return true;
	}

	string LoadFile(string &path)
	{
		FILE* f=fopen(path.c_str(),"rb");
		if(f==NULL)
			return "";
		fseek(f,0,SEEK_END);
		int flen=ftell(f);
		fseek(f,0,SEEK_SET);
		char* buf=new char[flen+1];
		flen=fread(buf,1,flen,f);
		buf[flen]='\0';
		fclose(f);
		string result=string(buf,flen);
		delete [] buf;
		buf = NULL;
		return result;
	}

	bool SaveFile(string &path,const string& content)
	{
		ReparePath(path);
		//	if (_access(path.c_str(), 0) == -1) {
		//		mkdirEx(path.c_str());
		//	}

		FILE* f=fopen(path.c_str(),"wb");
		if(f==NULL)
			return false;
		fwrite(content.c_str(),1,content.length(),f);
		fclose(f);
		return true;
	}

	bool SaveFileAdd(string &path,const string& content)
	{
		ReparePath(path);
		//	if (_access(path.c_str(), 0) == -1) {
		//		mkdirEx(path.c_str());
		//	}

		FILE* f=fopen(path.c_str(),"a+");
		if(f==NULL)
			return false;
		fwrite(content.c_str(),1,content.length(),f);
		fclose(f);
		return true;
	}

	string GetItemData(string aLineData, string aItem)
	{
		string ItemText = "";
		string SItem, EItem;
		size_t Begin, End;

		SItem = "<"  + aItem + ">";
		EItem = "</" + aItem + ">";
		size_t StrLen = SItem.size();

		if((Begin =  aLineData.find(SItem)) != string::npos){
			End = aLineData.find(EItem, Begin + StrLen);
			if(End - Begin > StrLen){
				ItemText = aLineData.substr(Begin + StrLen,End - Begin - StrLen);
			}
		}
		return ItemText;
	}

	string GetItemData(string aLineData, string aFirstItem, string aSecondItem)
	{
		string ItemText = "";
		string SItem, EItem;
		size_t Begin, End;

		SItem = aFirstItem;
		EItem = aSecondItem;
		size_t StrLen = SItem.size();

		if((Begin =  aLineData.find(SItem)) != string::npos){
			End = aLineData.find(EItem, Begin + StrLen);
			if(End - Begin > StrLen){
				ItemText = aLineData.substr(Begin + StrLen,End - Begin - StrLen);
			}
		}
		return ItemText;
	}

	vector<string> ExtractStringList(string FileContent, string strItem)
	{
		vector<string> StringList;

		if (FileContent.empty())
			return StringList;

		string strStart = "<" + strItem + ">";
		string strEnd = "</" + strItem + ">";

		size_t Start = 0;
		size_t End   = 0;

		while ((Start = FileContent.find(strStart, Start)) != string::npos) {
			End = FileContent.find(strEnd, Start+1);
			if (End > Start) {
				string LineData = FileContent.substr(Start+strStart.size(), End-Start-strStart.size());
				StringList.push_back(LineData);
				//HC: 载入完成
				Start = End;
			} else break;
		}

		return StringList;
	}

	vector<string> ExtractStringList(string FileContent, string strItem1, string strItem2)
	{
		vector<string> StringList;

		if (FileContent.empty())
			return StringList;

		size_t Start = 0;
		size_t End   = 0;

		while ((Start = FileContent.find(strItem1, Start)) != string::npos) {
			End = FileContent.find(strItem2, Start+1);
			if (End > Start) {
				string LineData = FileContent.substr(Start+strItem1.size(), End-Start-strItem1.size());
				StringList.push_back(LineData);
				//HC: 载入完成
				Start = End;
			} else break;
		}

		return StringList;
	}

	/*void FormatTime(time_t time1, char *szTime)
	{
		struct tm tm1;

#ifdef WIN32
		tm1 = *localtime(&time1);
#else
		localtime_r(&time1, &tm1 );
#endif
		sprintf( szTime, "%4.4d%2.2d%2.2d%2.2d%2.2d%2.2d",
			tm1.tm_year+1900, tm1.tm_mon+1, tm1.tm_mday,
			tm1.tm_hour, tm1.tm_min,tm1.tm_sec);
	}*/
};
#endif
