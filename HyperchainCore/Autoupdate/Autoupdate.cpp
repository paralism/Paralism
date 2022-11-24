#include "../UpdateInfo.h"
#include <iostream>
#include <string>
#include <thread>
#ifdef WIN32
#include <direct.h>
#include <windows.h>
#include <tlhelp32.h>
#endif

using namespace std;

#ifdef WIN32
bool FindProcess(string& strprocess)
{
	bool bfind = false;
	PROCESSENTRY32 pe32;
	pe32.dwSize = sizeof(pe32);
	HANDLE hProcessSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

	char    szCurPath[MAX_PATH];
	_getcwd(szCurPath, MAX_PATH);
	string exePath = szCurPath;
	exePath += "\\hc.exe";


	bool bMore = Process32First(hProcessSnap, &pe32);
	while (bMore)
	{
		if (stricmp(strprocess.c_str(), pe32.szExeFile) == 0)
		{
			MODULEENTRY32 me32;
			me32.dwSize = sizeof(MODULEENTRY32);

			hProcessSnap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, pe32.th32ProcessID);
			if (Module32First(hProcessSnap, &me32)) {
				if (stricmp(me32.szExePath, exePath.c_str()) == 0) {
					bfind = true;
					break;
				}
			}
		}
		bMore = ::Process32Next(hProcessSnap, &pe32);
	}

	CloseHandle(hProcessSnap);
	return bfind;
}
#endif

int main()
{
	UpdateInfo updateinfo;
	string serverurl = string(MYSERVER_URL);

	#ifdef WIN32
	bool bwait = true;
	while (true) {
		string strprocess("hc.exe");
		if (!FindProcess(strprocess)) {
			break;
		}

		if (bwait) {
			cout << "hc.exe is running! waiting for exit......" << endl;
			bwait = false;
		}

		this_thread::sleep_for(chrono::milliseconds(1000));

		}
	#endif

	if (updateinfo.GetUpdateInfo()) {
		cout << "Auto update start!" << endl;	

		if (!updateinfo.Updatefiles())
			cout << "update files error! update at another time" << endl;
		else
			cout << "update files finished! program is aready the latest now!" << endl;

	}
	else
		cout << "get update info error! update at another time" << endl;

	cout << "press any key to exit!" << endl;
	getchar();

	return 0;
}