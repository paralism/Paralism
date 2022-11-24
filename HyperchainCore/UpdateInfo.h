#pragma once
#include <string>
#include <vector>
#include "./util/md5.h"
#include "globalconfig.h"
#include <boost/filesystem.hpp>
#include <boost/filesystem/fstream.hpp>

using namespace std;

#define MYSERVER_URL GetUpdateUrl()
//#ifdef WIN32
//	#define MYSERVER_URL "http://www.hyperchain.net/test_renew/chenlx/win/"
//#else
//	#define MYSERVER_URL "http://www.hyperchain.net/test_renew/chenlx/linux/"
//#endif

class UpdateInfo
{
public:
	struct fileinfo {
		string filename;
		string filemd5;
	};

	int fminingversion;
	vector<string> updatemsg;
	vector<fileinfo> preupdatefile;
	vector<fileinfo> updatefile;
	vector<fileinfo> libfile;

	boost::filesystem::path pathFileDir;

public:
	UpdateInfo(){
		fminingversion = 0;
		pathFileDir = boost::filesystem::complete(".");
	}

	UpdateInfo(boost::filesystem::path& pathDir) {
		fminingversion = 0;
		pathFileDir = pathDir;
		boost::filesystem::current_path(pathDir);
	}


	~UpdateInfo() {
		updatemsg.clear();
		preupdatefile.clear();
		updatefile.clear();
		libfile.clear();
	}

	static string FileDigest(const string& file);
	static bool DownloadFromServer(string serverurl, string strFilename);
	bool GetUpdateInfo();
	bool PreUpdate();
	bool Updatefiles();
	bool CheckUpdate();
};

