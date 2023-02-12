#pragma once
#include <string>
#include <vector>
#include "./util/md5.h"
#include "globalconfig.h"
#include <boost/filesystem.hpp>
#include <boost/filesystem/fstream.hpp>

using namespace std;

#define MYSERVER_URL GetUpdateUrl()

//HCE:
//HCE: @brief A class used to download files from difined URL:MYSERVER_URL
//HCE: pathFileDir: the file path for download files
//HCE: 

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
    //HCE: Constructor
	UpdateInfo(){
		fminingversion = 0;
		pathFileDir = boost::filesystem::complete(".");
	}

    //HCE: Constructor
	UpdateInfo(boost::filesystem::path& pathDir) {
		fminingversion = 0;
		pathFileDir = pathDir;
	}

    //HCE: Destructor
	~UpdateInfo() {
		updatemsg.clear();
		preupdatefile.clear();
		updatefile.clear();
		libfile.clear();
	}

    //HCE: Digest a file and get its md5 value.
    //HCE: @param pathFile The file to digest.
    //HCE: @returns Md5 value of the file.
	static string FileDigest(boost::filesystem::path& pathFile);

    //HCE: Download files from server.
    //HCE: @param serverurl Server URL.
    //HCE: @param strFilename Download file name.
    //HCE: @param pathDownload The file path for download file.
    //HCE: @returns True if download seccess.
	static bool DownloadFromServer(string& serverurl, string& strFilename, boost::filesystem::path& pathDownload);

    //HCE: Get update infomation according to the file:hcUpdate.ini in server.
    //HCE: Compare md5 values between local files and remote files in server,and record which local files need to download.
    //HCE: @returns True if seccess.
	bool GetUpdateInfo();

    //HCE: Download the files in file vector preupdatefile from server URL(MYSERVER_URL).
    //HCE: @returns True if seccess.
	bool PreUpdate();

    //HCE: Check if there is difference between the local files and the remote ones according to their md5 values.
    //HCE: @returns True if there is a difference.
	bool Updatefiles();

    //HCE: Download the files in file vector updatefile and libfile from server URL(MYSERVER_URL).
    //HCE: @returns True if seccess.
	bool CheckUpdate();
};

