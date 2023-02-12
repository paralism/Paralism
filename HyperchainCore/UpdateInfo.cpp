#include "UpdateInfo.h"
#include <iostream>
#include <string>
#include <vector>
#include <fstream>
#include <cpprest/http_client.h>
#include <cpprest/filestream.h>
#include <cpprest/containerstream.h>

using namespace std;
bool UpdateInfo::DownloadFromServer(string& serverurl, string& strFilename, boost::filesystem::path& pathDownload) {
    string urlFile = serverurl + strFilename;

    try
    {
        web::http::client::http_client client(web::uri(utility::conversions::to_string_t(urlFile)));
        web::http::http_response response = client.request(web::http::methods::GET).get();

        concurrency::streams::stringstreambuf buffer;
        response.body().read_to_end(buffer).get();
        string& filedata = buffer.collection();

        boost::filesystem::path pathFile = pathDownload / strFilename;
        boost::filesystem::ofstream fout(pathFile, ios::binary);
        if (!fout.is_open())
            return "open file error!";

        fout.write(filedata.c_str(), filedata.size());
        fout.close();

    }
    catch (std::exception& e)
    {
        std::cout << "Exception: " << e.what() << std::endl;
        return false;
    }

    return true;

}

string UpdateInfo::FileDigest(boost::filesystem::path& pathFile) {
    boost::filesystem::ifstream fin(pathFile, ios::binary);
    if (!fin.is_open())
        return "open file error!";

    MD5 md5;
    std::streamsize length;
    char buffer[1024];
    while (!fin.eof()) {
        fin.read(buffer, 1024);
        length = fin.gcount();
        if (length > 0)
            md5.update((unsigned char*)buffer, length);
    }
    fin.close();
    md5.finalize();

    return md5.hex_digest();
}

bool UpdateInfo::GetUpdateInfo() {
    string serverurl(MYSERVER_URL);
    string strUpdate = "hcUpdate.ini";
    if (DownloadFromServer(serverurl, strUpdate, pathFileDir)) {
        boost::filesystem::path pathFile = pathFileDir / "hcUpdate.ini";
        boost::filesystem::ifstream fin(pathFile);
        if (!fin.is_open()) {
            cout << "open hcUpdate.ini error!" << endl;
            return false;
        }

        string strline;
        size_t found, offset;
        struct fileinfo tmpinfo;
        fminingversion = 0;
        bool border = true;

        while (getline(fin, strline)) {
            found = strline.find("updatemsg=");
            if (found != string::npos) {
                offset = found + sizeof("updatemsg=");
                string strmsg = strline.substr(offset - 1);
                updatemsg.push_back(strmsg);
                continue;
            }

            found = strline.find("miningversion=");
            if (found != string::npos) {
                offset = found + sizeof("miningversion=");
                string str = strline.substr(offset - 1);
                fminingversion = stoi(str);
                continue;
            }

            found = strline.find("preupdate=");
            if (found != string::npos) {
                offset = found + sizeof("preupdate=");
                tmpinfo.filename = strline.substr(offset - 1);
                if (getline(fin, strline)) {
                    found = strline.find("md5=");
                    if (found != string::npos) {
                        offset = found + sizeof("md5=");
                        tmpinfo.filemd5 = strline.substr(offset - 1);
                        preupdatefile.push_back(tmpinfo);
                        continue;
                    }
                }
                border = false;
                break;
            }

            found = strline.find("updatefile=");
            if (found != string::npos) {
                offset = found + sizeof("updatefile=");
                tmpinfo.filename = strline.substr(offset - 1);
                if (getline(fin, strline)) {
                    found = strline.find("md5=");
                    if (found != string::npos) {
                        offset = found + sizeof("md5=");
                        tmpinfo.filemd5 = strline.substr(offset - 1);
                        updatefile.push_back(tmpinfo);
                        continue;
                    }
                }
                border = false;
                break;
            }

            found = strline.find("libfile=");
            if (found != string::npos) {
                offset = found + sizeof("libfile=");
                tmpinfo.filename = strline.substr(offset - 1);
                if (getline(fin, strline)) {
                    found = strline.find("md5=");
                    if (found != string::npos) {
                        offset = found + sizeof("md5=");
                        tmpinfo.filemd5 = strline.substr(offset - 1);
                        libfile.push_back(tmpinfo);
                        continue;
                    }
                }
                border = false;
                break;
            }
        }

        if (!border)
            cout << "The following line error! It must be md5=..." << endl;

        fin.close();
        return true;
    }
    else {
        cout << "Download hcUpdate.ini error! Check if download url is right and the file hcUpdate.ini exits" << endl;
        return false;
    }
}

bool UpdateInfo::PreUpdate() {
    bool bdownload = true;
    string serverurl(MYSERVER_URL);
    string localmd5;
    boost::filesystem::path pathFile;

    for (auto& file : preupdatefile) {
        pathFile = pathFileDir / file.filename;
        localmd5 = FileDigest(pathFile);
        if (localmd5 != file.filemd5) {
            if (!DownloadFromServer(serverurl, file.filename, pathFileDir)) {
                cout << "download file " << file.filename << " failed!" << endl;
                bdownload = false;
                break;
            }
        }
    }
    return bdownload;
}

bool UpdateInfo::CheckUpdate() {
    string localmd5;
    boost::filesystem::path pathFile;

    for (auto& file : updatefile) {
        pathFile = pathFileDir / file.filename;
        localmd5 = FileDigest(pathFile);
        if (localmd5 != file.filemd5) {
            return true;
        }
    }

    for (auto& file : libfile) {
        pathFile = pathFileDir / "lib" / file.filename;
        localmd5 = FileDigest(pathFile);
        if (localmd5 != file.filemd5) {
            return true;
        }
    }

    return false;
}

bool UpdateInfo::Updatefiles() {
    boost::filesystem::path pathTemp;
    pathTemp = pathFileDir / "updatetmp";

    cout << "update dir: " << pathTemp << endl;
    if (!boost::filesystem::exists(pathTemp))
        boost::filesystem::create_directory(pathTemp);

    bool bdownload = true;
    string serverurl(MYSERVER_URL);
    string localmd5;
    vector<string> downloadfiles, libfiles;
    string oldpath, newpath;

    boost::filesystem::path pathFile;
    for (auto& file : updatefile) {
        pathFile = pathFileDir / file.filename;
        localmd5 = FileDigest(pathFile);
        if (localmd5 != file.filemd5) {
            if (!DownloadFromServer(serverurl, file.filename, pathTemp)) {
                cout << "download file " << file.filename << " failed!" << endl;
                bdownload = false;
                break;
            }
            downloadfiles.push_back(file.filename);
       }
    }

    for (auto& file : libfile) {
        pathFile = pathFileDir / "lib" / file.filename;
        localmd5 = FileDigest(pathFile);
        if (localmd5 != file.filemd5) {
            if (!DownloadFromServer(serverurl, file.filename, pathTemp)) {
                cout << "download file " << file.filename << " failed!" << endl;
                bdownload = false;
                break;
            }
            libfiles.push_back(file.filename);
        }
    }

    if (!downloadfiles.empty()) {
        for (auto& file : downloadfiles) {
            boost::filesystem::remove(pathFileDir / file);
            boost::filesystem::rename(pathTemp / file, pathFileDir / file);
        }
    }

    if (!libfiles.empty()) {
        for (auto& file : libfiles) {
            boost::filesystem::remove(pathFileDir / "lib" / file);
            boost::filesystem::rename(pathTemp / file, pathFileDir / "lib" / file);
        }
    }

    boost::filesystem::remove_all(pathTemp);

    return bdownload;
}
