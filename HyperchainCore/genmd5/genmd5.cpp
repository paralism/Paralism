#include "../UpdateInfo.h"
#include <iostream>
#include <string>
#include <boost/filesystem/fstream.hpp>

using namespace std;

//HCE:
//HCE: @brief A tool to generate localhc.ini according to filelist.ini.
//HCE: The program reads the file list from filelist.ini,and write the file list and the corresponding md5 values into localhc.ini. 
//HCE:
int main()
{
	boost::filesystem::ifstream fin("filelist.ini");
	if (fin.is_open()) {
        string strline, filename;
        size_t found, offset, length;
        vector<string> preupdatefile,updatefile,libfile;

        while (getline(fin, strline)) {
            found = strline.find("preupdate=");
            if (found != string::npos) {
                offset = found + sizeof("preupdate=");
                filename = strline.substr(offset - 1);
                preupdatefile.push_back(filename);
            }
			else{
				found = strline.find("updatefile=");
				if (found != string::npos) {
					offset = found + sizeof("updatefile=");
					filename = strline.substr(offset - 1);
					updatefile.push_back(filename);
				}
				else {
					found = strline.find("libfile=");
					if (found != string::npos) {
						offset = found + sizeof("libfile=");
						filename = strline.substr(offset - 1);
						libfile.push_back(filename);
					}
				}
            }
		}
        fin.close();

        boost::filesystem::path pathCurrent = boost::filesystem::current_path();
        boost::filesystem::path pathFile;
	 	boost::filesystem::ofstream fout("localhc.ini",ios::out);
		if (fout.is_open()) {
			string localmd5;
			fout << "[preupdate files]" << endl;
			for (auto& file : preupdatefile) {
                pathFile = pathCurrent / file;
				localmd5 = UpdateInfo::FileDigest(pathFile);
				fout << "preupdate=" << file << endl;
				fout << "md5=" << localmd5 << endl;
			}

			fout << endl;
			fout<<"[update files]" << endl;
			for (auto& file : updatefile) {
                pathFile = pathCurrent / file;
                localmd5 = UpdateInfo::FileDigest(pathFile);
                fout << "updatefile=" << file << endl;
				fout << "md5=" << localmd5 << endl;
			}

			fout << endl;
			fout << "[lib files]" << endl;
			for (auto& file : libfile) {
                pathFile = pathCurrent / file;
                localmd5 = UpdateInfo::FileDigest(pathFile);
                fout << "libfile=" << file << endl;
				fout << "md5=" << localmd5 << endl;
			}

			fout.close();
		}
		else
			cout << "file localhc.ini open error!" << endl;
	}
	else
		cout << "file filelist.ini open error!" << endl;

	cout << "press any key to exit!" << endl;
	getchar();

	return 0;
}
