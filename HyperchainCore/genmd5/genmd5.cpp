#include "../UpdateInfo.h"
#include <iostream>
#include <string>
#include <boost/filesystem/fstream.hpp>


using namespace std;

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

	 	boost::filesystem::ofstream fout("localhc.ini",ios::out);
		if (fout.is_open()) {
			string localmd5;
			fout << "[preupdate files]" << endl;
			for (auto& file : preupdatefile) {
				localmd5 = UpdateInfo::FileDigest(file);
				fout << "preupdate=" << file << endl;
				fout << "md5=" << localmd5 << endl;
			}

			fout << endl;
			fout<<"[update files]" << endl;
			for (auto& file : updatefile) {
				localmd5 = UpdateInfo::FileDigest(file);
				fout << "updatefile=" << file << endl;
				fout << "md5=" << localmd5 << endl;
			}

			fout << endl;
			fout << "[lib files]" << endl;
			for (auto& file : libfile) {
				localmd5 = UpdateInfo::FileDigest(file);
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
