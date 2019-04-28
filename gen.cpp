#include <fstream>
#include <iostream>
#include <random>
#include <cmath>
#include <iostream>
#include <string>
using namespace std;

int main(int argc, char** argv){

    default_random_engine eng;
    uniform_real_distribution<float> dist(0,1);
    string s = "Data_";
    string a = string(argv[1]);
    string buf = s+a;
    cout << buf;
    //char *buf = new char[strlen(argv[1]) + sizeof(s) + 1];
    //sprintf(s.,"%s%s",s,argv[1]);
    ofstream fout(argv[1],ios::binary);
    int size = atoi(argv[1]);
    size = size /4;
    for(int i=0; i<size; i++){
        float x = dist(eng);
        fout.write((char*)&x,sizeof(float));
        
    }
    fout.close();

    return 0;

}
