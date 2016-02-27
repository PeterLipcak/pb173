/* 
 * File:   main.cpp
 * Author: peter
 *
 * Created on February 27, 2016, 12:46 PM
 */

#include <cstdlib>
#include <iostream>
#include <fstream>
//#include <mbedtls/aes.h>

using namespace std;

void read_file(){
    ifstream ifs ("test.txt", std::ifstream::in);
    
    char c = ifs.get();

    while (ifs.good()) {
        std::cout << c;
        c = ifs.get();
    }

    ifs.close();    
}

/*
 * 
 */
int main(int argc, char** argv) {
    read_file();
    return 0;
}

