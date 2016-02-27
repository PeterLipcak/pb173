/* 
 * File:   main.cpp
 * Author: peter
 *
 * Created on February 27, 2016, 12:46 PM
 */

#include <cstdlib>
#include <iostream>
#include <fstream>
#include <mbedtls/aes.h>
#include <mbedtls/sha512.h>

using namespace std;

mbedtls_aes_context aes;

unsigned char key[32];
unsigned char iv[16];

unsigned char input [128];
unsigned char output[128];

size_t input_len = 40;
size_t output_len = 0;

void generateSHA(string file){
    int length = file.length();
    unsigned char output[64];
    mbedtls_sha512((const unsigned char *)file.c_str(), length, output, 0);
    
    cout << "SHA2-512 = " << output << endl;
}
string read_file(){
    ifstream ifs ("test.txt", std::ifstream::in);
    
    string file = "";
    
    file = ifs.get();

    while (ifs.good()) {
        file += ((char)ifs.get());
    }

    ifs.close();  
    
    return file;
}

/*
 * 
 */
int main(int argc, char** argv) {
    generateSHA(read_file());
    return 0;
}

