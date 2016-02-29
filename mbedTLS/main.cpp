/* 
 * File:   main.cpp
 * Author: peter
 *
 * Created on February 27, 2016, 12:46 PM
 */

#include <cstdlib>
#include <stdio.h>
#include <string.h>
#include <iostream>
#include <fstream>
#include <mbedtls/aes.h>
#include <mbedtls/sha512.h>

using namespace std;

mbedtls_aes_context aes;

unsigned char key[32] =  { 0xa5, 0x84, 0x99, 0x8d, 0x0d, 0xbd, 0xb1, 0x54,
                           0xbb, 0xc5, 0x4f, 0xed, 0x86, 0x9a, 0x66, 0x11,
                           0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda,
                           0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5 };

unsigned char iv[16] = {   0x6c, 0x70, 0xed, 0x50, 0xfd, 0xed, 0xb9, 0xda,
                           0x51, 0xa3, 0x40, 0xbd, 0x92, 0x9d, 0x38, 0x9d };

unsigned char input [128];
unsigned char output[128];

size_t input_len = 40;
size_t output_len = 0;

void generateSHA(string file){
    int length = file.length();
    cout << length << endl;
    unsigned char output[64];
    memset(output, '0', 64);
    mbedtls_sha512((const unsigned char *)file.c_str(), length, output, 0);
    
    cout << "SHA2-512 = " << output << endl;
}

bool encrypt_data(const unsigned char * inputData, int inputSize, unsigned char * outputData, int & outputSize){
    if ((outputSize-16) < inputSize)
    {
        return false;
    }

    int keyLen = 32;
    int blockLen = 16;

    int padLen = blockLen - (inputSize % blockLen);
    int tempBuffSize = inputSize + padLen;
    unsigned char * tempBuff = new unsigned char[tempBuffSize];
    memcpy(tempBuff, inputData, inputSize);
    for (int pos = 0; pos < padLen; ++pos)
    {
        tempBuff[inputSize + pos] = padLen;  // padding the data 
    }

    mbedtls_aes_context ctx;
    mbedtls_aes_setkey_dec(&ctx, key, keyLen * 8);
    mbedtls_aes_crypt_cbc(&ctx, MBEDTLS_AES_ENCRYPT, tempBuffSize, iv, tempBuff, outputData);
    outputSize = tempBuffSize;

    return true;
}



string read_file(){
    ifstream ifs ("test.txt", std::ifstream::in);
    string file = "";
    
    file = ifs.get();
    
    while (ifs.good()) {
        file += ((char)ifs.get());
    }

    ifs.close();  
    cout << file;
    return file;
}

void write_to_file(string content){
    std::ofstream ofs ("encrypted.txt", std::ofstream::out);

    ofs << content;

    ofs.close();
}

/*
 * 
 */
int main(int argc, char** argv) {
    string content = read_file();
    generateSHA(content);
    
    char encrypted_data[256] = { 0 };
    int out_size = 256;
    encrypt_data((const unsigned char *)content.c_str(),content.length(),(unsigned char *)encrypted_data,out_size);
    
    cout << encrypted_data;
    
    return 0;
}

