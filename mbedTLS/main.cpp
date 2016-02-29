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

//AES key - 16 bytes
    unsigned char key[16] =  { 0xa5, 0x84, 0x99, 0x8d, 0x0d, 0xbd, 0xb1, 0x54,
        0xbb, 0xc5, 0x4f, 0xed, 0x86, 0x9a, 0x66, 0x11 };
    
    //Initialization Vector
    unsigned char iv[16] = {
        0x6c, 0x70, 0xed, 0x50, 0xfd, 0xed, 0xb9, 0xda,
        0x51, 0xa3, 0x40, 0xbd, 0x92, 0x9d, 0x38, 0x9d };



void generateSHA(unsigned char *fileContent, unsigned char* shaResult){
    memset(shaResult, 0, 64);
    mbedtls_sha512(fileContent, strlen((const char*)fileContent), shaResult, 0);   
    cout << "SHA2-512 = " << shaResult << endl;
}

bool encrypt(const unsigned char * inputData, int inputSize, unsigned char * outputData, int & outputSize, unsigned char * encryptIv){
    int keyLen = 16;
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
    mbedtls_aes_init( &ctx );
    mbedtls_aes_setkey_enc(&ctx, key, keyLen * 8);
    mbedtls_aes_crypt_cbc(&ctx, MBEDTLS_AES_ENCRYPT, tempBuffSize, encryptIv, tempBuff, outputData);
    outputSize = tempBuffSize;
    
    mbedtls_aes_free( &ctx );

    return true;
}

bool decrypt(const unsigned char * inputData, int inputSize, unsigned char * outputData, unsigned char * decryptIv)
{
    int keyLen = 16;
    int blockLen = 16;

    mbedtls_aes_context ctx;
    mbedtls_aes_init( &ctx );
    
    mbedtls_aes_setkey_dec(&ctx, key, keyLen * 8);
    mbedtls_aes_crypt_cbc(&ctx, MBEDTLS_AES_DECRYPT, inputSize, decryptIv, inputData, outputData);
    outputData[inputSize - outputData[inputSize-1]] = '\0';
    
    mbedtls_aes_free( &ctx );

    return true;
}


void readFile(const char* fileName, char** fileContent)
{
    ifstream file(fileName);
    
    if (file.is_open())
    {
        file.seekg(0, ios::end);
        int size = file.tellg();
        *fileContent = new char [size + 16];
        file.seekg (0, ios::beg);
        file.read (*fileContent, size);
        file.close();
    } else  {
        cout << "Unable to open input file"; 
    }
}

void writeToFile(const char* fileName, char* fileContent)
{
    ofstream file(fileName);
    
    if (file.is_open())
    {
        file << fileContent;
        file.close();
    } else {
        cout << "Unable to open input file"; 
    }
}

/*
 * 
 */
int main(int argc, char** argv) {
    
    //iv for encryption and decryption
    unsigned char encryptIv[16];
    unsigned char decryptIv[16];
    
    memcpy(encryptIv, iv, 16);    
    memcpy(decryptIv, iv, 16);
    
    char *fileInput;
    char *encryptedOutput;
    char *decryptedOutput;
    
    int outSize;
    
    readFile("test.txt", &fileInput);
    
    cout << "Input file:  " << fileInput << endl;
    
    unsigned char shaResult[64] = { 0 };
    generateSHA((unsigned char*)fileInput, shaResult);
    
    encryptedOutput = new char [strlen(fileInput)];
    decryptedOutput = new char [strlen(fileInput)];
    
    encrypt((const unsigned char*)fileInput, strlen((const char *)fileInput), (unsigned char *)encryptedOutput, outSize, encryptIv);
    free(fileInput);
    writeToFile("encrypt_output.txt", encryptedOutput);  
    
    cout << "Encrypted file:  " << encryptedOutput << endl;
    
    decrypt((const unsigned char*)encryptedOutput, strlen((const char *)encryptedOutput), (unsigned char *)decryptedOutput, decryptIv);
    free(encryptedOutput);
    
    cout << "Decrypted file:  " << decryptedOutput << endl;
    
    writeToFile("decrypt_output.txt", decryptedOutput);
    free(decryptedOutput);
    
    unsigned char shaResult2[64] = { 0 };
    generateSHA((unsigned char*)decryptedOutput, shaResult2);
    
    if(strcmp((const char *)shaResult,(const char *)shaResult2) == 0) cout << "Encryption and decryption was successful!";
    else cout << "Encryption and decryption was not successful!";
    
    return 0;
}

