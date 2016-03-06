#include "crypto.h"

#include <iostream>
#include <fstream>
#include "string.h"

#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/aes.h"


using namespace std;

void Crypto::read_file(const char* file_name, unsigned char** file_content)
{
    ifstream file(file_name);
    
    if (file.is_open())
    {
        file.seekg(0, ios::end);
        int size = file.tellg();
        printf("%d", size);
        int offset = 16 - ((size + 16) % 16);
	*file_content = new unsigned char [size + offset];
        file.seekg (0, ios::beg);
        file.read (*((char**)file_content), size);
        file.close();
    } else  {
        cout << "Unable to open input file"; 
    }
}



void Crypto::write_to_file(const char* file_name, unsigned char* file_content)
{
    ofstream file(file_name);
    
    if (file.is_open())
    {
        file << file_content;
        file.close();
    } else {
        cout << "Unable to open input file"; 
    }
}



bool Crypto::encrypt(unsigned char* key, const unsigned char* input_data, int input_size, 
        unsigned char* enc_data, int & enc_size, unsigned char * enc_iv)
{
//    PKCS#7
//    The value of each added byte is the number of bytes that are added,
//    i.e. N bytes, each of value N are added. The number of bytes added will
//    depend on the block boundary to which the message needs to be extended.
    int pad_len = BLOCKLEN - (input_size % BLOCKLEN);
    int temp_buff_size = input_size + pad_len;
    unsigned char * temp_buff = new unsigned char[temp_buff_size];
    memcpy(temp_buff, input_data, input_size);
    for (int pos = 0; pos < pad_len; ++pos)
    {
        temp_buff[input_size + pos] = pad_len;  // padding the data 
    }  
    
    mbedtls_aes_context aes_ctx;
    
    mbedtls_aes_setkey_enc(&aes_ctx, key, KEYLEN * 8);
    mbedtls_aes_crypt_cbc(&aes_ctx, MBEDTLS_AES_ENCRYPT, temp_buff_size, enc_iv, temp_buff, enc_data);
    enc_size = temp_buff_size;
    
    delete[] temp_buff;
    return true;
}




bool Crypto::decrypt(unsigned char* key, const unsigned char * input_data, int input_size, 
        unsigned char * dec_output, unsigned char * dec_iv)
{    
    mbedtls_aes_context aes_ctx;
    
    mbedtls_aes_init( &aes_ctx );
    
    mbedtls_aes_setkey_dec(&aes_ctx, key, KEYLEN * 8);
    mbedtls_aes_crypt_cbc(&aes_ctx, MBEDTLS_AES_DECRYPT, input_size, dec_iv, input_data, dec_output);
    dec_output[input_size - dec_output[input_size-1]] = '\0';
    
    return true;
}



void Crypto::hash_file(unsigned char *file_content, unsigned char* sha_result){
    mbedtls_sha512(file_content, strlen((const char*)file_content), sha_result, 0);   
//    cout << "Hash -> " << sha_result << endl;
}
