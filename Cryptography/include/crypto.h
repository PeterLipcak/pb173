/* 
 * File:   crypto.h
 * Author: pedro1
 *
 * Created on March 4, 2016, 2:34 PM
 */

#ifndef CRYPTO_H
#define	CRYPTO_H


namespace Crypto {

    //length of key
    const int KEYLEN = 16;
    //CBS mode -> 16 bytes long blocks
    const int BLOCKLEN = 16;
    
    
    int read_file(const char* file_name, unsigned char** file_content);
    int write_to_file(const char* file_name, unsigned char* file_content);
    
    bool encrypt(unsigned char* key, const unsigned char* input_data, int input_size, 
        unsigned char* enc_data, int & enc_size, unsigned char * enc_iv);
    bool decrypt(unsigned char* key, const unsigned char * input_data, int input_size, 
        unsigned char * dec_output, unsigned char * dec_iv);
    
    void hash_file(unsigned char *file_content, unsigned char* sha_result);

}



#endif	/* CRYPTO_H */

