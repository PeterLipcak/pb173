/* 
 * File:   main.cpp
 * Author: pedro1
 *
 * Created on February 26, 2016, 12:50 PM
 */
#include "crypto.h"


#include "string.h"
#include "stdio.h"


using namespace std;


int main(int argc, char** argv) {
    
    //AES key - 16 bytes
    unsigned char key[16] =  { 0xa5, 0x84, 0x99, 0x8d, 0x0d, 0xbd, 0xb1, 0x54,
        0xbb, 0xc5, 0x4f, 0xed, 0x86, 0x9a, 0x66, 0x11 };
    
    //Initialization Vector
    unsigned char iv[16] = {
        0x6c, 0x70, 0xed, 0x50, 0xfd, 0xed, 0xb9, 0xda,
        0x51, 0xa3, 0x40, 0xbd, 0x92, 0x9d, 0x38, 0x9d };
    
    //iv for encryption and decryption
    unsigned char encrypt_iv[16];
    unsigned char decrypt_iv[16];
    
    memcpy(encrypt_iv, iv, 16);    
    memcpy(decrypt_iv, iv, 16);

    
    
    unsigned char *file_input;
    
    int out_size;
    
    Crypto::read_file("../input.txt", &file_input);
    
//  SHA2-512  
    unsigned char sha_result1[64] = { 0 };
    unsigned char sha_result2[64] = { 0 };
    
    Crypto::hash_file((unsigned char*)file_input, sha_result1);
    
    unsigned int length = strlen((const char *)file_input);
    unsigned char encrypted_output[length];
    unsigned char decrypted_output[length];
    
    memset( encrypted_output, 0, length*sizeof(char) );
    memset( decrypted_output, 0, length*sizeof(char) );
      
    
    printf("Povodny subor: %s\n", file_input);
    printf("Dlzka povodneho subora: %lu\n", strlen((const char *)file_input)); 
    Crypto::encrypt(key, file_input, strlen((const char *)file_input), encrypted_output, out_size, encrypt_iv);
    //Crypto::hash_file((unsigned char*)encrypted_output, sha_result1);
    //Crypto::hash_file((unsigned char*)encrypted_output, sha_result2);
    printf("Zasifrovany subor: %s\n", encrypted_output); 
    printf("Dlzka zasifrovaneho subora: %lu\n", strlen((const char *)encrypted_output));
    Crypto::write_to_file("../encrypt_output.txt", encrypted_output);
    Crypto::decrypt(key, (const unsigned char*)encrypted_output, out_size, decrypted_output, decrypt_iv);
    printf("Desifrovany subor: %s\n", decrypted_output);
    printf("Dlzka desifrovaneho subora: %lu\n", strlen((const char *)decrypted_output));
    Crypto::write_to_file("../decrypt_output.txt", decrypted_output); 
    
    Crypto::hash_file((unsigned char*)decrypted_output, sha_result2);
    
    printf("Hash1 -> ");
    for (const unsigned char* p = sha_result1; *p; ++p)
    {
        printf("%02x", *p);
        ++p;
    }
    printf("\n");
    printf("Hash2 -> ");
    for (const unsigned char* p = sha_result2; *p; ++p)
    {
        printf("%02x", *p);
    }
    printf("\n");
    if(memcmp(sha_result1, sha_result2, 64))//strlen((const char*)file_input)))
    {
        printf("Hashes are the same.\n");
    } else  {
        printf("Hashes are different.\n");
    }
    
    delete[] file_input;
    return 0;
}
