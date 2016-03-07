/** 
 * @file main.cpp
 * @author Martin Ukrop
 * @licence MIT Licence
 */

#include "crypto.h"
#include "string.h"

// Tell CATCH to define its main function here
#define CATCH_CONFIG_MAIN
#include "catch.hpp"

//AES key - 16 bytes
    unsigned char key[16] =  { 0xa5, 0x84, 0x99, 0x8d, 0x0d, 0xbd, 0xb1, 0x54,
        0xbb, 0xc5, 0x4f, 0xed, 0x86, 0x9a, 0x66, 0x11 };

    //Initialization Vector
    unsigned char iv[16] = {
        0x6c, 0x70, 0xed, 0x50, 0xfd, 0xed, 0xb9, 0xda,
        0x51, 0xa3, 0x40, 0xbd, 0x92, 0x9d, 0x38, 0x9d };


TEST_CASE("Encrypt + Decrypt", "Test if encMessage and original message are the same") {
    
    
    //iv for encryption and decryption
    unsigned char encrypt_iv[16];
    unsigned char decrypt_iv[16];
    
    memcpy(encrypt_iv, iv, 16);    
    memcpy(decrypt_iv, iv, 16);
    
    
    unsigned char message[] = "Secret Message";
    unsigned char enc_message[32] = { 0 };
    unsigned char dec_message[32] = { 0 };
    
    int out_size = 0;
    
    SECTION( "encryption", "encMessage divided by 16" )
    {
        Crypto::encrypt(key, message, strlen((const char *)message), enc_message, out_size, encrypt_iv);
        INFO("Length of encrypted message divided by 16 -> " << (strlen((char*)enc_message) % 16));
        CHECK( (strlen((char*)enc_message) % 16) == 0 );
        
        SECTION( "decryption", "decMessage same as original message" )
        {
            REQUIRE( message != dec_message );
            Crypto::decrypt(key, (const unsigned char*)enc_message, out_size, dec_message, decrypt_iv);    
            INFO("Decrypted message -> \"" << dec_message << "\"");
            //CHECK( strcmp("dsad", (char *)dec_message) == 0 );         
        }
    }
}

TEST_CASE("Decryption", "Decryption with wrong key") {

    //iv for encryption and decryption
    unsigned char encrypt_iv[16];
    unsigned char decrypt_iv[16];

    memcpy(encrypt_iv, iv, 16);
    memcpy(decrypt_iv, iv, 16);
    
    decrypt_iv[5] = 0x70;

    unsigned char message[] = "Secret Message";
    unsigned char enc_message[32] = { 0 };
    unsigned char dec_message[32] = { 0 };

    int out_size = 0;

        Crypto::encrypt(key, message, strlen((const char *)message), enc_message, out_size, encrypt_iv);

            REQUIRE( message != dec_message );
            Crypto::decrypt(key, (const unsigned char*)enc_message, out_size, dec_message, decrypt_iv);
            INFO("Decrypted message -> \"" << dec_message << "\"");
            CHECK( strcmp((char *)message, (char *)dec_message) != 0 );         


}

TEST_CASE("Hash", "Test if hashes are the same") {
    
    //iv for encryption and decryption
    unsigned char encrypt_iv[16];
    unsigned char decrypt_iv[16];
    
    memcpy(encrypt_iv, iv, 16);    
    memcpy(decrypt_iv, iv, 16);
    
    
    unsigned char message[] = "Secret Message";
    unsigned char enc_message[32] = { 0 };
    unsigned char dec_message[32] = { 0 };
    
    int out_size = 0;
    
    //  SHA2-512  
    unsigned char sha_result1[65] = { 0 };
    unsigned char sha_result2[65] = { 0 };
    
    Crypto::hash_file(message, sha_result1);
    INFO("Hash of original message -> " << sha_result1);
    
    Crypto::encrypt(key, message, strlen((const char *)message), enc_message, out_size, encrypt_iv);
    Crypto::decrypt(key, (const unsigned char*)enc_message, out_size, dec_message, decrypt_iv);    
    
    Crypto::hash_file(dec_message, sha_result2);
    INFO("Hash of decrypted message -> " << sha_result2);
    
    CHECK(strcmp((char *)sha_result1, (char *)sha_result2) == 0);
}

TEST_CASE("File", "Test if file exists or cannot be read/written into") {

    unsigned char *file_input;
    
    CHECK(Crypto::read_file("input.txt", &file_input) == 0);

    CHECK(Crypto::write_to_file("decrypt_output.txt", file_input) == 0);
    
}



