/*
 * Created by zzzzer on 3/11/19.
 */

#include "cryptor.h"
#include "log.h"
#include "helper.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define KEY_LEN 32
#define IV_LEN 16

#define PASSWD (unsigned char *)"abc123"
unsigned char g_key[KEY_LEN+1];
unsigned char g_iv[IV_LEN+1];

static void
hex_print(unsigned char *data, int len)
{
    for (int i = 0; i < len; i++) {
        printf("%02x", data[i]);
    }
    printf("\n");
}

static void
test_bytes_to_key()
{
    bytes_to_key(PASSWD, g_key, KEY_LEN, g_iv, IV_LEN);
    hex_print(g_key, KEY_LEN);
    hex_print(g_iv, IV_LEN);
}

static void
test_encrypt_and_decrypt()
{
    bytes_to_key(PASSWD, g_key, KEY_LEN, g_iv, IV_LEN);
    EVP_CIPHER_CTX *encrypt_ctx = INIT_AES128CTR_ENCRYPT_CTX(g_key, g_iv);
    EVP_CIPHER_CTX *decrypt_ctx = INIT_AES128CTR_DECRYPT_CTX(g_key, g_iv);
    unsigned char plaintext[] = "abc123";
    int plaintext_len = (int)strlen((char *)plaintext);
    unsigned char ciphertext[256];
    int ciphertext_len = encrypt(encrypt_ctx, plaintext, plaintext_len, ciphertext);
    // hex_print(ciphertext, ciphertext_len);
    plaintext_len = decrypt(decrypt_ctx, ciphertext, ciphertext_len, plaintext);
    EXPECT_EQ_INT(6, plaintext_len);
    EXPECT_EQ_STRING("abc123", plaintext, plaintext_len);
}

void
test_cryptor()
{
    // test_bytes_to_key();
    test_encrypt_and_decrypt();
}