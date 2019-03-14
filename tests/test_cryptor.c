/*
 * Created by zzzzer on 3/11/19.
 */

#include "cryptor.h"
#include "helper.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define KEY_LEN 32
#define IV_LEN 16

#define PASSWD "abc123"
#define PASSWD_TO_KEY "e99a18c428cb38d5f260853678922e0388fc221acae10caf2921f7435051325c"
#define PASSWD_TO_IV "1243734da46f16a118114ad51cfd48e2"

static size_t
bytes_to_hex(unsigned char *data, size_t len, char *buf)
{
    size_t i;
    for (i = 0; i < len; i++) {
        // snprintf() 会在最后加个 '\0'
        snprintf(buf+i*2, 3, "%02x", data[i]);
    }

    return i*2;
}

static void
test_bytes_to_key()
{
    unsigned char key[KEY_LEN+1];
    unsigned char iv[IV_LEN+1];
    bytes_to_key((unsigned char *)PASSWD, key, KEY_LEN, iv, IV_LEN);

    char *key_hex = (char *)malloc(KEY_LEN*2+1);
    size_t key_hex_len = bytes_to_hex(key, KEY_LEN, key_hex);
    EXPECT_EQ_STRING(PASSWD_TO_KEY, key_hex, key_hex_len);
    free(key_hex);

    char *iv_hex = (char *)malloc(IV_LEN*2+1);
    size_t iv_hex_len = bytes_to_hex(iv, IV_LEN, iv_hex);
    EXPECT_EQ_STRING(PASSWD_TO_IV, iv_hex, iv_hex_len);
    free(iv_hex);
}

static void
test_encrypt_and_decrypt()
{
    CryptorInfo *ci = malloc(sizeof(CryptorInfo));
    strncpy(ci->cipher_name, "aes-128-ctr", sizeof(ci->cipher_name));
    ci->key_len = 32;
    ci->iv_len = 16;
    unsigned char iv[IV_LEN+1];

    bytes_to_key((unsigned char *)PASSWD, ci->key, ci->key_len, iv, ci->iv_len);

    const EVP_CIPHER *cipher = get_cipher(ci->cipher_name);
    EVP_CIPHER_CTX *encrypt_ctx = INIT_ENCRYPT_CTX(cipher, ci->key, iv);
    EVP_CIPHER_CTX *decrypt_ctx = INIT_DECRYPT_CTX(cipher, ci->key, iv);

    unsigned char plaintext[] = "你好";
    size_t plaintext_len = (int)strlen((char *)plaintext);
    unsigned char ciphertext[256];
    size_t ciphertext_len = encrypt(encrypt_ctx, plaintext, plaintext_len, ciphertext);
    plaintext_len = decrypt(decrypt_ctx, ciphertext, ciphertext_len, plaintext);
    EXPECT_EQ_INT(6, (int)plaintext_len);
    EXPECT_EQ_STRING("你好", plaintext, plaintext_len);
}

void
test_cryptor()
{
    test_bytes_to_key();
    test_encrypt_and_decrypt();
}