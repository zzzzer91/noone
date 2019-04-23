/*
 * Created by zzzzer on 3/11/19.
 */

#include "helper.h"
#include "cryptor.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define TEST_PASSWD (unsigned char *)"abc123"

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
    size_t key_len = 32;
    size_t iv_len = 16;
    unsigned char key[MAX_KEY_LEN];
    unsigned char iv[MAX_IV_LEN];
    bytes_to_key(TEST_PASSWD, key, key_len, iv, iv_len);

    char *key_hex = malloc(MAX_KEY_LEN*2+1);
    size_t key_hex_len = bytes_to_hex(key, key_len, key_hex);
    EXPECT_EQ_STRING("e99a18c428cb38d5f260853678922e0388fc221acae10caf2921f7435051325c",
                     key_hex, key_hex_len);
    free(key_hex);

    char *iv_hex = malloc(MAX_IV_LEN*2+1);
    size_t iv_hex_len = bytes_to_hex(iv, iv_len, iv_hex);
    EXPECT_EQ_STRING("1243734da46f16a118114ad51cfd48e2", iv_hex, iv_hex_len);
    free(iv_hex);
}

static void
test_aes128ctr_encrypt_and_decrypt()
{
    NooneCryptorInfo *ci = init_noone_cryptor_info("aes-128-ctr", TEST_PASSWD, 32, 16);

    NooneCipherCtx *c_ctx = init_noone_cipher_ctx();
    // 加密
    c_ctx->encrypt_ctx = INIT_ENCRYPT_CTX(ci->cipher_name, ci->key, ci->iv);
    char plaintext[256];
    char ciphertext[256];
    strcpy(plaintext, "abc123");
    size_t plaintext_len = strlen(plaintext);
    size_t ciphertext_len = encrypt(c_ctx->encrypt_ctx,
            (uint8_t *)plaintext, plaintext_len, (uint8_t *)ciphertext);
    EXPECT_EQ_LONG(plaintext_len, ciphertext_len);
    // 解密
    c_ctx->decrypt_ctx = INIT_DECRYPT_CTX(ci->cipher_name, ci->key, ci->iv);
    char plaintext_result[256];
    size_t plaintext_len_result = decrypt(c_ctx->decrypt_ctx,
            (uint8_t *)ciphertext, ciphertext_len, (uint8_t *)plaintext_result);
    EXPECT_EQ_LONG(plaintext_len, plaintext_len_result);
    EXPECT_EQ_STRING("abc123", plaintext_result, plaintext_len_result);

    // 测试多次加密，一次解密
    ciphertext_len = encrypt(c_ctx->encrypt_ctx,
            (uint8_t *)plaintext, plaintext_len, (uint8_t *)ciphertext);
    ciphertext_len += encrypt(c_ctx->encrypt_ctx,
            (uint8_t *)plaintext, plaintext_len, (uint8_t *)ciphertext+ciphertext_len);
    EXPECT_EQ_LONG(plaintext_len*2, ciphertext_len);
    // 解密
    plaintext_len_result = decrypt(c_ctx->decrypt_ctx,
            (uint8_t *)ciphertext, ciphertext_len, (uint8_t *)plaintext_result);
    EXPECT_EQ_LONG(plaintext_len*2, plaintext_len_result);
    EXPECT_EQ_STRING("abc123abc123", plaintext_result, plaintext_len_result);

    free_noone_cipher_ctx(c_ctx);
    free_noone_cryptor_info(ci);
}

void
test_cryptor()
{
    test_bytes_to_key();
    test_aes128ctr_encrypt_and_decrypt();
}