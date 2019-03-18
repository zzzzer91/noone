/*
 * Created by zzzzer on 3/11/19.
 */

#include "helper.h"
#include "cryptor.h"
#include "tcp.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define PASSWD (unsigned char *)"abc123"
// aes-128-ctr
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
test_encrypt_and_decrypt()
{
    CryptorInfo *ci = init_cryptor_info("aes-128-ctr", PASSWD, 32, 16);
    StreamData *sd = init_stream_data();

    bytes_to_key(PASSWD, ci->key, ci->key_len, sd->iv, ci->iv_len);

    char *key_hex = (char *)malloc(MAX_KEY_LEN*2+1);
    size_t key_hex_len = bytes_to_hex(ci->key, ci->key_len, key_hex);
    EXPECT_EQ_STRING(PASSWD_TO_KEY, key_hex, key_hex_len);
    free(key_hex);

    char *iv_hex = (char *)malloc(MAX_IV_LEN*2+1);
    size_t iv_hex_len = bytes_to_hex(sd->iv, ci->iv_len, iv_hex);
    EXPECT_EQ_STRING(PASSWD_TO_IV, iv_hex, iv_hex_len);
    free(iv_hex);

    // 加密
    sd->encrypt_ctx = INIT_ENCRYPT_CTX(ci->cipher, ci->key, sd->iv);
    strcpy((char *)sd->plaintext, "你好");
    sd->plaintext_len = (int)strlen((char *)sd->plaintext);
    sd->ciphertext_len = encrypt(sd->encrypt_ctx,
            sd->plaintext, sd->plaintext_len, sd->ciphertext);
    free(sd->encrypt_ctx);

    // 解密
    sd->decrypt_ctx = INIT_DECRYPT_CTX(ci->cipher, ci->key, sd->iv);
    sd->plaintext_len = decrypt(sd->decrypt_ctx,
            sd->ciphertext, sd->ciphertext_len, sd->plaintext);
    free(sd->decrypt_ctx);

    EXPECT_EQ_INT(6, (int)sd->plaintext_len);
    EXPECT_EQ_STRING("你好", sd->plaintext, sd->plaintext_len);

    free(sd);
    free(ci);
}

void
test_cryptor()
{
    test_encrypt_and_decrypt();
}