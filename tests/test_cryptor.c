/*
 * Created by zzzzer on 3/11/19.
 */

#include "helper.h"
#include "cryptor.h"
#include "transport.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define PASSWD (unsigned char *)"abc123"

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
// aes-128-ctr
#define PASSWD_TO_KEY "e99a18c428cb38d5f260853678922e0388fc221acae10caf2921f7435051325c"
#define PASSWD_TO_IV "1243734da46f16a118114ad51cfd48e2"

    CryptorInfo *ci = init_cryptor_info("aes-128-ctr", PASSWD, 32, 16);
    NetData *nd = init_net_data();

    bytes_to_key(PASSWD, ci->key, ci->key_len, nd->cipher_ctx.iv, ci->iv_len);

    char *key_hex = malloc(MAX_KEY_LEN*2+1);
    size_t key_hex_len = bytes_to_hex(ci->key, ci->key_len, key_hex);
    EXPECT_EQ_STRING(PASSWD_TO_KEY, key_hex, key_hex_len);
    free(key_hex);

    char *iv_hex = malloc(MAX_IV_LEN*2+1);
    size_t iv_hex_len = bytes_to_hex(nd->cipher_ctx.iv, ci->iv_len, iv_hex);
    EXPECT_EQ_STRING(PASSWD_TO_IV, iv_hex, iv_hex_len);
    free(iv_hex);

    // 加密
    nd->cipher_ctx.encrypt_ctx = INIT_ENCRYPT_CTX(ci->cipher_name, ci->key, nd->cipher_ctx.iv);
    strcpy((char *)nd->plaintext.data, "你好");
    nd->plaintext.len = strlen((char *)nd->plaintext.data);
    nd->ciphertext.len = encrypt(nd->cipher_ctx.encrypt_ctx,
            nd->plaintext.data, nd->plaintext.len, nd->ciphertext.data);
    // 测试多次加密，一次解密
    nd->ciphertext.len += encrypt(nd->cipher_ctx.encrypt_ctx,
            nd->plaintext.data, nd->plaintext.len, nd->ciphertext.data+nd->plaintext.len);

    // 解密
    nd->cipher_ctx.decrypt_ctx = INIT_DECRYPT_CTX(ci->cipher_name, ci->key, nd->cipher_ctx.iv);
    nd->plaintext.len = decrypt(nd->cipher_ctx.decrypt_ctx,
            nd->ciphertext.data, nd->ciphertext.len, nd->plaintext.data);

    EXPECT_EQ_LONG(12L, nd->plaintext.len);
    EXPECT_EQ_STRING("你好你好", nd->plaintext.data, nd->plaintext.len);

    free(ci);
    free_net_data(nd);
}

static void
test_encrypt_and_decrypt_fail()
{
    CryptorInfo *ci = init_cryptor_info("aes-128-ctr", PASSWD, 32, 16);
    NetData *nd = init_net_data();

    bytes_to_key(PASSWD, ci->key, ci->key_len, nd->cipher_ctx.iv, ci->iv_len);
    nd->cipher_ctx.encrypt_ctx = INIT_ENCRYPT_CTX(ci->cipher_name, ci->key, nd->cipher_ctx.iv);
    strcpy((char *)nd->plaintext.data, "你好");
    nd->plaintext.len = strlen((char *)nd->plaintext.data);
    encrypt(nd->cipher_ctx.encrypt_ctx,
            nd->plaintext.data, nd->plaintext.len, nd->plaintext.data);

    // 解密失败
    bytes_to_key((unsigned char *)"123123123123",
            ci->key, ci->key_len, nd->cipher_ctx.iv, ci->iv_len);
    nd->cipher_ctx.decrypt_ctx = INIT_DECRYPT_CTX(ci->cipher_name, ci->key, nd->cipher_ctx.iv);
    size_t ret = decrypt(nd->cipher_ctx.decrypt_ctx,
            nd->plaintext.data, nd->ciphertext.len, nd->plaintext.data);
    EXPECT_EQ_LONG(0L, ret);

    free(ci);
    free_net_data(nd);
}

void
test_cryptor()
{
    test_encrypt_and_decrypt();
    test_encrypt_and_decrypt_fail();
}