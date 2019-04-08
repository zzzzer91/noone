/*
 * Created by zzzzer on 2/11/19.
 */

#ifndef _NOONE_CRYPTO_H_
#define _NOONE_CRYPTO_H_

#include <stddef.h>
#include <openssl/evp.h>

#define MAX_KEY_LEN 32
#define MAX_IV_LEN 32
#define MAX_CIPHER_NAME_LEN 32

#define MD5_LEN 16

typedef struct NooneCryptorInfo {
    char cipher_name[MAX_CIPHER_NAME_LEN];
    uint8_t key[MAX_KEY_LEN];
    uint8_t iv[MAX_IV_LEN];
    int cipher_name_len;
    int key_len;
    int iv_len;
} NooneCryptorInfo;

typedef struct NooneCipherCtx {
    EVP_CIPHER_CTX *encrypt_ctx;
    EVP_CIPHER_CTX *decrypt_ctx;
} NooneCipherCtx;

void crypto_md5(const uint8_t *data, size_t data_len, uint8_t *buf);

void bytes_to_key(const uint8_t *passwd,
                  uint8_t *key, size_t key_len,
                  uint8_t *iv, size_t iv_len);

const EVP_CIPHER *get_cipher(const char *cipher_name);

NooneCryptorInfo *init_noone_cryptor_info(const char *name,
        const uint8_t *passwd, size_t key_len, size_t iv_len);

void free_noone_cryptor_info(NooneCryptorInfo *cryptor_info);

NooneCipherCtx *init_noone_cipher_ctx();

void free_noone_cipher_ctx(NooneCipherCtx *cipher_ctx);

EVP_CIPHER_CTX *init_evp_cipher_ctx(const EVP_CIPHER *cipher,
        const uint8_t *key, const uint8_t *iv, int op);

#define INIT_ENCRYPT_CTX(cipher_name, key, iv) \
    init_evp_cipher_ctx(get_cipher(cipher_name), key, iv, 1)

#define INIT_DECRYPT_CTX(cipher_name, key, iv) \
    init_evp_cipher_ctx(get_cipher(cipher_name), key, iv, 0)

size_t encrypt(EVP_CIPHER_CTX *ctx, uint8_t *plaintext,
        size_t plaintext_len, uint8_t *ciphertext);

size_t decrypt(EVP_CIPHER_CTX *ctx, uint8_t *ciphertext,
        size_t ciphertext_len, uint8_t *plaintext);

#endif  /* _NOONE_CRYPTO_H_ */
