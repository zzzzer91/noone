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

typedef struct CryptorInfo {
    char cipher_name[MAX_CIPHER_NAME_LEN];
    unsigned char key[MAX_KEY_LEN+1];
    size_t key_len;
    size_t iv_len;
} CryptorInfo;

typedef struct CipherCtx {
    EVP_CIPHER_CTX *encrypt_ctx;
    EVP_CIPHER_CTX *decrypt_ctx;
    unsigned char key[MAX_KEY_LEN+1];
    size_t key_len;
    unsigned char iv[MAX_IV_LEN+1];
    size_t iv_len;
} CipherCtx;

void crypto_md5(const unsigned char *data, size_t data_len, unsigned char *buf);

void bytes_to_key(const unsigned char *passwd,
             unsigned char *key, size_t key_len,
             unsigned char *iv, size_t iv_len);

const EVP_CIPHER *get_cipher(const char *cipher_name);

CryptorInfo *init_cryptor_info(const char *name,
        const unsigned char *passwd, size_t key_len, size_t iv_len);

EVP_CIPHER_CTX *init_cipher_ctx(const EVP_CIPHER *cipher,
        const unsigned char *key, const unsigned char *iv, int op);

#define INIT_ENCRYPT_CTX(cipher_name, key, iv) \
    init_cipher_ctx(get_cipher(cipher_name), key, iv, 1)

#define INIT_DECRYPT_CTX(cipher_name, key, iv) \
    init_cipher_ctx(get_cipher(cipher_name), key, iv, 0)

size_t encrypt(EVP_CIPHER_CTX *ctx, unsigned char *plaintext,
        size_t plaintext_len, unsigned char *ciphertext);

size_t decrypt(EVP_CIPHER_CTX *ctx, unsigned char *ciphertext,
        size_t ciphertext_len, unsigned char *plaintext);

#endif  /* _NOONE_CRYPTO_H_ */
