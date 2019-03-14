/*
 * Created by zzzzer on 2/11/19.
 */

#ifndef _NOONE_CRYPTO_H_
#define _NOONE_CRYPTO_H_

#include <stddef.h>
#include <openssl/evp.h>

#define KEY_LEN 32
#define CIPHER_NAME_LEN 32

#define MD5_LEN 16

typedef struct CryptorInfo{
    char cipher_name[CIPHER_NAME_LEN];
    unsigned char key[KEY_LEN+1];
    size_t key_len;
    size_t iv_len;
} CryptorInfo;

void crypto_md5(const unsigned char *data, size_t data_len, unsigned char *buf);

int bytes_to_key(const unsigned char *passwd,
             unsigned char *key, size_t key_len,
             unsigned char *iv, size_t iv_len);

CryptorInfo *init_cryptor_info(const char *name,
        const unsigned char *passwd, size_t key_len, size_t iv_len);

const EVP_CIPHER *get_cipher(const char *cipher_name);

EVP_CIPHER_CTX *init_cipher_ctx(const EVP_CIPHER *cipher,
        const unsigned char *key, const unsigned char *iv, int op);

#define INIT_ENCRYPT_CTX(cipher, key, iv) \
    init_cipher_ctx(cipher, key, iv, 1)

#define INIT_DECRYPT_CTX(cipher, key, iv) \
    init_cipher_ctx(cipher, key, iv, 0)

size_t encrypt(EVP_CIPHER_CTX *ctx, unsigned char *plaintext,
        size_t plaintext_len, unsigned char *ciphertext);

size_t decrypt(EVP_CIPHER_CTX *ctx, unsigned char *ciphertext,
        size_t ciphertext_len, unsigned char *plaintext);

#endif  /* _NOONE_CRYPTO_H_ */
