/*
 * Created by zzzzer on 2/11/19.
 */

#ifndef _NOONE_CRYPTO_H_
#define _NOONE_CRYPTO_H_

#include <stddef.h>
#include <openssl/evp.h>

#define MD5_LEN 16

void crypto_md5(const unsigned char *data, size_t data_len, unsigned char *buf);

int bytes_to_key(const unsigned char *passwd,
             unsigned char *key, size_t key_len,
             unsigned char *iv, size_t iv_len);

EVP_CIPHER_CTX *init_cipher_ctx(const EVP_CIPHER *cipher,
        const unsigned char *key, const unsigned char *iv, int op);

#define INIT_AES128CTR_ENCRYPT_CTX(key, iv) \
    init_cipher_ctx(EVP_aes_128_ctr(), key, iv, 1)

#define INIT_AES128CTR_DECRYPT_CTX(key, iv) \
    init_cipher_ctx(EVP_aes_128_ctr(), key, iv, 0)

int crypto_init(const unsigned char *key, const unsigned char *iv);

int encrypt(EVP_CIPHER_CTX *ctx, unsigned char *plaintext,
        int plaintext_len, unsigned char *ciphertext);

int decrypt(EVP_CIPHER_CTX *ctx, unsigned char *ciphertext,
        int ciphertext_len, unsigned char *plaintext);

#endif  /* _NOONE_CRYPTO_H_ */
