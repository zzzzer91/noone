/*
 * Created by zzzzer on 2/11/19.
 */

#include "cryptor.h"
#include <string.h>
#include <unistd.h>
#include <openssl/evp.h>

void
crypto_md5(const unsigned char *data, size_t data_len, unsigned char *buf)
{
    EVP_Digest(data, data_len, buf, NULL, EVP_md5(), NULL);
}

/*
 * shadowsocks 采用的将 PASSWD 转为 key 和 iv 的方法
 *
 *   指 cfb，ctr
 *   aes-128 的 key 为 16 字节，iv 为 16 字节
 *   aes-192 的 key 为 24 字节，iv 为 16 字节
 *   aes-256 的 key 为 32 字节，iv 为 16 字节
 */
int
bytes_to_key(const unsigned char *passwd,
        unsigned char *key, size_t key_len,
        unsigned char *iv, size_t iv_len)
{
    unsigned char buf[128];

    size_t key_and_iv_len = key_len + iv_len;

    size_t passwd_len = strlen((char *)passwd);

    crypto_md5(passwd, passwd_len, buf);

    size_t buf_len = MD5_LEN;

    while (buf_len < key_and_iv_len) {
        memcpy(buf+buf_len, passwd, passwd_len);
        crypto_md5(buf+(buf_len-MD5_LEN), passwd_len+MD5_LEN, buf+buf_len);
        buf_len += MD5_LEN;
    }

    memcpy(key, buf, key_len);
    if (iv != NULL) {
        memcpy(iv, buf + key_len, iv_len);
    }

    return 0;
}

EVP_CIPHER_CTX *
init_cipher_ctx(const EVP_CIPHER *cipher,
        const unsigned char *key, const unsigned char *iv, int op)
{

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    EVP_CipherInit_ex(ctx, cipher, NULL, key, iv, op);
    return ctx;
}

int
encrypt(EVP_CIPHER_CTX *ctx, unsigned char *plaintext,
        int plaintext_len, unsigned char *ciphertext)
{
    int ciphertext_len;
    int outlen;

    EVP_EncryptUpdate(ctx, ciphertext, &outlen, plaintext, plaintext_len);
    ciphertext_len = outlen;

    EVP_EncryptFinal_ex(ctx, ciphertext+outlen, &outlen);
    ciphertext_len += outlen;

    return ciphertext_len;
}

int
decrypt(EVP_CIPHER_CTX *ctx, unsigned char *ciphertext,
        int ciphertext_len, unsigned char *plaintext)
{
    int plaintext_len;
    int outlen;

    EVP_DecryptUpdate(ctx, plaintext, &outlen, ciphertext, ciphertext_len);
    plaintext_len = outlen;

    EVP_DecryptFinal_ex(ctx, plaintext+outlen, &outlen);
    plaintext_len += outlen;

    return plaintext_len;
}
