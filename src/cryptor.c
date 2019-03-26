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
void
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
    key[key_len] = 0;
    if (iv != NULL) {
        memcpy(iv, buf + key_len, iv_len);
        iv[iv_len] = 0;
    }
}

const EVP_CIPHER *
get_cipher(const char *cipher_name) {
    if (!strncmp(cipher_name, "aes-128-ctr", MAX_CIPHER_NAME_LEN)) {
        return EVP_aes_128_ctr();
    } else if (!strncmp(cipher_name, "aes-256-ctr", MAX_CIPHER_NAME_LEN)) {
        return EVP_aes_256_ctr();
    } else if (!strncmp(cipher_name, "aes-128-cfb", MAX_CIPHER_NAME_LEN)) {
        return EVP_aes_128_cfb();
    } else if (!strncmp(cipher_name, "aes-256-cfb", MAX_CIPHER_NAME_LEN)) {
        return EVP_aes_256_cfb();
    }

    return NULL;
}

CryptorInfo *
init_cryptor_info(const char *name,
                  const unsigned char *passwd, size_t key_len, size_t iv_len)
{
    CryptorInfo *ci = malloc(sizeof(CryptorInfo));
    if (ci == NULL) {
        return NULL;
    }

    size_t name_len = strlen(name);
    memcpy(ci->cipher_name, name, name_len);
    ci->cipher_name[name_len] = 0;
    ci->key_len = key_len;
    ci->iv_len = iv_len;
    bytes_to_key(passwd, ci->key, key_len, NULL, iv_len);

    return ci;
}

EVP_CIPHER_CTX *
init_cipher_ctx(const EVP_CIPHER *cipher,
        const unsigned char *key, const unsigned char *iv, int op)
{
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (ctx == NULL) {
        return NULL;
    }
    if (!EVP_CipherInit_ex(ctx, cipher, NULL, key, iv, op)) {
        EVP_CIPHER_CTX_free(ctx);
        return NULL;
    }
    return ctx;
}

/*
 * 加密失败，返回 0。
 */
size_t
encrypt(EVP_CIPHER_CTX *ctx, unsigned char *plaintext,
        size_t plaintext_len, unsigned char *ciphertext)
{
    size_t ciphertext_len;
    int outlen;

    if (!EVP_EncryptUpdate(ctx, ciphertext, &outlen, plaintext, (int)plaintext_len)) {
        return 0;
    }
    ciphertext_len = (size_t)outlen;

    if (!EVP_EncryptFinal_ex(ctx, ciphertext+outlen, &outlen)) {
        return 0;
    }
    ciphertext_len += outlen;

    return ciphertext_len;
}

/*
 * 解密失败，返回 0。
 */
size_t
decrypt(EVP_CIPHER_CTX *ctx, unsigned char *ciphertext,
        size_t ciphertext_len, unsigned char *plaintext)
{
    size_t plaintext_len;
    int outlen;

    if (!EVP_DecryptUpdate(ctx, plaintext, &outlen, ciphertext, (int)ciphertext_len)) {
        return 0;
    }
    plaintext_len = (size_t)outlen;

    if (!EVP_DecryptFinal_ex(ctx, plaintext+outlen, &outlen)) {
        return 0;
    }
    plaintext_len += outlen;

    return plaintext_len;
}
