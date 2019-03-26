/*
 * Created by zzzzer on 3/18/19.
 */

#include "transport.h"

NetData *
init_net_data()
{
    NetData *nd = malloc(sizeof(NetData));
    if (nd == NULL) {
        return NULL;
    }

    nd->ssclient_fd = -1;
    nd->remote_fd = -1;

    nd->ss_stage = STAGE_INIT;
    nd->cipher_ctx.encrypt_ctx = NULL;
    nd->cipher_ctx.decrypt_ctx = NULL;

    init_buffer(&nd->ciphertext, BUF_CAPACITY);
    init_buffer(&nd->plaintext, BUF_CAPACITY);
    init_buffer(&nd->remote, BUF_CAPACITY);
    init_buffer(&nd->remote_cipher, BUF_CAPACITY);
    nd->is_iv_send = 0;

    return nd;
}

void
free_net_data(NetData *nd)
{
    if (nd->cipher_ctx.encrypt_ctx != NULL) {
        EVP_CIPHER_CTX_free(nd->cipher_ctx.encrypt_ctx);
    }
    if (nd->cipher_ctx.decrypt_ctx != NULL) {
        EVP_CIPHER_CTX_free(nd->cipher_ctx.decrypt_ctx);
    }
    free_buffer(&nd->ciphertext);
    free_buffer(&nd->plaintext);
    free_buffer(&nd->remote);
    free_buffer(&nd->remote_cipher);
    free(nd);
}