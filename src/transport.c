/*
 * Created by zzzzer on 3/18/19.
 */

#include "transport.h"

NetData *
init_net_data()
{
    NetData *nd = malloc(sizeof(NetData));
    if (nd == NULL) return NULL;

    nd->ss_stage = STAGE_INIT;
    nd->ciphertext_len = 0;
    nd->ciphertext_p = nd->ciphertext;
    nd->plaintext_len = 0;
    nd->plaintext_p = nd->plaintext;
    nd->remote_buf_len = 0;
    nd->remote_buf_p = nd->remote_buf;
    nd->is_iv_send = 0;

    return nd;
}