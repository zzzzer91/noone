/*
 * Created by zzzzer on 3/18/19.
 */

#include "transport.h"

NetData *
init_net_data()
{
    NetData *stream_data = malloc(sizeof(NetData));
    if (stream_data == NULL) return NULL;

    stream_data->ss_stage = STAGE_INIT;
    stream_data->ciphertext_len = 0;
    stream_data->ciphertext_p = stream_data->ciphertext;
    stream_data->plaintext_len = 0;
    stream_data->plaintext_p = stream_data->plaintext;
    stream_data->remote_buf_len = 0;
    stream_data->remote_buf_p = stream_data->remote_buf;

    return stream_data;
}