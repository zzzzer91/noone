/*
 * Created by zzzzer on 4/1/19.
 */

#ifndef _NOONE_QUEUE_H_
#define _NOONE_QUEUE_H_

typedef struct SeqQueue {
    void **data;
    int capacity;
    int front, rear; /* 队空:front==rear, 队满:front==(rear+1)%capacity，会损失一格 */
} SeqQueue;

SeqQueue *init_seqqueue(int capacity);
void free_seqqueue(SeqQueue *queue);
int seqqueue_is_empty(const SeqQueue *queue);
int seqqueue_is_full(const SeqQueue *queue);
void *seqqueue_append(SeqQueue *queue, void *elem);
void *seqqueue_pop(SeqQueue *queue);

#endif  /* _NOONE_QUEUE_H_ */
