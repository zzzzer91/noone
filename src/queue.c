/*
 * Created by zzzzer on 4/1/19.
 */

#include "queue.h"
#include <stdlib.h>
#include <assert.h>

SeqQueue *
init_seqqueue(int capacity)
{
    assert(capacity>0);

    SeqQueue *queue = malloc(sizeof(SeqQueue));
    if (queue == NULL) {
        return NULL;
    }
    // 会损失一个位置，用于判断队满
    queue->data = calloc(capacity+1, sizeof(void *));
    if (queue->data == NULL) {
        return NULL;
    }

    queue->capacity = capacity;
    queue->rear = queue->front = 0;

    return queue;
}

void
free_seqqueue(SeqQueue *queue)
{
    assert(queue!=NULL);

    free(queue->data);
    free(queue);
}

inline int
seqqueue_is_empty(const SeqQueue *queue)
{
    return queue->front == queue->rear;
}

inline int
seqqueue_is_full(const SeqQueue *queue)
{
    return queue->front == (queue->rear + 1) % (queue->capacity+1);
}

/*
 * 当队列满时返回最前面的元素，用于调用者释放
 */
void *
seqqueue_append(SeqQueue *queue, void *elem)
{
    assert(queue!=NULL);

    /* 队满 */
    void *ele = NULL;
    if (seqqueue_is_full(queue)) {
        ele = queue->data[queue->front];
        queue->front = (queue->front + 1) % (queue->capacity+1);
    }

    queue->data[queue->rear] = elem;
    queue->rear = (queue->rear + 1) % (queue->capacity+1);

    return ele;
}

void *
seqqueue_pop(SeqQueue *queue)
{
    assert(queue!=NULL);

    /* 队空 */
    if (seqqueue_is_empty(queue)) {
        return NULL;
    }

    void *elem = queue->data[queue->front];
    queue->front = (queue->front + 1) % (queue->capacity+1);

    return elem;
}