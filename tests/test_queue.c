/*
 * Created by zzzzer on 4/1/19.
 */

#include "helper.h"
#include "queue.h"
#include <stdlib.h>

void
test_queue()
{
    int capacity = 3;
    SeqQueue *queue = init_seqqueue(capacity);
    EXPECT_EQ_INT(1, seqqueue_is_empty(queue));
    EXPECT_EQ_INT(0, seqqueue_is_full(queue));
    int *a = malloc(sizeof(int));
    *a = -1;
    int *b = malloc(sizeof(int));
    *b = -2;
    int *c = malloc(sizeof(int));
    *c = -3;
    int *d = malloc(sizeof(int));
    *d = -4;
    seqqueue_append(queue, a);
    seqqueue_append(queue, b);
    seqqueue_append(queue, c);
    EXPECT_EQ_INT(1, seqqueue_is_full(queue));
    void *ele = seqqueue_append(queue, d);
    EXPECT_EQ_INT(-1, *(int *)ele);
    free(ele);
    ele = seqqueue_pop(queue);
    EXPECT_EQ_INT(-2, *(int *)ele);
    free(ele);
    ele = seqqueue_pop(queue);
    EXPECT_EQ_INT(-3, *(int *)ele);
    free(ele);
    ele = seqqueue_pop(queue);
    EXPECT_EQ_INT(-4, *(int *)ele);
    free(ele);
    EXPECT_EQ_INT(1, seqqueue_is_empty(queue));

    free_seqqueue(queue);
}