/* Copyright (C) 2007-2010 Open Information Security Foundation
 *
 * You can copy, redistribute or modify this Program under the terms of
 * the GNU General Public License version 2 as published by the Free
 * Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * version 2 along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
 * 02110-1301, USA.
 */

/**
 * \file
 *
 * \author Victor Julien <victor@inliniac.net>
 *
 * Thread module management functions
 */

#include "suricata.h"
#include "threads.h"
#include "tm-queues.h"
#include "util-debug.h"

/*
*相应地，创建队列的函数TmqCreateQueue流程为：
1. 获取tmqs[tmq_id]的地址，作为返回的Tmq指针。
2. 设置该Tmq的name、id、type，其中id设为tmq_id，然后递增tmq_id。
该函数在TmThreadCreate中被直接或间接调用。
● 对于线程的inq，首先查inq_name对应的队列是否已存在，若不存在则直接调用TmqCreateQueue创建。
● 对于线程的outq，则首先要看outqh的OutHandlerCtxSetup是否设置，若设置了则会调用该函数去间接创建队列，否则跟创建inq类似。间接创建目前只有一种情况：使用”flow”作为线程的outqh->TmqhOutputFlowSetupCtx->StoreQueueId解析队列名字符串->TmqCreateQueue。
下面的小节都是关于线程间队列的。
队列数量:
Suricata中究竟会创造多少个线程间队列呢？这取决于系统的运行模式。

运行模式	     线程数                                 	队列数	        说明
single	      IDS: 取决于接口配置; IPS: 取决于nqueue	0	           单线程模式，不需要队列
workers	取决于网卡数量; IDS: 取决于接口配置; IPS: 取决于nqueue	0	多线程工人模式，但每个线程做所有事（从抓包到输出日志），因此也不需要队列
autofp	IDS：多个包获取线程，多个其他线程; IPS：与IDS下类似，但裁决/响应为单独线程	多个pickup队列，其余各1个	多线程自动流绑定负载均衡模式（auto flow pinned load balancing），每个流的包只会被同一个检测线程处理（flow pinned）。其中pickup对立个数与其reader线程数量一致，因为每个线程只能有1个inq。
*
*
*
*/
#define TMQ_MAX_QUEUES 256

static uint16_t tmq_id = 0;
static Tmq tmqs[TMQ_MAX_QUEUES];

Tmq* TmqAlloc(void)
{
    Tmq *q = SCMalloc(sizeof(Tmq));
    if (unlikely(q == NULL))
        goto error;

    memset(q, 0, sizeof(Tmq));
    return q;

error:
    return NULL;
}

Tmq* TmqCreateQueue(char *name)
{
    if (tmq_id >= TMQ_MAX_QUEUES)
        goto error;

    Tmq *q = &tmqs[tmq_id];
    q->name = SCStrdup(name);
    if (q->name == NULL)
        goto error;

    q->id = tmq_id++;
    /* for cuda purposes */
    q->q_type = 0;

    SCLogDebug("created queue \'%s\', %p", name, q);
    return q;

error:
    SCLogError(SC_ERR_THREAD_QUEUE, "too many thread queues %u, max is %u", tmq_id+1, TMQ_MAX_QUEUES);
    return NULL;
}

Tmq* TmqGetQueueByName(char *name)
{
    uint16_t i;

    for (i = 0; i < tmq_id; i++) {
        if (strcmp(tmqs[i].name, name) == 0)
            return &tmqs[i];
    }

    return NULL;
}

void TmqDebugList(void)
{
    uint16_t i = 0;
    for (i = 0; i < tmq_id; i++) {
        /* get a lock accessing the len */
        SCMutexLock(&trans_q[tmqs[i].id].mutex_q);
        printf("TmqDebugList: id %" PRIu32 ", name \'%s\', len %" PRIu32 "\n", tmqs[i].id, tmqs[i].name, trans_q[tmqs[i].id].len);
        SCMutexUnlock(&trans_q[tmqs[i].id].mutex_q);
    }
}

void TmqResetQueues(void)
{
    uint16_t i;
    for (i = 0; i < TMQ_MAX_QUEUES; i++) {
        if (tmqs[i].name) {
            SCFree(tmqs[i].name);
        }
    }
    memset(&tmqs, 0x00, sizeof(tmqs));
    tmq_id = 0;
}

/**
 * \brief Checks if all the queues allocated so far have at least one reader
 *        and writer.
 */
void TmValidateQueueState(void)
{
    int i = 0;
    char err = FALSE;

    for (i = 0; i < tmq_id; i++) {
        SCMutexLock(&trans_q[tmqs[i].id].mutex_q);
        if (tmqs[i].reader_cnt == 0) {
            SCLogError(SC_ERR_THREAD_QUEUE, "queue \"%s\" doesn't have a reader (id %d, max %u)", tmqs[i].name, i, tmq_id);
            err = TRUE;
        } else if (tmqs[i].writer_cnt == 0) {
            SCLogError(SC_ERR_THREAD_QUEUE, "queue \"%s\" doesn't have a writer (id %d, max %u)", tmqs[i].name, i, tmq_id);
            err = TRUE;
        }
        SCMutexUnlock(&trans_q[tmqs[i].id].mutex_q);

        if (err == TRUE)
            goto error;
    }

    return;

error:
    SCLogError(SC_ERR_FATAL, "fatal error during threading setup");
    exit(EXIT_FAILURE);
}
