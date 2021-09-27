/* Copyright (C) 2007-2011 Open Information Security Foundation
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
 * \author Anoop Saldanha <anoopsaldanha@gmail.com>
 */

#ifndef __TM_THREADS_H__
#define __TM_THREADS_H__

#include "tmqh-packetpool.h"
#include "tm-threads-common.h"
#include "tm-modules.h"

#define TM_QUEUE_NAME_MAX 16
#define TM_THREAD_NAME_MAX 16

typedef TmEcode (*TmSlotFunc)(ThreadVars *, Packet *, void *, PacketQueue *,
                        PacketQueue *);

typedef struct TmSlot_ {
    /* the TV holding this slot */
    ThreadVars *tv;

    /* function pointers */
    SC_ATOMIC_DECLARE(TmSlotFunc, SlotFunc);

    TmEcode (*PktAcqLoop)(ThreadVars *, void *, void *);

    TmEcode (*SlotThreadInit)(ThreadVars *, void *, void **);
    void (*SlotThreadExitPrintStats)(ThreadVars *, void *);
    TmEcode (*SlotThreadDeinit)(ThreadVars *, void *);

    /* data storage */
    void *slot_initdata;
    SC_ATOMIC_DECLARE(void *, slot_data);

    /* queue filled by the SlotFunc with packets that will
     * be processed futher _before_ the current packet.
     * The locks in the queue are NOT used */
    PacketQueue slot_pre_pq;

    /* queue filled by the SlotFunc with packets that will
     * be processed futher _after_ the current packet. The
     * locks in the queue are NOT used */
    PacketQueue slot_post_pq;

    /* store the thread module id */
    int tm_id;

    /* slot id, only used my TmVarSlot to know what the first slot is */
    int id;

    /* linked list, only used when you have multiple slots(used by TmVarSlot) */
    struct TmSlot_ *slot_next;

    /* just called once, so not perf critical */
    TmEcode (*Management)(ThreadVars *, void *);

} TmSlot;

extern ThreadVars *tv_root[TVT_MAX];

extern SCMutex tv_root_lock;

void TmSlotSetFuncAppend(ThreadVars *, TmModule *, void *);
void TmSlotSetFuncAppendDelayed(ThreadVars *, TmModule *, void *, int delayed);
TmSlot *TmSlotGetSlotForTM(int);

ThreadVars *TmThreadCreate(const char *, char *, char *, char *, char *, char *,
                           void *(fn_p)(void *), int);
ThreadVars *TmThreadCreatePacketHandler(const char *, char *, char *, char *, char *,
                                        char *);
ThreadVars *TmThreadCreateMgmtThread(const char *name, void *(fn_p)(void *), int);
ThreadVars *TmThreadCreateMgmtThreadByName(const char *name, char *module,
                                     int mucond);
ThreadVars *TmThreadCreateCmdThreadByName(const char *name, char *module,
                                     int mucond);
TmEcode TmThreadSpawn(ThreadVars *);
void TmThreadSetFlags(ThreadVars *, uint8_t);
void TmThreadKillThread(ThreadVars *);
void TmThreadKillThreadsFamily(int family);
void TmThreadKillThreads(void);
void TmThreadClearThreadsFamily(int family);
void TmThreadAppend(ThreadVars *, int);
void TmThreadRemove(ThreadVars *, int);
void TmThreadSetGroupName(ThreadVars *tv, const char *name);

TmEcode TmThreadSetCPUAffinity(ThreadVars *, uint16_t);
TmEcode TmThreadSetThreadPriority(ThreadVars *, int);
TmEcode TmThreadSetCPU(ThreadVars *, uint8_t);
TmEcode TmThreadSetupOptions(ThreadVars *);
void TmThreadSetPrio(ThreadVars *);
int TmThreadGetNbThreads(uint8_t type);

void TmThreadInitMC(ThreadVars *);
void TmThreadTestThreadUnPaused(ThreadVars *);
void TmThreadContinue(ThreadVars *);
void TmThreadContinueThreads(void);
void TmThreadPause(ThreadVars *);
void TmThreadPauseThreads(void);
void TmThreadCheckThreadState(void);
TmEcode TmThreadWaitOnThreadInit(void);
ThreadVars *TmThreadsGetCallingThread(void);

int TmThreadsCheckFlag(ThreadVars *, uint16_t);
void TmThreadsSetFlag(ThreadVars *, uint16_t);
void TmThreadsUnsetFlag(ThreadVars *, uint16_t);
void TmThreadWaitForFlag(ThreadVars *, uint16_t);

TmEcode TmThreadsSlotVarRun (ThreadVars *tv, Packet *p, TmSlot *slot);

ThreadVars *TmThreadsGetTVContainingSlot(TmSlot *);
void TmThreadDisablePacketThreads(void);
void TmThreadDisableReceiveThreads(void);
TmSlot *TmThreadGetFirstTmSlotForPartialPattern(const char *);

uint32_t TmThreadCountThreadsByTmmFlags(uint8_t flags);

/**
 *  \brief Process the rest of the functions (if any) and queue.
 其中，s就是前面一路传下来的slot，而p为当前要处理的Packet。处理流程如下：
1.调用TmThreadsSlotVarRun，将数据包依次传入后续的各个slot进行处理。
2.若返回失败，则调用TmqhOutputPacketpool将数据包（以及各个slot的slot_post_pq中的数据包）进行回收或释放。然后设置线程标志为THV_FAILED，等待主线程处理。
3.若返回成功，则调用tmqh_out（线程创建时设置为与该线程绑定的outqh的处理函数OutHandler，在这里默认为TmqhOutputFlowActivePackets），将数据包送到后续队列中去。
4.此外，由于各模块在处理过程中可能会新生成数据包（如隧道数据包、重组数据包），
这些数据包存储在与每个slot绑定的slot_pre_pq或slot_post_pq队列中，因此还需要类似上述流程，
对这些数据包进行处理。这里只集中处理了slot_post_pq，slot_pre_pq将在处理每个slot后立即处理。
对数据包进行进一步处理的TmThreadsSlotVarRun函数原型如下：
TmEcode TmThreadsSlotVarRun(ThreadVars *tv, Packet *p,TmSlot *slot)
按照函数头的注释说明，这个函数被从母函数中拉出来独立存在的原因是，为了能够对其进行递归调用。

函数主流程是一个遍历所有slot的for循环，其执行过程如下：
1.调用slot的处理函数SlotFunc。
2.若返回失败，处理流程与上面类似。
3.若返回成功，则继续处理slot_pre_pq：对其中每个数据包，都递归调用TmThreadsSlotVarRun，
将其送入下一个slot进行处理。
4.注： slot_pre_pq vs. slot_post_pq： 某个slot在处理某个母数据包时新产生的子数据包，
若放入slot_pre_pq中，则这个数据包将在本个slot处理完母数据包后，在后续slot处理母数据包之前，
先将这些子数据包放到后续的slot去处理；而如果是放如slot_post_pq，
则需要等到母数据包被所有slot都处理完后，在下一个数据包处理之前，再去集中处理，如上面所述。

前一篇main()的笔记中已经记录了，抓包线程中只有两个slot，第一个slot在嵌入的即是前面所介绍
的ReceivePcap模块，而下一个slot函数中嵌入的模块为DecodePcap，其对应的SlotFunc是DecodePcap，
其任务是对从通过pcap抓取的数据包进行解码。
到次，这个pcap实时数据包源的任务已经完成了。其他数据包源模块的功能和流程也基本类似，
最终都会递交给相应的解码模块。
 */
static inline TmEcode TmThreadsSlotProcessPkt(ThreadVars *tv, TmSlot *s, Packet *p)
{
    TmEcode r = TM_ECODE_OK;

    if (s == NULL) {
        tv->tmqh_out(tv, p);
        return r;
    }

    if (TmThreadsSlotVarRun(tv, p, s) == TM_ECODE_FAILED) {
        TmqhOutputPacketpool(tv, p);
        TmSlot *slot = s;
        while (slot != NULL) {
            SCMutexLock(&slot->slot_post_pq.mutex_q);
            TmqhReleasePacketsToPacketPool(&slot->slot_post_pq);
            SCMutexUnlock(&slot->slot_post_pq.mutex_q);

            slot = slot->slot_next;
        }
        TmThreadsSetFlag(tv, THV_FAILED);
        r = TM_ECODE_FAILED;

    } else {
        tv->tmqh_out(tv, p);

        /* post process pq */
        TmSlot *slot = s;
        while (slot != NULL) {
            if (slot->slot_post_pq.top != NULL) {
                while (1) {
                    SCMutexLock(&slot->slot_post_pq.mutex_q);
                    Packet *extra_p = PacketDequeue(&slot->slot_post_pq);
                    SCMutexUnlock(&slot->slot_post_pq.mutex_q);

                    if (extra_p == NULL)
                        break;

                    if (slot->slot_next != NULL) {
                        r = TmThreadsSlotVarRun(tv, extra_p, slot->slot_next);
                        if (r == TM_ECODE_FAILED) {
                            SCMutexLock(&slot->slot_post_pq.mutex_q);
                            TmqhReleasePacketsToPacketPool(&slot->slot_post_pq);
                            SCMutexUnlock(&slot->slot_post_pq.mutex_q);

                            TmqhOutputPacketpool(tv, extra_p);
                            TmThreadsSetFlag(tv, THV_FAILED);
                            break;
                        }
                    }
                    tv->tmqh_out(tv, extra_p);
                }
            } /* if (slot->slot_post_pq.top != NULL) */
            slot = slot->slot_next;
        } /* while (slot != NULL) */
    }

    return r;
}

/** \brief inject packet if THV_CAPTURE_INJECT_PKT is set
 *  Allow caller to supply their own packet
 *
 *  Meant for detect reload process that interupts an sleeping capture thread
 *  to force a packet through the engine to complete a reload */
static inline void TmThreadsCaptureInjectPacket(ThreadVars *tv, TmSlot *slot, Packet *p)
{
    if (TmThreadsCheckFlag(tv, THV_CAPTURE_INJECT_PKT)) {
        TmThreadsUnsetFlag(tv, THV_CAPTURE_INJECT_PKT);
        if (p == NULL)
            p = PacketGetFromQueueOrAlloc();
        if (p != NULL) {
            p->flags |= PKT_PSEUDO_STREAM_END;
            if (TmThreadsSlotProcessPkt(tv, slot, p) != TM_ECODE_OK) {
                TmqhOutputPacketpool(tv, p);
            }
        }
    }
}

void TmThreadsListThreads(void);
int TmThreadsRegisterThread(ThreadVars *tv, const int type);
void TmThreadsUnregisterThread(const int id);
int TmThreadsInjectPacketsById(Packet **, int id);

void TmThreadsSetThreadTimestamp(const int id, const struct timeval *ts);
void TmreadsGetMinimalTimestamp(struct timeval *ts);

#endif /* __TM_THREADS_H__ */
