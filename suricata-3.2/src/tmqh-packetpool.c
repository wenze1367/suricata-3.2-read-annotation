/* Copyright (C) 2007-2014 Open Information Security Foundation
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
 * Packetpool queue handlers. Packet pool is implemented as a stack.
 */

#include "suricata.h"
#include "packet-queue.h"
#include "decode.h"
#include "detect.h"
#include "detect-uricontent.h"
#include "threads.h"
#include "threadvars.h"
#include "flow.h"
#include "flow-util.h"
#include "host.h"

#include "stream.h"
#include "stream-tcp-reassemble.h"

#include "tm-queuehandlers.h"
#include "tm-threads.h"
#include "tm-modules.h"

#include "pkt-var.h"

#include "tmqh-packetpool.h"

#include "util-debug.h"
#include "util-error.h"
#include "util-profiling.h"
#include "util-device.h"

/* Number of freed packet to save for one pool before freeing them. */
#define MAX_PENDING_RETURN_PACKETS 32
static uint32_t max_pending_return_packets = MAX_PENDING_RETURN_PACKETS;

#ifdef TLS
__thread PktPool thread_pkt_pool;

static inline PktPool *GetThreadPacketPool(void)
{
    return &thread_pkt_pool;
}
#else
/* __thread not supported. */
static pthread_key_t pkt_pool_thread_key;
static SCMutex pkt_pool_thread_key_mutex = SCMUTEX_INITIALIZER;
static int pkt_pool_thread_key_initialized = 0;

static void PktPoolThreadDestroy(void * buf)
{
    SCFreeAligned(buf);
}

static void TmqhPacketPoolInit(void)
{
    SCMutexLock(&pkt_pool_thread_key_mutex);
    if (pkt_pool_thread_key_initialized) {
        /* Key has already been created. */
        SCMutexUnlock(&pkt_pool_thread_key_mutex);
        return;
    }

    /* Create the pthread Key that is used to look up thread specific
     * data buffer. Needs to be created only once.
     */
    int r = pthread_key_create(&pkt_pool_thread_key, PktPoolThreadDestroy);
    if (r != 0) {
        SCLogError(SC_ERR_MEM_ALLOC, "pthread_key_create failed with %d", r);
        exit(EXIT_FAILURE);
    }

    pkt_pool_thread_key_initialized = 1;
    SCMutexUnlock(&pkt_pool_thread_key_mutex);
}

static PktPool *ThreadPacketPoolCreate(void)
{
    TmqhPacketPoolInit();

    /* Create a new pool for this thread. */
    PktPool* pool = (PktPool*)SCMallocAligned(sizeof(PktPool), CLS);
    if (pool == NULL) {
        SCLogError(SC_ERR_MEM_ALLOC, "malloc failed");
        exit(EXIT_FAILURE);
    }
    memset(pool,0x0,sizeof(*pool));

    int r = pthread_setspecific(pkt_pool_thread_key, pool);
    if (r != 0) {
        SCLogError(SC_ERR_MEM_ALLOC, "pthread_setspecific failed with %d", r);
        exit(EXIT_FAILURE);
    }

    return pool;
}

static inline PktPool *GetThreadPacketPool(void)
{
    PktPool* pool = (PktPool*)pthread_getspecific(pkt_pool_thread_key);
    if (pool == NULL)
        pool = ThreadPacketPoolCreate();

    return pool;
}
#endif

/**
 * \brief TmqhPacketpoolRegister
 * \initonly
 */
void TmqhPacketpoolRegister (void)
{
    tmqh_table[TMQH_PACKETPOOL].name = "packetpool";
    tmqh_table[TMQH_PACKETPOOL].InHandler = TmqhInputPacketpool;
    tmqh_table[TMQH_PACKETPOOL].OutHandler = TmqhOutputPacketpool;
}

static int PacketPoolIsEmpty(PktPool *pool)
{
    /* Check local stack first. */
    if (pool->head || pool->return_stack.head)
        return 0;

    return 1;
}

/*
*在所有接收模式中（pcap, netmap, pfring, napatech等）都有一个循环接收数据包的函数，在该函数中每次都会调用PacketPoolWait来判断receive线程的packet_pool中是否有空闲的packet可用来接收数据包。
如果有空闲的packet则PacketPoolWait会直接返回，进行后续的接收操作，如果没有，
则会在SCCondWait处等待worker线程归还packet资源，并等待worker线程的cond信号量
来唤醒receive线程。
*/
void PacketPoolWait(void)
{
	//my_pool就是thread_pkt_pool;
    PktPool *my_pool = GetThreadPacketPool();

	//当my_pool->head和my_pool->return_stack.head都为NULL时返回true。
    if (PacketPoolIsEmpty(my_pool)) {
        SCMutexLock(&my_pool->return_stack.mutex);

	//给原子变量return_stack.sync_now加1，使得worker线程归还packet;
        SC_ATOMIC_ADD(my_pool->return_stack.sync_now, 1);

		//程序会在此处等待worker的cond来唤醒线程;
        SCCondWait(&my_pool->return_stack.cond, &my_pool->return_stack.mutex);
        SCMutexUnlock(&my_pool->return_stack.mutex);
    }

    while(PacketPoolIsEmpty(my_pool))
        cc_barrier();
}

/** \brief Wait until we have the requested ammount of packets in the pool
 *
 *  In some cases waiting for packets is undesirable. Especially when
 *  a wait would happen under a lock of some kind, other parts of the
 *  engine could have to wait.
 *
 *  This function only returns when at least N packets are in our pool.
 *
 *  \param n number of packets needed
 */
void PacketPoolWaitForN(int n)
{
    PktPool *my_pool = GetThreadPacketPool();
    Packet *p = NULL;

    while (1) {
        int i = 0;
        PacketPoolWait();

        /* count packets in our stack */
        p = my_pool->head;
        while (p != NULL) {
            if (++i == n)
                return;

            p = p->next;
        }

        /* continue counting in the return stack */
        if (my_pool->return_stack.head != NULL) {
            SCMutexLock(&my_pool->return_stack.mutex);
            p = my_pool->return_stack.head;
            while (p != NULL) {
                if (++i == n) {
                    SCMutexUnlock(&my_pool->return_stack.mutex);
                    return;
                }
                p = p->next;
            }
            SCMutexUnlock(&my_pool->return_stack.mutex);

        /* or signal that we need packets and wait */
        } else {
            SCMutexLock(&my_pool->return_stack.mutex);
            SC_ATOMIC_ADD(my_pool->return_stack.sync_now, 1);
            SCCondWait(&my_pool->return_stack.cond, &my_pool->return_stack.mutex);
            SCMutexUnlock(&my_pool->return_stack.mutex);
        }
    }
}

/** \brief a initialized packet
 *
 *  \warning Use *only* at init, not at packet runtime
 */
static void PacketPoolStorePacket(Packet *p)
{
    /* Clear the PKT_ALLOC flag, since that indicates to push back
     * onto the ring buffer. */
    p->flags &= ~PKT_ALLOC;
    p->pool = GetThreadPacketPool();
    p->ReleasePacket = PacketPoolReturnPacket;
    PacketPoolReturnPacket(p);
}

static void PacketPoolGetReturnedPackets(PktPool *pool)
{
    SCMutexLock(&pool->return_stack.mutex);
    /* Move all the packets from the locked return stack to the local stack. */
    pool->head = pool->return_stack.head;
    pool->return_stack.head = NULL;
    SCMutexUnlock(&pool->return_stack.mutex);
}

/** \brief Get a new packet from the packet pool
 *
 * Only allocates from the thread's local stack, or mallocs new packets.
 * If the local stack is empty, first move all the return stack packets to
 * the local stack.
 *  \retval Packet pointer, or NULL on failure.
 */
Packet *PacketPoolGetPacket(void)
{
    PktPool *pool = GetThreadPacketPool();
#ifdef DEBUG_VALIDATION
    BUG_ON(pool->initialized == 0);
    BUG_ON(pool->destroyed == 1);
#endif /* DEBUG_VALIDATION */
    if (pool->head) {
        /* Stack is not empty. */
        Packet *p = pool->head;
        pool->head = p->next;
        p->pool = pool;
        PACKET_REINIT(p);
        return p;
    }

    /* Local Stack is empty, so check the return stack, which requires
     * locking. */
    PacketPoolGetReturnedPackets(pool);

    /* Try to allocate again. Need to check for not empty again, since the
     * return stack might have been empty too.
     */
    if (pool->head) {
        /* Stack is not empty. */
        Packet *p = pool->head;
        pool->head = p->next;
        p->pool = pool;
        PACKET_REINIT(p);
        return p;
    }

    /* Failed to allocate a packet, so return NULL. */
    /* Optionally, could allocate a new packet here. */
    return NULL;
}

/** \brief Return packet to Packet pool
 *
 在worker线程中针对每个包都会通过在TmqhOutputPacketpool中
 调用p->ReleasePacket指向的PacketPoolReturnPacket来归还packet资源。
 */
void PacketPoolReturnPacket(Packet *p)
{
	//此处获取当前线程的全局线程变量thread_pkt_pool;
    PktPool *my_pool = GetThreadPacketPool();

    PACKET_RELEASE_REFS(p);

	//此处获取的是receive线程中存放p的packet_pool的地址;
    PktPool *pool = p->pool;
    if (pool == NULL) {
        PacketFree(p);
        return;
    }
#ifdef DEBUG_VALIDATION
    BUG_ON(pool->initialized == 0);
    BUG_ON(pool->destroyed == 1);
    BUG_ON(my_pool->initialized == 0);
    BUG_ON(my_pool->destroyed == 1);
#endif /* DEBUG_VALIDATION */

	//只有当前线程为receive线程时才会进入此分支;
    if (pool == my_pool) {
        /* Push back onto this thread's own stack, so no locking. */
        p->next = my_pool->head;
        my_pool->head = p;
    } else {
		//只有当前线程为worker线程时才会进入此分支;
        PktPool *pending_pool = my_pool->pending_pool;
        if (pending_pool == NULL) {
            /* No pending packet, so store the current packet. */
            p->next = NULL;
            my_pool->pending_pool = pool;
            my_pool->pending_head = p;
            my_pool->pending_tail = p;
            my_pool->pending_count = 1;
        }
		/*将worker线程的packet_pool的pending_pool指向p所对应的r
              eceive线程的packet_pool;*/
		else if (pending_pool == pool) {
            /* Another packet for the pending pool list. */
            p->next = my_pool->pending_head;
            my_pool->pending_head = p;
		
	//使用头插的方式将将p插入到pending_head链表的头部，并增加计数;
            my_pool->pending_count++;
	
	//如果return_stack.sync_now不为0，或pending_count>32，进入此分支;
            if (SC_ATOMIC_GET(pool->return_stack.sync_now) || my_pool->pending_count > max_pending_return_packets) {
                /* Return the entire list of pending packets. */
                SCMutexLock(&pool->return_stack.mutex);
                my_pool->pending_tail->next = pool->return_stack.head;

		/*将worker线程的packet_pool中的pending_head到pending_tail这段链表
归还到receive线程的packet_pool的return_stack.head*/
                pool->return_stack.head = my_pool->pending_head;
                SC_ATOMIC_RESET(pool->return_stack.sync_now);
                SCMutexUnlock(&pool->return_stack.mutex);
				
                SCCondSignal(&pool->return_stack.cond);//发送信号唤醒receive线程;
                /* Clear the list of pending packets to return. */
			//将pending的相关内容清空，以便再次使用;
                my_pool->pending_pool = NULL;
                my_pool->pending_head = NULL;
                my_pool->pending_tail = NULL;
                my_pool->pending_count = 0;
            }
        } else {
	/*直接将p归还到receive线程的packet_pool的return_stack.head*/
            /* Push onto return stack for this pool */
            SCMutexLock(&pool->return_stack.mutex);
            p->next = pool->return_stack.head;
            pool->return_stack.head = p;
            SC_ATOMIC_RESET(pool->return_stack.sync_now);
            SCMutexUnlock(&pool->return_stack.mutex);
            SCCondSignal(&pool->return_stack.cond);
        }
    }
}

void PacketPoolInitEmpty(void)
{
#ifndef TLS
    TmqhPacketPoolInit();
#endif

    PktPool *my_pool = GetThreadPacketPool();

#ifdef DEBUG_VALIDATION
    BUG_ON(my_pool->initialized);
    my_pool->initialized = 1;
    my_pool->destroyed = 0;
#endif /* DEBUG_VALIDATION */

    SCMutexInit(&my_pool->return_stack.mutex, NULL);
    SCCondInit(&my_pool->return_stack.cond, NULL);
    SC_ATOMIC_INIT(my_pool->return_stack.sync_now);
}

void PacketPoolInit(void)
{
    extern intmax_t max_pending_packets;

#ifndef TLS
    TmqhPacketPoolInit();
#endif

    PktPool *my_pool = GetThreadPacketPool();

#ifdef DEBUG_VALIDATION
    BUG_ON(my_pool->initialized);
    my_pool->initialized = 1;
    my_pool->destroyed = 0;
#endif /* DEBUG_VALIDATION */

    SCMutexInit(&my_pool->return_stack.mutex, NULL);
    SCCondInit(&my_pool->return_stack.cond, NULL);
    SC_ATOMIC_INIT(my_pool->return_stack.sync_now);

    /* pre allocate packets */
    SCLogDebug("preallocating packets... packet size %" PRIuMAX "",
               (uintmax_t)SIZE_OF_PACKET);
    int i = 0;
    for (i = 0; i < max_pending_packets; i++) {
        Packet *p = PacketGetFromAlloc();
        if (unlikely(p == NULL)) {
            SCLogError(SC_ERR_FATAL, "Fatal error encountered while allocating a packet. Exiting...");
            exit(EXIT_FAILURE);
        }
        PacketPoolStorePacket(p);
    }

    //SCLogInfo("preallocated %"PRIiMAX" packets. Total memory %"PRIuMAX"",
    //        max_pending_packets, (uintmax_t)(max_pending_packets*SIZE_OF_PACKET));
}

void PacketPoolDestroy(void)
{
    Packet *p = NULL;
    PktPool *my_pool = GetThreadPacketPool();

#ifdef DEBUG_VALIDATION
    BUG_ON(my_pool->destroyed);
#endif /* DEBUG_VALIDATION */

    if (my_pool && my_pool->pending_pool != NULL) {
        p = my_pool->pending_head;
        while (p) {
            Packet *next_p = p->next;
            PacketFree(p);
            p = next_p;
            my_pool->pending_count--;
        }
#ifdef DEBUG_VALIDATION
        BUG_ON(my_pool->pending_count);
#endif /* DEBUG_VALIDATION */
        my_pool->pending_pool = NULL;
        my_pool->pending_head = NULL;
        my_pool->pending_tail = NULL;
    }

    while ((p = PacketPoolGetPacket()) != NULL) {
        PacketFree(p);
    }

    SC_ATOMIC_DESTROY(my_pool->return_stack.sync_now);

#ifdef DEBUG_VALIDATION
    my_pool->initialized = 0;
    my_pool->destroyed = 1;
#endif /* DEBUG_VALIDATION */
}

Packet *TmqhInputPacketpool(ThreadVars *tv)
{
    return PacketPoolGetPacket();
}

void TmqhOutputPacketpool(ThreadVars *t, Packet *p)
{
    int proot = 0;

    SCEnter();
    SCLogDebug("Packet %p, p->root %p, alloced %s", p, p->root, p->flags & PKT_ALLOC ? "true" : "false");

    if (IS_TUNNEL_PKT(p)) {
        SCLogDebug("Packet %p is a tunnel packet: %s",
            p,p->root ? "upper layer" : "tunnel root");

        /* get a lock to access root packet fields */
        SCMutex *m = p->root ? &p->root->tunnel_mutex : &p->tunnel_mutex;
        SCMutexLock(m);

        if (IS_TUNNEL_ROOT_PKT(p)) {
            SCLogDebug("IS_TUNNEL_ROOT_PKT == TRUE");
            if (TUNNEL_PKT_TPR(p) == 0) {
                SCLogDebug("TUNNEL_PKT_TPR(p) == 0, no more tunnel packet "
                        "depending on this root");
                /* if this packet is the root and there are no
                 * more tunnel packets, return it to the pool */

                /* fall through */
            } else {
                SCLogDebug("tunnel root Packet %p: TUNNEL_PKT_TPR(p) > 0, so "
                        "packets are still depending on this root, setting "
                        "p->tunnel_verdicted == 1", p);
                /* if this is the root and there are more tunnel
                 * packets, return this to the pool. It's still referenced
                 * by the tunnel packets, and we will return it
                 * when we handle them */
                SET_TUNNEL_PKT_VERDICTED(p);

                PACKET_PROFILING_END(p);
                SCMutexUnlock(m);
                SCReturn;
            }
        } else {
            SCLogDebug("NOT IS_TUNNEL_ROOT_PKT, so tunnel pkt");

            /* the p->root != NULL here seems unnecessary: IS_TUNNEL_PKT checks
             * that p->tunnel_pkt == 1, IS_TUNNEL_ROOT_PKT checks that +
             * p->root == NULL. So when we are here p->root can only be
             * non-NULL, right? CLANG thinks differently. May be a FP, but
             * better safe than sorry. VJ */
            if (p->root != NULL && IS_TUNNEL_PKT_VERDICTED(p->root) &&
                    TUNNEL_PKT_TPR(p) == 1)
            {
                SCLogDebug("p->root->tunnel_verdicted == 1 && TUNNEL_PKT_TPR(p) == 1");
                /* the root is ready and we are the last tunnel packet,
                 * lets enqueue them both. */
                TUNNEL_DECR_PKT_TPR_NOLOCK(p);

                /* handle the root */
                SCLogDebug("setting proot = 1 for root pkt, p->root %p "
                        "(tunnel packet %p)", p->root, p);
                proot = 1;

                /* fall through */
            } else {
                /* root not ready yet, so get rid of the tunnel pkt only */

                SCLogDebug("NOT p->root->tunnel_verdicted == 1 && "
                        "TUNNEL_PKT_TPR(p) == 1 (%" PRIu32 ")", TUNNEL_PKT_TPR(p));

                TUNNEL_DECR_PKT_TPR_NOLOCK(p);

                 /* fall through */
            }
        }
        SCMutexUnlock(m);

        SCLogDebug("tunnel stuff done, move on (proot %d)", proot);
    }

    FlowDeReference(&p->flow);

    /* we're done with the tunnel root now as well */
    if (proot == 1) {
        SCLogDebug("getting rid of root pkt... alloc'd %s", p->root->flags & PKT_ALLOC ? "true" : "false");

        FlowDeReference(&p->root->flow);

        p->root->ReleasePacket(p->root);
        p->root = NULL;
    }

    PACKET_PROFILING_END(p);

    p->ReleasePacket(p);

    SCReturn;
}

/**
 *  \brief Release all the packets in the queue back to the packetpool.  Mainly
 *         used by threads that have failed, and wants to return the packets back
 *         to the packetpool.
 *
 *  \param pq Pointer to the packetqueue from which the packets have to be
 *            returned back to the packetpool
 *
 *  \warning this function assumes that the pq does not use locking
 */
void TmqhReleasePacketsToPacketPool(PacketQueue *pq)
{
    Packet *p = NULL;

    if (pq == NULL)
        return;

    while ( (p = PacketDequeue(pq)) != NULL)
        TmqhOutputPacketpool(NULL, p);

    return;
}

/**
 *  \brief Set the max_pending_return_packets value
 *
 *  Set it to the max pending packets value, devided by the number
 *  of lister threads. Normally, in autofp these are the stream/detect/log
 *  worker threads.
 *
 *  The max_pending_return_packets value needs to stay below the packet
 *  pool size of the 'producers' (normally pkt capture threads but also
 *  flow timeout injection ) to avoid a deadlock where all the 'workers'
 *  keep packets in their return pools, while the capture thread can't
 *  continue because its pool is empty.
 */
void PacketPoolPostRunmodes(void)
{
    extern intmax_t max_pending_packets;

    uint32_t threads = TmThreadCountThreadsByTmmFlags(TM_FLAG_DETECT_TM);
    if (threads == 0)
        return;
    if (threads > max_pending_packets)
        return;

    uint32_t packets = (max_pending_packets / threads) - 1;
    if (packets < max_pending_return_packets)
        max_pending_return_packets = packets;

    SCLogDebug("detect threads %u, max packets %u, max_pending_return_packets %u",
            threads, (uint)threads, max_pending_return_packets);
}
