/* Copyright (C) 2007-2013 Open Information Security Foundation
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
 *  \file
 *
 *  \author Victor Julien <victor@inliniac.net>
 *  \author Pablo Rincon Crespo <pablo.rincon.crespo@gmail.com>
 *
 *  Flow Hashing functions.
 */

#include "suricata-common.h"
#include "threads.h"

#include "decode.h"
#include "detect-engine-state.h"

#include "flow.h"
#include "flow-hash.h"
#include "flow-util.h"
#include "flow-private.h"
#include "flow-manager.h"
#include "flow-storage.h"
#include "app-layer-parser.h"

#include "util-time.h"
#include "util-debug.h"

#include "util-hash-lookup3.h"

#include "conf.h"
#include "output.h"
#include "output-flow.h"

#define FLOW_DEFAULT_FLOW_PRUNE 5

SC_ATOMIC_EXTERN(unsigned int, flow_prune_idx);
SC_ATOMIC_EXTERN(unsigned int, flow_flags);

static Flow *FlowGetUsedFlow(ThreadVars *tv, DecodeThreadVars *dtv);

/** \brief compare two raw ipv6 addrs
 *
 *  \note we don't care about the real ipv6 ip's, this is just
 *        to consistently fill the FlowHashKey6 struct, without all
 *        the ntohl calls.
 *
 *  \warning do not use elsewhere unless you know what you're doing.
 *           detect-engine-address-ipv6.c's AddressIPv6GtU32 is likely
 *           what you are looking for.
 */
static inline int FlowHashRawAddressIPv6GtU32(const uint32_t *a, const uint32_t *b)
{
    int i;

    for (i = 0; i < 4; i++) {
        if (a[i] > b[i])
            return 1;
        if (a[i] < b[i])
            break;
    }

    return 0;
}

typedef struct FlowHashKey4_ {
    union {
        struct {
            uint32_t src, dst;
            uint16_t sp, dp;
            uint16_t proto; /**< u16 so proto and recur add up to u32 */
            uint16_t recur; /**< u16 so proto and recur add up to u32 */
            uint16_t vlan_id[2];
        };
        const uint32_t u32[5];
    };
} FlowHashKey4;

typedef struct FlowHashKey6_ {
    union {
        struct {
            uint32_t src[4], dst[4];
            uint16_t sp, dp;
            uint16_t proto; /**< u16 so proto and recur add up to u32 */
            uint16_t recur; /**< u16 so proto and recur add up to u32 */
            uint16_t vlan_id[2];
        };
        const uint32_t u32[11];
    };
} FlowHashKey6;

/* calculate the hash key for this packet
 *
 * we're using:
 *  hash_rand -- set at init time
 *  source port
 *  destination port
 *  source address
 *  destination address
 *  recursion level -- for tunnels, make sure different tunnel layers can
 *                     never get mixed up.
 *
 *  For ICMP we only consider UNREACHABLE errors atm.
 */
static inline uint32_t FlowGetHash(const Packet *p)
{
    uint32_t hash = 0;

    if (p->ip4h != NULL) {
        if (p->tcph != NULL || p->udph != NULL) {
            FlowHashKey4 fhk;
            if (p->src.addr_data32[0] > p->dst.addr_data32[0]) {
                fhk.src = p->src.addr_data32[0];
                fhk.dst = p->dst.addr_data32[0];
            } else {
                fhk.src = p->dst.addr_data32[0];
                fhk.dst = p->src.addr_data32[0];
            }
            if (p->sp > p->dp) {
                fhk.sp = p->sp;
                fhk.dp = p->dp;
            } else {
                fhk.sp = p->dp;
                fhk.dp = p->sp;
            }
            fhk.proto = (uint16_t)p->proto;
            fhk.recur = (uint16_t)p->recursion_level;
            fhk.vlan_id[0] = p->vlan_id[0];
            fhk.vlan_id[1] = p->vlan_id[1];

            hash = hashword(fhk.u32, 5, flow_config.hash_rand);

        } else if (ICMPV4_DEST_UNREACH_IS_VALID(p)) {
            uint32_t psrc = IPV4_GET_RAW_IPSRC_U32(ICMPV4_GET_EMB_IPV4(p));
            uint32_t pdst = IPV4_GET_RAW_IPDST_U32(ICMPV4_GET_EMB_IPV4(p));
            FlowHashKey4 fhk;
            if (psrc > pdst) {
                fhk.src = psrc;
                fhk.dst = pdst;
            } else {
                fhk.src = pdst;
                fhk.dst = psrc;
            }
            if (p->icmpv4vars.emb_sport > p->icmpv4vars.emb_dport) {
                fhk.sp = p->icmpv4vars.emb_sport;
                fhk.dp = p->icmpv4vars.emb_dport;
            } else {
                fhk.sp = p->icmpv4vars.emb_dport;
                fhk.dp = p->icmpv4vars.emb_sport;
            }
            fhk.proto = (uint16_t)ICMPV4_GET_EMB_PROTO(p);
            fhk.recur = (uint16_t)p->recursion_level;
            fhk.vlan_id[0] = p->vlan_id[0];
            fhk.vlan_id[1] = p->vlan_id[1];

            hash = hashword(fhk.u32, 5, flow_config.hash_rand);

        } else {
            FlowHashKey4 fhk;
            if (p->src.addr_data32[0] > p->dst.addr_data32[0]) {
                fhk.src = p->src.addr_data32[0];
                fhk.dst = p->dst.addr_data32[0];
            } else {
                fhk.src = p->dst.addr_data32[0];
                fhk.dst = p->src.addr_data32[0];
            }
            fhk.sp = 0xfeed;
            fhk.dp = 0xbeef;
            fhk.proto = (uint16_t)p->proto;
            fhk.recur = (uint16_t)p->recursion_level;
            fhk.vlan_id[0] = p->vlan_id[0];
            fhk.vlan_id[1] = p->vlan_id[1];

            hash = hashword(fhk.u32, 5, flow_config.hash_rand);
        }
    } else if (p->ip6h != NULL) {
        FlowHashKey6 fhk;
        if (FlowHashRawAddressIPv6GtU32(p->src.addr_data32, p->dst.addr_data32)) {
            fhk.src[0] = p->src.addr_data32[0];
            fhk.src[1] = p->src.addr_data32[1];
            fhk.src[2] = p->src.addr_data32[2];
            fhk.src[3] = p->src.addr_data32[3];
            fhk.dst[0] = p->dst.addr_data32[0];
            fhk.dst[1] = p->dst.addr_data32[1];
            fhk.dst[2] = p->dst.addr_data32[2];
            fhk.dst[3] = p->dst.addr_data32[3];
        } else {
            fhk.src[0] = p->dst.addr_data32[0];
            fhk.src[1] = p->dst.addr_data32[1];
            fhk.src[2] = p->dst.addr_data32[2];
            fhk.src[3] = p->dst.addr_data32[3];
            fhk.dst[0] = p->src.addr_data32[0];
            fhk.dst[1] = p->src.addr_data32[1];
            fhk.dst[2] = p->src.addr_data32[2];
            fhk.dst[3] = p->src.addr_data32[3];
        }
        if (p->sp > p->dp) {
            fhk.sp = p->sp;
            fhk.dp = p->dp;
        } else {
            fhk.sp = p->dp;
            fhk.dp = p->sp;
        }
        fhk.proto = (uint16_t)p->proto;
        fhk.recur = (uint16_t)p->recursion_level;
        fhk.vlan_id[0] = p->vlan_id[0];
        fhk.vlan_id[1] = p->vlan_id[1];

        hash = hashword(fhk.u32, 11, flow_config.hash_rand);
    }

    return hash;
}

/* Since two or more flows can have the same hash key, we need to compare
 * the flow with the current flow key. */
#define CMP_FLOW(f1,f2) \
    (((CMP_ADDR(&(f1)->src, &(f2)->src) && \
       CMP_ADDR(&(f1)->dst, &(f2)->dst) && \
       CMP_PORT((f1)->sp, (f2)->sp) && CMP_PORT((f1)->dp, (f2)->dp)) || \
      (CMP_ADDR(&(f1)->src, &(f2)->dst) && \
       CMP_ADDR(&(f1)->dst, &(f2)->src) && \
       CMP_PORT((f1)->sp, (f2)->dp) && CMP_PORT((f1)->dp, (f2)->sp))) && \
     (f1)->proto == (f2)->proto && \
     (f1)->recursion_level == (f2)->recursion_level && \
     (f1)->vlan_id[0] == (f2)->vlan_id[0] && \
     (f1)->vlan_id[1] == (f2)->vlan_id[1])

/**
 *  \brief See if a ICMP packet belongs to a flow by comparing the embedded
 *         packet in the ICMP error packet to the flow.
 *
 *  \param f flow
 *  \param p ICMP packet
 *
 *  \retval 1 match
 *  \retval 0 no match
 */
static inline int FlowCompareICMPv4(Flow *f, const Packet *p)
{
    if (ICMPV4_DEST_UNREACH_IS_VALID(p)) {
        /* first check the direction of the flow, in other words, the client ->
         * server direction as it's most likely the ICMP error will be a
         * response to the clients traffic */
        if ((f->src.addr_data32[0] == IPV4_GET_RAW_IPSRC_U32( ICMPV4_GET_EMB_IPV4(p) )) &&
                (f->dst.addr_data32[0] == IPV4_GET_RAW_IPDST_U32( ICMPV4_GET_EMB_IPV4(p) )) &&
                f->sp == p->icmpv4vars.emb_sport &&
                f->dp == p->icmpv4vars.emb_dport &&
                f->proto == ICMPV4_GET_EMB_PROTO(p) &&
                f->recursion_level == p->recursion_level &&
                f->vlan_id[0] == p->vlan_id[0] &&
                f->vlan_id[1] == p->vlan_id[1])
        {
            return 1;

        /* check the less likely case where the ICMP error was a response to
         * a packet from the server. */
        } else if ((f->dst.addr_data32[0] == IPV4_GET_RAW_IPSRC_U32( ICMPV4_GET_EMB_IPV4(p) )) &&
                (f->src.addr_data32[0] == IPV4_GET_RAW_IPDST_U32( ICMPV4_GET_EMB_IPV4(p) )) &&
                f->dp == p->icmpv4vars.emb_sport &&
                f->sp == p->icmpv4vars.emb_dport &&
                f->proto == ICMPV4_GET_EMB_PROTO(p) &&
                f->recursion_level == p->recursion_level &&
                f->vlan_id[0] == p->vlan_id[0] &&
                f->vlan_id[1] == p->vlan_id[1])
        {
            return 1;
        }

        /* no match, fall through */
    } else {
        /* just treat ICMP as a normal proto for now */
        return CMP_FLOW(f, p);
    }

    return 0;
}

void FlowSetupPacket(Packet *p)
{
    p->flags |= PKT_WANTS_FLOW;
    p->flow_hash = FlowGetHash(p);
}

int TcpSessionPacketSsnReuse(const Packet *p, const Flow *f, void *tcp_ssn);

static inline int FlowCompare(Flow *f, const Packet *p)
{
    if (p->proto == IPPROTO_ICMP) {
        return FlowCompareICMPv4(f, p);
    } else if (p->proto == IPPROTO_TCP) {
        if (CMP_FLOW(f, p) == 0)
            return 0;

        /* if this session is 'reused', we don't return it anymore,
         * so return false on the compare */
        if (f->flags & FLOW_TCP_REUSED)
            return 0;

        return 1;
    } else {
        return CMP_FLOW(f, p);
    }
}

/**
 *  \brief Check if we should create a flow based on a packet
 *
 *  We use this check to filter out flow creation based on:
 *  - ICMP error messages
 *
 *  \param p packet
 *  \retval 1 true
 *  \retval 0 false
 */
static inline int FlowCreateCheck(const Packet *p)
{
    if (PKT_IS_ICMPV4(p)) {
        if (ICMPV4_IS_ERROR_MSG(p)) {
            return 0;
        }
    }

    return 1;
}

/**
 *  \brief Get a new flow
 *
 *  Get a new flow. We're checking memcap first and will try to make room
 *  if the memcap is reached.
 *
 *  \param tv thread vars
 *  \param dtv decode thread vars (for flow log api thread data)
 *
 *  \retval f *LOCKED* flow on succes, NULL on error.
 */
static Flow *FlowGetNew(ThreadVars *tv, DecodeThreadVars *dtv, const Packet *p)
{
    Flow *f = NULL;

    if (FlowCreateCheck(p) == 0) {
        return NULL;
    }

    /* get a flow from the spare queue */
    f = FlowDequeue(&flow_spare_q);
    if (f == NULL) {
        /* If we reached the max memcap, we get a used flow */
        if (!(FLOW_CHECK_MEMCAP(sizeof(Flow) + FlowStorageSize()))) {
            /* declare state of emergency */
            if (!(SC_ATOMIC_GET(flow_flags) & FLOW_EMERGENCY)) {
                SC_ATOMIC_OR(flow_flags, FLOW_EMERGENCY);

                FlowTimeoutsEmergency();

                /* under high load, waking up the flow mgr each time leads
                 * to high cpu usage. Flows are not timed out much faster if
                 * we check a 1000 times a second. */
                FlowWakeupFlowManagerThread();
            }

            f = FlowGetUsedFlow(tv, dtv);
            if (f == NULL) {
                /* max memcap reached, so increments the counter */
                if (tv != NULL && dtv != NULL) {
                    StatsIncr(tv, dtv->counter_flow_memcap);
                }

                /* very rare, but we can fail. Just giving up */
                return NULL;
            }

            /* freed a flow, but it's unlocked */
        } else {
            /* now see if we can alloc a new flow */
            f = FlowAlloc();
            if (f == NULL) {
                if (tv != NULL && dtv != NULL) {
                    StatsIncr(tv, dtv->counter_flow_memcap);
                }
                return NULL;
            }

            /* flow is initialized but *unlocked* */
        }
    } else {
        /* flow has been recycled before it went into the spare queue */

        /* flow is initialized (recylced) but *unlocked* */
    }

    FLOWLOCK_WRLOCK(f);
    return f;
}

//流重用函数;
static Flow *TcpReuseReplace(ThreadVars *tv, DecodeThreadVars *dtv,
                             FlowBucket *fb, Flow *old_f,
                             const uint32_t hash, const Packet *p)
{
    /* tag flow as reused so future lookups won't find it */
	/*将老流标识为已重用*/
    old_f->flags |= FLOW_TCP_REUSED;
	
    /* get some settings that we move over to the new flow */
	/*备份thread_id，后续会根据thread_id将一些设置备份到新的流中;*/
    FlowThreadId thread_id = old_f->thread_id;

    /* since fb lock is still held this flow won't be found until we are done */
    FLOWLOCK_UNLOCK(old_f);

    /* Get a new flow. It will be either a locked flow or NULL */
	/*申请新的流，这点之后会详细说明;*/
    Flow *f = FlowGetNew(tv, dtv, p);
    if (f == NULL) {
        return NULL;
    }

    /* flow is locked */

    /* put at the start of the list */
    f->hnext = fb->head;
    fb->head->hprev = f;
    fb->head = f;

    /* initialize and return */
	/*根据包初始化流的值，并指明流所属的hash;*/
    FlowInit(f, p);
    f->flow_hash = hash;
    f->fb = fb;

	/*将之前保存的thread_id赋值给新的流;*/
    f->thread_id = thread_id;
    return f;
}

/** \brief Get Flow for packet
 *
 * Hash retrieval function for flows. Looks up the hash bucket containing the
 * flow pointer. Then compares the packet with the found flow to see if it is
 * the flow we need. If it isn't, walk the list until the right flow is found.
 *
 * If the flow is not found or the bucket was emtpy, a new flow is taken from
 * the queue. FlowDequeue() will alloc new flows as long as we stay within our
 * memcap limit.
 *
 * The p->flow pointer is updated to point to the flow.
 *
 *  \param tv thread vars
 *  \param dtv decode thread vars (for flow log api thread data)
 *
 *  \retval f *LOCKED* flow or NULL;

 流查找/分配
通过FlowWorker线程函数中调用FlowHandlePacket来找到流。 
下面将按照FlowHandlePacket的流程，分析flow engine对于新送入的解码后的数据包是如何处理的。 
对于一个Packet，首先在流表中查找其所属的流是否已经存在，若存在，则直接返回该流的引用即可，否则就需要分配一个新流。 
该过程的实现由FlowGetFlowFromHash完成，函数会返回一个Flow指针，表示找到的或新分配的流。
**********
 1.调用FlowGetKey计算该包的hash key。对于IPv4包，使用FlowHashKey4结构体作为hash输入：
 typedef struct FlowHashKey4_ {
	 union {
		 struct {
			 uint32_t src, dst;
			 uint16_t sp, dp;
			 uint16_t proto; //< u16 so proto and recur add up to u32 
			 uint16_t recur; //< u16 so proto and recur add up to u32 
			 uint16_t vlan_id[2];
		 };
		 const uint32_t u32[5];
	 };
 } FlowHashKey4;
 
 其中，recur设置为Packet的recursion_level，防止隧道包与普通包hash到一块；vlan_id设置为Packet的
 	vlan_id，这样就能将不同的VLAN的流进行隔离；sp和dp，在TCP/UDP情况下就设置为端口，
 	其余包就设置为两个特殊值（0xfeed、0xbeef）。特别地，ICMP unreachable包的src, 
 	dst, sp, dp, proto都设置成了其附带的数据包头中的相应信息（Why?）。
 
 对于IPv6包，使用FlowHashKey6结构体作为hash输入，结构与FlowHashKey4类似，只是src和dst长度为16字节。
 实际计算hash的函数为hashword，该函数以word（4字节）为单位对输入数据进行hash。值得注意的是，
 该函数带了个参数initval，hash时会把这个值也考虑进去。FlowGetKey中对应这个参数传递的值
 为flow_config.hash_rand，这个值是在FlowInitConfig中随机计算出来的。这样一来，
 即使对于相同的数据流量，Suricata每次运行时所生成的流表结构都会不一样，
 这种随机行为能否防止针对Suricata本身的攻击（例如找到了hash算法的漏洞，构造特定的数据包试图让Suricata的流表退化成链表）。
 以获取到的key为索引，在流表flow_hash中获取到一个FlowBucket的指针，该结构定义为：
 flow hash bucket -- the hash is basically an array of these buckets.
 Each bucket contains a flow or list of flows. All these flows have
 the same hashkey (the hash is a chained hash). When doing modifications
 to the list, the entire bucket is locked. 

 typedef struct FlowBucket_ {
	 Flow *head;
	 Flow *tail;
#ifdef FBLOCK_MUTEX
	 SCMutex m;
#elif defined FBLOCK_SPIN
	 SCSpinlock s;
#else
    #error Enable FBLOCK_SPIN or FBLOCK_MUTEX
#endif
 } __attribute__((aligned(CLS))) FlowBucket;
 
 使用FBLOCK_LOCK对该bucket上锁。实际使用的锁可能为spin lock或mutext，取决于FBLOCK_SPIN是否定义。
 若head为NULL，说明这个bucket中还没有流，因此首先调用FlowGetNew新分配一个流，然后把它与bucket互相链接起来。接着，FlowInit函数使用Packet的信息初始化这个新流，然后FBLOCK_UNLOCK解锁并返回这个流。由于FlowGetNew中会调用FLOWLOCK_WRLOCK对flow进行上锁（因为后面需要使用），因此这里就不需要再锁了。
 不为NULL，则bucket中有流，将尝试从其中的Flow链表中查找该packet所属的Flow。值得注意的是，这里做了个基于时间局部性（与缓存原理类似）的优化：将最近访问的流放到链表的头部，这样对于活跃的流的查找代价就会大大减少。在实施这种优化的情况下，处理流程为：
 使用FlowCompare比较head flow与packet，若相匹配，则说明已经找到了，且这个流已经在头部不需要再调整，则先锁上该flow再解锁bucket，然后返回。
 若不匹配，则继续遍历flow链表，如果找到了，则先把这个flow移到链表头部，再与上面一样lock & return。
 若未找到，则与4类似，获取一个新流并初始化，然后挂到链表尾部再返回。注意，这里并没有移到头部，
 因为新流不代表就是活跃流。
 */
Flow *FlowGetFlowFromHash(ThreadVars *tv, DecodeThreadVars *dtv, const Packet *p, Flow **dest)
{
    Flow *f = NULL;

    /* get our hash bucket and lock it ;
	获取包的hash，这里的hash是由p带来的。p的flow_hash是通过在FlowSetupPacket函数调用FlowGetHash，
	又通过FlowGetHash中的hashword生成的，对于 hash_key的获取方法以后另行分析。
	*/
    const uint32_t hash = p->flow_hash;

	//以获取到的key为索引，在流表flow_hash中获取到一个FlowBucket的指针;
	//获取对应的bucket;
    FlowBucket *fb = &flow_hash[hash % flow_config.hash_size];

	//使用FBLOCK_LOCK对该bucket上锁。实际使用的锁可能为spin lock或mutext，取决于FBLOCK_SPIN是否定义。
    FBLOCK_LOCK(fb);

    SCLogDebug("fb %p fb->head %p", fb, fb->head);

    /* see if the bucket already has a flow;*/
    //说明这个bucket中还没有流;
    /*如果p->flow_hash找不到对应的FlowBucket，则新建flow挂到对
应的bucket上，并通过参数dest返回.*/
    if (fb->head == NULL) {
		//调用FlowGetNew新分配一个流;
        f = FlowGetNew(tv, dtv, p);
        if (f == NULL) {
            FBLOCK_UNLOCK(fb);
            return NULL;
        }

        /* flow is locked */
        fb->head = f;
        fb->tail = f;

        /* got one, now lock, initialize and return */
		//使用Packet的信息初始化这个新流;
        FlowInit(f, p);
        f->flow_hash = hash;
		
		//设置流的flow_hash和fb;
        f->fb = fb;

		//记录最后一次更新流的时间;
        FlowUpdateState(f, FLOW_STATE_NEW);

		/*使用FlowReference将p->flow指向刚获取流，该函数内部会使用FlowIncrUsecnt增加该流的使用计数。
		注意，该机制的目的与通常的引用计数不同，
		不是为了在没有引用时回收资源，而是为了避免出现误删除等问题;		
		*/
        FlowReference(dest, f);
		
		/*FBLOCK_UNLOCK解锁并返回这个流。由于FlowGetNew中会调用FLOWLOCK_WRLOCK对flow进行上锁（因为后面需要使用），
		因此这里就不需要再锁了。
		*/
        FBLOCK_UNLOCK(fb);
        return f;
    }

    /* ok, we have a flow in the bucket. Let's find out if it is our flow */
	//以下代码为fb->head不为NULL，即bucket中有流时，尝试从其中的Flow链表中查找该packet所属的Flow;
    f = fb->head;

    /* see if this is the flow we are looking for */
	//如果packet和bucket的第一个flow不匹配（五元组+vlan不完全相同）;
    if (FlowCompare(f, p) == 0) {
		//代表f和p不匹配，为1匹配，为0不匹配;
        Flow *pf = NULL; /* previous flow */

        while (f) {
            pf = f;
            f = f->hnext;

	/*若遍历整个bucket链表找不到对应的flow，则新建flow挂到对应
的bucket上，并通过参数dest返回.*/
            if (f == NULL) {
                f = pf->hnext = FlowGetNew(tv, dtv, p);
                if (f == NULL) {
                    FBLOCK_UNLOCK(fb);
                    return NULL;
                }
                fb->tail = f;

                /* flow is locked */

                f->hprev = pf;

                /* initialize and return */
                FlowInit(f, p);
                f->flow_hash = hash;
                f->fb = fb;
                FlowUpdateState(f, FLOW_STATE_NEW);

                FlowReference(dest, f);

                FBLOCK_UNLOCK(fb);
                return f;
            }
			
/*若未找到，则与4类似，获取一个新流并初始化，然后挂到链表尾部再返回。
注意，这里并没有移到头部，因为新流不代表就是活跃流。
*/
			/*若遍历bucket链表找到对应的flow，将当前flow放到bucket的flow->head，
			判断流重用，并通过参数dest返回.*/
            if (FlowCompare(f, p) != 0) {
                /* we found our flow, lets put it on top of the
                 * hash list -- this rewards active flows */
                if (f->hnext) {
                    f->hnext->hprev = f->hprev;
                }
                if (f->hprev) {
                    f->hprev->hnext = f->hnext;
                }
                if (f == fb->tail) {
                    fb->tail = f->hprev;
                }

                f->hnext = fb->head;
                f->hprev = NULL;
                fb->head->hprev = f;
                fb->head = f;

                /* found our flow, lock & return */
				/*如果packet和bucket的第一个flow匹配（五元组+vlan相同），
判断流重用，并通过参数dest返回*/
                FLOWLOCK_WRLOCK(f);
                if (unlikely(TcpSessionPacketSsnReuse(p, f, f->protoctx) == 1)) {
                    f = TcpReuseReplace(tv, dtv, fb, f, hash, p);
                    if (f == NULL) {
                        FBLOCK_UNLOCK(fb);
                        return NULL;
                    }
                }

                FlowReference(dest, f);

                FBLOCK_UNLOCK(fb);
                return f;
            }
	/*使用FlowCompare比较head flow与packet，若相匹配，则说明已经找到了，
	且这个流已经在头部不需要再调整，则先锁上该flow再解锁bucket，然后返回。
	*/
        }
    }

    /* lock & return */
    FLOWLOCK_WRLOCK(f);
    if (unlikely(TcpSessionPacketSsnReuse(p, f, f->protoctx) == 1)) {
        f = TcpReuseReplace(tv, dtv, fb, f, hash, p);
        if (f == NULL) {
            FBLOCK_UNLOCK(fb);
            return NULL;
        }
    }
	
	//将dest指向f，此处dest为p->flow，由函数传入。
    FlowReference(dest, f);

    FBLOCK_UNLOCK(fb);
    return f;
}

/** \internal
 *  \brief Get a flow from the hash directly.
 *
 *  Called in conditions where the spare queue is empty and memcap is reached.
 *
 *  Walks the hash until a flow can be freed. Timeouts are disregarded, use_cnt
 *  is adhered to. "flow_prune_idx" atomic int makes sure we don't start at the
 *  top each time since that would clear the top of the hash leading to longer
 *  and longer search times under high pressure (observed).
 *
 *  \param tv thread vars
 *  \param dtv decode thread vars (for flow log api thread data)
 *
 *  \retval f flow or NULL
 */
static Flow *FlowGetUsedFlow(ThreadVars *tv, DecodeThreadVars *dtv)
{
    uint32_t idx = SC_ATOMIC_GET(flow_prune_idx) % flow_config.hash_size;
    uint32_t cnt = flow_config.hash_size;

    while (cnt--) {
        if (++idx >= flow_config.hash_size)
            idx = 0;

        FlowBucket *fb = &flow_hash[idx];

        if (FBLOCK_TRYLOCK(fb) != 0)
            continue;

        Flow *f = fb->tail;
        if (f == NULL) {
            FBLOCK_UNLOCK(fb);
            continue;
        }

        if (FLOWLOCK_TRYWRLOCK(f) != 0) {
            FBLOCK_UNLOCK(fb);
            continue;
        }

        /** never prune a flow that is used by a packet or stream msg
         *  we are currently processing in one of the threads */
        if (SC_ATOMIC_GET(f->use_cnt) > 0) {
            FBLOCK_UNLOCK(fb);
            FLOWLOCK_UNLOCK(f);
            continue;
        }

        /* remove from the hash */
        if (f->hprev != NULL)
            f->hprev->hnext = f->hnext;
        if (f->hnext != NULL)
            f->hnext->hprev = f->hprev;
        if (fb->head == f)
            fb->head = f->hnext;
        if (fb->tail == f)
            fb->tail = f->hprev;

        f->hnext = NULL;
        f->hprev = NULL;
        f->fb = NULL;
        SC_ATOMIC_SET(fb->next_ts, 0);
        FBLOCK_UNLOCK(fb);

        int state = SC_ATOMIC_GET(f->flow_state);
        if (state == FLOW_STATE_NEW)
            f->flow_end_flags |= FLOW_END_FLAG_STATE_NEW;
        else if (state == FLOW_STATE_ESTABLISHED)
            f->flow_end_flags |= FLOW_END_FLAG_STATE_ESTABLISHED;
        else if (state == FLOW_STATE_CLOSED)
            f->flow_end_flags |= FLOW_END_FLAG_STATE_CLOSED;
        else if (state == FLOW_STATE_CAPTURE_BYPASSED)
            f->flow_end_flags |= FLOW_END_FLAG_STATE_BYPASSED;
        else if (state == FLOW_STATE_LOCAL_BYPASSED)
            f->flow_end_flags |= FLOW_END_FLAG_STATE_BYPASSED;

        f->flow_end_flags |= FLOW_END_FLAG_FORCED;

        if (SC_ATOMIC_GET(flow_flags) & FLOW_EMERGENCY)
            f->flow_end_flags |= FLOW_END_FLAG_EMERGENCY;

        /* invoke flow log api */
        if (dtv && dtv->output_flow_thread_data)
            (void)OutputFlowLog(tv, dtv->output_flow_thread_data, f);

        FlowClearMemory(f, f->protomap);

        FlowUpdateState(f, FLOW_STATE_NEW);

        FLOWLOCK_UNLOCK(f);

        (void) SC_ATOMIC_ADD(flow_prune_idx, (flow_config.hash_size - cnt));
        return f;
    }

    return NULL;
}
