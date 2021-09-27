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
 * \file
 *
 * \author Victor Julien <victor@inliniac.net>
 * \author Gurvinder Singh <gurvindersinghdahiya@gmail.com>
 *
 * TCP stream tracking and reassembly engine.
 *
 * \todo - 4WHS: what if after the 2nd SYN we turn out to be normal 3WHS anyway?
 */

#include "suricata-common.h"
#include "suricata.h"

#include "decode.h"
#include "debug.h"
#include "detect.h"

#include "flow.h"
#include "flow-util.h"

#include "conf.h"
#include "conf-yaml-loader.h"

#include "threads.h"
#include "threadvars.h"
#include "tm-threads.h"

#include "util-pool.h"
#include "util-pool-thread.h"
#include "util-checksum.h"
#include "util-unittest.h"
#include "util-print.h"
#include "util-debug.h"
#include "util-device.h"

#include "stream-tcp-private.h"
#include "stream-tcp-reassemble.h"
#include "stream-tcp.h"
#include "stream-tcp-inline.h"
#include "stream-tcp-sack.h"
#include "stream-tcp-util.h"
#include "stream.h"

#include "pkt-var.h"
#include "host.h"

#include "app-layer.h"
#include "app-layer-parser.h"
#include "app-layer-protos.h"
#include "app-layer-htp-mem.h"

#include "util-host-os-info.h"
#include "util-privs.h"
#include "util-profiling.h"
#include "util-misc.h"
#include "util-validate.h"
#include "util-runmodes.h"

#include "source-pcap-file.h"

//#define DEBUG

#define STREAMTCP_DEFAULT_PREALLOC              2048
#define STREAMTCP_DEFAULT_MEMCAP                (32 * 1024 * 1024) /* 32mb */
#define STREAMTCP_DEFAULT_REASSEMBLY_MEMCAP     (64 * 1024 * 1024) /* 64mb */
#define STREAMTCP_DEFAULT_TOSERVER_CHUNK_SIZE   2560
#define STREAMTCP_DEFAULT_TOCLIENT_CHUNK_SIZE   2560
#define STREAMTCP_DEFAULT_MAX_SYNACK_QUEUED     5

#define STREAMTCP_NEW_TIMEOUT                   60
#define STREAMTCP_EST_TIMEOUT                   3600
#define STREAMTCP_CLOSED_TIMEOUT                120

#define STREAMTCP_EMERG_NEW_TIMEOUT             10
#define STREAMTCP_EMERG_EST_TIMEOUT             300
#define STREAMTCP_EMERG_CLOSED_TIMEOUT          20

static int StreamTcpHandleFin(ThreadVars *tv, StreamTcpThread *, TcpSession *, Packet *, PacketQueue *);
void StreamTcpReturnStreamSegments (TcpStream *);
void StreamTcpInitConfig(char);
int StreamTcpGetFlowState(void *);
void StreamTcpSetOSPolicy(TcpStream*, Packet*);
void StreamTcpPseudoPacketCreateStreamEndPacket(ThreadVars *tv, StreamTcpThread *stt, Packet *p, TcpSession *ssn, PacketQueue *pq);

static int StreamTcpValidateTimestamp(TcpSession * , Packet *);
static int StreamTcpHandleTimestamp(TcpSession * , Packet *);
static int StreamTcpValidateRst(TcpSession * , Packet *);
static inline int StreamTcpValidateAck(TcpSession *ssn, TcpStream *, Packet *);

static PoolThread *ssn_pool = NULL;
static SCMutex ssn_pool_mutex = SCMUTEX_INITIALIZER; /**< init only, protect initializing and growing pool */
#ifdef DEBUG
static uint64_t ssn_pool_cnt = 0; /** counts ssns, protected by ssn_pool_mutex */
#endif

uint64_t StreamTcpReassembleMemuseGlobalCounter(void);
SC_ATOMIC_DECLARE(uint64_t, st_memuse);

/* stream engine running in "inline" mode. */
int stream_inline = 0;

void StreamTcpIncrMemuse(uint64_t size)
{
    (void) SC_ATOMIC_ADD(st_memuse, size);
    return;
}

void StreamTcpDecrMemuse(uint64_t size)
{
    (void) SC_ATOMIC_SUB(st_memuse, size);
    return;
}

uint64_t StreamTcpMemuseCounter(void)
{
    uint64_t memusecopy = SC_ATOMIC_GET(st_memuse);
    return memusecopy;
}

/**
 *  \brief Check if alloc'ing "size" would mean we're over memcap
 *
 *  \retval 1 if in bounds
 *  \retval 0 if not in bounds
 */
int StreamTcpCheckMemcap(uint64_t size)
{
    if (stream_config.memcap == 0 || size + SC_ATOMIC_GET(st_memuse) <= stream_config.memcap)
        return 1;
    return 0;
}

void StreamTcpStreamCleanup(TcpStream *stream)
{
    if (stream != NULL) {
        StreamTcpSackFreeList(stream);
        StreamTcpReturnStreamSegments(stream);
    }
}

/**
 *  \brief Session cleanup function. Does not free the ssn.
 *  \param ssn tcp session
 */
void StreamTcpSessionCleanup(TcpSession *ssn)
{
    SCEnter();

    StreamMsg *smsg = NULL;
    TcpStateQueue *q, *q_next;

    if (ssn == NULL)
        return;

    StreamTcpStreamCleanup(&ssn->client);
    StreamTcpStreamCleanup(&ssn->server);

    /* if we have (a) smsg(s), return to the pool */
    smsg = ssn->toserver_smsg_head;
    while(smsg != NULL) {
        StreamMsg *smsg_next = smsg->next;
        SCLogDebug("returning smsg %p to pool", smsg);
        smsg->next = NULL;
        smsg->prev = NULL;
        StreamMsgReturnToPool(smsg);
        smsg = smsg_next;
    }
    ssn->toserver_smsg_head = NULL;

    smsg = ssn->toclient_smsg_head;
    while(smsg != NULL) {
        StreamMsg *smsg_next = smsg->next;
        SCLogDebug("returning smsg %p to pool", smsg);
        smsg->next = NULL;
        smsg->prev = NULL;
        StreamMsgReturnToPool(smsg);
        smsg = smsg_next;
    }
    ssn->toclient_smsg_head = NULL;

    q = ssn->queue;
    while (q != NULL) {
        q_next = q->next;
        SCFree(q);
        q = q_next;
        StreamTcpDecrMemuse((uint64_t)sizeof(TcpStateQueue));
    }
    ssn->queue = NULL;
    ssn->queue_len = 0;

    SCReturn;
}

/**
 *  \brief Function to return the stream back to the pool. It returns the
 *         segments in the stream to the segment pool.
 *
 *  This function is called when the flow is destroyed, so it should free
 *  *everything* related to the tcp session. So including the app layer
 *  data. We are guaranteed to only get here when the flow's use_cnt is 0.
 *
 *  \param ssn Void ptr to the ssn.
 */
void StreamTcpSessionClear(void *ssnptr)
{
    SCEnter();
    TcpSession *ssn = (TcpSession *)ssnptr;
    if (ssn == NULL)
        return;

    StreamTcpSessionCleanup(ssn);

    /* HACK: don't loose track of thread id */
    PoolThreadReserved a = ssn->res;
    memset(ssn, 0, sizeof(TcpSession));
    ssn->res = a;

    PoolThreadReturn(ssn_pool, ssn);
#ifdef DEBUG
    SCMutexLock(&ssn_pool_mutex);
    ssn_pool_cnt--;
    SCMutexUnlock(&ssn_pool_mutex);
#endif

    SCReturn;
}

/**
 *  \brief Function to return the stream segments back to the pool.
 *
 *  We don't clear out the app layer storage here as that is under protection
 *  of the "use_cnt" reference counter in the flow. This function is called
 *  when the use_cnt is always at least 1 (this pkt has incremented the flow
 *  use_cnt itself), so we don't bother.
 *
 *  \param p Packet used to identify the stream.
 */
void StreamTcpSessionPktFree (Packet *p)
{
    SCEnter();

    TcpSession *ssn = (TcpSession *)p->flow->protoctx;
    if (ssn == NULL)
        SCReturn;

    StreamTcpReturnStreamSegments(&ssn->client);
    StreamTcpReturnStreamSegments(&ssn->server);

    SCReturn;
}

/** \brief Stream alloc function for the Pool
 *  \retval ptr void ptr to TcpSession structure with all vars set to 0/NULL
 */
static void *StreamTcpSessionPoolAlloc()
{
    void *ptr = NULL;

    if (StreamTcpCheckMemcap((uint32_t)sizeof(TcpSession)) == 0)
        return NULL;

    ptr = SCMalloc(sizeof(TcpSession));
    if (unlikely(ptr == NULL))
        return NULL;

    return ptr;
}

static int StreamTcpSessionPoolInit(void *data, void* initdata)
{
    memset(data, 0, sizeof(TcpSession));
    StreamTcpIncrMemuse((uint64_t)sizeof(TcpSession));

    return 1;
}

/** \brief Pool cleanup function
 *  \param s Void ptr to TcpSession memory */
static void StreamTcpSessionPoolCleanup(void *s)
{
    if (s != NULL) {
        StreamTcpSessionCleanup(s);
        /** \todo not very clean, as the memory is not freed here */
        StreamTcpDecrMemuse((uint64_t)sizeof(TcpSession));
    }
}

/** \brief          To initialize the stream global configuration data
 *
 *  \param  quiet   It tells the mode of operation, if it is TRUE nothing will
 *                  be get printed.
 */

void StreamTcpInitConfig(char quiet)
{
    intmax_t value = 0;
    uint16_t rdrange = 10;

    SCLogDebug("Initializing Stream");

    memset(&stream_config,  0, sizeof(stream_config));

    if ((ConfGetInt("stream.max-sessions", &value)) == 1) {
        SCLogWarning(SC_WARN_OPTION_OBSOLETE, "max-sessions is obsolete. "
            "Number of concurrent sessions is now only limited by Flow and "
            "TCP stream engine memcaps.");
    }

    if ((ConfGetInt("stream.prealloc-sessions", &value)) == 1) {
        stream_config.prealloc_sessions = (uint32_t)value;
    } else {
        if (RunmodeIsUnittests()) {
            stream_config.prealloc_sessions = 128;
        } else {
            stream_config.prealloc_sessions = STREAMTCP_DEFAULT_PREALLOC;
            if (ConfGetNode("stream.prealloc-sessions") != NULL) {
                WarnInvalidConfEntry("stream.prealloc_sessions",
                                     "%"PRIu32,
                                     stream_config.prealloc_sessions);
            }
        }
    }
    if (!quiet) {
        SCLogConfig("stream \"prealloc-sessions\": %"PRIu32" (per thread)",
                stream_config.prealloc_sessions);
    }

    char *temp_stream_memcap_str;
    if (ConfGet("stream.memcap", &temp_stream_memcap_str) == 1) {
        if (ParseSizeStringU64(temp_stream_memcap_str, &stream_config.memcap) < 0) {
            SCLogError(SC_ERR_SIZE_PARSE, "Error parsing stream.memcap "
                       "from conf file - %s.  Killing engine",
                       temp_stream_memcap_str);
            exit(EXIT_FAILURE);
        }
    } else {
        stream_config.memcap = STREAMTCP_DEFAULT_MEMCAP;
    }

    if (!quiet) {
        SCLogConfig("stream \"memcap\": %"PRIu64, stream_config.memcap);
    }

    ConfGetBool("stream.midstream", &stream_config.midstream);

    if (!quiet) {
        SCLogConfig("stream \"midstream\" session pickups: %s", stream_config.midstream ? "enabled" : "disabled");
    }

    ConfGetBool("stream.async-oneside", &stream_config.async_oneside);

    if (!quiet) {
        SCLogConfig("stream \"async-oneside\": %s", stream_config.async_oneside ? "enabled" : "disabled");
    }

    int csum = 0;

    if ((ConfGetBool("stream.checksum-validation", &csum)) == 1) {
        if (csum == 1) {
            stream_config.flags |= STREAMTCP_INIT_FLAG_CHECKSUM_VALIDATION;
        }
    /* Default is that we validate the checksum of all the packets */
    } else {
        stream_config.flags |= STREAMTCP_INIT_FLAG_CHECKSUM_VALIDATION;
    }

    if (!quiet) {
        SCLogConfig("stream \"checksum-validation\": %s",
                stream_config.flags & STREAMTCP_INIT_FLAG_CHECKSUM_VALIDATION ?
                "enabled" : "disabled");
    }

    char *temp_stream_inline_str;
    if (ConfGet("stream.inline", &temp_stream_inline_str) == 1) {
        int inl = 0;

        /* checking for "auto" and falling back to boolean to provide
         * backward compatibility */
        if (strcmp(temp_stream_inline_str, "auto") == 0) {
            if (EngineModeIsIPS()) {
                stream_inline = 1;
            } else {
                stream_inline = 0;
            }
        } else if (ConfGetBool("stream.inline", &inl) == 1) {
            stream_inline = inl;
        }
    } else {
        /* default to 'auto' */
        if (EngineModeIsIPS()) {
            stream_inline = 1;
        } else {
            stream_inline = 0;
        }
    }

    if (!quiet) {
        SCLogConfig("stream.\"inline\": %s", stream_inline ? "enabled" : "disabled");
    }

    int bypass = 0;
    if ((ConfGetBool("stream.bypass", &bypass)) == 1) {
        if (bypass == 1) {
            stream_config.bypass = 1;
        } else {
            stream_config.bypass = 0;
        }
    } else {
        stream_config.bypass = 0;
    }

    if (!quiet) {
        SCLogConfig("stream \"bypass\": %s", bypass ? "enabled" : "disabled");
    }

    if ((ConfGetInt("stream.max-synack-queued", &value)) == 1) {
        if (value >= 0 && value <= 255) {
            stream_config.max_synack_queued = (uint8_t)value;
        } else {
            stream_config.max_synack_queued = (uint8_t)STREAMTCP_DEFAULT_MAX_SYNACK_QUEUED;
        }
    } else {
        stream_config.max_synack_queued = (uint8_t)STREAMTCP_DEFAULT_MAX_SYNACK_QUEUED;
    }
    if (!quiet) {
        SCLogConfig("stream \"max-synack-queued\": %"PRIu8, stream_config.max_synack_queued);
    }

    char *temp_stream_reassembly_memcap_str;
    if (ConfGet("stream.reassembly.memcap", &temp_stream_reassembly_memcap_str) == 1) {
        if (ParseSizeStringU64(temp_stream_reassembly_memcap_str,
                               &stream_config.reassembly_memcap) < 0) {
            SCLogError(SC_ERR_SIZE_PARSE, "Error parsing "
                       "stream.reassembly.memcap "
                       "from conf file - %s.  Killing engine",
                       temp_stream_reassembly_memcap_str);
            exit(EXIT_FAILURE);
        }
    } else {
        stream_config.reassembly_memcap = STREAMTCP_DEFAULT_REASSEMBLY_MEMCAP;
    }

    if (!quiet) {
        SCLogConfig("stream.reassembly \"memcap\": %"PRIu64"", stream_config.reassembly_memcap);
    }

    char *temp_stream_reassembly_depth_str;
    if (ConfGet("stream.reassembly.depth", &temp_stream_reassembly_depth_str) == 1) {
        if (ParseSizeStringU32(temp_stream_reassembly_depth_str,
                               &stream_config.reassembly_depth) < 0) {
            SCLogError(SC_ERR_SIZE_PARSE, "Error parsing "
                       "stream.reassembly.depth "
                       "from conf file - %s.  Killing engine",
                       temp_stream_reassembly_depth_str);
            exit(EXIT_FAILURE);
        }
    } else {
        stream_config.reassembly_depth = 0;
    }

    if (!quiet) {
        SCLogConfig("stream.reassembly \"depth\": %"PRIu32"", stream_config.reassembly_depth);
    }

    int randomize = 0;
    if ((ConfGetBool("stream.reassembly.randomize-chunk-size", &randomize)) == 0) {
        /* randomize by default if value not set
         * In ut mode we disable, to get predictible test results */
        if (!(RunmodeIsUnittests()))
            randomize = 1;
    }

    if (randomize) {
        char *temp_rdrange;
        if (ConfGet("stream.reassembly.randomize-chunk-range",
                    &temp_rdrange) == 1) {
            if (ParseSizeStringU16(temp_rdrange, &rdrange) < 0) {
                SCLogError(SC_ERR_SIZE_PARSE, "Error parsing "
                        "stream.reassembly.randomize-chunk-range "
                        "from conf file - %s.  Killing engine",
                        temp_rdrange);
                exit(EXIT_FAILURE);
            } else if (rdrange >= 100) {
                SCLogError(SC_ERR_INVALID_VALUE,
                           "stream.reassembly.randomize-chunk-range "
                           "must be lower than 100");
                exit(EXIT_FAILURE);
            }
        }
        /* set a "random" seed */
        srandom(time(0));
    }

    char *temp_stream_reassembly_toserver_chunk_size_str;
    if (ConfGet("stream.reassembly.toserver-chunk-size",
                &temp_stream_reassembly_toserver_chunk_size_str) == 1) {
        if (ParseSizeStringU16(temp_stream_reassembly_toserver_chunk_size_str,
                               &stream_config.reassembly_toserver_chunk_size) < 0) {
            SCLogError(SC_ERR_SIZE_PARSE, "Error parsing "
                       "stream.reassembly.toserver-chunk-size "
                       "from conf file - %s.  Killing engine",
                       temp_stream_reassembly_toserver_chunk_size_str);
            exit(EXIT_FAILURE);
        }
    } else {
        stream_config.reassembly_toserver_chunk_size =
            STREAMTCP_DEFAULT_TOSERVER_CHUNK_SIZE;
    }

    if (randomize) {
        stream_config.reassembly_toserver_chunk_size +=
            (int) (stream_config.reassembly_toserver_chunk_size *
                   (random() * 1.0 / RAND_MAX - 0.5) * rdrange / 100);
    }
    StreamMsgQueueSetMinChunkLen(FLOW_PKT_TOSERVER,
            stream_config.reassembly_toserver_chunk_size);

    char *temp_stream_reassembly_toclient_chunk_size_str;
    if (ConfGet("stream.reassembly.toclient-chunk-size",
                &temp_stream_reassembly_toclient_chunk_size_str) == 1) {
        if (ParseSizeStringU16(temp_stream_reassembly_toclient_chunk_size_str,
                               &stream_config.reassembly_toclient_chunk_size) < 0) {
            SCLogError(SC_ERR_SIZE_PARSE, "Error parsing "
                       "stream.reassembly.toclient-chunk-size "
                       "from conf file - %s.  Killing engine",
                       temp_stream_reassembly_toclient_chunk_size_str);
            exit(EXIT_FAILURE);
        }
    } else {
        stream_config.reassembly_toclient_chunk_size =
            STREAMTCP_DEFAULT_TOCLIENT_CHUNK_SIZE;
    }

    if (randomize) {
        stream_config.reassembly_toclient_chunk_size +=
            (int) (stream_config.reassembly_toclient_chunk_size *
                   (random() * 1.0 / RAND_MAX - 0.5) * rdrange / 100);
    }

    StreamMsgQueueSetMinChunkLen(FLOW_PKT_TOCLIENT,
            stream_config.reassembly_toclient_chunk_size);

    if (!quiet) {
        SCLogConfig("stream.reassembly \"toserver-chunk-size\": %"PRIu16,
            stream_config.reassembly_toserver_chunk_size);
        SCLogConfig("stream.reassembly \"toclient-chunk-size\": %"PRIu16,
            stream_config.reassembly_toclient_chunk_size);
    }

    int enable_raw = 1;
    if (ConfGetBool("stream.reassembly.raw", &enable_raw) == 1) {
        if (!enable_raw) {
            stream_config.ssn_init_flags = STREAMTCP_FLAG_DISABLE_RAW;
            stream_config.segment_init_flags = SEGMENTTCP_FLAG_RAW_PROCESSED;
        }
    } else {
        enable_raw = 1;
    }
    if (!quiet)
        SCLogConfig("stream.reassembly.raw: %s", enable_raw ? "enabled" : "disabled");

    /* init the memcap/use tracking */
    SC_ATOMIC_INIT(st_memuse);
    StatsRegisterGlobalCounter("tcp.memuse", StreamTcpMemuseCounter);

    StreamTcpReassembleInit(quiet);

    /* set the default free function and flow state function
     * values. */
    FlowSetProtoFreeFunc(IPPROTO_TCP, StreamTcpSessionClear);

#ifdef UNITTESTS
    if (RunmodeIsUnittests()) {
        SCMutexLock(&ssn_pool_mutex);
        if (ssn_pool == NULL) {
            ssn_pool = PoolThreadInit(1, /* thread */
                    0, /* unlimited */
                    stream_config.prealloc_sessions,
                    sizeof(TcpSession),
                    StreamTcpSessionPoolAlloc,
                    StreamTcpSessionPoolInit, NULL,
                    StreamTcpSessionPoolCleanup, NULL);
        }
        SCMutexUnlock(&ssn_pool_mutex);
    }
#endif
}

void StreamTcpFreeConfig(char quiet)
{
    StreamTcpReassembleFree(quiet);

    SCMutexLock(&ssn_pool_mutex);
    if (ssn_pool != NULL) {
        PoolThreadFree(ssn_pool);
        ssn_pool = NULL;
    }
    SCMutexUnlock(&ssn_pool_mutex);
    SCMutexDestroy(&ssn_pool_mutex);

    SCLogDebug("ssn_pool_cnt %"PRIu64"", ssn_pool_cnt);
}

/** \brief The function is used to to fetch a TCP session from the
 *         ssn_pool, when a TCP SYN is received.
 *
 *  \param p packet starting the new TCP session.
 *  \param id thread pool id
 *
 *  \retval ssn new TCP session.
 */
TcpSession *StreamTcpNewSession (Packet *p, int id)
{
    TcpSession *ssn = (TcpSession *)p->flow->protoctx;

    if (ssn == NULL) {
        p->flow->protoctx = PoolThreadGetById(ssn_pool, id);
#ifdef DEBUG
        SCMutexLock(&ssn_pool_mutex);
        if (p->flow->protoctx != NULL)
            ssn_pool_cnt++;
        SCMutexUnlock(&ssn_pool_mutex);
#endif

        ssn = (TcpSession *)p->flow->protoctx;
        if (ssn == NULL) {
            SCLogDebug("ssn_pool is empty");
            return NULL;
        }

        ssn->state = TCP_NONE;
        ssn->reassembly_depth = stream_config.reassembly_depth;
        ssn->flags = stream_config.ssn_init_flags;
        ssn->tcp_packet_flags = p->tcph ? p->tcph->th_flags : 0;

        if (PKT_IS_TOSERVER(p)) {
            ssn->client.tcp_flags = p->tcph ? p->tcph->th_flags : 0;
            ssn->server.tcp_flags = 0;
        } else if (PKT_IS_TOCLIENT(p)) {
            ssn->server.tcp_flags = p->tcph ? p->tcph->th_flags : 0;
            ssn->client.tcp_flags = 0;
        }
    }

    return ssn;
}

static void StreamTcpPacketSetState(Packet *p, TcpSession *ssn,
                                           uint8_t state)
{
    if (state == ssn->state || PKT_IS_PSEUDOPKT(p))
        return;

    ssn->state = state;

    /* update the flow state */
    switch(ssn->state) {
        case TCP_ESTABLISHED:
        case TCP_FIN_WAIT1:
        case TCP_FIN_WAIT2:
        case TCP_CLOSING:
        case TCP_CLOSE_WAIT:
            FlowUpdateState(p->flow, FLOW_STATE_ESTABLISHED);
            break;
        case TCP_LAST_ACK:
        case TCP_TIME_WAIT:
        case TCP_CLOSED:
            FlowUpdateState(p->flow, FLOW_STATE_CLOSED);
            break;
    }
}

/**
 *  \brief  Function to set the OS policy for the given stream based on the
 *          destination of the received packet.
 *
 *  \param  stream  TcpStream of which os_policy needs to set
 *  \param  p       Packet which is used to set the os policy
 */
void StreamTcpSetOSPolicy(TcpStream *stream, Packet *p)
{
    int ret = 0;

    if (PKT_IS_IPV4(p)) {
        /* Get the OS policy based on destination IP address, as destination
           OS will decide how to react on the anomalies of newly received
           packets */
        ret = SCHInfoGetIPv4HostOSFlavour((uint8_t *)GET_IPV4_DST_ADDR_PTR(p));
        if (ret > 0)
            stream->os_policy = ret;
        else
            stream->os_policy = OS_POLICY_DEFAULT;

    } else if (PKT_IS_IPV6(p)) {
        /* Get the OS policy based on destination IP address, as destination
           OS will decide how to react on the anomalies of newly received
           packets */
        ret = SCHInfoGetIPv6HostOSFlavour((uint8_t *)GET_IPV6_DST_ADDR(p));
        if (ret > 0)
            stream->os_policy = ret;
        else
            stream->os_policy = OS_POLICY_DEFAULT;
    }

    if (stream->os_policy == OS_POLICY_BSD_RIGHT)
        stream->os_policy = OS_POLICY_BSD;
    else if (stream->os_policy == OS_POLICY_OLD_SOLARIS)
        stream->os_policy = OS_POLICY_SOLARIS;

    SCLogDebug("Policy is %"PRIu8"", stream->os_policy);

}

/**
 *  \brief get the size of a stream
 *
 *  \note this just calculates the diff between isn and last_ack
 *        and will not consider sequence wrap arounds (streams
 *        bigger than 4gb).
 *
 *  \retval size stream size
 */
uint32_t StreamTcpGetStreamSize(TcpStream *stream)
{
    return (stream->last_ack - stream->isn - 1);
}

/**
 *  \brief macro to update last_ack only if the new value is higher
 *
 *  \param ssn session
 *  \param stream stream to update
 *  \param ack ACK value to test and set
 */
#define StreamTcpUpdateLastAck(ssn, stream, ack) { \
    if (SEQ_GT((ack), (stream)->last_ack)) \
    { \
        SCLogDebug("ssn %p: last_ack set to %"PRIu32", moved %u forward", (ssn), (ack), (ack) - (stream)->last_ack); \
        if ((SEQ_LEQ((stream)->last_ack, (stream)->next_seq) && SEQ_GT((ack),(stream)->next_seq))) { \
            SCLogDebug("last_ack just passed next_seq: %u (was %u) > %u", (ack), (stream)->last_ack, (stream)->next_seq); \
        } else { \
            SCLogDebug("next_seq (%u) <> last_ack now %d", (stream)->next_seq, (int)(stream)->next_seq - (ack)); \
        }\
        (stream)->last_ack = (ack); \
        StreamTcpSackPruneList((stream)); \
    } else { \
        SCLogDebug("ssn %p: no update: ack %u, last_ack %"PRIu32", next_seq %u (state %u)", \
                    (ssn), (ack), (stream)->last_ack, (stream)->next_seq, (ssn)->state); \
    }\
}

/**
 *  \brief macro to update next_win only if the new value is higher
 *
 *  \param ssn session
 *  \param stream stream to update
 *  \param win window value to test and set
 */
#define StreamTcpUpdateNextWin(ssn, stream, win) { \
    uint32_t sacked_size__ = StreamTcpSackedSize((stream)); \
    if (SEQ_GT(((win) + sacked_size__), (stream)->next_win)) { \
        (stream)->next_win = ((win) + sacked_size__); \
        SCLogDebug("ssn %p: next_win set to %"PRIu32, (ssn), (stream)->next_win); \
    } \
}

static int StreamTcpPacketIsRetransmission(TcpStream *stream, Packet *p)
{
    if (p->payload_len == 0)
        SCReturnInt(0);

    /* retransmission of already partially ack'd data */
    if (SEQ_LT(TCP_GET_SEQ(p), stream->last_ack) && SEQ_GT((TCP_GET_SEQ(p) + p->payload_len), stream->last_ack))
    {
        StreamTcpSetEvent(p, STREAM_PKT_RETRANSMISSION);
        SCReturnInt(1);
    }

    /* retransmission of already ack'd data */
    if (SEQ_LEQ((TCP_GET_SEQ(p) + p->payload_len), stream->last_ack)) {
        StreamTcpSetEvent(p, STREAM_PKT_RETRANSMISSION);
        SCReturnInt(1);
    }

    /* retransmission of in flight data */
    if (SEQ_LEQ((TCP_GET_SEQ(p) + p->payload_len), stream->next_seq)) {
        StreamTcpSetEvent(p, STREAM_PKT_RETRANSMISSION);
        SCReturnInt(2);
    }

    SCLogDebug("seq %u payload_len %u => %u, last_ack %u, next_seq %u", TCP_GET_SEQ(p),
            p->payload_len, (TCP_GET_SEQ(p) + p->payload_len), stream->last_ack, stream->next_seq);
    SCReturnInt(0);
}

/**
 *  \internal
 *  \brief  Function to handle the TCP_CLOSED or NONE state. The function handles
 *          packets while the session state is None which means a newly
 *          initialized structure, or a fully closed session.
 *
 *  \param  tv      Thread Variable containig  input/output queue, cpu affinity
 *  \param  p       Packet which has to be handled in this TCP state.
 *  \param  stt     Strean Thread module registered to handle the stream handling
 *
 *  \retval 0 ok
 *  \retval -1 error
 */
static int StreamTcpPacketStateNone(ThreadVars *tv, Packet *p,
                        StreamTcpThread *stt, TcpSession *ssn, PacketQueue *pq)
{
    if (p->tcph->th_flags & TH_RST) {
        StreamTcpSetEvent(p, STREAM_RST_BUT_NO_SESSION);
        SCLogDebug("RST packet received, no session setup");
        return -1;

    } else if (p->tcph->th_flags & TH_FIN) {
        StreamTcpSetEvent(p, STREAM_FIN_BUT_NO_SESSION);
        SCLogDebug("FIN packet received, no session setup");
        return -1;

    /* SYN/ACK */
    } else if ((p->tcph->th_flags & (TH_SYN|TH_ACK)) == (TH_SYN|TH_ACK)) {
        if (stream_config.midstream == FALSE &&
                stream_config.async_oneside == FALSE)
            return 0;

        if (ssn == NULL) {
            ssn = StreamTcpNewSession(p, stt->ssn_pool_id);
            if (ssn == NULL) {
                StatsIncr(tv, stt->counter_tcp_ssn_memcap);
                return -1;
            }
            StatsIncr(tv, stt->counter_tcp_sessions);
        }
        /* set the state */
        StreamTcpPacketSetState(p, ssn, TCP_SYN_RECV);
        SCLogDebug("ssn %p: =~ midstream picked ssn state is now "
                "TCP_SYN_RECV", ssn);
        ssn->flags |= STREAMTCP_FLAG_MIDSTREAM;
        /* Flag used to change the direct in the later stage in the session */
        ssn->flags |= STREAMTCP_FLAG_MIDSTREAM_SYNACK;

        /* sequence number & window */
        ssn->server.isn = TCP_GET_SEQ(p);
        STREAMTCP_SET_RA_BASE_SEQ(&ssn->server, ssn->server.isn);
        ssn->server.next_seq = ssn->server.isn + 1;
        ssn->server.window = TCP_GET_WINDOW(p);
        SCLogDebug("ssn %p: server window %u", ssn, ssn->server.window);

        ssn->client.isn = TCP_GET_ACK(p) - 1;
        STREAMTCP_SET_RA_BASE_SEQ(&ssn->client, ssn->client.isn);
        ssn->client.next_seq = ssn->client.isn + 1;

        ssn->client.last_ack = TCP_GET_ACK(p);
        ssn->server.last_ack = TCP_GET_SEQ(p);

        ssn->server.next_win = ssn->server.last_ack + ssn->server.window;

        /** If the client has a wscale option the server had it too,
         *  so set the wscale for the server to max. Otherwise none
         *  will have the wscale opt just like it should. */
        if (TCP_HAS_WSCALE(p)) {
            ssn->client.wscale = TCP_GET_WSCALE(p);
            ssn->server.wscale = TCP_WSCALE_MAX;
        }

        SCLogDebug("ssn %p: ssn->client.isn %"PRIu32", ssn->client.next_seq"
                " %"PRIu32", ssn->client.last_ack %"PRIu32"", ssn,
                ssn->client.isn, ssn->client.next_seq,
                ssn->client.last_ack);
        SCLogDebug("ssn %p: ssn->server.isn %"PRIu32", ssn->server.next_seq"
                " %"PRIu32", ssn->server.last_ack %"PRIu32"", ssn,
                ssn->server.isn, ssn->server.next_seq,
                ssn->server.last_ack);

        /* Set the timestamp value for both streams, if packet has timestamp
         * option enabled.*/
        if (TCP_HAS_TS(p)) {
            ssn->server.last_ts = TCP_GET_TSVAL(p);
            ssn->client.last_ts = TCP_GET_TSECR(p);
            SCLogDebug("ssn %p: ssn->server.last_ts %" PRIu32" "
                    "ssn->client.last_ts %" PRIu32"", ssn,
                    ssn->server.last_ts, ssn->client.last_ts);

            ssn->flags |= STREAMTCP_FLAG_TIMESTAMP;

            ssn->server.last_pkt_ts = p->ts.tv_sec;
            if (ssn->server.last_ts == 0)
                ssn->server.flags |= STREAMTCP_STREAM_FLAG_ZERO_TIMESTAMP;
            if (ssn->client.last_ts == 0)
                ssn->client.flags |= STREAMTCP_STREAM_FLAG_ZERO_TIMESTAMP;

        } else {
            ssn->server.last_ts = 0;
            ssn->client.last_ts = 0;
        }

        if (TCP_GET_SACKOK(p) == 1) {
            ssn->flags |= STREAMTCP_FLAG_SACKOK;
            SCLogDebug("ssn %p: SYN/ACK with SACK permitted, assuming "
                    "SACK permitted for both sides", ssn);
        }

        /* packet thinks it is in the wrong direction, flip it */
        StreamTcpPacketSwitchDir(ssn, p);

    } else if (p->tcph->th_flags & TH_SYN) {
        if (ssn == NULL) {
            ssn = StreamTcpNewSession(p, stt->ssn_pool_id);
            if (ssn == NULL) {
                StatsIncr(tv, stt->counter_tcp_ssn_memcap);
                return -1;
            }

            StatsIncr(tv, stt->counter_tcp_sessions);
        }

        /* set the state */
        StreamTcpPacketSetState(p, ssn, TCP_SYN_SENT);
        SCLogDebug("ssn %p: =~ ssn state is now TCP_SYN_SENT", ssn);

        /* set the sequence numbers and window */
        ssn->client.isn = TCP_GET_SEQ(p);
        STREAMTCP_SET_RA_BASE_SEQ(&ssn->client, ssn->client.isn);
        ssn->client.next_seq = ssn->client.isn + 1;

        /* Set the stream timestamp value, if packet has timestamp option
         * enabled. */
        if (TCP_HAS_TS(p)) {
            ssn->client.last_ts = TCP_GET_TSVAL(p);
            SCLogDebug("ssn %p: %02x", ssn, ssn->client.last_ts);

            if (ssn->client.last_ts == 0)
                ssn->client.flags |= STREAMTCP_STREAM_FLAG_ZERO_TIMESTAMP;

            ssn->client.last_pkt_ts = p->ts.tv_sec;
            ssn->client.flags |= STREAMTCP_STREAM_FLAG_TIMESTAMP;
        }

        ssn->server.window = TCP_GET_WINDOW(p);
        if (TCP_HAS_WSCALE(p)) {
            ssn->flags |= STREAMTCP_FLAG_SERVER_WSCALE;
            ssn->server.wscale = TCP_GET_WSCALE(p);
        }

        if (TCP_GET_SACKOK(p) == 1) {
            ssn->flags |= STREAMTCP_FLAG_CLIENT_SACKOK;
            SCLogDebug("ssn %p: SACK permited on SYN packet", ssn);
        }

        SCLogDebug("ssn %p: ssn->client.isn %" PRIu32 ", "
                "ssn->client.next_seq %" PRIu32 ", ssn->client.last_ack "
                "%"PRIu32"", ssn, ssn->client.isn, ssn->client.next_seq,
                ssn->client.last_ack);

    } else if (p->tcph->th_flags & TH_ACK) {
        if (stream_config.midstream == FALSE)
            return 0;

        if (ssn == NULL) {
            ssn = StreamTcpNewSession(p, stt->ssn_pool_id);
            if (ssn == NULL) {
                StatsIncr(tv, stt->counter_tcp_ssn_memcap);
                return -1;
            }
            StatsIncr(tv, stt->counter_tcp_sessions);
        }
        /* set the state */
        StreamTcpPacketSetState(p, ssn, TCP_ESTABLISHED);
        SCLogDebug("ssn %p: =~ midstream picked ssn state is now "
                "TCP_ESTABLISHED", ssn);

        ssn->flags = STREAMTCP_FLAG_MIDSTREAM;
        ssn->flags |= STREAMTCP_FLAG_MIDSTREAM_ESTABLISHED;

        /** window scaling for midstream pickups, we can't do much other
         *  than assume that it's set to the max value: 14 */
        ssn->client.wscale = TCP_WSCALE_MAX;
        ssn->server.wscale = TCP_WSCALE_MAX;

        /* set the sequence numbers and window */
        ssn->client.isn = TCP_GET_SEQ(p) - 1;
        STREAMTCP_SET_RA_BASE_SEQ(&ssn->client, ssn->client.isn);
        ssn->client.next_seq = TCP_GET_SEQ(p) + p->payload_len;
        ssn->client.window = TCP_GET_WINDOW(p) << ssn->client.wscale;
        ssn->client.last_ack = TCP_GET_SEQ(p);
        ssn->client.next_win = ssn->client.last_ack + ssn->client.window;
        SCLogDebug("ssn %p: ssn->client.isn %u, ssn->client.next_seq %u",
                ssn, ssn->client.isn, ssn->client.next_seq);

        ssn->server.isn = TCP_GET_ACK(p) - 1;
        STREAMTCP_SET_RA_BASE_SEQ(&ssn->server, ssn->server.isn);
        ssn->server.next_seq = ssn->server.isn + 1;
        ssn->server.last_ack = TCP_GET_ACK(p);
        ssn->server.next_win = ssn->server.last_ack;

        SCLogDebug("ssn %p: ssn->client.next_win %"PRIu32", "
                "ssn->server.next_win %"PRIu32"", ssn,
                ssn->client.next_win, ssn->server.next_win);
        SCLogDebug("ssn %p: ssn->client.last_ack %"PRIu32", "
                "ssn->server.last_ack %"PRIu32"", ssn,
                ssn->client.last_ack, ssn->server.last_ack);

        /* Set the timestamp value for both streams, if packet has timestamp
         * option enabled.*/
        if (TCP_HAS_TS(p)) {
            ssn->client.last_ts = TCP_GET_TSVAL(p);
            ssn->server.last_ts = TCP_GET_TSECR(p);
            SCLogDebug("ssn %p: ssn->server.last_ts %" PRIu32" "
                    "ssn->client.last_ts %" PRIu32"", ssn,
                    ssn->server.last_ts, ssn->client.last_ts);

            ssn->flags |= STREAMTCP_FLAG_TIMESTAMP;

            ssn->client.last_pkt_ts = p->ts.tv_sec;
            if (ssn->server.last_ts == 0)
                ssn->server.flags |= STREAMTCP_STREAM_FLAG_ZERO_TIMESTAMP;
            if (ssn->client.last_ts == 0)
                ssn->client.flags |= STREAMTCP_STREAM_FLAG_ZERO_TIMESTAMP;

        } else {
            ssn->server.last_ts = 0;
            ssn->client.last_ts = 0;
        }

        StreamTcpReassembleHandleSegment(tv, stt->ra_ctx, ssn, &ssn->client, p, pq);

        ssn->flags |= STREAMTCP_FLAG_SACKOK;
        SCLogDebug("ssn %p: assuming SACK permitted for both sides", ssn);

    } else {
        SCLogDebug("default case");
    }

    return 0;
}

/** \internal
 *  \brief Setup TcpStateQueue based on SYN/ACK packet
 */
static inline void StreamTcp3whsSynAckToStateQueue(Packet *p, TcpStateQueue *q)
{
    q->flags = 0;
    q->wscale = 0;
    q->ts = 0;
    q->win = TCP_GET_WINDOW(p);
    q->seq = TCP_GET_SEQ(p);
    q->ack = TCP_GET_ACK(p);
    q->pkt_ts = p->ts.tv_sec;

    if (TCP_GET_SACKOK(p) == 1)
        q->flags |= STREAMTCP_QUEUE_FLAG_SACK;

    if (TCP_HAS_WSCALE(p)) {
        q->flags |= STREAMTCP_QUEUE_FLAG_WS;
        q->wscale = TCP_GET_WSCALE(p);
    }
    if (TCP_HAS_TS(p)) {
        q->flags |= STREAMTCP_QUEUE_FLAG_TS;
        q->ts = TCP_GET_TSVAL(p);
    }
}

/** \internal
 *  \brief Find the Queued SYN/ACK that is the same as this SYN/ACK
 *  \retval q or NULL */
TcpStateQueue *StreamTcp3whsFindSynAckBySynAck(TcpSession *ssn, Packet *p)
{
    TcpStateQueue *q = ssn->queue;
    TcpStateQueue search;

    StreamTcp3whsSynAckToStateQueue(p, &search);

    while (q != NULL) {
        if (search.flags == q->flags &&
            search.wscale == q->wscale &&
            search.win == q->win &&
            search.seq == q->seq &&
            search.ack == q->ack &&
            search.ts == q->ts) {
            return q;
        }

        q = q->next;
    }

    return q;
}

int StreamTcp3whsQueueSynAck(TcpSession *ssn, Packet *p)
{
    /* first see if this is already in our list */
    if (StreamTcp3whsFindSynAckBySynAck(ssn, p) != NULL)
        return 0;

    if (ssn->queue_len == stream_config.max_synack_queued) {
        SCLogDebug("ssn %p: =~ SYN/ACK queue limit reached", ssn);
        StreamTcpSetEvent(p, STREAM_3WHS_SYNACK_FLOOD);
        return -1;
    }

    if (StreamTcpCheckMemcap((uint32_t)sizeof(TcpStateQueue)) == 0) {
        SCLogDebug("ssn %p: =~ SYN/ACK queue failed: stream memcap reached", ssn);
        return -1;
    }

    TcpStateQueue *q = SCMalloc(sizeof(*q));
    if (unlikely(q == NULL)) {
        SCLogDebug("ssn %p: =~ SYN/ACK queue failed: alloc failed", ssn);
        return -1;
    }
    memset(q, 0x00, sizeof(*q));
    StreamTcpIncrMemuse((uint64_t)sizeof(TcpStateQueue));

    StreamTcp3whsSynAckToStateQueue(p, q);

    /* put in list */
    q->next = ssn->queue;
    ssn->queue = q;
    ssn->queue_len++;
    return 0;
}

/** \internal
 *  \brief Find the Queued SYN/ACK that goes with this ACK
 *  \retval q or NULL */
TcpStateQueue *StreamTcp3whsFindSynAckByAck(TcpSession *ssn, Packet *p)
{
    uint32_t ack = TCP_GET_SEQ(p);
    uint32_t seq = TCP_GET_ACK(p) - 1;
    TcpStateQueue *q = ssn->queue;

    while (q != NULL) {
        if (seq == q->seq &&
            ack == q->ack) {
            return q;
        }

        q = q->next;
    }

    return NULL;
}

/** \internal
 *  \brief Update SSN after receiving a valid SYN/ACK
 *
 *  Normally we update the SSN from the SYN/ACK packet. But in case
 *  of queued SYN/ACKs, we can use one of those.
 *
 *  \param ssn TCP session
 *  \param p Packet
 *  \param q queued state if used, NULL otherwise
 *
 *  To make sure all SYN/ACK based state updates are in one place,
 *  this function can updated based on Packet or TcpStateQueue, where
 *  the latter takes precedence.
 */
static void StreamTcp3whsSynAckUpdate(TcpSession *ssn, Packet *p, TcpStateQueue *q)
{
    TcpStateQueue update;
    if (likely(q == NULL)) {
        StreamTcp3whsSynAckToStateQueue(p, &update);
        q = &update;
    }

    if (ssn->state != TCP_SYN_RECV) {
        /* update state */
        StreamTcpPacketSetState(p, ssn, TCP_SYN_RECV);
        SCLogDebug("ssn %p: =~ ssn state is now TCP_SYN_RECV", ssn);
    }
    /* sequence number & window */
    ssn->server.isn = q->seq;
    STREAMTCP_SET_RA_BASE_SEQ(&ssn->server, ssn->server.isn);
    ssn->server.next_seq = ssn->server.isn + 1;

    ssn->client.window = q->win;
    SCLogDebug("ssn %p: window %" PRIu32 "", ssn, ssn->server.window);

    /* Set the timestamp values used to validate the timestamp of
     * received packets.*/
    if ((q->flags & STREAMTCP_QUEUE_FLAG_TS) &&
            (ssn->client.flags & STREAMTCP_STREAM_FLAG_TIMESTAMP))
    {
        ssn->server.last_ts = q->ts;
        SCLogDebug("ssn %p: ssn->server.last_ts %" PRIu32" "
                "ssn->client.last_ts %" PRIu32"", ssn,
                ssn->server.last_ts, ssn->client.last_ts);
        ssn->flags |= STREAMTCP_FLAG_TIMESTAMP;
        ssn->server.last_pkt_ts = q->pkt_ts;
        if (ssn->server.last_ts == 0)
            ssn->server.flags |= STREAMTCP_STREAM_FLAG_ZERO_TIMESTAMP;
    } else {
        ssn->client.last_ts = 0;
        ssn->server.last_ts = 0;
        ssn->client.flags &= ~STREAMTCP_STREAM_FLAG_ZERO_TIMESTAMP;
    }

    ssn->client.last_ack = q->ack;
    ssn->server.last_ack = ssn->server.isn + 1;

    /** check for the presense of the ws ptr to determine if we
     *  support wscale at all */
    if ((ssn->flags & STREAMTCP_FLAG_SERVER_WSCALE) &&
            (q->flags & STREAMTCP_QUEUE_FLAG_WS))
    {
        ssn->client.wscale = q->wscale;
    } else {
        ssn->client.wscale = 0;
    }

    if ((ssn->flags & STREAMTCP_FLAG_CLIENT_SACKOK) &&
            (q->flags & STREAMTCP_QUEUE_FLAG_SACK)) {
        ssn->flags |= STREAMTCP_FLAG_SACKOK;
        SCLogDebug("ssn %p: SACK permitted for session", ssn);
    } else {
        ssn->flags &= ~STREAMTCP_FLAG_SACKOK;
    }

    ssn->server.next_win = ssn->server.last_ack + ssn->server.window;
    ssn->client.next_win = ssn->client.last_ack + ssn->client.window;
    SCLogDebug("ssn %p: ssn->server.next_win %" PRIu32 "", ssn,
            ssn->server.next_win);
    SCLogDebug("ssn %p: ssn->client.next_win %" PRIu32 "", ssn,
            ssn->client.next_win);
    SCLogDebug("ssn %p: ssn->server.isn %" PRIu32 ", "
            "ssn->server.next_seq %" PRIu32 ", "
            "ssn->server.last_ack %" PRIu32 " "
            "(ssn->client.last_ack %" PRIu32 ")", ssn,
            ssn->server.isn, ssn->server.next_seq,
            ssn->server.last_ack, ssn->client.last_ack);

    /* unset the 4WHS flag as we received this SYN/ACK as part of a
     * (so far) valid 3WHS */
    if (ssn->flags & STREAMTCP_FLAG_4WHS)
        SCLogDebug("ssn %p: STREAMTCP_FLAG_4WHS unset, normal SYN/ACK"
                " so considering 3WHS", ssn);

    ssn->flags &=~ STREAMTCP_FLAG_4WHS;
}

/**
 *  \brief  Function to handle the TCP_SYN_SENT state. The function handles
 *          SYN, SYN/ACK, RST packets and correspondingly changes the connection
 *          state.
 *
 *  \param  tv      Thread Variable containig  input/output queue, cpu affinity
 *  \param  p       Packet which has to be handled in this TCP state.
 *  \param  stt     Strean Thread module registered to handle the stream handling.

以StreamTcpPacketStateSynSent为例，处理流程为：
1.若为RST包：
(1)调用StreamTcpValidateRst进行验证，不合法则返回。
(2)将session状态设置为CLOSED。
2.若为FIN包：代码中写着todo…
3.若为SYN/ACK包：
(1)处理4WHS（SYN-SYN-SYN/ACK-ACK）的特殊情况。
(2)若数据包方向为TO_SERVER，添加STREAM_3WHS_SYNACK_IN_WRONG_DIRECTION事件并返回。
(3)若ACK值不等于client.isn（initial sequence number）+1，则添加STREAM_3WHS_SYNACK_WITH_WRONG_ACK事件并返回。
(4)到这里，就说明是个正常的3WHS SYN/ACK包了，则调用StreamTcp3whsSynAckUpdate更新session的各个属性值，这个函数会：
a.将session状态更新为TCP_SYN_RECV。
b.将server.isn设为该包的seq，next_seq设为isn+1（SYN/FIN包都会使序列号+1，参见Understanding TCP Sequence and Acknowledgment Numbers）
c.将client.window设为该包的win值，从这可以看出TCPStream的window为流的目标端所宣传的窗口值。
d.更新时间戳选项相关的值和标志。
e.将client.last_ack设为该包的ack，而server.last_ack设为server.isn+1（这个不太理解，因为客户端的ACK还没发过来呢，为什么就设置了？）。
f.若支持，则设置client.wscale为该包的wscale，即窗口扩大因子。
g.更新SACK相关的标志。
h.将server.next_win（在窗口范围内能发送的下一个最大的seq）和client.next_win分别设为各自的last_ack+window。
4.若为SYN包：
(1)若数据包方向不为TO_CLIENT，则不会做任何处理。
(2)否则，说明这是一个4WHS，给session打上相应标记。
(3)与SYN/ACK的处理类似，更新server的isn、next_seq、timestamp、window、wscale、sack。注意的是，并没有更新client相应数据。
5.若为ACK包：
(1)异步（单边）流的情况：从同一个主机收到SYN后再收到ACK，而没有收到SYN/ACK。若async_oneside配置未打开，就返回。
(2)检查p.seq是否等于client.next_seq，若不是则添加STREAM_3WHS_ASYNC_WRONG_SEQ事件并返回。
(3)给session打上STREAMTCP_FLAG_ASYNC标记，并更新状态为ESTABLISHED。
(4)与上面类似，更新client和server的相应属性值。
其他状态处理函数也类似，组合到一起，就构成了一个非常复杂的有限状态机，其中有多个错误终止状态
（如错误序列号），但只有一个正常终止状态（TCP_CLOSED），并且还存在很多“捷径”
（如从SYN_SENT直接到CLOSED）。状态的跳转并不只是依赖于当前的主状态（session->state），
还包括很多附属状态（TCPSession、TCPStream的各种字段），这些附属状态在跳转过程中也会不断更新。
这个理解不一定准确，但从源码中来看，TCP会话的跟踪和验证确实非常繁琐。
 */

static int StreamTcpPacketStateSynSent(ThreadVars *tv, Packet *p,
                        StreamTcpThread *stt, TcpSession *ssn, PacketQueue *pq)
{
    if (ssn == NULL)
        return -1;

    SCLogDebug("ssn %p: pkt received: %s", ssn, PKT_IS_TOCLIENT(p) ?
               "toclient":"toserver");

    /* RST */
    if (p->tcph->th_flags & TH_RST) {
        if (!StreamTcpValidateRst(ssn, p))
            return -1;

        if (PKT_IS_TOSERVER(p)) {
            if (SEQ_EQ(TCP_GET_SEQ(p), ssn->client.isn) &&
                    SEQ_EQ(TCP_GET_WINDOW(p), 0) &&
                    SEQ_EQ(TCP_GET_ACK(p), (ssn->client.isn + 1)))
            {
                StreamTcpPacketSetState(p, ssn, TCP_CLOSED);
                SCLogDebug("ssn %p: Reset received and state changed to "
                        "TCP_CLOSED", ssn);
            }
        } else {
            StreamTcpPacketSetState(p, ssn, TCP_CLOSED);
            SCLogDebug("ssn %p: Reset received and state changed to "
                    "TCP_CLOSED", ssn);
        }

    /* FIN */
    } else if (p->tcph->th_flags & TH_FIN) {
        /** \todo */

    /* SYN/ACK */
    } else if ((p->tcph->th_flags & (TH_SYN|TH_ACK)) == (TH_SYN|TH_ACK)) {
        if ((ssn->flags & STREAMTCP_FLAG_4WHS) && PKT_IS_TOSERVER(p)) {
            SCLogDebug("ssn %p: SYN/ACK received on 4WHS session", ssn);

            /* Check if the SYN/ACK packet ack's the earlier
             * received SYN packet. */
            if (!(SEQ_EQ(TCP_GET_ACK(p), ssn->server.isn + 1))) {
                StreamTcpSetEvent(p, STREAM_4WHS_SYNACK_WITH_WRONG_ACK);

                SCLogDebug("ssn %p: 4WHS ACK mismatch, packet ACK %"PRIu32""
                        " != %" PRIu32 " from stream", ssn,
                        TCP_GET_ACK(p), ssn->server.isn + 1);
                return -1;
            }

            /* Check if the SYN/ACK packet SEQ's the *FIRST* received SYN
             * packet. */
            if (!(SEQ_EQ(TCP_GET_SEQ(p), ssn->client.isn))) {
                StreamTcpSetEvent(p, STREAM_4WHS_SYNACK_WITH_WRONG_SYN);

                SCLogDebug("ssn %p: 4WHS SEQ mismatch, packet SEQ %"PRIu32""
                        " != %" PRIu32 " from *first* SYN pkt", ssn,
                        TCP_GET_SEQ(p), ssn->client.isn);
                return -1;
            }


            /* update state */
            StreamTcpPacketSetState(p, ssn, TCP_SYN_RECV);
            SCLogDebug("ssn %p: =~ 4WHS ssn state is now TCP_SYN_RECV", ssn);

            /* sequence number & window */
            ssn->client.isn = TCP_GET_SEQ(p);
            STREAMTCP_SET_RA_BASE_SEQ(&ssn->client, ssn->client.isn);
            ssn->client.next_seq = ssn->client.isn + 1;

            ssn->server.window = TCP_GET_WINDOW(p);
            SCLogDebug("ssn %p: 4WHS window %" PRIu32 "", ssn,
                    ssn->client.window);

            /* Set the timestamp values used to validate the timestamp of
             * received packets. */
            if ((TCP_HAS_TS(p)) &&
                    (ssn->server.flags & STREAMTCP_STREAM_FLAG_TIMESTAMP))
            {
                ssn->client.last_ts = TCP_GET_TSVAL(p);
                SCLogDebug("ssn %p: 4WHS ssn->client.last_ts %" PRIu32" "
                        "ssn->server.last_ts %" PRIu32"", ssn,
                        ssn->client.last_ts, ssn->server.last_ts);
                ssn->flags |= STREAMTCP_FLAG_TIMESTAMP;
                ssn->client.last_pkt_ts = p->ts.tv_sec;
                if (ssn->client.last_ts == 0)
                    ssn->client.flags |= STREAMTCP_STREAM_FLAG_ZERO_TIMESTAMP;
            } else {
                ssn->server.last_ts = 0;
                ssn->client.last_ts = 0;
                ssn->server.flags &= ~STREAMTCP_STREAM_FLAG_ZERO_TIMESTAMP;
            }

            ssn->server.last_ack = TCP_GET_ACK(p);
            ssn->client.last_ack = ssn->client.isn + 1;

            /** check for the presense of the ws ptr to determine if we
             *  support wscale at all */
            if ((ssn->flags & STREAMTCP_FLAG_SERVER_WSCALE) &&
                    (TCP_HAS_WSCALE(p)))
            {
                ssn->server.wscale = TCP_GET_WSCALE(p);
            } else {
                ssn->server.wscale = 0;
            }

            if ((ssn->flags & STREAMTCP_FLAG_CLIENT_SACKOK) &&
                    TCP_GET_SACKOK(p) == 1) {
                ssn->flags |= STREAMTCP_FLAG_SACKOK;
                SCLogDebug("ssn %p: SACK permitted for 4WHS session", ssn);
            }

            ssn->client.next_win = ssn->client.last_ack + ssn->client.window;
            ssn->server.next_win = ssn->server.last_ack + ssn->server.window;
            SCLogDebug("ssn %p: 4WHS ssn->client.next_win %" PRIu32 "", ssn,
                    ssn->client.next_win);
            SCLogDebug("ssn %p: 4WHS ssn->server.next_win %" PRIu32 "", ssn,
                    ssn->server.next_win);
            SCLogDebug("ssn %p: 4WHS ssn->client.isn %" PRIu32 ", "
                    "ssn->client.next_seq %" PRIu32 ", "
                    "ssn->client.last_ack %" PRIu32 " "
                    "(ssn->server.last_ack %" PRIu32 ")", ssn,
                    ssn->client.isn, ssn->client.next_seq,
                    ssn->client.last_ack, ssn->server.last_ack);

            /* done here */
            return 0;
        }

        if (PKT_IS_TOSERVER(p)) {
            StreamTcpSetEvent(p, STREAM_3WHS_SYNACK_IN_WRONG_DIRECTION);
            SCLogDebug("ssn %p: SYN/ACK received in the wrong direction", ssn);
            return -1;
        }

        /* Check if the SYN/ACK packet ack's the earlier
         * received SYN packet. */
        if (!(SEQ_EQ(TCP_GET_ACK(p), ssn->client.isn + 1))) {
            StreamTcpSetEvent(p, STREAM_3WHS_SYNACK_WITH_WRONG_ACK);
            SCLogDebug("ssn %p: ACK mismatch, packet ACK %" PRIu32 " != "
                    "%" PRIu32 " from stream", ssn, TCP_GET_ACK(p),
                    ssn->client.isn + 1);
            return -1;
        }

        StreamTcp3whsSynAckUpdate(ssn, p, /* no queue override */NULL);

    } else if (p->tcph->th_flags & TH_SYN) {
        SCLogDebug("ssn %p: SYN packet on state SYN_SENT... resent", ssn);
        if (ssn->flags & STREAMTCP_FLAG_4WHS) {
            SCLogDebug("ssn %p: SYN packet on state SYN_SENT... resent of "
                    "4WHS SYN", ssn);
        }

        if (PKT_IS_TOCLIENT(p)) {
            /** a SYN only packet in the opposite direction could be:
             *  http://www.breakingpointsystems.com/community/blog/tcp-
             *  portals-the-three-way-handshake-is-a-lie
             *
             * \todo improve resetting the session */

            /* indicate that we're dealing with 4WHS here */
            ssn->flags |= STREAMTCP_FLAG_4WHS;
            SCLogDebug("ssn %p: STREAMTCP_FLAG_4WHS flag set", ssn);

            /* set the sequence numbers and window for server
             * We leave the ssn->client.isn in place as we will
             * check the SYN/ACK pkt with that.
             */
            ssn->server.isn = TCP_GET_SEQ(p);
            STREAMTCP_SET_RA_BASE_SEQ(&ssn->server, ssn->server.isn);
            ssn->server.next_seq = ssn->server.isn + 1;

            /* Set the stream timestamp value, if packet has timestamp
             * option enabled. */
            if (TCP_HAS_TS(p)) {
                ssn->server.last_ts = TCP_GET_TSVAL(p);
                SCLogDebug("ssn %p: %02x", ssn, ssn->server.last_ts);

                if (ssn->server.last_ts == 0)
                    ssn->server.flags |= STREAMTCP_STREAM_FLAG_ZERO_TIMESTAMP;
                ssn->server.last_pkt_ts = p->ts.tv_sec;
                ssn->server.flags |= STREAMTCP_STREAM_FLAG_TIMESTAMP;
            }

            ssn->server.window = TCP_GET_WINDOW(p);
            if (TCP_HAS_WSCALE(p)) {
                ssn->flags |= STREAMTCP_FLAG_SERVER_WSCALE;
                ssn->server.wscale = TCP_GET_WSCALE(p);
            } else {
                ssn->flags &= ~STREAMTCP_FLAG_SERVER_WSCALE;
                ssn->server.wscale = 0;
            }

            if (TCP_GET_SACKOK(p) == 1) {
                ssn->flags |= STREAMTCP_FLAG_CLIENT_SACKOK;
            } else {
                ssn->flags &= ~STREAMTCP_FLAG_CLIENT_SACKOK;
            }

            SCLogDebug("ssn %p: 4WHS ssn->server.isn %" PRIu32 ", "
                    "ssn->server.next_seq %" PRIu32 ", "
                    "ssn->server.last_ack %"PRIu32"", ssn,
                    ssn->server.isn, ssn->server.next_seq,
                    ssn->server.last_ack);
            SCLogDebug("ssn %p: 4WHS ssn->client.isn %" PRIu32 ", "
                    "ssn->client.next_seq %" PRIu32 ", "
                    "ssn->client.last_ack %"PRIu32"", ssn,
                    ssn->client.isn, ssn->client.next_seq,
                    ssn->client.last_ack);
        }

        /** \todo check if it's correct or set event */

    } else if (p->tcph->th_flags & TH_ACK) {
        /* Handle the asynchronous stream, when we receive a  SYN packet
           and now istead of receving a SYN/ACK we receive a ACK from the
           same host, which sent the SYN, this suggests the ASNYC streams.*/
        if (stream_config.async_oneside == FALSE)
            return 0;

        /* we are in AYNC (one side) mode now. */

        /* one side async means we won't see a SYN/ACK, so we can
         * only check the SYN. */
        if (!(SEQ_EQ(TCP_GET_SEQ(p), ssn->client.next_seq))) {
            StreamTcpSetEvent(p, STREAM_3WHS_ASYNC_WRONG_SEQ);

            SCLogDebug("ssn %p: SEQ mismatch, packet SEQ %" PRIu32 " != "
                    "%" PRIu32 " from stream",ssn, TCP_GET_SEQ(p),
                    ssn->client.next_seq);
            return -1;
        }

        ssn->flags |= STREAMTCP_FLAG_ASYNC;
        StreamTcpPacketSetState(p, ssn, TCP_ESTABLISHED);
        SCLogDebug("ssn %p: =~ ssn state is now TCP_ESTABLISHED", ssn);

        ssn->client.window = TCP_GET_WINDOW(p);
        ssn->client.last_ack = TCP_GET_SEQ(p);
        ssn->client.next_win = ssn->client.last_ack + ssn->client.window;

        /* Set the server side parameters */
        ssn->server.isn = TCP_GET_ACK(p) - 1;
        STREAMTCP_SET_RA_BASE_SEQ(&ssn->server, ssn->server.isn);
        ssn->server.next_seq = ssn->server.isn + 1;
        ssn->server.last_ack = ssn->server.next_seq;
        ssn->server.next_win = ssn->server.last_ack;

        SCLogDebug("ssn %p: synsent => Asynchronous stream, packet SEQ"
                " %" PRIu32 ", payload size %" PRIu32 " (%" PRIu32 "), "
                "ssn->client.next_seq %" PRIu32 ""
                ,ssn, TCP_GET_SEQ(p), p->payload_len, TCP_GET_SEQ(p)
                + p->payload_len, ssn->client.next_seq);

        /* if SYN had wscale, assume it to be supported. Otherwise
         * we know it not to be supported. */
        if (ssn->flags & STREAMTCP_FLAG_SERVER_WSCALE) {
            ssn->client.wscale = TCP_WSCALE_MAX;
        }

        /* Set the timestamp values used to validate the timestamp of
         * received packets.*/
        if (TCP_HAS_TS(p) &&
                (ssn->client.flags & STREAMTCP_STREAM_FLAG_TIMESTAMP))
        {
            ssn->flags |= STREAMTCP_FLAG_TIMESTAMP;
            ssn->client.flags &= ~STREAMTCP_STREAM_FLAG_TIMESTAMP;
            ssn->client.last_pkt_ts = p->ts.tv_sec;
        } else {
            ssn->client.last_ts = 0;
            ssn->client.flags &= ~STREAMTCP_STREAM_FLAG_ZERO_TIMESTAMP;
        }

        if (ssn->flags & STREAMTCP_FLAG_CLIENT_SACKOK) {
            ssn->flags |= STREAMTCP_FLAG_SACKOK;
        }

        StreamTcpReassembleHandleSegment(tv, stt->ra_ctx, ssn,
                &ssn->client, p, pq);

    } else {
        SCLogDebug("ssn %p: default case", ssn);
    }

    return 0;
}

/**
 *  \brief  Function to handle the TCP_SYN_RECV state. The function handles
 *          SYN, SYN/ACK, ACK, FIN, RST packets and correspondingly changes
 *          the connection state.
 *
 *  \param  tv      Thread Variable containig  input/output queue, cpu affinity
 *  \param  p       Packet which has to be handled in this TCP state.
 *  \param  stt     Strean Thread module registered to handle the stream handling
 *
 *  \retval  0 ok
 *  \retval -1 error
 */

static int StreamTcpPacketStateSynRecv(ThreadVars *tv, Packet *p,
                        StreamTcpThread *stt, TcpSession *ssn, PacketQueue *pq)
{
    if (ssn == NULL)
        return -1;

    if (p->tcph->th_flags & TH_RST) {
        if (!StreamTcpValidateRst(ssn, p))
            return -1;

        uint8_t reset = TRUE;
        /* After receiveing the RST in SYN_RECV state and if detection
           evasion flags has been set, then the following operating
           systems will not closed the connection. As they consider the
           packet as stray packet and not belonging to the current
           session, for more information check
           http://www.packetstan.com/2010/06/recently-ive-been-on-campaign-to-make.html */
        if (ssn->flags & STREAMTCP_FLAG_DETECTION_EVASION_ATTEMPT) {
            if (PKT_IS_TOSERVER(p)) {
                if ((ssn->server.os_policy == OS_POLICY_LINUX) ||
                        (ssn->server.os_policy == OS_POLICY_OLD_LINUX) ||
                        (ssn->server.os_policy == OS_POLICY_SOLARIS))
                {
                    reset = FALSE;
                    SCLogDebug("Detection evasion has been attempted, so"
                            " not resetting the connection !!");
                }
            } else {
                if ((ssn->client.os_policy == OS_POLICY_LINUX) ||
                        (ssn->client.os_policy == OS_POLICY_OLD_LINUX) ||
                        (ssn->client.os_policy == OS_POLICY_SOLARIS))
                {
                    reset = FALSE;
                    SCLogDebug("Detection evasion has been attempted, so"
                            " not resetting the connection !!");
                }
            }
        }

        if (reset == TRUE) {
            StreamTcpPacketSetState(p, ssn, TCP_CLOSED);
            SCLogDebug("ssn %p: Reset received and state changed to "
                    "TCP_CLOSED", ssn);

            if (ssn->flags & STREAMTCP_FLAG_TIMESTAMP) {
                StreamTcpHandleTimestamp(ssn, p);
            }
        }

    } else if (p->tcph->th_flags & TH_FIN) {
        /* FIN is handled in the same way as in TCP_ESTABLISHED case */;
        if (ssn->flags & STREAMTCP_FLAG_TIMESTAMP) {
            if (!StreamTcpValidateTimestamp(ssn, p))
                return -1;
        }

        if ((StreamTcpHandleFin(tv, stt, ssn, p, pq)) == -1)
            return -1;

    /* SYN/ACK */
    } else if ((p->tcph->th_flags & (TH_SYN|TH_ACK)) == (TH_SYN|TH_ACK)) {
        SCLogDebug("ssn %p: SYN/ACK packet on state SYN_RECV. resent", ssn);

        if (PKT_IS_TOSERVER(p)) {
            SCLogDebug("ssn %p: SYN/ACK-pkt to server in SYN_RECV state", ssn);

            StreamTcpSetEvent(p, STREAM_3WHS_SYNACK_TOSERVER_ON_SYN_RECV);
            return -1;
        }

        /* Check if the SYN/ACK packets ACK matches the earlier
         * received SYN/ACK packet. */
        if (!(SEQ_EQ(TCP_GET_ACK(p), ssn->client.last_ack))) {
            SCLogDebug("ssn %p: ACK mismatch, packet ACK %" PRIu32 " != "
                    "%" PRIu32 " from stream", ssn, TCP_GET_ACK(p),
                    ssn->client.isn + 1);

            StreamTcpSetEvent(p, STREAM_3WHS_SYNACK_RESEND_WITH_DIFFERENT_ACK);
            return -1;
        }

        /* Check if the SYN/ACK packet SEQ the earlier
         * received SYN/ACK packet, server resend with different ISN. */
        if (!(SEQ_EQ(TCP_GET_SEQ(p), ssn->server.isn))) {
            SCLogDebug("ssn %p: SEQ mismatch, packet SEQ %" PRIu32 " != "
                    "%" PRIu32 " from stream", ssn, TCP_GET_SEQ(p),
                    ssn->client.isn);

            if (StreamTcp3whsQueueSynAck(ssn, p) == -1)
                return -1;
            SCLogDebug("ssn %p: queued different SYN/ACK", ssn);
        }

    } else if (p->tcph->th_flags & TH_SYN) {
        SCLogDebug("ssn %p: SYN packet on state SYN_RECV... resent", ssn);

        if (PKT_IS_TOCLIENT(p)) {
            SCLogDebug("ssn %p: SYN-pkt to client in SYN_RECV state", ssn);

            StreamTcpSetEvent(p, STREAM_3WHS_SYN_TOCLIENT_ON_SYN_RECV);
            return -1;
        }

        if (!(SEQ_EQ(TCP_GET_SEQ(p), ssn->client.isn))) {
            SCLogDebug("ssn %p: SYN with different SEQ on SYN_RECV state", ssn);

            StreamTcpSetEvent(p, STREAM_3WHS_SYN_RESEND_DIFF_SEQ_ON_SYN_RECV);
            return -1;
        }

    } else if (p->tcph->th_flags & TH_ACK) {
        if (ssn->queue_len) {
            SCLogDebug("ssn %p: checking ACK against queued SYN/ACKs", ssn);
            TcpStateQueue *q = StreamTcp3whsFindSynAckByAck(ssn, p);
            if (q != NULL) {
                SCLogDebug("ssn %p: here we update state against queued SYN/ACK", ssn);
                StreamTcp3whsSynAckUpdate(ssn, p, /* using queue to update state */q);
            } else {
                SCLogDebug("ssn %p: none found, now checking ACK against original SYN/ACK (state)", ssn);
            }
        }


        /* If the timestamp option is enabled for both the streams, then
         * validate the received packet timestamp value against the
         * stream->last_ts. If the timestamp is valid then process the
         * packet normally otherwise the drop the packet (RFC 1323)*/
        if (ssn->flags & STREAMTCP_FLAG_TIMESTAMP) {
            if (!(StreamTcpValidateTimestamp(ssn, p))) {
                return -1;
            }
        }

        if ((ssn->flags & STREAMTCP_FLAG_4WHS) && PKT_IS_TOCLIENT(p)) {
            SCLogDebug("ssn %p: ACK received on 4WHS session",ssn);

            if (!(SEQ_EQ(TCP_GET_SEQ(p), ssn->server.next_seq))) {
                SCLogDebug("ssn %p: 4WHS wrong seq nr on packet", ssn);
                StreamTcpSetEvent(p, STREAM_4WHS_WRONG_SEQ);
                return -1;
            }

            if (StreamTcpValidateAck(ssn, &ssn->client, p) == -1) {
                SCLogDebug("ssn %p: 4WHS invalid ack nr on packet", ssn);
                StreamTcpSetEvent(p, STREAM_4WHS_INVALID_ACK);
                return -1;
            }

            SCLogDebug("4WHS normal pkt");
            SCLogDebug("ssn %p: pkt (%" PRIu32 ") is to client: SEQ "
                    "%" PRIu32 ", ACK %" PRIu32 "", ssn, p->payload_len,
                    TCP_GET_SEQ(p), TCP_GET_ACK(p));

            if (ssn->flags & STREAMTCP_FLAG_TIMESTAMP) {
                StreamTcpHandleTimestamp(ssn, p);
            }

            StreamTcpUpdateLastAck(ssn, &ssn->client, TCP_GET_ACK(p));
            ssn->server.next_seq += p->payload_len;
            ssn->client.window = TCP_GET_WINDOW(p) << ssn->client.wscale;
            ssn->client.next_win = ssn->client.last_ack + ssn->client.window;

            StreamTcpPacketSetState(p, ssn, TCP_ESTABLISHED);
            SCLogDebug("ssn %p: =~ ssn state is now TCP_ESTABLISHED", ssn);

            StreamTcpReassembleHandleSegment(tv, stt->ra_ctx, ssn,
                    &ssn->server, p, pq);

            SCLogDebug("ssn %p: ssn->client.next_win %" PRIu32 ", "
                    "ssn->client.last_ack %"PRIu32"", ssn,
                    ssn->client.next_win, ssn->client.last_ack);
            return 0;
        }

        /* Check if the ACK received is in right direction. But when we have
         * picked up a mid stream session after missing the initial SYN pkt,
         * in this case the ACK packet can arrive from either client (normal
         * case) or from server itself (asynchronous streams). Therefore
         *  the check has been avoided in this case */
        if (PKT_IS_TOCLIENT(p)) {
            /* special case, handle 4WHS, so SYN/ACK in the opposite
             * direction */
            if (ssn->flags & STREAMTCP_FLAG_MIDSTREAM_SYNACK) {
                SCLogDebug("ssn %p: ACK received on midstream SYN/ACK "
                        "pickup session",ssn);
                /* fall through */
            } else {
                SCLogDebug("ssn %p: ACK received in the wrong direction",
                        ssn);

                StreamTcpSetEvent(p, STREAM_3WHS_ACK_IN_WRONG_DIR);
                return -1;
            }
        }

        SCLogDebug("ssn %p: pkt (%" PRIu32 ") is to server: SEQ %" PRIu32 ""
                ", ACK %" PRIu32 "", ssn, p->payload_len, TCP_GET_SEQ(p),
                TCP_GET_ACK(p));

        /* Check both seq and ack number before accepting the packet and
           changing to ESTABLISHED state */
        if ((SEQ_EQ(TCP_GET_SEQ(p), ssn->client.next_seq)) &&
                SEQ_EQ(TCP_GET_ACK(p), ssn->server.next_seq)) {
            SCLogDebug("normal pkt");

            /* process the packet normal, No Async streams :) */

            if (ssn->flags & STREAMTCP_FLAG_TIMESTAMP) {
                StreamTcpHandleTimestamp(ssn, p);
            }

            StreamTcpUpdateLastAck(ssn, &ssn->server, TCP_GET_ACK(p));

            ssn->client.next_seq += p->payload_len;
            ssn->server.window = TCP_GET_WINDOW(p) << ssn->server.wscale;

            ssn->server.next_win = ssn->server.last_ack + ssn->server.window;

            if (ssn->flags & STREAMTCP_FLAG_MIDSTREAM) {
                ssn->client.window = TCP_GET_WINDOW(p) << ssn->client.wscale;
                ssn->client.next_win = ssn->client.last_ack + ssn->client.window;
                ssn->server.next_win = ssn->server.last_ack +
                    ssn->server.window;
                if (!(ssn->flags & STREAMTCP_FLAG_MIDSTREAM_SYNACK)) {
                    /* window scaling for midstream pickups, we can't do much
                     * other than assume that it's set to the max value: 14 */
                    ssn->server.wscale = TCP_WSCALE_MAX;
                    ssn->client.wscale = TCP_WSCALE_MAX;
                    ssn->flags |= STREAMTCP_FLAG_SACKOK;
                }
            }

            StreamTcpPacketSetState(p, ssn, TCP_ESTABLISHED);
            SCLogDebug("ssn %p: =~ ssn state is now TCP_ESTABLISHED", ssn);

            StreamTcpReassembleHandleSegment(tv, stt->ra_ctx, ssn,
                    &ssn->client, p, pq);

            /* If asynchronous stream handling is allowed then set the session,
               if packet's seq number is equal the expected seq no.*/
        } else if (stream_config.async_oneside == TRUE &&
                (SEQ_EQ(TCP_GET_SEQ(p), ssn->server.next_seq)))
        {
            /*set the ASYNC flag used to indicate the session as async stream
              and helps in relaxing the windows checks.*/
            ssn->flags |= STREAMTCP_FLAG_ASYNC;
            ssn->server.next_seq += p->payload_len;
            ssn->server.last_ack = TCP_GET_SEQ(p);

            ssn->client.window = TCP_GET_WINDOW(p) << ssn->client.wscale;
            ssn->client.last_ack = TCP_GET_ACK(p);

            if (ssn->flags & STREAMTCP_FLAG_TIMESTAMP) {
                StreamTcpHandleTimestamp(ssn, p);
            }

            if (ssn->flags & STREAMTCP_FLAG_MIDSTREAM) {
                ssn->server.window = TCP_GET_WINDOW(p);
                ssn->client.next_win = ssn->server.last_ack +
                    ssn->server.window;
                /* window scaling for midstream pickups, we can't do much
                 * other than assume that it's set to the max value: 14 */
                ssn->server.wscale = TCP_WSCALE_MAX;
                ssn->client.wscale = TCP_WSCALE_MAX;
                ssn->flags |= STREAMTCP_FLAG_SACKOK;
            }

            SCLogDebug("ssn %p: synrecv => Asynchronous stream, packet SEQ"
                    " %" PRIu32 ", payload size %" PRIu32 " (%" PRIu32 "), "
                    "ssn->server.next_seq %" PRIu32 "\n"
                    , ssn, TCP_GET_SEQ(p), p->payload_len, TCP_GET_SEQ(p)
                    + p->payload_len, ssn->server.next_seq);

            StreamTcpPacketSetState(p, ssn, TCP_ESTABLISHED);
            SCLogDebug("ssn %p: =~ ssn state is now TCP_ESTABLISHED", ssn);

            StreamTcpReassembleHandleSegment(tv, stt->ra_ctx, ssn,
                    &ssn->server, p, pq);
            /* Upon receiving the packet with correct seq number and wrong
               ACK number, it causes the other end to send RST. But some target
               system (Linux & solaris) does not RST the connection, so it is
               likely to avoid the detection */
        } else if (SEQ_EQ(TCP_GET_SEQ(p), ssn->client.next_seq)){
            ssn->flags |= STREAMTCP_FLAG_DETECTION_EVASION_ATTEMPT;
            SCLogDebug("ssn %p: wrong ack nr on packet, possible evasion!!",
                    ssn);

            StreamTcpSetEvent(p, STREAM_3WHS_RIGHT_SEQ_WRONG_ACK_EVASION);
            return -1;

        /* if we get a packet with a proper ack, but a seq that is beyond
         * next_seq but in-window, we probably missed some packets */
        } else if (SEQ_GT(TCP_GET_SEQ(p), ssn->client.next_seq) &&
                   SEQ_LEQ(TCP_GET_SEQ(p),ssn->client.next_win) &&
                   SEQ_EQ(TCP_GET_ACK(p), ssn->server.next_seq))
        {
            SCLogDebug("ssn %p: ACK for missing data", ssn);

            if (ssn->flags & STREAMTCP_FLAG_TIMESTAMP) {
                StreamTcpHandleTimestamp(ssn, p);
            }

            StreamTcpUpdateLastAck(ssn, &ssn->server, TCP_GET_ACK(p));

            ssn->client.next_seq = TCP_GET_SEQ(p) + p->payload_len;
            SCLogDebug("ssn %p: ACK for missing data: ssn->client.next_seq %u", ssn, ssn->client.next_seq);
            ssn->server.window = TCP_GET_WINDOW(p) << ssn->server.wscale;

            ssn->server.next_win = ssn->server.last_ack + ssn->server.window;

            if (ssn->flags & STREAMTCP_FLAG_MIDSTREAM) {
                ssn->client.window = TCP_GET_WINDOW(p);
                ssn->server.next_win = ssn->server.last_ack +
                    ssn->server.window;
                /* window scaling for midstream pickups, we can't do much
                 * other than assume that it's set to the max value: 14 */
                ssn->server.wscale = TCP_WSCALE_MAX;
                ssn->client.wscale = TCP_WSCALE_MAX;
                ssn->flags |= STREAMTCP_FLAG_SACKOK;
            }

            StreamTcpPacketSetState(p, ssn, TCP_ESTABLISHED);
            SCLogDebug("ssn %p: =~ ssn state is now TCP_ESTABLISHED", ssn);

            StreamTcpReassembleHandleSegment(tv, stt->ra_ctx, ssn,
                    &ssn->client, p, pq);
        } else {
            SCLogDebug("ssn %p: wrong seq nr on packet", ssn);

            StreamTcpSetEvent(p, STREAM_3WHS_WRONG_SEQ_WRONG_ACK);
            return -1;
        }

        SCLogDebug("ssn %p: ssn->server.next_win %" PRIu32 ", "
                "ssn->server.last_ack %"PRIu32"", ssn,
                ssn->server.next_win, ssn->server.last_ack);
    } else {
        SCLogDebug("ssn %p: default case", ssn);
    }

    return 0;
}

/**
 *  \brief  Function to handle the TCP_ESTABLISHED state packets, which are
 *          sent by the client to server. The function handles
 *          ACK packets and call StreamTcpReassembleHandleSegment() to handle
 *          the reassembly.
 *
 *  Timestamp has already been checked at this point.
 *
 *  \param  tv      Thread Variable containig  input/output queue, cpu affinity etc.
 *  \param  ssn     Pointer to the current TCP session
 *  \param  p       Packet which has to be handled in this TCP state.
 *  \param  stt     Strean Thread module registered to handle the stream handling
 */
static int HandleEstablishedPacketToServer(ThreadVars *tv, TcpSession *ssn, Packet *p,
                        StreamTcpThread *stt, PacketQueue *pq)
{
    SCLogDebug("ssn %p: =+ pkt (%" PRIu32 ") is to server: SEQ %" PRIu32 ","
               "ACK %" PRIu32 ", WIN %"PRIu16"", ssn, p->payload_len,
                TCP_GET_SEQ(p), TCP_GET_ACK(p), TCP_GET_WINDOW(p));

    if (StreamTcpValidateAck(ssn, &(ssn->server), p) == -1) {
        SCLogDebug("ssn %p: rejecting because of invalid ack value", ssn);
        StreamTcpSetEvent(p, STREAM_EST_INVALID_ACK);
        return -1;
    }

    /* check for Keep Alive */
    if ((p->payload_len == 0 || p->payload_len == 1) &&
            (TCP_GET_SEQ(p) == (ssn->client.next_seq - 1))) {
        SCLogDebug("ssn %p: pkt is keep alive", ssn);

    /* normal pkt */
    } else if (!(SEQ_GEQ((TCP_GET_SEQ(p)+p->payload_len), ssn->client.last_ack))) {
        if (ssn->flags & STREAMTCP_FLAG_ASYNC) {
            SCLogDebug("ssn %p: server => Asynchrouns stream, packet SEQ"
                    " %" PRIu32 ", payload size %" PRIu32 " (%" PRIu32 "),"
                    " ssn->client.last_ack %" PRIu32 ", ssn->client.next_win"
                    "%" PRIu32"(%"PRIu32")", ssn, TCP_GET_SEQ(p),
                    p->payload_len, TCP_GET_SEQ(p) + p->payload_len,
                    ssn->client.last_ack, ssn->client.next_win,
                    TCP_GET_SEQ(p) + p->payload_len - ssn->client.next_win);

            /* update the last_ack to current seq number as the session is
             * async and other stream is not updating it anymore :( */
            StreamTcpUpdateLastAck(ssn, &ssn->client, TCP_GET_SEQ(p));

        } else if (SEQ_EQ(ssn->client.next_seq, TCP_GET_SEQ(p)) &&
                (stream_config.async_oneside == TRUE) &&
                (ssn->flags & STREAMTCP_FLAG_MIDSTREAM)) {
            SCLogDebug("ssn %p: server => Asynchronous stream, packet SEQ."
                    " %" PRIu32 ", payload size %" PRIu32 " (%" PRIu32 "), "
                    "ssn->client.last_ack %" PRIu32 ", ssn->client.next_win "
                    "%" PRIu32 "(%"PRIu32")", ssn, TCP_GET_SEQ(p),
                    p->payload_len, TCP_GET_SEQ(p) + p->payload_len,
                    ssn->client.last_ack, ssn->client.next_win,
                    TCP_GET_SEQ(p) + p->payload_len - ssn->client.next_win);

            /* it seems we missed SYN and SYN/ACK packets of this session.
             * Update the last_ack to current seq number as the session
             * is async and other stream is not updating it anymore :( */
            StreamTcpUpdateLastAck(ssn, &ssn->client, TCP_GET_SEQ(p));
            ssn->flags |= STREAMTCP_FLAG_ASYNC;

        } else if (SEQ_EQ(ssn->client.last_ack, (ssn->client.isn + 1)) &&
                (stream_config.async_oneside == TRUE) &&
                (ssn->flags & STREAMTCP_FLAG_MIDSTREAM)) {
            SCLogDebug("ssn %p: server => Asynchronous stream, packet SEQ"
                    " %" PRIu32 ", payload size %" PRIu32 " (%" PRIu32 "), "
                    "ssn->client.last_ack %" PRIu32 ", ssn->client.next_win "
                    "%" PRIu32 "(%"PRIu32")", ssn, TCP_GET_SEQ(p),
                    p->payload_len, TCP_GET_SEQ(p) + p->payload_len,
                    ssn->client.last_ack, ssn->client.next_win,
                    TCP_GET_SEQ(p) + p->payload_len - ssn->client.next_win);

            /* it seems we missed SYN and SYN/ACK packets of this session.
             * Update the last_ack to current seq number as the session
             * is async and other stream is not updating it anymore :(*/
            StreamTcpUpdateLastAck(ssn, &ssn->client, TCP_GET_SEQ(p));
            ssn->flags |= STREAMTCP_FLAG_ASYNC;

        /* if last ack is beyond next_seq, we have accepted ack's for missing data.
         * In this case we do accept the data before last_ack if it is (partly)
         * beyond next seq */
        } else if (SEQ_GT(ssn->client.last_ack, ssn->client.next_seq) &&
                   SEQ_GT((TCP_GET_SEQ(p)+p->payload_len),ssn->client.next_seq))
        {
            SCLogDebug("ssn %p: PKT SEQ %"PRIu32" payload_len %"PRIu16
                    " before last_ack %"PRIu32", after next_seq %"PRIu32":"
                    " acked data that we haven't seen before",
                    ssn, TCP_GET_SEQ(p), p->payload_len, ssn->client.last_ack, ssn->client.next_seq);
            if (SEQ_EQ(TCP_GET_SEQ(p),ssn->client.next_seq)) {
                ssn->client.next_seq += p->payload_len;
            }
        } else {
            SCLogDebug("ssn %p: server => SEQ before last_ack, packet SEQ"
                    " %" PRIu32 ", payload size %" PRIu32 " (%" PRIu32 "), "
                    "ssn->client.last_ack %" PRIu32 ", ssn->client.next_win "
                    "%" PRIu32 "(%"PRIu32")", ssn, TCP_GET_SEQ(p),
                    p->payload_len, TCP_GET_SEQ(p) + p->payload_len,
                    ssn->client.last_ack, ssn->client.next_win,
                    TCP_GET_SEQ(p) + p->payload_len - ssn->client.next_win);

            SCLogDebug("ssn %p: rejecting because pkt before last_ack", ssn);
            StreamTcpSetEvent(p, STREAM_EST_PKT_BEFORE_LAST_ACK);
            return -1;
        }
    }

    int zerowindowprobe = 0;
    /* zero window probe */
    if (p->payload_len == 1 && TCP_GET_SEQ(p) == ssn->client.next_seq && ssn->client.window == 0) {
        SCLogDebug("ssn %p: zero window probe", ssn);
        zerowindowprobe = 1;

    /* expected packet */
    } else if (SEQ_EQ(ssn->client.next_seq, TCP_GET_SEQ(p))) {
        ssn->client.next_seq += p->payload_len;
        SCLogDebug("ssn %p: ssn->client.next_seq %" PRIu32 "",
                    ssn, ssn->client.next_seq);
    /* not completely as expected, but valid */
    } else if (SEQ_LT(TCP_GET_SEQ(p),ssn->client.next_seq) &&
               SEQ_GT((TCP_GET_SEQ(p)+p->payload_len), ssn->client.next_seq))
    {
        ssn->client.next_seq = TCP_GET_SEQ(p) + p->payload_len;
        SCLogDebug("ssn %p: ssn->client.next_seq %"PRIu32
                   " (started before next_seq, ended after)",
                   ssn, ssn->client.next_seq);
    /* if next_seq has fallen behind last_ack, we got some catching up to do */
    } else if (SEQ_LT(ssn->client.next_seq, ssn->client.last_ack)) {
        ssn->client.next_seq = TCP_GET_SEQ(p) + p->payload_len;
        SCLogDebug("ssn %p: ssn->client.next_seq %"PRIu32
                   " (next_seq had fallen behind last_ack)",
                   ssn, ssn->client.next_seq);
    } else {
        SCLogDebug("ssn %p: no update to ssn->client.next_seq %"PRIu32
                   " SEQ %u SEQ+ %u last_ack %u",
                   ssn, ssn->client.next_seq,
                   TCP_GET_SEQ(p), TCP_GET_SEQ(p)+p->payload_len, ssn->client.last_ack);
    }

    /* in window check */
    if (zerowindowprobe) {
        SCLogDebug("ssn %p: zero window probe, skipping oow check", ssn);
    } else if (SEQ_LEQ(TCP_GET_SEQ(p) + p->payload_len, ssn->client.next_win) ||
            (ssn->flags & STREAMTCP_FLAG_MIDSTREAM) ||
            (ssn->flags & STREAMTCP_FLAG_ASYNC))
    {
        SCLogDebug("ssn %p: seq %"PRIu32" in window, ssn->client.next_win "
                   "%" PRIu32 "", ssn, TCP_GET_SEQ(p), ssn->client.next_win);

        ssn->server.window = TCP_GET_WINDOW(p) << ssn->server.wscale;
        SCLogDebug("ssn %p: ssn->server.window %"PRIu32"", ssn,
                    ssn->server.window);

        /* Check if the ACK value is sane and inside the window limit */
        StreamTcpUpdateLastAck(ssn, &ssn->server, TCP_GET_ACK(p));
        SCLogDebug("ack %u last_ack %u next_seq %u", TCP_GET_ACK(p), ssn->server.last_ack, ssn->server.next_seq);

        if (ssn->flags & STREAMTCP_FLAG_TIMESTAMP) {
            StreamTcpHandleTimestamp(ssn, p);
        }

        StreamTcpSackUpdatePacket(&ssn->server, p);

        /* update next_win */
        StreamTcpUpdateNextWin(ssn, &ssn->server, (ssn->server.last_ack + ssn->server.window));

        /* handle data (if any) */
        StreamTcpReassembleHandleSegment(tv, stt->ra_ctx, ssn, &ssn->client, p, pq);
    } else {
        SCLogDebug("ssn %p: toserver => SEQ out of window, packet SEQ "
                "%" PRIu32 ", payload size %" PRIu32 " (%" PRIu32 "),"
                "ssn->client.last_ack %" PRIu32 ", ssn->client.next_win "
                "%" PRIu32 "(%"PRIu32")", ssn, TCP_GET_SEQ(p),
                p->payload_len, TCP_GET_SEQ(p) + p->payload_len,
                ssn->client.last_ack, ssn->client.next_win,
                (TCP_GET_SEQ(p) + p->payload_len) - ssn->client.next_win);
        SCLogDebug("ssn %p: window %u sacked %u", ssn, ssn->client.window,
                StreamTcpSackedSize(&ssn->client));
        StreamTcpSetEvent(p, STREAM_EST_PACKET_OUT_OF_WINDOW);
        return -1;
    }
    return 0;
}

/**
 *  \brief  Function to handle the TCP_ESTABLISHED state packets, which are
 *          sent by the server to client. The function handles
 *          ACK packets and call StreamTcpReassembleHandleSegment() to handle
 *          the reassembly
 *
 *  Timestamp has already been checked at this point.
 *
 *  \param  tv      Thread Variable containig  input/output queue, cpu affinity etc.
 *  \param  ssn     Pointer to the current TCP session
 *  \param  p       Packet which has to be handled in this TCP state.
 *  \param  stt     Strean Thread module registered to handle the stream handling
 */
static int HandleEstablishedPacketToClient(ThreadVars *tv, TcpSession *ssn, Packet *p,
                        StreamTcpThread *stt, PacketQueue *pq)
{
    SCLogDebug("ssn %p: =+ pkt (%" PRIu32 ") is to client: SEQ %" PRIu32 ","
               " ACK %" PRIu32 ", WIN %"PRIu16"", ssn, p->payload_len,
                TCP_GET_SEQ(p), TCP_GET_ACK(p), TCP_GET_WINDOW(p));

    if (StreamTcpValidateAck(ssn, &ssn->client, p) == -1) {
        SCLogDebug("ssn %p: rejecting because of invalid ack value", ssn);
        StreamTcpSetEvent(p, STREAM_EST_INVALID_ACK);
        return -1;
    }

    /* To get the server window value from the servers packet, when connection
       is picked up as midstream */
    if ((ssn->flags & STREAMTCP_FLAG_MIDSTREAM) &&
            (ssn->flags & STREAMTCP_FLAG_MIDSTREAM_ESTABLISHED))
    {
        ssn->server.window = TCP_GET_WINDOW(p);
        ssn->server.next_win = ssn->server.last_ack + ssn->server.window;
        ssn->flags &= ~STREAMTCP_FLAG_MIDSTREAM_ESTABLISHED;
        SCLogDebug("ssn %p: adjusted midstream ssn->server.next_win to "
                "%" PRIu32 "", ssn, ssn->server.next_win);
    }

    /* check for Keep Alive */
    if ((p->payload_len == 0 || p->payload_len == 1) &&
            (TCP_GET_SEQ(p) == (ssn->server.next_seq - 1))) {
        SCLogDebug("ssn %p: pkt is keep alive", ssn);

    /* normal pkt */
    } else if (!(SEQ_GEQ((TCP_GET_SEQ(p)+p->payload_len), ssn->server.last_ack))) {
        if (ssn->flags & STREAMTCP_FLAG_ASYNC) {

            SCLogDebug("ssn %p: client => Asynchrouns stream, packet SEQ"
                    " %" PRIu32 ", payload size %" PRIu32 " (%" PRIu32 "),"
                    " ssn->client.last_ack %" PRIu32 ", ssn->client.next_win"
                    " %"PRIu32"(%"PRIu32")", ssn, TCP_GET_SEQ(p),
                    p->payload_len, TCP_GET_SEQ(p) + p->payload_len,
                    ssn->server.last_ack, ssn->server.next_win,
                    TCP_GET_SEQ(p) + p->payload_len - ssn->server.next_win);

            ssn->server.last_ack = TCP_GET_SEQ(p);

        /* if last ack is beyond next_seq, we have accepted ack's for missing data.
         * In this case we do accept the data before last_ack if it is (partly)
         * beyond next seq */
        } else if (SEQ_GT(ssn->server.last_ack, ssn->server.next_seq) &&
                   SEQ_GT((TCP_GET_SEQ(p)+p->payload_len),ssn->server.next_seq))
        {
            SCLogDebug("ssn %p: PKT SEQ %"PRIu32" payload_len %"PRIu16
                    " before last_ack %"PRIu32", after next_seq %"PRIu32":"
                    " acked data that we haven't seen before",
                    ssn, TCP_GET_SEQ(p), p->payload_len, ssn->server.last_ack, ssn->server.next_seq);
            if (SEQ_EQ(TCP_GET_SEQ(p),ssn->server.next_seq)) {
                ssn->server.next_seq += p->payload_len;
            }
        } else {
            SCLogDebug("ssn %p: PKT SEQ %"PRIu32" payload_len %"PRIu16
                    " before last_ack %"PRIu32". next_seq %"PRIu32,
                    ssn, TCP_GET_SEQ(p), p->payload_len, ssn->server.last_ack, ssn->server.next_seq);
            StreamTcpSetEvent(p, STREAM_EST_PKT_BEFORE_LAST_ACK);
            return -1;
        }
    }

    int zerowindowprobe = 0;
    /* zero window probe */
    if (p->payload_len == 1 && TCP_GET_SEQ(p) == ssn->server.next_seq && ssn->server.window == 0) {
        SCLogDebug("ssn %p: zero window probe", ssn);
        zerowindowprobe = 1;

    /* expected packet */
    } else if (SEQ_EQ(ssn->server.next_seq, TCP_GET_SEQ(p))) {
        ssn->server.next_seq += p->payload_len;
        SCLogDebug("ssn %p: ssn->server.next_seq %" PRIu32 "",
                ssn, ssn->server.next_seq);
    /* not completely as expected, but valid */
    } else if (SEQ_LT(TCP_GET_SEQ(p),ssn->server.next_seq) &&
               SEQ_GT((TCP_GET_SEQ(p)+p->payload_len), ssn->server.next_seq))
    {
        ssn->server.next_seq = TCP_GET_SEQ(p) + p->payload_len;
        SCLogDebug("ssn %p: ssn->server.next_seq %" PRIu32
                   " (started before next_seq, ended after)",
                   ssn, ssn->server.next_seq);
    /* if next_seq has fallen behind last_ack, we got some catching up to do */
    } else if (SEQ_LT(ssn->server.next_seq, ssn->server.last_ack)) {
        ssn->server.next_seq = TCP_GET_SEQ(p) + p->payload_len;
        SCLogDebug("ssn %p: ssn->server.next_seq %"PRIu32
                   " (next_seq had fallen behind last_ack)",
                   ssn, ssn->server.next_seq);
    } else {
        SCLogDebug("ssn %p: no update to ssn->server.next_seq %"PRIu32
                   " SEQ %u SEQ+ %u last_ack %u",
                   ssn, ssn->server.next_seq,
                   TCP_GET_SEQ(p), TCP_GET_SEQ(p)+p->payload_len, ssn->server.last_ack);
    }

    if (zerowindowprobe) {
        SCLogDebug("ssn %p: zero window probe, skipping oow check", ssn);
    } else if (SEQ_LEQ(TCP_GET_SEQ(p) + p->payload_len, ssn->server.next_win) ||
            (ssn->flags & STREAMTCP_FLAG_MIDSTREAM) ||
            (ssn->flags & STREAMTCP_FLAG_ASYNC)) {
        SCLogDebug("ssn %p: seq %"PRIu32" in window, ssn->server.next_win "
                "%" PRIu32 "", ssn, TCP_GET_SEQ(p), ssn->server.next_win);
        ssn->client.window = TCP_GET_WINDOW(p) << ssn->client.wscale;
        SCLogDebug("ssn %p: ssn->client.window %"PRIu32"", ssn,
                    ssn->client.window);

        StreamTcpUpdateLastAck(ssn, &ssn->client, TCP_GET_ACK(p));

        if (ssn->flags & STREAMTCP_FLAG_TIMESTAMP) {
            StreamTcpHandleTimestamp(ssn, p);
        }

        StreamTcpSackUpdatePacket(&ssn->client, p);

        StreamTcpUpdateNextWin(ssn, &ssn->client, (ssn->client.last_ack + ssn->client.window));

        StreamTcpReassembleHandleSegment(tv, stt->ra_ctx, ssn, &ssn->server, p, pq);
    } else {
        SCLogDebug("ssn %p: client => SEQ out of window, packet SEQ"
                   "%" PRIu32 ", payload size %" PRIu32 " (%" PRIu32 "),"
                   " ssn->server.last_ack %" PRIu32 ", ssn->server.next_win "
                   "%" PRIu32 "(%"PRIu32")", ssn, TCP_GET_SEQ(p),
                   p->payload_len, TCP_GET_SEQ(p) + p->payload_len,
                   ssn->server.last_ack, ssn->server.next_win,
                   TCP_GET_SEQ(p) + p->payload_len - ssn->server.next_win);
        StreamTcpSetEvent(p, STREAM_EST_PACKET_OUT_OF_WINDOW);
        return -1;
    }
    return 0;
}

/**
 *  \internal
 *
 *  \brief Find the highest sequence number needed to consider all segments as ACK'd
 *
 *  Used to treat all segments as ACK'd upon receiving a valid RST.
 *
 *  \param stream stream to inspect the segments from
 *  \param seq sequence number to check against
 *
 *  \retval ack highest ack we need to set
 */
static inline uint32_t StreamTcpResetGetMaxAck(TcpStream *stream, uint32_t seq)
{
    uint32_t ack = seq;

    if (stream->seg_list_tail != NULL) {
        if (SEQ_GT((stream->seg_list_tail->seq + stream->seg_list_tail->payload_len), ack))
        {
            ack = stream->seg_list_tail->seq + stream->seg_list_tail->payload_len;
        }
    }

    SCReturnUInt(ack);
}

/**
 *  \brief  Function to handle the TCP_ESTABLISHED state. The function handles
 *          ACK, FIN, RST packets and correspondingly changes the connection
 *          state. The function handles the data inside packets and call
 *          StreamTcpReassembleHandleSegment(tv, ) to handle the reassembling.
 *
 *  \param  tv      Thread Variable containig  input/output queue, cpu affinity etc.
 *  \param  p       Packet which has to be handled in this TCP state.
 *  \param  stt     Strean Thread module registered to handle the stream handling
 */

static int StreamTcpPacketStateEstablished(ThreadVars *tv, Packet *p,
                        StreamTcpThread *stt, TcpSession *ssn, PacketQueue *pq)
{
    if (ssn == NULL)
        return -1;

    if (p->tcph->th_flags & TH_RST) {
        if (!StreamTcpValidateRst(ssn, p))
            return -1;

        /* force both streams to reassemble, if necessary */
        StreamTcpPseudoPacketCreateStreamEndPacket(tv, stt, p, ssn, pq);

        if (PKT_IS_TOSERVER(p)) {
            StreamTcpPacketSetState(p, ssn, TCP_CLOSED);
            SCLogDebug("ssn %p: Reset received and state changed to "
                    "TCP_CLOSED", ssn);

            ssn->server.next_seq = TCP_GET_ACK(p);
            ssn->client.next_seq = TCP_GET_SEQ(p) + p->payload_len;
            SCLogDebug("ssn %p: ssn->server.next_seq %" PRIu32 "", ssn,
                    ssn->server.next_seq);
            ssn->client.window = TCP_GET_WINDOW(p) << ssn->client.wscale;

            if ((p->tcph->th_flags & TH_ACK) && StreamTcpValidateAck(ssn, &ssn->server, p) == 0)
                StreamTcpUpdateLastAck(ssn, &ssn->server,
                        StreamTcpResetGetMaxAck(&ssn->server, TCP_GET_ACK(p)));

            StreamTcpUpdateLastAck(ssn, &ssn->client,
                    StreamTcpResetGetMaxAck(&ssn->client, TCP_GET_SEQ(p)));

            if (ssn->flags & STREAMTCP_FLAG_TIMESTAMP) {
                StreamTcpHandleTimestamp(ssn, p);
            }

            StreamTcpReassembleHandleSegment(tv, stt->ra_ctx, ssn,
                    &ssn->client, p, pq);
            SCLogDebug("ssn %p: =+ next SEQ %" PRIu32 ", last ACK "
                    "%" PRIu32 "", ssn, ssn->client.next_seq,
                    ssn->server.last_ack);

            /* don't return packets to pools here just yet, the pseudo
             * packet will take care, otherwise the normal session
             * cleanup. */
        } else {
            StreamTcpPacketSetState(p, ssn, TCP_CLOSED);
            SCLogDebug("ssn %p: Reset received and state changed to "
                    "TCP_CLOSED", ssn);

            ssn->server.next_seq = TCP_GET_SEQ(p) + p->payload_len + 1;
            ssn->client.next_seq = TCP_GET_ACK(p);

            SCLogDebug("ssn %p: ssn->server.next_seq %" PRIu32 "", ssn,
                    ssn->server.next_seq);
            ssn->server.window = TCP_GET_WINDOW(p) << ssn->server.wscale;

            if ((p->tcph->th_flags & TH_ACK) && StreamTcpValidateAck(ssn, &ssn->client, p) == 0)
                StreamTcpUpdateLastAck(ssn, &ssn->client,
                        StreamTcpResetGetMaxAck(&ssn->client, TCP_GET_ACK(p)));

            StreamTcpUpdateLastAck(ssn, &ssn->server,
                    StreamTcpResetGetMaxAck(&ssn->server, TCP_GET_SEQ(p)));

            if (ssn->flags & STREAMTCP_FLAG_TIMESTAMP) {
                StreamTcpHandleTimestamp(ssn, p);
            }

            StreamTcpReassembleHandleSegment(tv, stt->ra_ctx, ssn,
                    &ssn->server, p, pq);
            SCLogDebug("ssn %p: =+ next SEQ %" PRIu32 ", last ACK "
                    "%" PRIu32 "", ssn, ssn->server.next_seq,
                    ssn->client.last_ack);

            /* don't return packets to pools here just yet, the pseudo
             * packet will take care, otherwise the normal session
             * cleanup. */
        }

    } else if (p->tcph->th_flags & TH_FIN) {
        if (ssn->flags & STREAMTCP_FLAG_TIMESTAMP) {
            if (!StreamTcpValidateTimestamp(ssn, p))
                return -1;
        }

        SCLogDebug("ssn (%p: FIN received SEQ"
                " %" PRIu32 ", last ACK %" PRIu32 ", next win %"PRIu32","
                " win %" PRIu32 "", ssn, ssn->server.next_seq,
                ssn->client.last_ack, ssn->server.next_win,
                ssn->server.window);

        if ((StreamTcpHandleFin(tv, stt, ssn, p, pq)) == -1)
            return -1;

    /* SYN/ACK */
    } else if ((p->tcph->th_flags & (TH_SYN|TH_ACK)) == (TH_SYN|TH_ACK)) {
        SCLogDebug("ssn %p: SYN/ACK packet on state ESTABLISHED... resent",
                ssn);

        if (PKT_IS_TOSERVER(p)) {
            SCLogDebug("ssn %p: SYN/ACK-pkt to server in ESTABLISHED state", ssn);

            StreamTcpSetEvent(p, STREAM_EST_SYNACK_TOSERVER);
            return -1;
        }

        /* Check if the SYN/ACK packets ACK matches the earlier
         * received SYN/ACK packet. */
        if (!(SEQ_EQ(TCP_GET_ACK(p), ssn->client.last_ack))) {
            SCLogDebug("ssn %p: ACK mismatch, packet ACK %" PRIu32 " != "
                    "%" PRIu32 " from stream", ssn, TCP_GET_ACK(p),
                    ssn->client.isn + 1);

            StreamTcpSetEvent(p, STREAM_EST_SYNACK_RESEND_WITH_DIFFERENT_ACK);
            return -1;
        }

        /* Check if the SYN/ACK packet SEQ the earlier
         * received SYN packet. */
        if (!(SEQ_EQ(TCP_GET_SEQ(p), ssn->server.isn))) {
            SCLogDebug("ssn %p: SEQ mismatch, packet SEQ %" PRIu32 " != "
                    "%" PRIu32 " from stream", ssn, TCP_GET_ACK(p),
                    ssn->client.isn + 1);

            StreamTcpSetEvent(p, STREAM_EST_SYNACK_RESEND_WITH_DIFF_SEQ);
            return -1;
        }

        if (ssn->flags & STREAMTCP_FLAG_3WHS_CONFIRMED) {
            /* a resend of a SYN while we are established already -- fishy */
            StreamTcpSetEvent(p, STREAM_EST_SYNACK_RESEND);
            return -1;
        }

        SCLogDebug("ssn %p: SYN/ACK packet on state ESTABLISHED... resent. "
                "Likely due server not receiving final ACK in 3whs", ssn);

        /* resetting state to TCP_SYN_RECV as we should get another ACK now */
        StreamTcpPacketSetState(p, ssn, TCP_SYN_RECV);
        SCLogDebug("ssn %p: =~ ssn state is now reset to TCP_SYN_RECV", ssn);
        return 0;

    } else if (p->tcph->th_flags & TH_SYN) {
        SCLogDebug("ssn %p: SYN packet on state ESTABLISED... resent", ssn);
        if (PKT_IS_TOCLIENT(p)) {
            SCLogDebug("ssn %p: SYN-pkt to client in EST state", ssn);

            StreamTcpSetEvent(p, STREAM_EST_SYN_TOCLIENT);
            return -1;
        }

        if (!(SEQ_EQ(TCP_GET_SEQ(p), ssn->client.isn))) {
            SCLogDebug("ssn %p: SYN with different SEQ on SYN_RECV state", ssn);

            StreamTcpSetEvent(p, STREAM_EST_SYN_RESEND_DIFF_SEQ);
            return -1;
        }

        /* a resend of a SYN while we are established already -- fishy */
        StreamTcpSetEvent(p, STREAM_EST_SYN_RESEND);
        return -1;

    } else if (p->tcph->th_flags & TH_ACK) {
        /* Urgent pointer size can be more than the payload size, as it tells
         * the future coming data from the sender will be handled urgently
         * until data of size equal to urgent offset has been processed
         * (RFC 2147) */

        /* If the timestamp option is enabled for both the streams, then
         * validate the received packet timestamp value against the
         * stream->last_ts. If the timestamp is valid then process the
         * packet normally otherwise the drop the packet (RFC 1323) */
        if (ssn->flags & STREAMTCP_FLAG_TIMESTAMP) {
            if (!StreamTcpValidateTimestamp(ssn, p))
                return -1;
        }

        if (PKT_IS_TOSERVER(p)) {
            /* Process the received packet to server */
            HandleEstablishedPacketToServer(tv, ssn, p, stt, pq);

            SCLogDebug("ssn %p: next SEQ %" PRIu32 ", last ACK %" PRIu32 ","
                    " next win %" PRIu32 ", win %" PRIu32 "", ssn,
                    ssn->client.next_seq, ssn->server.last_ack
                    ,ssn->client.next_win, ssn->client.window);

        } else { /* implied to client */
            if (!(ssn->flags & STREAMTCP_FLAG_3WHS_CONFIRMED)) {
                ssn->flags |= STREAMTCP_FLAG_3WHS_CONFIRMED;
                SCLogDebug("3whs is now confirmed by server");
            }

            /* Process the received packet to client */
            HandleEstablishedPacketToClient(tv, ssn, p, stt, pq);

            SCLogDebug("ssn %p: next SEQ %" PRIu32 ", last ACK %" PRIu32 ","
                    " next win %" PRIu32 ", win %" PRIu32 "", ssn,
                    ssn->server.next_seq, ssn->client.last_ack,
                    ssn->server.next_win, ssn->server.window);
        }
    } else {
        SCLogDebug("ssn %p: default case", ssn);
    }

    return 0;
}

/**
 *  \brief  Function to handle the FIN packets for states TCP_SYN_RECV and
 *          TCP_ESTABLISHED and changes to another TCP state as required.
 *
 *  \param  tv      Thread Variable containig  input/output queue, cpu affinity
 *  \param  p       Packet which has to be handled in this TCP state.
 *  \param  stt     Strean Thread module registered to handle the stream handling
 *
 *  \retval 0 success
 *  \retval -1 something wrong with the packet
 */

static int StreamTcpHandleFin(ThreadVars *tv, StreamTcpThread *stt,
                                TcpSession *ssn, Packet *p, PacketQueue *pq)
{
    if (PKT_IS_TOSERVER(p)) {
        SCLogDebug("ssn %p: pkt (%" PRIu32 ") is to server: SEQ %" PRIu32 ","
                " ACK %" PRIu32 "", ssn, p->payload_len, TCP_GET_SEQ(p),
                TCP_GET_ACK(p));

        if (StreamTcpValidateAck(ssn, &ssn->server, p) == -1) {
            SCLogDebug("ssn %p: rejecting because of invalid ack value", ssn);
            StreamTcpSetEvent(p, STREAM_FIN_INVALID_ACK);
            return -1;
        }

        if (SEQ_LT(TCP_GET_SEQ(p), ssn->client.next_seq) ||
            SEQ_GT(TCP_GET_SEQ(p), (ssn->client.last_ack + ssn->client.window)))
        {
            SCLogDebug("ssn %p: -> SEQ mismatch, packet SEQ %" PRIu32 " != "
                    "%" PRIu32 " from stream", ssn, TCP_GET_SEQ(p),
                    ssn->client.next_seq);

            StreamTcpSetEvent(p, STREAM_FIN_OUT_OF_WINDOW);
            return -1;
        }

        StreamTcpPacketSetState(p, ssn, TCP_CLOSE_WAIT);
        SCLogDebug("ssn %p: state changed to TCP_CLOSE_WAIT", ssn);

        if (SEQ_EQ(TCP_GET_SEQ(p), ssn->client.next_seq))
            ssn->client.next_seq = TCP_GET_SEQ(p) + p->payload_len;

        SCLogDebug("ssn %p: ssn->client.next_seq %" PRIu32 "", ssn,
                    ssn->client.next_seq);
        ssn->server.window = TCP_GET_WINDOW(p) << ssn->server.wscale;

        StreamTcpUpdateLastAck(ssn, &ssn->server, TCP_GET_ACK(p));

        if (ssn->flags & STREAMTCP_FLAG_TIMESTAMP) {
            StreamTcpHandleTimestamp(ssn, p);
        }

        /* Update the next_seq, in case if we have missed the client packet
           and server has already received and acked it */
        if (SEQ_LT(ssn->server.next_seq, TCP_GET_ACK(p)))
            ssn->server.next_seq = TCP_GET_ACK(p);

        StreamTcpReassembleHandleSegment(tv, stt->ra_ctx, ssn, &ssn->client, p, pq);

        SCLogDebug("ssn %p: =+ next SEQ %" PRIu32 ", last ACK %" PRIu32 "",
                ssn, ssn->client.next_seq, ssn->server.last_ack);
    } else { /* implied to client */
        SCLogDebug("ssn %p: pkt (%" PRIu32 ") is to client: SEQ %" PRIu32 ", "
                   "ACK %" PRIu32 "", ssn, p->payload_len, TCP_GET_SEQ(p),
                    TCP_GET_ACK(p));

        if (StreamTcpValidateAck(ssn, &ssn->client, p) == -1) {
            SCLogDebug("ssn %p: rejecting because of invalid ack value", ssn);
            StreamTcpSetEvent(p, STREAM_FIN_INVALID_ACK);
            return -1;
        }

        if (SEQ_LT(TCP_GET_SEQ(p), ssn->server.next_seq) ||
            SEQ_GT(TCP_GET_SEQ(p), (ssn->server.last_ack + ssn->server.window)))
        {
            SCLogDebug("ssn %p: -> SEQ mismatch, packet SEQ %" PRIu32 " != "
                       "%" PRIu32 " from stream", ssn, TCP_GET_SEQ(p),
                        ssn->server.next_seq);

            StreamTcpSetEvent(p, STREAM_FIN_OUT_OF_WINDOW);
            return -1;
        }

        StreamTcpPacketSetState(p, ssn, TCP_FIN_WAIT1);
        SCLogDebug("ssn %p: state changed to TCP_FIN_WAIT1", ssn);

        if (SEQ_EQ(TCP_GET_SEQ(p), ssn->server.next_seq))
            ssn->server.next_seq = TCP_GET_SEQ(p) + p->payload_len;

        SCLogDebug("ssn %p: ssn->server.next_seq %" PRIu32 "", ssn,
                    ssn->server.next_seq);
        ssn->client.window = TCP_GET_WINDOW(p) << ssn->client.wscale;

        StreamTcpUpdateLastAck(ssn, &ssn->client, TCP_GET_ACK(p));

        if (ssn->flags & STREAMTCP_FLAG_TIMESTAMP) {
            StreamTcpHandleTimestamp(ssn, p);
        }

        /* Update the next_seq, in case if we have missed the client packet
           and server has already received and acked it */
        if (SEQ_LT(ssn->client.next_seq, TCP_GET_ACK(p)))
            ssn->client.next_seq = TCP_GET_ACK(p);

        StreamTcpReassembleHandleSegment(tv, stt->ra_ctx, ssn, &ssn->server, p, pq);

        SCLogDebug("ssn %p: =+ next SEQ %" PRIu32 ", last ACK %" PRIu32 "",
                ssn, ssn->server.next_seq, ssn->client.last_ack);
    }

    return 0;
}

/**
 *  \brief  Function to handle the TCP_FIN_WAIT1 state. The function handles
 *          ACK, FIN, RST packets and correspondingly changes the connection
 *          state.
 *
 *  \param  tv      Thread Variable containig  input/output queue, cpu affinity
 *  \param  p       Packet which has to be handled in this TCP state.
 *  \param  stt     Strean Thread module registered to handle the stream handling
 *
 *  \retval 0 success
 *  \retval -1 something wrong with the packet
 */

static int StreamTcpPacketStateFinWait1(ThreadVars *tv, Packet *p,
                        StreamTcpThread *stt, TcpSession *ssn, PacketQueue *pq)
{
    if (ssn == NULL)
        return -1;

    if (p->tcph->th_flags & TH_RST) {
        if (!StreamTcpValidateRst(ssn, p))
            return -1;

        /* force both streams to reassemble, if necessary */
        StreamTcpPseudoPacketCreateStreamEndPacket(tv, stt, p, ssn, pq);

        StreamTcpPacketSetState(p, ssn, TCP_CLOSED);
        SCLogDebug("ssn %p: Reset received state changed to TCP_CLOSED",
                ssn);

        if (PKT_IS_TOSERVER(p)) {
            if ((p->tcph->th_flags & TH_ACK) && StreamTcpValidateAck(ssn, &ssn->server, p) == 0)
                StreamTcpUpdateLastAck(ssn, &ssn->server,
                        StreamTcpResetGetMaxAck(&ssn->server, TCP_GET_ACK(p)));

            StreamTcpUpdateLastAck(ssn, &ssn->client,
                    StreamTcpResetGetMaxAck(&ssn->client, TCP_GET_SEQ(p)));

            if (ssn->flags & STREAMTCP_FLAG_TIMESTAMP) {
                StreamTcpHandleTimestamp(ssn, p);
            }

            StreamTcpReassembleHandleSegment(tv, stt->ra_ctx, ssn,
                    &ssn->client, p, pq);
        } else {
            if ((p->tcph->th_flags & TH_ACK) && StreamTcpValidateAck(ssn, &ssn->client, p) == 0)
                StreamTcpUpdateLastAck(ssn, &ssn->client,
                        StreamTcpResetGetMaxAck(&ssn->client, TCP_GET_ACK(p)));

            StreamTcpUpdateLastAck(ssn, &ssn->server,
                    StreamTcpResetGetMaxAck(&ssn->server, TCP_GET_SEQ(p)));

            if (ssn->flags & STREAMTCP_FLAG_TIMESTAMP) {
                StreamTcpHandleTimestamp(ssn, p);
            }

            StreamTcpReassembleHandleSegment(tv, stt->ra_ctx, ssn,
                    &ssn->server, p, pq);
        }

    } else if ((p->tcph->th_flags & (TH_FIN|TH_ACK)) == (TH_FIN|TH_ACK)) {
        if (ssn->flags & STREAMTCP_FLAG_TIMESTAMP) {
            if (!StreamTcpValidateTimestamp(ssn, p))
                return -1;
        }

        if (PKT_IS_TOSERVER(p)) {
            SCLogDebug("ssn %p: pkt (%" PRIu32 ") is to server: SEQ "
                    "%" PRIu32 ", ACK %" PRIu32 "", ssn, p->payload_len,
                    TCP_GET_SEQ(p), TCP_GET_ACK(p));
            int retransmission = 0;

            if (StreamTcpPacketIsRetransmission(&ssn->client, p)) {
                SCLogDebug("ssn %p: packet is retransmission", ssn);
                retransmission = 1;

            } else if (SEQ_LT(TCP_GET_SEQ(p), ssn->client.next_seq) ||
                    SEQ_GT(TCP_GET_SEQ(p), (ssn->client.last_ack + ssn->client.window)))
            {
                SCLogDebug("ssn %p: -> SEQ mismatch, packet SEQ %" PRIu32 ""
                        " != %" PRIu32 " from stream", ssn,
                        TCP_GET_SEQ(p), ssn->client.next_seq);
                StreamTcpSetEvent(p, STREAM_FIN1_FIN_WRONG_SEQ);
                return -1;
            }

            if (StreamTcpValidateAck(ssn, &ssn->server, p) == -1) {
                SCLogDebug("ssn %p: rejecting because of invalid ack value", ssn);
                StreamTcpSetEvent(p, STREAM_FIN1_INVALID_ACK);
                return -1;
            }

            if (!retransmission) {
                StreamTcpPacketSetState(p, ssn, TCP_TIME_WAIT);
                SCLogDebug("ssn %p: state changed to TCP_TIME_WAIT", ssn);

                ssn->server.window = TCP_GET_WINDOW(p) << ssn->server.wscale;
            }

            StreamTcpUpdateLastAck(ssn, &ssn->server, TCP_GET_ACK(p));

            if (ssn->flags & STREAMTCP_FLAG_TIMESTAMP) {
                StreamTcpHandleTimestamp(ssn, p);
            }

            /* Update the next_seq, in case if we have missed the client
               packet and server has already received and acked it */
            if (SEQ_LT(ssn->server.next_seq, TCP_GET_ACK(p)))
                ssn->server.next_seq = TCP_GET_ACK(p);

            if (SEQ_EQ(ssn->client.next_seq, TCP_GET_SEQ(p))) {
                ssn->client.next_seq += p->payload_len;
                SCLogDebug("ssn %p: ssn->client.next_seq %" PRIu32 "",
                        ssn, ssn->client.next_seq);
            }

            StreamTcpReassembleHandleSegment(tv, stt->ra_ctx, ssn,
                    &ssn->client, p, pq);

            SCLogDebug("ssn %p: =+ next SEQ %" PRIu32 ", last ACK "
                    "%" PRIu32 "", ssn, ssn->client.next_seq,
                    ssn->server.last_ack);
        } else { /* implied to client */
            SCLogDebug("ssn %p: pkt (%" PRIu32 ") is to client: SEQ "
                    "%" PRIu32 ", ACK %" PRIu32 "", ssn, p->payload_len,
                    TCP_GET_SEQ(p), TCP_GET_ACK(p));
            int retransmission = 0;

            if (StreamTcpPacketIsRetransmission(&ssn->server, p)) {
                SCLogDebug("ssn %p: packet is retransmission", ssn);
                retransmission = 1;

            } else if (SEQ_LT(TCP_GET_SEQ(p), ssn->server.next_seq) ||
                    SEQ_GT(TCP_GET_SEQ(p), (ssn->server.last_ack + ssn->server.window)))
            {
                SCLogDebug("ssn %p: -> SEQ mismatch, packet SEQ %" PRIu32 ""
                        " != %" PRIu32 " from stream", ssn,
                        TCP_GET_SEQ(p), ssn->server.next_seq);
                StreamTcpSetEvent(p, STREAM_FIN1_FIN_WRONG_SEQ);
                return -1;
            }

            if (StreamTcpValidateAck(ssn, &ssn->client, p) == -1) {
                SCLogDebug("ssn %p: rejecting because of invalid ack value", ssn);
                StreamTcpSetEvent(p, STREAM_FIN1_INVALID_ACK);
                return -1;
            }

            if (!retransmission) {
                StreamTcpPacketSetState(p, ssn, TCP_TIME_WAIT);
                SCLogDebug("ssn %p: state changed to TCP_TIME_WAIT", ssn);

                ssn->client.window = TCP_GET_WINDOW(p) << ssn->client.wscale;
            }

            StreamTcpUpdateLastAck(ssn, &ssn->client, TCP_GET_ACK(p));

            if (ssn->flags & STREAMTCP_FLAG_TIMESTAMP) {
                StreamTcpHandleTimestamp(ssn, p);
            }

            /* Update the next_seq, in case if we have missed the client
               packet and server has already received and acked it */
            if (SEQ_LT(ssn->client.next_seq, TCP_GET_ACK(p)))
                ssn->client.next_seq = TCP_GET_ACK(p);

            if (SEQ_EQ(ssn->server.next_seq, TCP_GET_SEQ(p))) {
                ssn->server.next_seq += p->payload_len;
                SCLogDebug("ssn %p: ssn->server.next_seq %" PRIu32 "",
                        ssn, ssn->server.next_seq);
            }

            StreamTcpReassembleHandleSegment(tv, stt->ra_ctx, ssn,
                    &ssn->server, p, pq);

            SCLogDebug("ssn %p: =+ next SEQ %" PRIu32 ", last ACK "
                    "%" PRIu32 "", ssn, ssn->server.next_seq,
                    ssn->client.last_ack);
        }

    } else if (p->tcph->th_flags & TH_FIN) {
        if (ssn->flags & STREAMTCP_FLAG_TIMESTAMP) {
            if (!StreamTcpValidateTimestamp(ssn, p))
                return -1;
        }

        if (PKT_IS_TOSERVER(p)) {
            SCLogDebug("ssn %p: pkt (%" PRIu32 ") is to server: SEQ "
                    "%" PRIu32 ", ACK %" PRIu32 "", ssn, p->payload_len,
                    TCP_GET_SEQ(p), TCP_GET_ACK(p));
            int retransmission = 0;

            if (StreamTcpPacketIsRetransmission(&ssn->client, p)) {
                SCLogDebug("ssn %p: packet is retransmission", ssn);
                retransmission = 1;

            } else if (SEQ_LT(TCP_GET_SEQ(p), ssn->client.next_seq) ||
                    SEQ_GT(TCP_GET_SEQ(p), (ssn->client.last_ack + ssn->client.window)))
            {
                SCLogDebug("ssn %p: -> SEQ mismatch, packet SEQ %" PRIu32 ""
                        " != %" PRIu32 " from stream", ssn,
                        TCP_GET_SEQ(p), ssn->client.next_seq);
                StreamTcpSetEvent(p, STREAM_FIN1_FIN_WRONG_SEQ);
                return -1;
            }

            if (StreamTcpValidateAck(ssn, &ssn->server, p) == -1) {
                SCLogDebug("ssn %p: rejecting because of invalid ack value", ssn);
                StreamTcpSetEvent(p, STREAM_FIN1_INVALID_ACK);
                return -1;
            }

            if (!retransmission) {
                StreamTcpPacketSetState(p, ssn, TCP_CLOSING);
                SCLogDebug("ssn %p: state changed to TCP_CLOSING", ssn);

                ssn->server.window = TCP_GET_WINDOW(p) << ssn->server.wscale;
            }

            StreamTcpUpdateLastAck(ssn, &ssn->server, TCP_GET_ACK(p));

            if (ssn->flags & STREAMTCP_FLAG_TIMESTAMP) {
                StreamTcpHandleTimestamp(ssn, p);
            }

            /* Update the next_seq, in case if we have missed the client
               packet and server has already received and acked it */
            if (SEQ_LT(ssn->server.next_seq, TCP_GET_ACK(p)))
                ssn->server.next_seq = TCP_GET_ACK(p);

            if (SEQ_EQ(ssn->client.next_seq, TCP_GET_SEQ(p))) {
                ssn->client.next_seq += p->payload_len;
                SCLogDebug("ssn %p: ssn->client.next_seq %" PRIu32 "",
                        ssn, ssn->client.next_seq);
            }

            StreamTcpReassembleHandleSegment(tv, stt->ra_ctx, ssn,
                    &ssn->client, p, pq);

            SCLogDebug("ssn %p: =+ next SEQ %" PRIu32 ", last ACK "
                    "%" PRIu32 "", ssn, ssn->client.next_seq,
                    ssn->server.last_ack);
        } else { /* implied to client */
            SCLogDebug("ssn %p: pkt (%" PRIu32 ") is to client: SEQ "
                    "%" PRIu32 ", ACK %" PRIu32 "", ssn, p->payload_len,
                    TCP_GET_SEQ(p), TCP_GET_ACK(p));

            int retransmission = 0;

            if (StreamTcpPacketIsRetransmission(&ssn->server, p)) {
                SCLogDebug("ssn %p: packet is retransmission", ssn);
                retransmission = 1;

            } else if (SEQ_LT(TCP_GET_SEQ(p), ssn->server.next_seq) ||
                    SEQ_GT(TCP_GET_SEQ(p), (ssn->server.last_ack + ssn->server.window)))
            {
                SCLogDebug("ssn %p: -> SEQ mismatch, packet SEQ %" PRIu32 ""
                        " != %" PRIu32 " from stream", ssn,
                        TCP_GET_SEQ(p), ssn->server.next_seq);
                StreamTcpSetEvent(p, STREAM_FIN1_FIN_WRONG_SEQ);
                return -1;
            }

            if (StreamTcpValidateAck(ssn, &ssn->client, p) == -1) {
                SCLogDebug("ssn %p: rejecting because of invalid ack value", ssn);
                StreamTcpSetEvent(p, STREAM_FIN1_INVALID_ACK);
                return -1;
            }

            if (!retransmission) {
                StreamTcpPacketSetState(p, ssn, TCP_CLOSING);
                SCLogDebug("ssn %p: state changed to TCP_CLOSING", ssn);

                ssn->client.window = TCP_GET_WINDOW(p) << ssn->client.wscale;
            }

            StreamTcpUpdateLastAck(ssn, &ssn->client, TCP_GET_ACK(p));

            if (ssn->flags & STREAMTCP_FLAG_TIMESTAMP) {
                StreamTcpHandleTimestamp(ssn, p);
            }

            /* Update the next_seq, in case if we have missed the client
               packet and server has already received and acked it */
            if (SEQ_LT(ssn->client.next_seq, TCP_GET_ACK(p)))
                ssn->client.next_seq = TCP_GET_ACK(p);

            if (SEQ_EQ(ssn->server.next_seq, TCP_GET_SEQ(p))) {
                ssn->server.next_seq += p->payload_len;
                SCLogDebug("ssn %p: ssn->server.next_seq %" PRIu32 "",
                        ssn, ssn->server.next_seq);
            }

            StreamTcpReassembleHandleSegment(tv, stt->ra_ctx, ssn,
                    &ssn->server, p, pq);

            SCLogDebug("ssn %p: =+ next SEQ %" PRIu32 ", last ACK "
                    "%" PRIu32 "", ssn, ssn->server.next_seq,
                    ssn->client.last_ack);
        }
    } else if (p->tcph->th_flags & TH_SYN) {
        SCLogDebug("ssn (%p): SYN pkt on FinWait1", ssn);
        StreamTcpSetEvent(p, STREAM_SHUTDOWN_SYN_RESEND);
        return -1;

    } else if (p->tcph->th_flags & TH_ACK) {
        if (ssn->flags & STREAMTCP_FLAG_TIMESTAMP) {
            if (!StreamTcpValidateTimestamp(ssn, p))
                return -1;
        }

        if (PKT_IS_TOSERVER(p)) {
            SCLogDebug("ssn %p: pkt (%" PRIu32 ") is to server: SEQ "
                    "%" PRIu32 ", ACK %" PRIu32 "", ssn, p->payload_len,
                    TCP_GET_SEQ(p), TCP_GET_ACK(p));
            int retransmission = 0;

            if (StreamTcpPacketIsRetransmission(&ssn->client, p)) {
                SCLogDebug("ssn %p: packet is retransmission", ssn);
                retransmission = 1;
            }

            if (StreamTcpValidateAck(ssn, &ssn->server, p) == -1) {
                SCLogDebug("ssn %p: rejecting because of invalid ack value", ssn);
                StreamTcpSetEvent(p, STREAM_FIN1_INVALID_ACK);
                return -1;
            }

            if (!retransmission) {
                if (SEQ_LEQ(TCP_GET_SEQ(p) + p->payload_len, ssn->client.next_win) ||
                        (ssn->flags & STREAMTCP_FLAG_MIDSTREAM) ||
                        ssn->flags & STREAMTCP_FLAG_ASYNC)
                {
                    SCLogDebug("ssn %p: seq %"PRIu32" in window, ssn->client.next_win "
                            "%" PRIu32 "", ssn, TCP_GET_SEQ(p), ssn->client.next_win);

                    if (TCP_GET_SEQ(p) == ssn->client.next_seq) {
                        StreamTcpPacketSetState(p, ssn, TCP_FIN_WAIT2);
                        SCLogDebug("ssn %p: state changed to TCP_FIN_WAIT2", ssn);
                    }
                } else {
                    SCLogDebug("ssn %p: -> SEQ mismatch, packet SEQ %" PRIu32 ""
                            " != %" PRIu32 " from stream", ssn,
                            TCP_GET_SEQ(p), ssn->client.next_seq);

                    StreamTcpSetEvent(p, STREAM_FIN1_ACK_WRONG_SEQ);
                    return -1;
                }

                ssn->server.window = TCP_GET_WINDOW(p) << ssn->server.wscale;
            }

            StreamTcpUpdateLastAck(ssn, &ssn->server, TCP_GET_ACK(p));

            if (ssn->flags & STREAMTCP_FLAG_TIMESTAMP) {
                StreamTcpHandleTimestamp(ssn, p);
            }

            /* Update the next_seq, in case if we have missed the client
               packet and server has already received and acked it */
            if (SEQ_LT(ssn->server.next_seq, TCP_GET_ACK(p)))
                ssn->server.next_seq = TCP_GET_ACK(p);

            if (SEQ_EQ(ssn->client.next_seq, TCP_GET_SEQ(p))) {
                ssn->client.next_seq += p->payload_len;
                SCLogDebug("ssn %p: ssn->client.next_seq %" PRIu32 "",
                        ssn, ssn->client.next_seq);
            }

            StreamTcpSackUpdatePacket(&ssn->server, p);

            /* update next_win */
            StreamTcpUpdateNextWin(ssn, &ssn->server, (ssn->server.last_ack + ssn->server.window));

            StreamTcpReassembleHandleSegment(tv, stt->ra_ctx, ssn,
                    &ssn->client, p, pq);

            SCLogDebug("ssn %p: =+ next SEQ %" PRIu32 ", last ACK "
                    "%" PRIu32 "", ssn, ssn->client.next_seq,
                    ssn->server.last_ack);

        } else { /* implied to client */

            SCLogDebug("ssn %p: pkt (%" PRIu32 ") is to client: SEQ "
                    "%" PRIu32 ", ACK %" PRIu32 "", ssn, p->payload_len,
                    TCP_GET_SEQ(p), TCP_GET_ACK(p));

            int retransmission = 0;

            if (StreamTcpPacketIsRetransmission(&ssn->server, p)) {
                SCLogDebug("ssn %p: packet is retransmission", ssn);
                retransmission = 1;
            }

            if (StreamTcpValidateAck(ssn, &ssn->client, p) == -1) {
                SCLogDebug("ssn %p: rejecting because of invalid ack value", ssn);
                StreamTcpSetEvent(p, STREAM_FIN1_INVALID_ACK);
                return -1;
            }

            if (!retransmission) {
                if (SEQ_LEQ(TCP_GET_SEQ(p) + p->payload_len, ssn->server.next_win) ||
                        (ssn->flags & STREAMTCP_FLAG_MIDSTREAM) ||
                        (ssn->flags & STREAMTCP_FLAG_ASYNC))
                {
                    SCLogDebug("ssn %p: seq %"PRIu32" in window, ssn->server.next_win "
                            "%" PRIu32 "", ssn, TCP_GET_SEQ(p), ssn->server.next_win);

                    if (TCP_GET_SEQ(p) == ssn->server.next_seq) {
                        StreamTcpPacketSetState(p, ssn, TCP_FIN_WAIT2);
                        SCLogDebug("ssn %p: state changed to TCP_FIN_WAIT2", ssn);
                    }
                } else {
                    SCLogDebug("ssn %p: -> SEQ mismatch, packet SEQ %" PRIu32 ""
                            " != %" PRIu32 " from stream", ssn,
                            TCP_GET_SEQ(p), ssn->server.next_seq);
                    StreamTcpSetEvent(p, STREAM_FIN1_ACK_WRONG_SEQ);
                    return -1;
                }

                ssn->client.window = TCP_GET_WINDOW(p) << ssn->client.wscale;
            }

            StreamTcpUpdateLastAck(ssn, &ssn->client, TCP_GET_ACK(p));

            if (ssn->flags & STREAMTCP_FLAG_TIMESTAMP) {
                StreamTcpHandleTimestamp(ssn, p);
            }

            /* Update the next_seq, in case if we have missed the client
               packet and server has already received and acked it */
            if (SEQ_LT(ssn->client.next_seq, TCP_GET_ACK(p)))
                ssn->client.next_seq = TCP_GET_ACK(p);

            if (SEQ_EQ(ssn->server.next_seq, TCP_GET_SEQ(p))) {
                ssn->server.next_seq += p->payload_len;
                SCLogDebug("ssn %p: ssn->server.next_seq %" PRIu32 "",
                        ssn, ssn->server.next_seq);
            }

            StreamTcpSackUpdatePacket(&ssn->client, p);

            /* update next_win */
            StreamTcpUpdateNextWin(ssn, &ssn->client, (ssn->client.last_ack + ssn->client.window));

            StreamTcpReassembleHandleSegment(tv, stt->ra_ctx, ssn,
                    &ssn->server, p, pq);

            SCLogDebug("ssn %p: =+ next SEQ %" PRIu32 ", last ACK "
                    "%" PRIu32 "", ssn, ssn->server.next_seq,
                    ssn->client.last_ack);
        }
    } else {
        SCLogDebug("ssn (%p): default case", ssn);
    }

    return 0;
}

/**
 *  \brief  Function to handle the TCP_FIN_WAIT2 state. The function handles
 *          ACK, RST, FIN packets and correspondingly changes the connection
 *          state.
 *
 *  \param  tv      Thread Variable containig  input/output queue, cpu affinity
 *  \param  p       Packet which has to be handled in this TCP state.
 *  \param  stt     Strean Thread module registered to handle the stream handling
 */

static int StreamTcpPacketStateFinWait2(ThreadVars *tv, Packet *p,
                        StreamTcpThread *stt, TcpSession *ssn, PacketQueue *pq)
{
    if (ssn == NULL)
        return -1;

    if (p->tcph->th_flags & TH_RST) {
        if (!StreamTcpValidateRst(ssn, p))
            return -1;

        /* force both streams to reassemble, if necessary */
        StreamTcpPseudoPacketCreateStreamEndPacket(tv, stt, p, ssn, pq);

        StreamTcpPacketSetState(p, ssn, TCP_CLOSED);
        SCLogDebug("ssn %p: Reset received state changed to TCP_CLOSED",
                ssn);

        if (PKT_IS_TOSERVER(p)) {
            if ((p->tcph->th_flags & TH_ACK) && StreamTcpValidateAck(ssn, &ssn->server, p) == 0)
                StreamTcpUpdateLastAck(ssn, &ssn->server,
                        StreamTcpResetGetMaxAck(&ssn->server, TCP_GET_ACK(p)));

            StreamTcpUpdateLastAck(ssn, &ssn->client,
                    StreamTcpResetGetMaxAck(&ssn->client, TCP_GET_SEQ(p)));

            if (ssn->flags & STREAMTCP_FLAG_TIMESTAMP) {
                StreamTcpHandleTimestamp(ssn, p);
            }

            StreamTcpReassembleHandleSegment(tv, stt->ra_ctx, ssn,
                    &ssn->client, p, pq);
        } else {
            if ((p->tcph->th_flags & TH_ACK) && StreamTcpValidateAck(ssn, &ssn->client, p) == 0)
                StreamTcpUpdateLastAck(ssn, &ssn->client,
                        StreamTcpResetGetMaxAck(&ssn->client, TCP_GET_ACK(p)));

            StreamTcpUpdateLastAck(ssn, &ssn->server,
                    StreamTcpResetGetMaxAck(&ssn->server, TCP_GET_SEQ(p)));

            if (ssn->flags & STREAMTCP_FLAG_TIMESTAMP) {
                StreamTcpHandleTimestamp(ssn, p);
            }

            StreamTcpReassembleHandleSegment(tv, stt->ra_ctx, ssn,
                    &ssn->server, p, pq);
        }

    } else if (p->tcph->th_flags & TH_FIN) {
        if (ssn->flags & STREAMTCP_FLAG_TIMESTAMP) {
            if (!StreamTcpValidateTimestamp(ssn, p))
                return -1;
        }

        if (PKT_IS_TOSERVER(p)) {
            SCLogDebug("ssn %p: pkt (%" PRIu32 ") is to server: SEQ "
                    "%" PRIu32 ", ACK %" PRIu32 "", ssn, p->payload_len,
                    TCP_GET_SEQ(p), TCP_GET_ACK(p));
            int retransmission = 0;

            if (SEQ_EQ(TCP_GET_SEQ(p), ssn->client.next_seq - 1) &&
                SEQ_EQ(TCP_GET_ACK(p), ssn->server.last_ack)) {
                SCLogDebug("ssn %p: retransmission", ssn);
                retransmission = 1;
            } else if (StreamTcpPacketIsRetransmission(&ssn->client, p)) {
                SCLogDebug("ssn %p: packet is retransmission", ssn);
                retransmission = 1;

            } else if (SEQ_LT(TCP_GET_SEQ(p), ssn->client.next_seq) ||
                    SEQ_GT(TCP_GET_SEQ(p), (ssn->client.last_ack + ssn->client.window)))
            {
                SCLogDebug("ssn %p: -> SEQ mismatch, packet SEQ "
                        "%" PRIu32 " != %" PRIu32 " from stream", ssn,
                        TCP_GET_SEQ(p), ssn->client.next_seq);
                StreamTcpSetEvent(p, STREAM_FIN2_FIN_WRONG_SEQ);
                return -1;
            }

            if (StreamTcpValidateAck(ssn, &ssn->server, p) == -1) {
                SCLogDebug("ssn %p: rejecting because of invalid ack value", ssn);
                StreamTcpSetEvent(p, STREAM_FIN2_INVALID_ACK);
                return -1;
            }

            if (!retransmission) {
                StreamTcpPacketSetState(p, ssn, TCP_TIME_WAIT);
                SCLogDebug("ssn %p: state changed to TCP_TIME_WAIT", ssn);

                ssn->server.window = TCP_GET_WINDOW(p) << ssn->server.wscale;
            }

            StreamTcpUpdateLastAck(ssn, &ssn->server, TCP_GET_ACK(p));

            if (ssn->flags & STREAMTCP_FLAG_TIMESTAMP) {
                StreamTcpHandleTimestamp(ssn, p);
            }

            /* Update the next_seq, in case if we have missed the client
               packet and server has already received and acked it */
            if (SEQ_LT(ssn->server.next_seq, TCP_GET_ACK(p)))
                ssn->server.next_seq = TCP_GET_ACK(p);

            StreamTcpReassembleHandleSegment(tv, stt->ra_ctx, ssn,
                    &ssn->client, p, pq);

            SCLogDebug("ssn %p: =+ next SEQ %" PRIu32 ", last ACK "
                    "%" PRIu32 "", ssn, ssn->client.next_seq,
                    ssn->server.last_ack);
        } else { /* implied to client */
            SCLogDebug("ssn %p: pkt (%" PRIu32 ") is to client: SEQ "
                    "%" PRIu32 ", ACK %" PRIu32 "", ssn, p->payload_len,
                    TCP_GET_SEQ(p), TCP_GET_ACK(p));
            int retransmission = 0;

            if (SEQ_EQ(TCP_GET_SEQ(p), ssn->server.next_seq - 1) &&
                SEQ_EQ(TCP_GET_ACK(p), ssn->client.last_ack)) {
                SCLogDebug("ssn %p: retransmission", ssn);
                retransmission = 1;
            } else if (StreamTcpPacketIsRetransmission(&ssn->server, p)) {
                SCLogDebug("ssn %p: packet is retransmission", ssn);
                retransmission = 1;

            } else if (SEQ_LT(TCP_GET_SEQ(p), ssn->server.next_seq) ||
                    SEQ_GT(TCP_GET_SEQ(p), (ssn->server.last_ack + ssn->server.window)))
            {
                SCLogDebug("ssn %p: -> SEQ mismatch, packet SEQ "
                        "%" PRIu32 " != %" PRIu32 " from stream", ssn,
                        TCP_GET_SEQ(p), ssn->server.next_seq);
                StreamTcpSetEvent(p, STREAM_FIN2_FIN_WRONG_SEQ);
                return -1;
            }

            if (StreamTcpValidateAck(ssn, &ssn->client, p) == -1) {
                SCLogDebug("ssn %p: rejecting because of invalid ack value", ssn);
                StreamTcpSetEvent(p, STREAM_FIN2_INVALID_ACK);
                return -1;
            }

            if (!retransmission) {
                StreamTcpPacketSetState(p, ssn, TCP_TIME_WAIT);
                SCLogDebug("ssn %p: state changed to TCP_TIME_WAIT", ssn);

                ssn->client.window = TCP_GET_WINDOW(p) << ssn->client.wscale;
            }

            StreamTcpUpdateLastAck(ssn, &ssn->client, TCP_GET_ACK(p));

            if (ssn->flags & STREAMTCP_FLAG_TIMESTAMP) {
                StreamTcpHandleTimestamp(ssn, p);
            }

            /* Update the next_seq, in case if we have missed the client
               packet and server has already received and acked it */
            if (SEQ_LT(ssn->client.next_seq, TCP_GET_ACK(p)))
                ssn->client.next_seq = TCP_GET_ACK(p);

            StreamTcpReassembleHandleSegment(tv, stt->ra_ctx, ssn,
                    &ssn->server, p, pq);
            SCLogDebug("ssn %p: =+ next SEQ %" PRIu32 ", last ACK "
                    "%" PRIu32 "", ssn, ssn->server.next_seq,
                    ssn->client.last_ack);
        }

    } else if (p->tcph->th_flags & TH_SYN) {
        SCLogDebug("ssn (%p): SYN pkt on FinWait2", ssn);
        StreamTcpSetEvent(p, STREAM_SHUTDOWN_SYN_RESEND);
        return -1;

    } else if (p->tcph->th_flags & TH_ACK) {
        if (ssn->flags & STREAMTCP_FLAG_TIMESTAMP) {
            if (!StreamTcpValidateTimestamp(ssn, p))
                return -1;
        }

        if (PKT_IS_TOSERVER(p)) {
            SCLogDebug("ssn %p: pkt (%" PRIu32 ") is to server: SEQ "
                    "%" PRIu32 ", ACK %" PRIu32 "", ssn, p->payload_len,
                    TCP_GET_SEQ(p), TCP_GET_ACK(p));
            int retransmission = 0;

            if (StreamTcpPacketIsRetransmission(&ssn->client, p)) {
                SCLogDebug("ssn %p: packet is retransmission", ssn);
                retransmission = 1;
            }

            if (StreamTcpValidateAck(ssn, &ssn->server, p) == -1) {
                SCLogDebug("ssn %p: rejecting because of invalid ack value", ssn);
                StreamTcpSetEvent(p, STREAM_FIN2_INVALID_ACK);
                return -1;
            }

            if (!retransmission) {
                if (SEQ_LEQ(TCP_GET_SEQ(p) + p->payload_len, ssn->client.next_win) ||
                        (ssn->flags & STREAMTCP_FLAG_MIDSTREAM) ||
                        (ssn->flags & STREAMTCP_FLAG_ASYNC))
                {
                    SCLogDebug("ssn %p: seq %"PRIu32" in window, ssn->client.next_win "
                            "%" PRIu32 "", ssn, TCP_GET_SEQ(p), ssn->client.next_win);

                } else {
                    SCLogDebug("ssn %p: -> SEQ mismatch, packet SEQ %" PRIu32 ""
                            " != %" PRIu32 " from stream", ssn,
                            TCP_GET_SEQ(p), ssn->client.next_seq);
                    StreamTcpSetEvent(p, STREAM_FIN2_ACK_WRONG_SEQ);
                    return -1;
                }

                ssn->server.window = TCP_GET_WINDOW(p) << ssn->server.wscale;
            }

            StreamTcpUpdateLastAck(ssn, &ssn->server, TCP_GET_ACK(p));

            if (ssn->flags & STREAMTCP_FLAG_TIMESTAMP) {
                StreamTcpHandleTimestamp(ssn, p);
            }

            if (SEQ_EQ(ssn->client.next_seq, TCP_GET_SEQ(p))) {
                ssn->client.next_seq += p->payload_len;
                SCLogDebug("ssn %p: ssn->client.next_seq %" PRIu32 "",
                        ssn, ssn->client.next_seq);
            }

            StreamTcpSackUpdatePacket(&ssn->server, p);

            /* update next_win */
            StreamTcpUpdateNextWin(ssn, &ssn->server, (ssn->server.last_ack + ssn->server.window));

            StreamTcpReassembleHandleSegment(tv, stt->ra_ctx, ssn,
                    &ssn->client, p, pq);

            SCLogDebug("ssn %p: =+ next SEQ %" PRIu32 ", last ACK "
                    "%" PRIu32 "", ssn, ssn->client.next_seq,
                    ssn->server.last_ack);
        } else { /* implied to client */
            SCLogDebug("ssn %p: pkt (%" PRIu32 ") is to client: SEQ "
                    "%" PRIu32 ", ACK %" PRIu32 "", ssn, p->payload_len,
                    TCP_GET_SEQ(p), TCP_GET_ACK(p));
            int retransmission = 0;

            if (StreamTcpPacketIsRetransmission(&ssn->server, p)) {
                SCLogDebug("ssn %p: packet is retransmission", ssn);
                retransmission = 1;
            }

            if (StreamTcpValidateAck(ssn, &ssn->client, p) == -1) {
                SCLogDebug("ssn %p: rejecting because of invalid ack value", ssn);
                StreamTcpSetEvent(p, STREAM_FIN2_INVALID_ACK);
                return -1;
            }

            if (!retransmission) {
                if (SEQ_LEQ(TCP_GET_SEQ(p) + p->payload_len, ssn->server.next_win) ||
                        (ssn->flags & STREAMTCP_FLAG_MIDSTREAM) ||
                        (ssn->flags & STREAMTCP_FLAG_ASYNC))
                {
                    SCLogDebug("ssn %p: seq %"PRIu32" in window, ssn->server.next_win "
                            "%" PRIu32 "", ssn, TCP_GET_SEQ(p), ssn->server.next_win);
                } else {
                    SCLogDebug("ssn %p: -> SEQ mismatch, packet SEQ %" PRIu32 ""
                            " != %" PRIu32 " from stream", ssn,
                            TCP_GET_SEQ(p), ssn->server.next_seq);
                    StreamTcpSetEvent(p, STREAM_FIN2_ACK_WRONG_SEQ);
                    return -1;
                }

                ssn->client.window = TCP_GET_WINDOW(p) << ssn->client.wscale;
            }

            StreamTcpUpdateLastAck(ssn, &ssn->client, TCP_GET_ACK(p));

            if (ssn->flags & STREAMTCP_FLAG_TIMESTAMP) {
                StreamTcpHandleTimestamp(ssn, p);
            }

            if (SEQ_EQ(ssn->server.next_seq, TCP_GET_SEQ(p))) {
                ssn->server.next_seq += p->payload_len;
                SCLogDebug("ssn %p: ssn->server.next_seq %" PRIu32 "",
                        ssn, ssn->server.next_seq);
            }

            StreamTcpSackUpdatePacket(&ssn->client, p);

            /* update next_win */
            StreamTcpUpdateNextWin(ssn, &ssn->client, (ssn->client.last_ack + ssn->client.window));

            StreamTcpReassembleHandleSegment(tv, stt->ra_ctx, ssn,
                    &ssn->server, p, pq);

            SCLogDebug("ssn %p: =+ next SEQ %" PRIu32 ", last ACK "
                    "%" PRIu32 "", ssn, ssn->server.next_seq,
                    ssn->client.last_ack);
        }
    } else {
        SCLogDebug("ssn %p: default case", ssn);
    }

    return 0;
}

/**
 *  \brief  Function to handle the TCP_CLOSING state. Upon arrival of ACK
 *          the connection goes to TCP_TIME_WAIT state. The state has been
 *          reached as both end application has been closed.
 *
 *  \param  tv      Thread Variable containig  input/output queue, cpu affinity
 *  \param  p       Packet which has to be handled in this TCP state.
 *  \param  stt     Strean Thread module registered to handle the stream handling
 */

static int StreamTcpPacketStateClosing(ThreadVars *tv, Packet *p,
                        StreamTcpThread *stt, TcpSession *ssn, PacketQueue *pq)
{
    if (ssn == NULL)
        return -1;

    if (p->tcph->th_flags & TH_RST) {
        if (!StreamTcpValidateRst(ssn, p))
            return -1;

        /* force both streams to reassemble, if necessary */
        StreamTcpPseudoPacketCreateStreamEndPacket(tv, stt, p, ssn, pq);

        StreamTcpPacketSetState(p, ssn, TCP_CLOSED);
        SCLogDebug("ssn %p: Reset received state changed to TCP_CLOSED",
                ssn);

        if (PKT_IS_TOSERVER(p)) {
            if ((p->tcph->th_flags & TH_ACK) && StreamTcpValidateAck(ssn, &ssn->server, p) == 0)
                StreamTcpUpdateLastAck(ssn, &ssn->server,
                        StreamTcpResetGetMaxAck(&ssn->server, TCP_GET_ACK(p)));

            StreamTcpUpdateLastAck(ssn, &ssn->client,
                    StreamTcpResetGetMaxAck(&ssn->client, TCP_GET_SEQ(p)));

            if (ssn->flags & STREAMTCP_FLAG_TIMESTAMP) {
                StreamTcpHandleTimestamp(ssn, p);
            }

            StreamTcpReassembleHandleSegment(tv, stt->ra_ctx, ssn,
                    &ssn->client, p, pq);
        } else {
            if ((p->tcph->th_flags & TH_ACK) && StreamTcpValidateAck(ssn, &ssn->client, p) == 0)
                StreamTcpUpdateLastAck(ssn, &ssn->client,
                        StreamTcpResetGetMaxAck(&ssn->client, TCP_GET_ACK(p)));

            StreamTcpUpdateLastAck(ssn, &ssn->server,
                    StreamTcpResetGetMaxAck(&ssn->server, TCP_GET_SEQ(p)));

            if (ssn->flags & STREAMTCP_FLAG_TIMESTAMP) {
                StreamTcpHandleTimestamp(ssn, p);
            }

            StreamTcpReassembleHandleSegment(tv, stt->ra_ctx, ssn,
                    &ssn->server, p, pq);
        }

    } else if (p->tcph->th_flags & TH_SYN) {
        SCLogDebug("ssn (%p): SYN pkt on Closing", ssn);
        StreamTcpSetEvent(p, STREAM_SHUTDOWN_SYN_RESEND);
        return -1;

    } else if (p->tcph->th_flags & TH_ACK) {
        if (ssn->flags & STREAMTCP_FLAG_TIMESTAMP) {
            if (!StreamTcpValidateTimestamp(ssn, p))
                return -1;
        }

        if (PKT_IS_TOSERVER(p)) {
            SCLogDebug("ssn %p: pkt (%" PRIu32 ") is to server: SEQ "
                    "%" PRIu32 ", ACK %" PRIu32 "", ssn, p->payload_len,
                    TCP_GET_SEQ(p), TCP_GET_ACK(p));
            int retransmission = 0;
            if (StreamTcpPacketIsRetransmission(&ssn->client, p)) {
                SCLogDebug("ssn %p: packet is retransmission", ssn);
                retransmission = 1;
            }

            if (TCP_GET_SEQ(p) != ssn->client.next_seq) {
                SCLogDebug("ssn %p: -> SEQ mismatch, packet SEQ %" PRIu32 ""
                        " != %" PRIu32 " from stream", ssn,
                        TCP_GET_SEQ(p), ssn->client.next_seq);
                StreamTcpSetEvent(p, STREAM_CLOSING_ACK_WRONG_SEQ);
                return -1;
            }

            if (StreamTcpValidateAck(ssn, &ssn->server, p) == -1) {
                SCLogDebug("ssn %p: rejecting because of invalid ack value", ssn);
                StreamTcpSetEvent(p, STREAM_CLOSING_INVALID_ACK);
                return -1;
            }

            if (!retransmission) {
                StreamTcpPacketSetState(p, ssn, TCP_TIME_WAIT);
                SCLogDebug("ssn %p: state changed to TCP_TIME_WAIT", ssn);

                ssn->client.window = TCP_GET_WINDOW(p) << ssn->client.wscale;
            }

            StreamTcpUpdateLastAck(ssn, &ssn->server, TCP_GET_ACK(p));

            if (ssn->flags & STREAMTCP_FLAG_TIMESTAMP) {
                StreamTcpHandleTimestamp(ssn, p);
            }
            /* Update the next_seq, in case if we have missed the client
               packet and server has already received and acked it */
            if (SEQ_LT(ssn->server.next_seq, TCP_GET_ACK(p)))
                ssn->server.next_seq = TCP_GET_ACK(p);

            StreamTcpReassembleHandleSegment(tv, stt->ra_ctx, ssn,
                    &ssn->client, p, pq);
            SCLogDebug("ssn %p: =+ next SEQ %" PRIu32 ", last ACK "
                    "%" PRIu32 "", ssn, ssn->client.next_seq,
                    ssn->server.last_ack);
        } else { /* implied to client */
            SCLogDebug("ssn %p: pkt (%" PRIu32 ") is to client: SEQ "
                    "%" PRIu32 ", ACK %" PRIu32 "", ssn, p->payload_len,
                    TCP_GET_SEQ(p), TCP_GET_ACK(p));
            int retransmission = 0;
            if (StreamTcpPacketIsRetransmission(&ssn->server, p)) {
                SCLogDebug("ssn %p: packet is retransmission", ssn);
                retransmission = 1;
            }

            if (TCP_GET_SEQ(p) != ssn->server.next_seq) {
                SCLogDebug("ssn %p: -> SEQ mismatch, packet SEQ %" PRIu32 ""
                        " != %" PRIu32 " from stream", ssn,
                        TCP_GET_SEQ(p), ssn->server.next_seq);
                StreamTcpSetEvent(p, STREAM_CLOSING_ACK_WRONG_SEQ);
                return -1;
            }

            if (StreamTcpValidateAck(ssn, &ssn->client, p) == -1) {
                SCLogDebug("ssn %p: rejecting because of invalid ack value", ssn);
                StreamTcpSetEvent(p, STREAM_CLOSING_INVALID_ACK);
                return -1;
            }

            if (!retransmission) {
                StreamTcpPacketSetState(p, ssn, TCP_TIME_WAIT);
                SCLogDebug("ssn %p: state changed to TCP_TIME_WAIT", ssn);

                ssn->client.window = TCP_GET_WINDOW(p) << ssn->client.wscale;
            }

            StreamTcpUpdateLastAck(ssn, &ssn->client, TCP_GET_ACK(p));

            if (ssn->flags & STREAMTCP_FLAG_TIMESTAMP) {
                StreamTcpHandleTimestamp(ssn, p);
            }

            /* Update the next_seq, in case if we have missed the client
               packet and server has already received and acked it */
            if (SEQ_LT(ssn->client.next_seq, TCP_GET_ACK(p)))
                ssn->client.next_seq = TCP_GET_ACK(p);

            StreamTcpReassembleHandleSegment(tv, stt->ra_ctx, ssn,
                    &ssn->server, p, pq);
            SCLogDebug("StreamTcpPacketStateClosing (%p): =+ next SEQ "
                    "%" PRIu32 ", last ACK %" PRIu32 "", ssn,
                    ssn->server.next_seq, ssn->client.last_ack);
        }
    } else {
        SCLogDebug("ssn %p: default case", ssn);
    }

    return 0;
}

/**
 *  \brief  Function to handle the TCP_CLOSE_WAIT state. Upon arrival of FIN
 *          packet from server the connection goes to TCP_LAST_ACK state.
 *          The state is possible only for server host.
 *
 *  \param  tv      Thread Variable containig  input/output queue, cpu affinity
 *  \param  p       Packet which has to be handled in this TCP state.
 *  \param  stt     Strean Thread module registered to handle the stream handling
 */

static int StreamTcpPacketStateCloseWait(ThreadVars *tv, Packet *p,
                        StreamTcpThread *stt, TcpSession *ssn, PacketQueue *pq)
{
    SCEnter();

    if (ssn == NULL) {
        SCReturnInt(-1);
    }

    if (PKT_IS_TOCLIENT(p)) {
        SCLogDebug("ssn %p: pkt (%" PRIu32 ") is to client: SEQ "
                "%" PRIu32 ", ACK %" PRIu32 "", ssn, p->payload_len,
                TCP_GET_SEQ(p), TCP_GET_ACK(p));
    } else {
        SCLogDebug("ssn %p: pkt (%" PRIu32 ") is to server: SEQ "
                "%" PRIu32 ", ACK %" PRIu32 "", ssn, p->payload_len,
                TCP_GET_SEQ(p), TCP_GET_ACK(p));
    }

    if (p->tcph->th_flags & TH_RST) {
        if (!StreamTcpValidateRst(ssn, p))
            return -1;

        /* force both streams to reassemble, if necessary */
        StreamTcpPseudoPacketCreateStreamEndPacket(tv, stt, p, ssn, pq);

        StreamTcpPacketSetState(p, ssn, TCP_CLOSED);
        SCLogDebug("ssn %p: Reset received state changed to TCP_CLOSED",
                ssn);

        if (PKT_IS_TOSERVER(p)) {
            if ((p->tcph->th_flags & TH_ACK) && StreamTcpValidateAck(ssn, &ssn->server, p) == 0)
                StreamTcpUpdateLastAck(ssn, &ssn->server,
                        StreamTcpResetGetMaxAck(&ssn->server, TCP_GET_ACK(p)));

            StreamTcpUpdateLastAck(ssn, &ssn->client,
                    StreamTcpResetGetMaxAck(&ssn->client, TCP_GET_SEQ(p)));

            if (ssn->flags & STREAMTCP_FLAG_TIMESTAMP) {
                StreamTcpHandleTimestamp(ssn, p);
            }

            StreamTcpReassembleHandleSegment(tv, stt->ra_ctx, ssn,
                    &ssn->client, p, pq);
        } else {
            if ((p->tcph->th_flags & TH_ACK) && StreamTcpValidateAck(ssn, &ssn->client, p) == 0)
                StreamTcpUpdateLastAck(ssn, &ssn->client,
                        StreamTcpResetGetMaxAck(&ssn->client, TCP_GET_ACK(p)));

            StreamTcpUpdateLastAck(ssn, &ssn->server,
                    StreamTcpResetGetMaxAck(&ssn->server, TCP_GET_SEQ(p)));

            if (ssn->flags & STREAMTCP_FLAG_TIMESTAMP) {
                StreamTcpHandleTimestamp(ssn, p);
            }

            StreamTcpReassembleHandleSegment(tv, stt->ra_ctx, ssn,
                    &ssn->server, p, pq);
        }

    } else if (p->tcph->th_flags & TH_FIN) {
        if (ssn->flags & STREAMTCP_FLAG_TIMESTAMP) {
            if (!StreamTcpValidateTimestamp(ssn, p))
                SCReturnInt(-1);
        }

        if (PKT_IS_TOSERVER(p)) {
            SCLogDebug("ssn %p: pkt (%" PRIu32 ") is to server: SEQ "
                    "%" PRIu32 ", ACK %" PRIu32 "", ssn, p->payload_len,
                    TCP_GET_SEQ(p), TCP_GET_ACK(p));

            int retransmission = 0;
            if (StreamTcpPacketIsRetransmission(&ssn->client, p)) {
                SCLogDebug("ssn %p: packet is retransmission", ssn);
                retransmission = 1;
            }

            if (!retransmission) {
                if (SEQ_LT(TCP_GET_SEQ(p), ssn->client.next_seq) ||
                        SEQ_GT(TCP_GET_SEQ(p), (ssn->client.last_ack + ssn->client.window)))
                {
                    SCLogDebug("ssn %p: -> SEQ mismatch, packet SEQ %" PRIu32 ""
                            " != %" PRIu32 " from stream", ssn,
                            TCP_GET_SEQ(p), ssn->client.next_seq);
                    StreamTcpSetEvent(p, STREAM_CLOSEWAIT_FIN_OUT_OF_WINDOW);
                    SCReturnInt(-1);
                }
            }

            if (StreamTcpValidateAck(ssn, &ssn->server, p) == -1) {
                SCLogDebug("ssn %p: rejecting because of invalid ack value", ssn);
                StreamTcpSetEvent(p, STREAM_CLOSEWAIT_INVALID_ACK);
                SCReturnInt(-1);
            }

            /* don't update to LAST_ACK here as we want a toclient FIN for that */

            if (!retransmission)
                ssn->server.window = TCP_GET_WINDOW(p) << ssn->server.wscale;

            StreamTcpUpdateLastAck(ssn, &ssn->server, TCP_GET_ACK(p));

            if (ssn->flags & STREAMTCP_FLAG_TIMESTAMP) {
                StreamTcpHandleTimestamp(ssn, p);
            }

            /* Update the next_seq, in case if we have missed the client
               packet and server has already received and acked it */
            if (SEQ_LT(ssn->server.next_seq, TCP_GET_ACK(p)))
                ssn->server.next_seq = TCP_GET_ACK(p);

            StreamTcpReassembleHandleSegment(tv, stt->ra_ctx, ssn,
                    &ssn->client, p, pq);
            SCLogDebug("ssn %p: =+ next SEQ %" PRIu32 ", last ACK "
                    "%" PRIu32 "", ssn, ssn->client.next_seq,
                    ssn->server.last_ack);
        } else {
            SCLogDebug("ssn %p: pkt (%" PRIu32 ") is to client: SEQ "
                    "%" PRIu32 ", ACK %" PRIu32 "", ssn, p->payload_len,
                    TCP_GET_SEQ(p), TCP_GET_ACK(p));

            int retransmission = 0;
            if (StreamTcpPacketIsRetransmission(&ssn->server, p)) {
                SCLogDebug("ssn %p: packet is retransmission", ssn);
                retransmission = 1;
            }

            if (!retransmission) {
                if (SEQ_LT(TCP_GET_SEQ(p), ssn->server.next_seq) ||
                        SEQ_GT(TCP_GET_SEQ(p), (ssn->server.last_ack + ssn->server.window)))
                {
                    SCLogDebug("ssn %p: -> SEQ mismatch, packet SEQ %" PRIu32 ""
                            " != %" PRIu32 " from stream", ssn,
                            TCP_GET_SEQ(p), ssn->server.next_seq);
                    StreamTcpSetEvent(p, STREAM_CLOSEWAIT_FIN_OUT_OF_WINDOW);
                    SCReturnInt(-1);
                }
            }

            if (StreamTcpValidateAck(ssn, &ssn->client, p) == -1) {
                SCLogDebug("ssn %p: rejecting because of invalid ack value", ssn);
                StreamTcpSetEvent(p, STREAM_CLOSEWAIT_INVALID_ACK);
                SCReturnInt(-1);
            }

            if (!retransmission) {
                StreamTcpPacketSetState(p, ssn, TCP_LAST_ACK);
                SCLogDebug("ssn %p: state changed to TCP_LAST_ACK", ssn);

                ssn->client.window = TCP_GET_WINDOW(p) << ssn->client.wscale;
            }

            StreamTcpUpdateLastAck(ssn, &ssn->client, TCP_GET_ACK(p));

            if (ssn->flags & STREAMTCP_FLAG_TIMESTAMP) {
                StreamTcpHandleTimestamp(ssn, p);
            }

            /* Update the next_seq, in case if we have missed the client
               packet and server has already received and acked it */
            if (SEQ_LT(ssn->client.next_seq, TCP_GET_ACK(p)))
                ssn->client.next_seq = TCP_GET_ACK(p);

            StreamTcpReassembleHandleSegment(tv, stt->ra_ctx, ssn,
                    &ssn->server, p, pq);
            SCLogDebug("ssn %p: =+ next SEQ %" PRIu32 ", last ACK "
                    "%" PRIu32 "", ssn, ssn->server.next_seq,
                    ssn->client.last_ack);
        }

    } else if (p->tcph->th_flags & TH_SYN) {
        SCLogDebug("ssn (%p): SYN pkt on CloseWait", ssn);
        StreamTcpSetEvent(p, STREAM_SHUTDOWN_SYN_RESEND);
        SCReturnInt(-1);

    } else if (p->tcph->th_flags & TH_ACK) {
        if (ssn->flags & STREAMTCP_FLAG_TIMESTAMP) {
            if (!StreamTcpValidateTimestamp(ssn, p))
                SCReturnInt(-1);
        }

        if (PKT_IS_TOSERVER(p)) {
            SCLogDebug("ssn %p: pkt (%" PRIu32 ") is to server: SEQ "
                    "%" PRIu32 ", ACK %" PRIu32 "", ssn, p->payload_len,
                    TCP_GET_SEQ(p), TCP_GET_ACK(p));

            int retransmission = 0;
            if (StreamTcpPacketIsRetransmission(&ssn->client, p)) {
                SCLogDebug("ssn %p: packet is retransmission", ssn);
                retransmission = 1;
            }

            if (p->payload_len > 0 && (SEQ_LEQ((TCP_GET_SEQ(p) + p->payload_len), ssn->client.last_ack))) {
                SCLogDebug("ssn %p: -> retransmission", ssn);
                StreamTcpSetEvent(p, STREAM_CLOSEWAIT_PKT_BEFORE_LAST_ACK);
                SCReturnInt(-1);

            } else if (SEQ_GT(TCP_GET_SEQ(p), (ssn->client.last_ack + ssn->client.window)))
            {
                SCLogDebug("ssn %p: -> SEQ mismatch, packet SEQ %" PRIu32 ""
                        " != %" PRIu32 " from stream", ssn,
                        TCP_GET_SEQ(p), ssn->client.next_seq);
                StreamTcpSetEvent(p, STREAM_CLOSEWAIT_ACK_OUT_OF_WINDOW);
                SCReturnInt(-1);
            }

            if (StreamTcpValidateAck(ssn, &ssn->server, p) == -1) {
                SCLogDebug("ssn %p: rejecting because of invalid ack value", ssn);
                StreamTcpSetEvent(p, STREAM_CLOSEWAIT_INVALID_ACK);
                SCReturnInt(-1);
            }

            if (!retransmission) {
                ssn->server.window = TCP_GET_WINDOW(p) << ssn->server.wscale;
            }

            StreamTcpUpdateLastAck(ssn, &ssn->server, TCP_GET_ACK(p));

            if (ssn->flags & STREAMTCP_FLAG_TIMESTAMP) {
                StreamTcpHandleTimestamp(ssn, p);
            }

            /* Update the next_seq, in case if we have missed the client
               packet and server has already received and acked it */
            if (SEQ_LT(ssn->server.next_seq, TCP_GET_ACK(p)))
                ssn->server.next_seq = TCP_GET_ACK(p);

            if (SEQ_EQ(TCP_GET_SEQ(p),ssn->client.next_seq))
                ssn->client.next_seq += p->payload_len;

            StreamTcpReassembleHandleSegment(tv, stt->ra_ctx, ssn,
                    &ssn->client, p, pq);
            SCLogDebug("ssn %p: =+ next SEQ %" PRIu32 ", last ACK "
                    "%" PRIu32 "", ssn, ssn->client.next_seq,
                    ssn->server.last_ack);
        } else {
            SCLogDebug("ssn %p: pkt (%" PRIu32 ") is to client: SEQ "
                    "%" PRIu32 ", ACK %" PRIu32 "", ssn, p->payload_len,
                    TCP_GET_SEQ(p), TCP_GET_ACK(p));
            int retransmission = 0;
            if (StreamTcpPacketIsRetransmission(&ssn->server, p)) {
                SCLogDebug("ssn %p: packet is retransmission", ssn);
                retransmission = 1;
            }

            if (p->payload_len > 0 && (SEQ_LEQ((TCP_GET_SEQ(p) + p->payload_len), ssn->server.last_ack))) {
                SCLogDebug("ssn %p: -> retransmission", ssn);
                StreamTcpSetEvent(p, STREAM_CLOSEWAIT_PKT_BEFORE_LAST_ACK);
                SCReturnInt(-1);

            } else if (SEQ_GT(TCP_GET_SEQ(p), (ssn->server.last_ack + ssn->server.window)))
            {
                SCLogDebug("ssn %p: -> SEQ mismatch, packet SEQ %" PRIu32 ""
                        " != %" PRIu32 " from stream", ssn,
                        TCP_GET_SEQ(p), ssn->server.next_seq);
                StreamTcpSetEvent(p, STREAM_CLOSEWAIT_ACK_OUT_OF_WINDOW);
                SCReturnInt(-1);
            }

            if (StreamTcpValidateAck(ssn, &ssn->client, p) == -1) {
                SCLogDebug("ssn %p: rejecting because of invalid ack value", ssn);
                StreamTcpSetEvent(p, STREAM_CLOSEWAIT_INVALID_ACK);
                SCReturnInt(-1);
            }

            if (!retransmission) {
                ssn->client.window = TCP_GET_WINDOW(p) << ssn->client.wscale;
            }

            StreamTcpUpdateLastAck(ssn, &ssn->client, TCP_GET_ACK(p));

            if (ssn->flags & STREAMTCP_FLAG_TIMESTAMP) {
                StreamTcpHandleTimestamp(ssn, p);
            }

            /* Update the next_seq, in case if we have missed the client
               packet and server has already received and acked it */
            if (SEQ_LT(ssn->client.next_seq, TCP_GET_ACK(p)))
                ssn->client.next_seq = TCP_GET_ACK(p);

            if (SEQ_EQ(TCP_GET_SEQ(p),ssn->server.next_seq))
                ssn->server.next_seq += p->payload_len;

            StreamTcpReassembleHandleSegment(tv, stt->ra_ctx, ssn,
                    &ssn->server, p, pq);
            SCLogDebug("ssn %p: =+ next SEQ %" PRIu32 ", last ACK "
                    "%" PRIu32 "", ssn, ssn->server.next_seq,
                    ssn->client.last_ack);
        }

    } else {
        SCLogDebug("ssn %p: default case", ssn);
    }
    SCReturnInt(0);
}

/**
 *  \brief  Function to handle the TCP_LAST_ACK state. Upon arrival of ACK
 *          the connection goes to TCP_CLOSED state and stream memory is
 *          returned back to pool. The state is possible only for server host.
 *
 *  \param  tv      Thread Variable containig  input/output queue, cpu affinity
 *  \param  p       Packet which has to be handled in this TCP state.
 *  \param  stt     Strean Thread module registered to handle the stream handling
 */

static int StreamTcpPacketStateLastAck(ThreadVars *tv, Packet *p,
                        StreamTcpThread *stt, TcpSession *ssn, PacketQueue *pq)
{
    if (ssn == NULL)
        return -1;

    if (p->tcph->th_flags & TH_RST) {
        if (!StreamTcpValidateRst(ssn, p))
            return -1;

        /* force both streams to reassemble, if necessary */
        StreamTcpPseudoPacketCreateStreamEndPacket(tv, stt, p, ssn, pq);

        StreamTcpPacketSetState(p, ssn, TCP_CLOSED);
        SCLogDebug("ssn %p: Reset received state changed to TCP_CLOSED",
                ssn);

        if (PKT_IS_TOSERVER(p)) {
            if ((p->tcph->th_flags & TH_ACK) && StreamTcpValidateAck(ssn, &ssn->server, p) == 0)
                StreamTcpUpdateLastAck(ssn, &ssn->server,
                        StreamTcpResetGetMaxAck(&ssn->server, TCP_GET_ACK(p)));

            StreamTcpUpdateLastAck(ssn, &ssn->client,
                    StreamTcpResetGetMaxAck(&ssn->client, TCP_GET_SEQ(p)));

            if (ssn->flags & STREAMTCP_FLAG_TIMESTAMP) {
                StreamTcpHandleTimestamp(ssn, p);
            }

            StreamTcpReassembleHandleSegment(tv, stt->ra_ctx, ssn,
                    &ssn->client, p, pq);
        } else {
            if ((p->tcph->th_flags & TH_ACK) && StreamTcpValidateAck(ssn, &ssn->client, p) == 0)
                StreamTcpUpdateLastAck(ssn, &ssn->client,
                        StreamTcpResetGetMaxAck(&ssn->client, TCP_GET_ACK(p)));

            StreamTcpUpdateLastAck(ssn, &ssn->server,
                    StreamTcpResetGetMaxAck(&ssn->server, TCP_GET_SEQ(p)));

            if (ssn->flags & STREAMTCP_FLAG_TIMESTAMP) {
                StreamTcpHandleTimestamp(ssn, p);
            }

            StreamTcpReassembleHandleSegment(tv, stt->ra_ctx, ssn,
                    &ssn->server, p, pq);
        }

    } else if (p->tcph->th_flags & TH_FIN) {
        /** \todo */

    } else if (p->tcph->th_flags & TH_SYN) {
        SCLogDebug("ssn (%p): SYN pkt on LastAck", ssn);
        StreamTcpSetEvent(p, STREAM_SHUTDOWN_SYN_RESEND);
        return -1;

    } else if (p->tcph->th_flags & TH_ACK) {
        if (ssn->flags & STREAMTCP_FLAG_TIMESTAMP) {
            if (!StreamTcpValidateTimestamp(ssn, p))
                return -1;
        }

        if (PKT_IS_TOSERVER(p)) {
            SCLogDebug("ssn %p: pkt (%" PRIu32 ") is to server: SEQ "
                    "%" PRIu32 ", ACK %" PRIu32 "", ssn, p->payload_len,
                    TCP_GET_SEQ(p), TCP_GET_ACK(p));

            int retransmission = 0;
            if (StreamTcpPacketIsRetransmission(&ssn->client, p)) {
                SCLogDebug("ssn %p: packet is retransmission", ssn);
                retransmission = 1;
            }

            if (TCP_GET_SEQ(p) != ssn->client.next_seq && TCP_GET_SEQ(p) != ssn->client.next_seq + 1) {
                SCLogDebug("ssn %p: -> SEQ mismatch, packet SEQ %" PRIu32 ""
                        " != %" PRIu32 " from stream", ssn,
                        TCP_GET_SEQ(p), ssn->client.next_seq);
                StreamTcpSetEvent(p, STREAM_LASTACK_ACK_WRONG_SEQ);
                return -1;
            }

            if (StreamTcpValidateAck(ssn, &ssn->server, p) == -1) {
                SCLogDebug("ssn %p: rejecting because of invalid ack value", ssn);
                StreamTcpSetEvent(p, STREAM_LASTACK_INVALID_ACK);
                SCReturnInt(-1);
            }

            if (!retransmission) {
                StreamTcpPacketSetState(p, ssn, TCP_CLOSED);
                SCLogDebug("ssn %p: state changed to TCP_CLOSED", ssn);

                ssn->server.window = TCP_GET_WINDOW(p) << ssn->server.wscale;
            }

            StreamTcpUpdateLastAck(ssn, &ssn->server, TCP_GET_ACK(p));

            if (ssn->flags & STREAMTCP_FLAG_TIMESTAMP) {
                StreamTcpHandleTimestamp(ssn, p);
            }

            /* Update the next_seq, in case if we have missed the client
               packet and server has already received and acked it */
            if (SEQ_LT(ssn->server.next_seq, TCP_GET_ACK(p)))
                ssn->server.next_seq = TCP_GET_ACK(p);

            StreamTcpReassembleHandleSegment(tv, stt->ra_ctx, ssn,
                    &ssn->client, p, pq);
            SCLogDebug("ssn %p: =+ next SEQ %" PRIu32 ", last ACK "
                    "%" PRIu32 "", ssn, ssn->client.next_seq,
                    ssn->server.last_ack);
        }
    } else {
        SCLogDebug("ssn %p: default case", ssn);
    }

    return 0;
}

/**
 *  \brief  Function to handle the TCP_TIME_WAIT state. Upon arrival of ACK
 *          the connection goes to TCP_CLOSED state and stream memory is
 *          returned back to pool.
 *
 *  \param  tv      Thread Variable containig  input/output queue, cpu affinity
 *  \param  p       Packet which has to be handled in this TCP state.
 *  \param  stt     Strean Thread module registered to handle the stream handling
 */

static int StreamTcpPacketStateTimeWait(ThreadVars *tv, Packet *p,
                        StreamTcpThread *stt, TcpSession *ssn, PacketQueue *pq)
{
    if (ssn == NULL)
        return -1;

    if (p->tcph->th_flags & TH_RST) {
        if (!StreamTcpValidateRst(ssn, p))
            return -1;

        /* force both streams to reassemble, if necessary */
        StreamTcpPseudoPacketCreateStreamEndPacket(tv, stt, p, ssn, pq);

        StreamTcpPacketSetState(p, ssn, TCP_CLOSED);
        SCLogDebug("ssn %p: Reset received state changed to TCP_CLOSED",
                ssn);

        if (PKT_IS_TOSERVER(p)) {
            if ((p->tcph->th_flags & TH_ACK) && StreamTcpValidateAck(ssn, &ssn->server, p) == 0)
                StreamTcpUpdateLastAck(ssn, &ssn->server,
                        StreamTcpResetGetMaxAck(&ssn->server, TCP_GET_ACK(p)));

            StreamTcpUpdateLastAck(ssn, &ssn->client,
                    StreamTcpResetGetMaxAck(&ssn->client, TCP_GET_SEQ(p)));

            if (ssn->flags & STREAMTCP_FLAG_TIMESTAMP) {
                StreamTcpHandleTimestamp(ssn, p);
            }

            StreamTcpReassembleHandleSegment(tv, stt->ra_ctx, ssn,
                    &ssn->client, p, pq);
        } else {
            if ((p->tcph->th_flags & TH_ACK) && StreamTcpValidateAck(ssn, &ssn->client, p) == 0)
                StreamTcpUpdateLastAck(ssn, &ssn->client,
                        StreamTcpResetGetMaxAck(&ssn->client, TCP_GET_ACK(p)));

            StreamTcpUpdateLastAck(ssn, &ssn->server,
                    StreamTcpResetGetMaxAck(&ssn->server, TCP_GET_SEQ(p)));

            if (ssn->flags & STREAMTCP_FLAG_TIMESTAMP) {
                StreamTcpHandleTimestamp(ssn, p);
            }

            StreamTcpReassembleHandleSegment(tv, stt->ra_ctx, ssn,
                    &ssn->server, p, pq);
        }

    } else if (p->tcph->th_flags & TH_FIN) {
        /** \todo */

    } else if (p->tcph->th_flags & TH_SYN) {
        SCLogDebug("ssn (%p): SYN pkt on TimeWait", ssn);
        StreamTcpSetEvent(p, STREAM_SHUTDOWN_SYN_RESEND);
        return -1;

    } else if (p->tcph->th_flags & TH_ACK) {
        if (ssn->flags & STREAMTCP_FLAG_TIMESTAMP) {
            if (!StreamTcpValidateTimestamp(ssn, p))
                return -1;
        }

        if (PKT_IS_TOSERVER(p)) {
            SCLogDebug("ssn %p: pkt (%" PRIu32 ") is to server: SEQ "
                    "%" PRIu32 ", ACK %" PRIu32 "", ssn, p->payload_len,
                    TCP_GET_SEQ(p), TCP_GET_ACK(p));
            int retransmission = 0;
            if (StreamTcpPacketIsRetransmission(&ssn->client, p)) {
                SCLogDebug("ssn %p: packet is retransmission", ssn);
                retransmission = 1;

            } else if (TCP_GET_SEQ(p) != ssn->client.next_seq && TCP_GET_SEQ(p) != ssn->client.next_seq+1) {
                SCLogDebug("ssn %p: -> SEQ mismatch, packet SEQ %" PRIu32 ""
                        " != %" PRIu32 " from stream", ssn,
                        TCP_GET_SEQ(p), ssn->client.next_seq);
                StreamTcpSetEvent(p, STREAM_TIMEWAIT_ACK_WRONG_SEQ);
                return -1;
            }

            if (StreamTcpValidateAck(ssn, &ssn->server, p) == -1) {
                SCLogDebug("ssn %p: rejecting because of invalid ack value", ssn);
                StreamTcpSetEvent(p, STREAM_TIMEWAIT_INVALID_ACK);
                SCReturnInt(-1);
            }

            if (!retransmission) {
                StreamTcpPacketSetState(p, ssn, TCP_CLOSED);
                SCLogDebug("ssn %p: state changed to TCP_CLOSED", ssn);

                ssn->server.window = TCP_GET_WINDOW(p) << ssn->server.wscale;
            }

            StreamTcpUpdateLastAck(ssn, &ssn->server, TCP_GET_ACK(p));

            if (ssn->flags & STREAMTCP_FLAG_TIMESTAMP) {
                StreamTcpHandleTimestamp(ssn, p);
            }

            /* Update the next_seq, in case if we have missed the client
               packet and server has already received and acked it */
            if (SEQ_LT(ssn->server.next_seq, TCP_GET_ACK(p)))
                ssn->server.next_seq = TCP_GET_ACK(p);

            StreamTcpReassembleHandleSegment(tv, stt->ra_ctx, ssn,
                    &ssn->client, p, pq);
            SCLogDebug("ssn %p: =+ next SEQ %" PRIu32 ", last ACK "
                    "%" PRIu32 "", ssn, ssn->client.next_seq,
                    ssn->server.last_ack);

            StreamTcpPseudoPacketCreateStreamEndPacket(tv, stt, p, ssn, pq);
        } else {
            SCLogDebug("ssn %p: pkt (%" PRIu32 ") is to client: SEQ "
                    "%" PRIu32 ", ACK %" PRIu32 "", ssn, p->payload_len,
                    TCP_GET_SEQ(p), TCP_GET_ACK(p));
            int retransmission = 0;
            if (StreamTcpPacketIsRetransmission(&ssn->server, p)) {
                SCLogDebug("ssn %p: packet is retransmission", ssn);
                retransmission = 1;
            } else if (TCP_GET_SEQ(p) != ssn->server.next_seq && TCP_GET_SEQ(p) != ssn->server.next_seq+1) {
                if (p->payload_len > 0 && TCP_GET_SEQ(p) == ssn->server.last_ack) {
                    SCLogDebug("ssn %p: -> retransmission", ssn);
                    SCReturnInt(0);
                } else {
                    SCLogDebug("ssn %p: -> SEQ mismatch, packet SEQ %" PRIu32 ""
                            " != %" PRIu32 " from stream", ssn,
                            TCP_GET_SEQ(p), ssn->server.next_seq);
                    StreamTcpSetEvent(p, STREAM_TIMEWAIT_ACK_WRONG_SEQ);
                    return -1;
                }
            }

            if (StreamTcpValidateAck(ssn, &ssn->client, p) == -1) {
                SCLogDebug("ssn %p: rejecting because of invalid ack value", ssn);
                StreamTcpSetEvent(p, STREAM_TIMEWAIT_INVALID_ACK);
                SCReturnInt(-1);
            }

            if (!retransmission) {
                StreamTcpPacketSetState(p, ssn, TCP_CLOSED);
                SCLogDebug("ssn %p: state changed to TCP_CLOSED", ssn);

                ssn->client.window = TCP_GET_WINDOW(p) << ssn->client.wscale;
            }

            StreamTcpUpdateLastAck(ssn, &ssn->client, TCP_GET_ACK(p));

            if (ssn->flags & STREAMTCP_FLAG_TIMESTAMP) {
                StreamTcpHandleTimestamp(ssn, p);
            }

            /* Update the next_seq, in case if we have missed the client
               packet and server has already received and acked it */
            if (SEQ_LT(ssn->client.next_seq, TCP_GET_ACK(p)))
                ssn->client.next_seq = TCP_GET_ACK(p);

            StreamTcpReassembleHandleSegment(tv, stt->ra_ctx, ssn,
                    &ssn->server, p, pq);
            SCLogDebug("ssn %p: =+ next SEQ %" PRIu32 ", last ACK "
                    "%" PRIu32 "", ssn, ssn->server.next_seq,
                    ssn->client.last_ack);

            StreamTcpPseudoPacketCreateStreamEndPacket(tv, stt, p, ssn, pq);
        }

    } else {
        SCLogDebug("ssn %p: default case", ssn);
    }

    return 0;
}

/**
 *  \retval 1 packet is a keep alive pkt
 *  \retval 0 packet is not a keep alive pkt
 */
static int StreamTcpPacketIsKeepAlive(TcpSession *ssn, Packet *p)
{
    TcpStream *stream = NULL, *ostream = NULL;
    uint32_t seq;
    uint32_t ack;

    if (p->flags & PKT_PSEUDO_STREAM_END)
        return 0;

    /*
       rfc 1122:
       An implementation SHOULD send a keep-alive segment with no
       data; however, it MAY be configurable to send a keep-alive
       segment containing one garbage octet, for compatibility with
       erroneous TCP implementations.
     */
    if (p->payload_len > 1)
        return 0;

    if ((p->tcph->th_flags & (TH_SYN|TH_FIN|TH_RST)) != 0) {
        return 0;
    }

    if (PKT_IS_TOSERVER(p)) {
        stream = &ssn->client;
        ostream = &ssn->server;
    } else {
        stream = &ssn->server;
        ostream = &ssn->client;
    }

    seq = TCP_GET_SEQ(p);
    ack = TCP_GET_ACK(p);

    if (ack == ostream->last_ack && seq == (stream->next_seq - 1)) {
        SCLogDebug("packet is TCP keep-alive: %"PRIu64, p->pcap_cnt);
        stream->flags |= STREAMTCP_STREAM_FLAG_KEEPALIVE;
        return 1;
    }
    SCLogDebug("seq %u (%u), ack %u (%u)", seq,  (stream->next_seq - 1), ack, ostream->last_ack);
    return 0;
}

/**
 *  \retval 1 packet is a keep alive ACK pkt
 *  \retval 0 packet is not a keep alive ACK pkt
 */
static int StreamTcpPacketIsKeepAliveACK(TcpSession *ssn, Packet *p)
{
    TcpStream *stream = NULL, *ostream = NULL;
    uint32_t seq;
    uint32_t ack;
    uint32_t pkt_win;

    if (p->flags & PKT_PSEUDO_STREAM_END)
        return 0;
    /* should get a normal ACK to a Keep Alive */
    if (p->payload_len > 0)
        return 0;

    if ((p->tcph->th_flags & (TH_SYN|TH_FIN|TH_RST)) != 0)
        return 0;

    if (TCP_GET_WINDOW(p) == 0)
        return 0;

    if (PKT_IS_TOSERVER(p)) {
        stream = &ssn->client;
        ostream = &ssn->server;
    } else {
        stream = &ssn->server;
        ostream = &ssn->client;
    }

    seq = TCP_GET_SEQ(p);
    ack = TCP_GET_ACK(p);

    pkt_win = TCP_GET_WINDOW(p) << ostream->wscale;
    if (pkt_win != ostream->window)
        return 0;

    if ((ostream->flags & STREAMTCP_STREAM_FLAG_KEEPALIVE) && ack == ostream->last_ack && seq == stream->next_seq) {
        SCLogDebug("packet is TCP keep-aliveACK: %"PRIu64, p->pcap_cnt);
        ostream->flags &= ~STREAMTCP_STREAM_FLAG_KEEPALIVE;
        return 1;
    }
    SCLogDebug("seq %u (%u), ack %u (%u) FLAG_KEEPALIVE: %s", seq, stream->next_seq, ack, ostream->last_ack,
            ostream->flags & STREAMTCP_STREAM_FLAG_KEEPALIVE ? "set" : "not set");
    return 0;
}

static void StreamTcpClearKeepAliveFlag(TcpSession *ssn, Packet *p)
{
    TcpStream *stream = NULL;

    if (p->flags & PKT_PSEUDO_STREAM_END)
        return;

    if (PKT_IS_TOSERVER(p)) {
        stream = &ssn->client;
    } else {
        stream = &ssn->server;
    }

    if (stream->flags & STREAMTCP_STREAM_FLAG_KEEPALIVE) {
        stream->flags &= ~STREAMTCP_STREAM_FLAG_KEEPALIVE;
        SCLogDebug("FLAG_KEEPALIVE cleared");
    }
}

/**
 *  \retval 1 packet is a window update pkt
 *  \retval 0 packet is not a window update pkt
 */
static int StreamTcpPacketIsWindowUpdate(TcpSession *ssn, Packet *p)
{
    TcpStream *stream = NULL, *ostream = NULL;
    uint32_t seq;
    uint32_t ack;
    uint32_t pkt_win;

    if (p->flags & PKT_PSEUDO_STREAM_END)
        return 0;

    if (ssn->state < TCP_ESTABLISHED)
        return 0;

    if (p->payload_len > 0)
        return 0;

    if ((p->tcph->th_flags & (TH_SYN|TH_FIN|TH_RST)) != 0)
        return 0;

    if (TCP_GET_WINDOW(p) == 0)
        return 0;

    if (PKT_IS_TOSERVER(p)) {
        stream = &ssn->client;
        ostream = &ssn->server;
    } else {
        stream = &ssn->server;
        ostream = &ssn->client;
    }

    seq = TCP_GET_SEQ(p);
    ack = TCP_GET_ACK(p);

    pkt_win = TCP_GET_WINDOW(p) << ostream->wscale;
    if (pkt_win == ostream->window)
        return 0;

    if (ack == ostream->last_ack && seq == stream->next_seq) {
        SCLogDebug("packet is TCP window update: %"PRIu64, p->pcap_cnt);
        return 1;
    }
    SCLogDebug("seq %u (%u), ack %u (%u)", seq, stream->next_seq, ack, ostream->last_ack);
    return 0;
}

/**
 *  Try to detect whether a packet is a valid FIN 4whs final ack.
 *
 */
static int StreamTcpPacketIsFinShutdownAck(TcpSession *ssn, Packet *p)
{
    TcpStream *stream = NULL, *ostream = NULL;
    uint32_t seq;
    uint32_t ack;

    if (p->flags & PKT_PSEUDO_STREAM_END)
        return 0;
    if (!(ssn->state == TCP_TIME_WAIT || ssn->state == TCP_CLOSE_WAIT || ssn->state == TCP_LAST_ACK))
        return 0;
    if (p->tcph->th_flags != TH_ACK)
        return 0;
    if (p->payload_len != 0)
        return 0;

    if (PKT_IS_TOSERVER(p)) {
        stream = &ssn->client;
        ostream = &ssn->server;
    } else {
        stream = &ssn->server;
        ostream = &ssn->client;
    }

    seq = TCP_GET_SEQ(p);
    ack = TCP_GET_ACK(p);

    SCLogDebug("%"PRIu64", seq %u ack %u stream->next_seq %u ostream->next_seq %u",
            p->pcap_cnt, seq, ack, stream->next_seq, ostream->next_seq);

    if (SEQ_EQ(stream->next_seq + 1, seq) && SEQ_EQ(ack, ostream->next_seq + 1)) {
        return 1;
    }
    return 0;
}

/**
 *  Try to detect packets doing bad window updates
 *
 *  See bug 1238.
 *
 *  Find packets that are unexpected, and shrink the window to the point
 *  where the packets we do expect are rejected for being out of window.
 *
 *  The logic we use here is:
 *  - packet seq > next_seq
 *  - packet ack > next_seq (packet acks unseen data)
 *  - packet shrinks window more than it's own data size
 *  - packet shrinks window more than the diff between it's ack and the
 *    last_ack value
 *
 *  Packets coming in after packet loss can look quite a bit like this.
 */
static int StreamTcpPacketIsBadWindowUpdate(TcpSession *ssn, Packet *p)
{
    TcpStream *stream = NULL, *ostream = NULL;
    uint32_t seq;
    uint32_t ack;
    uint32_t pkt_win;

    if (p->flags & PKT_PSEUDO_STREAM_END)
        return 0;

    if (ssn->state < TCP_ESTABLISHED || ssn->state == TCP_CLOSED)
        return 0;

    if ((p->tcph->th_flags & (TH_SYN|TH_FIN|TH_RST)) != 0)
        return 0;

    if (PKT_IS_TOSERVER(p)) {
        stream = &ssn->client;
        ostream = &ssn->server;
    } else {
        stream = &ssn->server;
        ostream = &ssn->client;
    }

    seq = TCP_GET_SEQ(p);
    ack = TCP_GET_ACK(p);

    pkt_win = TCP_GET_WINDOW(p) << ostream->wscale;

    if (pkt_win < ostream->window) {
        uint32_t diff = ostream->window - pkt_win;
        if (diff > p->payload_len &&
                SEQ_GT(ack, ostream->next_seq) &&
                SEQ_GT(seq, stream->next_seq))
        {
            SCLogDebug("%"PRIu64", pkt_win %u, stream win %u, diff %u, dsize %u",
                p->pcap_cnt, pkt_win, ostream->window, diff, p->payload_len);
            SCLogDebug("%"PRIu64", pkt_win %u, stream win %u",
                p->pcap_cnt, pkt_win, ostream->window);
            SCLogDebug("%"PRIu64", seq %u ack %u ostream->next_seq %u ostream->last_ack %u, ostream->next_win %u, diff %u (%u)",
                    p->pcap_cnt, seq, ack, ostream->next_seq, ostream->last_ack, ostream->next_win,
                    ostream->next_seq - ostream->last_ack, stream->next_seq - stream->last_ack);

            /* get the expected window shrinking from looking at ack vs last_ack.
             * Observed a lot of just a little overrunning that value. So added some
             * margin that is still ok. To make sure this isn't a loophole to still
             * close the window, this is limited to windows above 1024. Both values
             * are rather arbitrary. */
            uint32_t adiff = ack - ostream->last_ack;
            if (((pkt_win > 1024) && (diff > (adiff + 32))) ||
                ((pkt_win <= 1024) && (diff > adiff)))
            {
                SCLogDebug("pkt ACK %u is %u bytes beyond last_ack %u, shrinks window by %u "
                        "(allowing 32 bytes extra): pkt WIN %u", ack, adiff, ostream->last_ack, diff, pkt_win);
                SCLogDebug("%u - %u = %u (state %u)", diff, adiff, diff - adiff, ssn->state);
                StreamTcpSetEvent(p, STREAM_PKT_BAD_WINDOW_UPDATE);
                return 1;
            }
        }

    }
    SCLogDebug("seq %u (%u), ack %u (%u)", seq, stream->next_seq, ack, ostream->last_ack);
    return 0;
}

/* flow is and stays locked.
*FlowWorker -> StreamTcp -> StreamTcpPacket;
StreamTcpPacket完成实际的工作，流程为：
1.存储在flow->protoctx中的TcpSession指针，变量名为ssn。
2.包的ACK字段不为空，然而ACK位却没设置，则设置STREAM_PKT_BROKEN_ACK事件。
3.StreamTcpCheckFlowDrops检查这个流是否已经被设置了drop action，若是则给该包也打上drop标记，然后返回。
4.ssn为NULL，或者其state为TCP_NONE，说明这个流还没有session或者session刚建立，则调用StreamTcpPacketStateNone处理：
   (1)若为RST包，说明这个这个流还没建立session就已经要结束了，添加STREAM_RST_BUT_NO_SESSION事件并返回。
   (2)若为FIN包，与上面类似，添加STREAM_FIN_BUT_NO_SESSION事件并返回。
   (3)若为SYN/ACK包，说明之前的SYN包没收到，若midstream和async_oneside配置都没打开，就返回。否则：
      a.若ssn为NULL，则先调用StreamTcpNewSession新建一个session。
      b.给session添加TCP_SYN_RECV状态，并打上一些midestream标志。
      c.设置session中的server和client相关数据（类型都为TcpStream），包括初始序列号、下一个序列号、窗口大小、时间戳等，另外还会设置是否支持SACK机制。
   (4)若为SYN包，这是最正常的情况，处理情况与上面类似，主要区别：给session添加的是TCP_SYN_SENT状态。
   (5)若为ACK包，说明之前的SYN/ACK、ACK都没，若midstream没打开就返回，否则处理与上面类似，主要区别：给session添加的是TCP_ESTABLISHED状态。
会调用StreamTcpReassembleHandleSegment进行重组，因为这个包可能包含协议数据。
会给client和server都默认打开SACK标志。
5.否则，说明这个流已经建立session了，流程如下：
  (1)如果这个流是syn/ack类型的midstream，则反转这个包的方向。因为流的初始方向应该为SYN包的方向，而不是SYN/ACK的方向。
  (2)判断这个包是否是窗口更新（window update）包。目前没有根据这个信息做任何动作。
  (3)若这个包是keep-alive包或这种包的ack，则跳过下面一步处理。
  (4)根据session的state进行不同操作：
     a.TCP_SYN_SENT -> StreamTcpPacketStateSynSent;
     b.TCP_SYN_RECV -> StreamTcpPacketStateSynRecv;
     c.TCP_ESTABLISHED -> StreamTcpPacketStateEstablished;
     d.TCP_FIN_WAIT1 -> StreamTcpPacketStateFinWait;
     e.TCP_FIN_WAIT2 -> StreamTcpPacketStateFinWait2;
     f.TCP_CLOSING -> StreamTcpPacketStateClosing;
     g.TCP_CLOSE_WAIT -> StreamTcpPacketStateCloseWait;
     h.TCP_LAST_ACK -> StreamTcpPacketStateLastAck;
     i.TCP_TIME_WAIT -> StreamTcpPacketStateTimeWait;
     j.TCP_CLOSED：说明client在结束一个session后，又新建了一个session且端口重用了。若这是一个SYN包，则可以重用这个TCPSession，进行一些重初始化，并把stat设为TCP_NONE，然后调用StreamTcpPacketStateNone去处理。
  (5)若session状态为ESTABLISHED及以后的，则把包的状态设为PKT_STREAM_EST。
  (6)若包所在的这一端（client或server）发送过FIN或RST，则把包状态设置为PKT_STREAM_EOF。
6.处理pseudo packet。目前只有在收到RST包时会产生，用来强制另一方向进行重组。
7.正常情况下，到这里就返回了。但如果之前有发现出错的数据包，则跳转到最后的error标号后执行：
  (1)若有pseudo packet，就把它们enqueue到post_queue中去，防止丢失，下次就会处理。
  (2)若包有PKT_STREAM_MODIFIED标志，说明被自身模块修改过，就重新计算校验和（为什么需要？）。
  (3)若stream_inline打开了，就给数据包打上DROP标记，后续将会丢弃这个数据包。
*/
int StreamTcpPacket (ThreadVars *tv, Packet *p, StreamTcpThread *stt,
                     PacketQueue *pq)
{
    SCEnter();

    DEBUG_ASSERT_FLOW_LOCKED(p->flow);

    SCLogDebug("p->pcap_cnt %"PRIu64, p->pcap_cnt);

    /* assign the thread id to the flow */
    if (unlikely(p->flow->thread_id == 0)) {
        p->flow->thread_id = (FlowThreadId)tv->id;
#ifdef DEBUG
    } else if (unlikely((FlowThreadId)tv->id != p->flow->thread_id)) {
        SCLogDebug("wrong thread: flow has %u, we are %d", p->flow->thread_id, tv->id);
#endif
    }

    TcpSession *ssn = (TcpSession *)p->flow->protoctx;

    /* track TCP flags */
    if (ssn != NULL) {
        ssn->tcp_packet_flags |= p->tcph->th_flags;
        if (PKT_IS_TOSERVER(p))
            ssn->client.tcp_flags |= p->tcph->th_flags;
        else if (PKT_IS_TOCLIENT(p))
            ssn->server.tcp_flags |= p->tcph->th_flags;
    }

    /* update counters */
    if ((p->tcph->th_flags & (TH_SYN|TH_ACK)) == (TH_SYN|TH_ACK)) {
        StatsIncr(tv, stt->counter_tcp_synack);
    } else if (p->tcph->th_flags & (TH_SYN)) {
        StatsIncr(tv, stt->counter_tcp_syn);
    }
    if (p->tcph->th_flags & (TH_RST)) {
        StatsIncr(tv, stt->counter_tcp_rst);
    }

    /* broken TCP http://ask.wireshark.org/questions/3183/acknowledgment-number-broken-tcp-the-acknowledge-field-is-nonzero-while-the-ack-flag-is-not-set */
    if (!(p->tcph->th_flags & TH_ACK) && TCP_GET_ACK(p) != 0) {
        StreamTcpSetEvent(p, STREAM_PKT_BROKEN_ACK);
    }

    /* If we are on IPS mode, and got a drop action triggered from
     * the IP only module, or from a reassembled msg and/or from an
     * applayer detection, then drop the rest of the packets of the
     * same stream and avoid inspecting it any further */
    if (StreamTcpCheckFlowDrops(p) == 1) {
        SCLogDebug("This flow/stream triggered a drop rule");
        FlowSetNoPacketInspectionFlag(p->flow);
        DecodeSetNoPacketInspectionFlag(p);
        StreamTcpDisableAppLayer(p->flow);
        PACKET_DROP(p);
        /* return the segments to the pool */
        StreamTcpSessionPktFree(p);
        SCReturnInt(0);
    }

    if (ssn == NULL || ssn->state == TCP_NONE) {
			/*
        	1. SYN数据包是tcp连接中的首个数据包，由client发送给server，flow结构刚刚分配，session还没有创建，这时会进入StreamTcpPacketStateNone函数。这里我们不关注midstream和async_onside，只关注正常的三次握手，也就是这时进入只有SYN标记的分支。
        	这里首先调用StreamTcpNewSession获得一个新的session，内部成员只进行了初始化，很简单。
        	由于一个SYN包已经发送出来，session状态设置为TCP_SYN_SENT。
        	更新session中client和server成员中tcp头相关的值，比如isn、next_seq、base_seq、last_ts、last_pkt_ts、flags、window、wscale等，这部分是tcp协议头相关，不做更多关注。
			*/
        if (StreamTcpPacketStateNone(tv, p, stt, ssn, &stt->pseudo_queue) == -1) {
            goto error;
        }

        if (ssn != NULL)
            SCLogDebug("ssn->alproto %"PRIu16"", p->flow->alproto);
    } else {
        /* special case for PKT_PSEUDO_STREAM_END packets:
         * bypass the state handling and various packet checks,
         * we care about reassembly here. */
        if (p->flags & PKT_PSEUDO_STREAM_END) {
            if (PKT_IS_TOCLIENT(p)) {
                ssn->client.last_ack = TCP_GET_ACK(p);
                StreamTcpReassembleHandleSegment(tv, stt->ra_ctx, ssn,
                        &ssn->server, p, pq);
            } else {
                ssn->server.last_ack = TCP_GET_ACK(p);
                StreamTcpReassembleHandleSegment(tv, stt->ra_ctx, ssn,
                        &ssn->client, p, pq);
            }
            /* straight to 'skip' as we already handled reassembly */
            goto skip;
        }

        /* check if the packet is in right direction, when we missed the
           SYN packet and picked up midstream session. */
        if (ssn->flags & STREAMTCP_FLAG_MIDSTREAM_SYNACK)
            StreamTcpPacketSwitchDir(ssn, p);

        if (StreamTcpPacketIsKeepAlive(ssn, p) == 1) {
            goto skip;
        }
        if (StreamTcpPacketIsKeepAliveACK(ssn, p) == 1) {
            StreamTcpClearKeepAliveFlag(ssn, p);
            goto skip;
        }
        StreamTcpClearKeepAliveFlag(ssn, p);

        /* if packet is not a valid window update, check if it is perhaps
         * a bad window update that we should ignore (and alert on) */
        if (StreamTcpPacketIsFinShutdownAck(ssn, p) == 0)
            if (StreamTcpPacketIsWindowUpdate(ssn, p) == 0)
                if (StreamTcpPacketIsBadWindowUpdate(ssn,p))
                    goto skip;

        switch (ssn->state) {
					/*
                	2. SYN/ACK数据包是tcp连接中的第二个数据包，由server发送给client。
                	这时session状态是TCP_SYN_SENT,
                	session状态更新为TCP_SYN_RECV。
                	更新session中client和server成员中tcp头相关的值。

                	Stream Tracking:
						那么，根据不同session状态处理数据包的那一簇函数StreamTcpPacketState*，做了什么事情呢？
						简要来说，这些函数对不同session当前所属的状态进行了跟踪，并相应地进行错误检测、事件记录以及状态更新。
					以StreamTcpPacketStateSynSent为例，处理流程为：
                	*/
            case TCP_SYN_SENT:
                if(StreamTcpPacketStateSynSent(tv, p, stt, ssn, &stt->pseudo_queue)) {
                    goto error;
                }
                break;
            case TCP_SYN_RECV:
					/*
                	3. 从第三个数据包开始，均为ACK数据包（这里先不考虑RST和FIN的情况），区别在于session状态的不同。第三个数据包收到时session状态为TCP_SYN_RECV
                	3.1. 更新session和其成员client与server的tcp协议头相关字段。
                	3.2. 更新session状态为TCP_ESTABLISHED。
                	3.3. 调用函数StreamTcpReassembleHandleSegment，这个函数从名字可以看出开始正式处理tcp数据包中可能携带的数据，并做reassembly。
					*/
                if(StreamTcpPacketStateSynRecv(tv, p, stt, ssn, &stt->pseudo_queue)) {
                    goto error;
                }
                break;
            case TCP_ESTABLISHED:
					/*
                	4. 从第四个数据包开始，session状态为TCP_ESTABLISHED
                	更新session和其成员client与server的tcp协议头相关字段.
                	调用函数StreamTcpReassembleHandleSegmen
					*/
                if(StreamTcpPacketStateEstablished(tv, p, stt, ssn, &stt->pseudo_queue)) {
                    goto error;
                }
                break;
            case TCP_FIN_WAIT1:
                if(StreamTcpPacketStateFinWait1(tv, p, stt, ssn, &stt->pseudo_queue)) {
                    goto error;
                }
                break;
            case TCP_FIN_WAIT2:
                if(StreamTcpPacketStateFinWait2(tv, p, stt, ssn, &stt->pseudo_queue)) {
                    goto error;
                }
                break;
            case TCP_CLOSING:
                if(StreamTcpPacketStateClosing(tv, p, stt, ssn, &stt->pseudo_queue)) {
                    goto error;
                }
                break;
            case TCP_CLOSE_WAIT:
                if(StreamTcpPacketStateCloseWait(tv, p, stt, ssn, &stt->pseudo_queue)) {
                    goto error;
                }
                break;
            case TCP_LAST_ACK:
                if(StreamTcpPacketStateLastAck(tv, p, stt, ssn, &stt->pseudo_queue)) {
                    goto error;
                }
                break;
            case TCP_TIME_WAIT:
                if(StreamTcpPacketStateTimeWait(tv, p, stt, ssn, &stt->pseudo_queue)) {
                    goto error;
                }
                break;
            case TCP_CLOSED:
                /* TCP session memory is not returned to pool until timeout. */
                SCLogDebug("packet received on closed state");
                break;
            default:
                SCLogDebug("packet received on default state");
                break;
        }
    skip:

        if (ssn->state >= TCP_ESTABLISHED) {
            p->flags |= PKT_STREAM_EST;
        }
    }

    /* deal with a pseudo packet that is created upon receiving a RST
     * segment. To be sure we process both sides of the connection, we
     * inject a fake packet into the system, forcing reassembly of the
     * opposing direction.
     * There should be only one, but to be sure we do a while loop. */
    if (ssn != NULL) {
        while (stt->pseudo_queue.len > 0) {
            SCLogDebug("processing pseudo packet / stream end");
            Packet *np = PacketDequeue(&stt->pseudo_queue);
            if (np != NULL) {
                /* process the opposing direction of the original packet */
                if (PKT_IS_TOSERVER(np)) {
                    SCLogDebug("pseudo packet is to server");
                    StreamTcpReassembleHandleSegment(tv, stt->ra_ctx, ssn,
                            &ssn->client, np, NULL);
                } else {
                    SCLogDebug("pseudo packet is to client");
                    StreamTcpReassembleHandleSegment(tv, stt->ra_ctx, ssn,
                            &ssn->server, np, NULL);
                }

                /* enqueue this packet so we inspect it in detect etc */
                PacketEnqueue(pq, np);
            }
            SCLogDebug("processing pseudo packet / stream end done");
        }

        /* recalc the csum on the packet if it was modified */
        if (p->flags & PKT_STREAM_MODIFIED) {
            ReCalculateChecksum(p);
        }

        /* check for conditions that may make us not want to log this packet */

        /* streams that hit depth */
        if ((ssn->client.flags & STREAMTCP_STREAM_FLAG_DEPTH_REACHED) &&
             (ssn->server.flags & STREAMTCP_STREAM_FLAG_DEPTH_REACHED))
        {
            /* we can call bypass callback, if enabled */
            if (StreamTcpBypassEnabled()) {
                PacketBypassCallback(p);
            }
        }

        if ((ssn->client.flags & STREAMTCP_STREAM_FLAG_DEPTH_REACHED) ||
             (ssn->server.flags & STREAMTCP_STREAM_FLAG_DEPTH_REACHED))
        {
            p->flags |= PKT_STREAM_NOPCAPLOG;
        }

        /* encrypted packets */
        if ((PKT_IS_TOSERVER(p) && (ssn->client.flags & STREAMTCP_STREAM_FLAG_NOREASSEMBLY)) ||
            (PKT_IS_TOCLIENT(p) && (ssn->server.flags & STREAMTCP_STREAM_FLAG_NOREASSEMBLY)))
        {
            p->flags |= PKT_STREAM_NOPCAPLOG;
        }

        if ((ssn->client.flags & STREAMTCP_STREAM_FLAG_NOREASSEMBLY) &&
            (ssn->server.flags & STREAMTCP_STREAM_FLAG_NOREASSEMBLY))
        {
            /* we can call bypass callback, if enabled */
            if (StreamTcpBypassEnabled()) {
                PacketBypassCallback(p);
            }
        }
    }

    SCReturnInt(0);

error:
    /* make sure we don't leave packets in our pseudo queue */
    while (stt->pseudo_queue.len > 0) {
        Packet *np = PacketDequeue(&stt->pseudo_queue);
        if (np != NULL) {
            PacketEnqueue(pq, np);
        }
    }

    /* recalc the csum on the packet if it was modified */
    if (p->flags & PKT_STREAM_MODIFIED) {
        ReCalculateChecksum(p);
    }

    if (StreamTcpInlineMode()) {
        PACKET_DROP(p);
    }
    SCReturnInt(-1);
}

/**
 *  \brief  Function to validate the checksum of the received packet. If the
 *          checksum is invalid, packet will be dropped, as the end system will
 *          also drop the packet.
 *
 *  \param  p       Packet of which checksum has to be validated
 *  \retval  1 if the checksum is valid, otherwise 0
 */
static inline int StreamTcpValidateChecksum(Packet *p)
{
    int ret = 1;

    if (p->flags & PKT_IGNORE_CHECKSUM)
        return ret;

    if (p->level4_comp_csum == -1) {
        if (PKT_IS_IPV4(p)) {
            p->level4_comp_csum = TCPCalculateChecksum(p->ip4h->s_ip_addrs,
                                                       (uint16_t *)p->tcph,
                                                       (p->payload_len +
                                                        TCP_GET_HLEN(p)));
        } else if (PKT_IS_IPV6(p)) {
            p->level4_comp_csum = TCPV6CalculateChecksum(p->ip6h->s_ip6_addrs,
                                                         (uint16_t *)p->tcph,
                                                         (p->payload_len +
                                                          TCP_GET_HLEN(p)));
        }
    }

    if (p->level4_comp_csum != p->tcph->th_sum) {
        ret = 0;
        SCLogDebug("Checksum of received packet %p is invalid",p);
        if (p->livedev) {
            (void) SC_ATOMIC_ADD(p->livedev->invalid_checksums, 1);
        } else if (p->pcap_cnt) {
            PcapIncreaseInvalidChecksum();
        }
    }

    return ret;
}

/** \internal
 *  \brief check if a packet is a valid stream started
 *  \retval bool true/false */
 /*判断包是否是会话的开始*/
static int TcpSessionPacketIsStreamStarter(const Packet *p)
{
	/*包的flags为TH_SYN返回1.*/
    if (p->tcph->th_flags == TH_SYN) {
        SCLogDebug("packet %"PRIu64" is a stream starter: %02x", p->pcap_cnt, p->tcph->th_flags);
        return 1;
    }

	/*中间流且包的标志为TH_SYN|TH_ACK，返回1.*/
    if (stream_config.midstream == TRUE || stream_config.async_oneside == TRUE) {
        if (p->tcph->th_flags == (TH_SYN|TH_ACK)) {
            SCLogDebug("packet %"PRIu64" is a midstream stream starter: %02x", p->pcap_cnt, p->tcph->th_flags);
            return 1;
        }
    }
    return 0;
}

/** \internal
 *  \brief Check if Flow and TCP SSN allow this flow/tuple to be reused
 *  \retval bool true yes reuse, false no keep tracking old ssn */
static int TcpSessionReuseDoneEnoughSyn(const Packet *p, const Flow *f, const TcpSession *ssn)
{
    if (FlowGetPacketDirection(f, p) == TOSERVER) {
        if (ssn == NULL) {
            SCLogDebug("steam starter packet %"PRIu64", ssn %p null. No reuse.", p->pcap_cnt, ssn);
            return 0;
        }
        if (SEQ_EQ(ssn->client.isn, TCP_GET_SEQ(p))) {
            SCLogDebug("steam starter packet %"PRIu64", ssn %p. Packet SEQ == Stream ISN. Retransmission. Don't reuse.", p->pcap_cnt, ssn);
            return 0;
        }
        if (ssn->state >= TCP_LAST_ACK) {
            SCLogDebug("steam starter packet %"PRIu64", ssn %p state >= TCP_LAST_ACK (%u). Reuse.", p->pcap_cnt, ssn, ssn->state);
            return 1;
        }
        if (ssn->state == TCP_NONE) {
            SCLogDebug("steam starter packet %"PRIu64", ssn %p state == TCP_NONE (%u). Reuse.", p->pcap_cnt, ssn, ssn->state);
            return 1;
        }
        if (ssn->state < TCP_LAST_ACK) {
            SCLogDebug("steam starter packet %"PRIu64", ssn %p state < TCP_LAST_ACK (%u). Don't reuse.", p->pcap_cnt, ssn, ssn->state);
            return 0;
        }

    } else {
        if (ssn == NULL) {
            SCLogDebug("steam starter packet %"PRIu64", ssn %p null. Reuse.", p->pcap_cnt, ssn);
            return 1;
        }
        if (ssn->state >= TCP_LAST_ACK) {
            SCLogDebug("steam starter packet %"PRIu64", ssn %p state >= TCP_LAST_ACK (%u). Reuse.", p->pcap_cnt, ssn, ssn->state);
            return 1;
        }
        if (ssn->state == TCP_NONE) {
            SCLogDebug("steam starter packet %"PRIu64", ssn %p state == TCP_NONE (%u). Reuse.", p->pcap_cnt, ssn, ssn->state);
            return 1;
        }
        if (ssn->state < TCP_LAST_ACK) {
            SCLogDebug("steam starter packet %"PRIu64", ssn %p state < TCP_LAST_ACK (%u). Don't reuse.", p->pcap_cnt, ssn, ssn->state);
            return 0;
        }
    }

    SCLogDebug("default: how did we get here?");
    return 0;
}

/** \internal
 *  \brief check if ssn is done enough for reuse by syn/ack
 *  \note should only be called if midstream is enabled
 */
static int TcpSessionReuseDoneEnoughSynAck(const Packet *p, const Flow *f, const TcpSession *ssn)
{
    if (FlowGetPacketDirection(f, p) == TOCLIENT) {
        if (ssn == NULL) {
            SCLogDebug("steam starter packet %"PRIu64", ssn %p null. No reuse.", p->pcap_cnt, ssn);
            return 0;
        }
        if (SEQ_EQ(ssn->server.isn, TCP_GET_SEQ(p))) {
            SCLogDebug("steam starter packet %"PRIu64", ssn %p. Packet SEQ == Stream ISN. Retransmission. Don't reuse.", p->pcap_cnt, ssn);
            return 0;
        }
        if (ssn->state >= TCP_LAST_ACK) {
            SCLogDebug("steam starter packet %"PRIu64", ssn %p state >= TCP_LAST_ACK (%u). Reuse.", p->pcap_cnt, ssn, ssn->state);
            return 1;
        }
        if (ssn->state == TCP_NONE) {
            SCLogDebug("steam starter packet %"PRIu64", ssn %p state == TCP_NONE (%u). Reuse.", p->pcap_cnt, ssn, ssn->state);
            return 1;
        }
        if (ssn->state < TCP_LAST_ACK) {
            SCLogDebug("steam starter packet %"PRIu64", ssn %p state < TCP_LAST_ACK (%u). Don't reuse.", p->pcap_cnt, ssn, ssn->state);
            return 0;
        }

    } else {
        if (ssn == NULL) {
            SCLogDebug("steam starter packet %"PRIu64", ssn %p null. Reuse.", p->pcap_cnt, ssn);
            return 1;
        }
        if (ssn->state >= TCP_LAST_ACK) {
            SCLogDebug("steam starter packet %"PRIu64", ssn %p state >= TCP_LAST_ACK (%u). Reuse.", p->pcap_cnt, ssn, ssn->state);
            return 1;
        }
        if (ssn->state == TCP_NONE) {
            SCLogDebug("steam starter packet %"PRIu64", ssn %p state == TCP_NONE (%u). Reuse.", p->pcap_cnt, ssn, ssn->state);
            return 1;
        }
        if (ssn->state < TCP_LAST_ACK) {
            SCLogDebug("steam starter packet %"PRIu64", ssn %p state < TCP_LAST_ACK (%u). Don't reuse.", p->pcap_cnt, ssn, ssn->state);
            return 0;
        }
    }

    SCLogDebug("default: how did we get here?");
    return 0;
}

/** \brief Check if SSN is done enough for reuse
 *
 *  Reuse means a new TCP session reuses the tuple (flow in suri)
 *
 *  \retval bool true if ssn can be reused, false if not */
 /*通过会话的状态判断流是否可以被重用.*/
int TcpSessionReuseDoneEnough(const Packet *p, const Flow *f, const TcpSession *ssn)
{
    if (p->tcph->th_flags == TH_SYN) {
        return TcpSessionReuseDoneEnoughSyn(p, f, ssn);
    }

    if (stream_config.midstream == TRUE || stream_config.async_oneside == TRUE) {
        if (p->tcph->th_flags == (TH_SYN|TH_ACK)) {
            return TcpSessionReuseDoneEnoughSynAck(p, f, ssn);
        }
    }

    return 0;
}

/*
*根据code，所谓流重用仅仅重用了流的thread_id。其他内容都是新建流得来的，
具体threa_id有什么作用以后看到了再分析，今天就说一下什么样的流可以被重用。
*/
//这就是判断包所属的流是否能重用的函数;
int TcpSessionPacketSsnReuse(const Packet *p, const Flow *f, const void *tcp_ssn)
{
    if (p->proto == IPPROTO_TCP && p->tcph != NULL) {

	/*判断包是不是一次会话中的第一个包，这里的会话可以理解为一次完整的tcp三次握手和四次挥手。*/
        if (TcpSessionPacketIsStreamStarter(p) == 1) {

	/*这里判断包的流向，并根据流向以及对应流中的状态判断该流是否可重用流。*/
            if (TcpSessionReuseDoneEnough(p, f, tcp_ssn) == 1) {
                return 1;
            }
        }
    }
    return 0;
}

/*函数功能:
StreamTCP是Suricata中用于实现TCP流跟踪（Tracking）和重组（Reassembly）的模块。
这个模块在Suricata的数据包处理流水线中是处于哪个位置呢？继续以前面介绍的Pcap实时类型的autofp模式为例：
当数据由抓包线程的ReceivePcap模块获取，再经过线程内下一个模块DecodePcap完成解码后，最终将在TmThreadsSlotProcessPkt中调用tmqh_out，
也即上一节介绍的TmqhOutputFlowActivePackets函数，把数据包送完输出队列，让后续线程再去继续处理。
而在对main()的介绍中，我们知道当前模式下，下一级线程配置的模块依次为：StreamTCP、Detect、
RespondReject和Output相关模块。因此，StreamTCP将是数据包解码完成后第一个流经的模块。
*/
TmEcode StreamTcp (ThreadVars *tv, Packet *p, void *data, PacketQueue *pq, PacketQueue *postpq)
{
    StreamTcpThread *stt = (StreamTcpThread *)data;

    SCLogDebug("p->pcap_cnt %"PRIu64, p->pcap_cnt);

    if (!(PKT_IS_TCP(p))) {
        return TM_ECODE_OK;
    }

    if (p->flow == NULL) {
        StatsIncr(tv, stt->counter_tcp_no_flow);
        return TM_ECODE_OK;
    }

    /* only TCP packets with a flow from here */

    if (!(p->flags & PKT_PSEUDO_STREAM_END)) {
        if (stream_config.flags & STREAMTCP_INIT_FLAG_CHECKSUM_VALIDATION) {
            if (StreamTcpValidateChecksum(p) == 0) {
                StatsIncr(tv, stt->counter_tcp_invalid_checksum);
                return TM_ECODE_OK;
            }
        } else {
            p->flags |= PKT_IGNORE_CHECKSUM;
        }
    } else {
        p->flags |= PKT_IGNORE_CHECKSUM; //TODO check that this is set at creation
    }
    AppLayerProfilingReset(stt->ra_ctx->app_tctx);

    (void)StreamTcpPacket(tv, p, stt, pq);

    return TM_ECODE_OK;
}

/*函数功能:
模块初始化
这个初始化指的是StreamTCP作为一个Thread Module，在其所嵌入的线程初始化阶段所被调用的该模块的ThreadInit函数。

TmModuleStreamTcpRegister注册时，将ThreadInit注册为了StreamTcpThreadInit，该函数流程为：

创建一个StreamTcpThread类型结构体stt作为该模块的在本线程的context。
设置stt->ssn_pool_id为-1。
注册一些性能计数器，例如TCP会话数、无效checksum包数、syn包数、synack包数、rst包数等。
调用StreamTcpReassembleInitThreadCtx初始化重组的context，保存在stt->ra_ctx。
若ssn_pool为NULL，则调用PoolThreadGrow为它创建一个新的PoolThread，预分配大小即为
stream_config.prealloc_sessions，而创建的对象为TcpSession。
若不为NULL，则调用PoolThreadGrow扩充原有的ssn_pool。
注：Pool是一个Suricata中实现的一个通用的池存储，可以避免不断malloc和free的开销，并且显著减少堆碎片。PoolThread只是在Pool上做了一层包装，允许多个同类线程共用一个Pool数组，每个线程对应其中一项。为什么要这么麻烦而不是每个线程自己创建自己的Pool呢？我也不太理解，有待进一步研究。

*/
TmEcode StreamTcpThreadInit(ThreadVars *tv, void *initdata, void **data)
{
    SCEnter();
    StreamTcpThread *stt = SCMalloc(sizeof(StreamTcpThread));
    if (unlikely(stt == NULL))
        SCReturnInt(TM_ECODE_FAILED);
    memset(stt, 0, sizeof(StreamTcpThread));
    stt->ssn_pool_id = -1;

    *data = (void *)stt;

    stt->counter_tcp_sessions = StatsRegisterCounter("tcp.sessions", tv);
    stt->counter_tcp_ssn_memcap = StatsRegisterCounter("tcp.ssn_memcap_drop", tv);
    stt->counter_tcp_pseudo = StatsRegisterCounter("tcp.pseudo", tv);
    stt->counter_tcp_pseudo_failed = StatsRegisterCounter("tcp.pseudo_failed", tv);
    stt->counter_tcp_invalid_checksum = StatsRegisterCounter("tcp.invalid_checksum", tv);
    stt->counter_tcp_no_flow = StatsRegisterCounter("tcp.no_flow", tv);
    stt->counter_tcp_syn = StatsRegisterCounter("tcp.syn", tv);
    stt->counter_tcp_synack = StatsRegisterCounter("tcp.synack", tv);
    stt->counter_tcp_rst = StatsRegisterCounter("tcp.rst", tv);

    /* init reassembly ctx */
    stt->ra_ctx = StreamTcpReassembleInitThreadCtx(tv);
    if (stt->ra_ctx == NULL)
        SCReturnInt(TM_ECODE_FAILED);

    stt->ra_ctx->counter_tcp_segment_memcap = StatsRegisterCounter("tcp.segment_memcap_drop", tv);
    stt->ra_ctx->counter_tcp_stream_depth = StatsRegisterCounter("tcp.stream_depth_reached", tv);
    stt->ra_ctx->counter_tcp_reass_gap = StatsRegisterCounter("tcp.reassembly_gap", tv);

    SCLogDebug("StreamTcp thread specific ctx online at %p, reassembly ctx %p",
                stt, stt->ra_ctx);

    SCMutexLock(&ssn_pool_mutex);
    if (ssn_pool == NULL) {
        ssn_pool = PoolThreadInit(1, /* thread */
                0, /* unlimited */
                stream_config.prealloc_sessions,
                sizeof(TcpSession),
                StreamTcpSessionPoolAlloc,
                StreamTcpSessionPoolInit, NULL,
                StreamTcpSessionPoolCleanup, NULL);
        stt->ssn_pool_id = 0;
        SCLogDebug("pool size %d, thread ssn_pool_id %d", PoolThreadSize(ssn_pool), stt->ssn_pool_id);
    } else {
        /* grow ssn_pool until we have a element for our thread id */
        stt->ssn_pool_id = PoolThreadGrow(ssn_pool,
                0, /* unlimited */
                stream_config.prealloc_sessions,
                sizeof(TcpSession),
                StreamTcpSessionPoolAlloc,
                StreamTcpSessionPoolInit, NULL,
                StreamTcpSessionPoolCleanup, NULL);
        SCLogDebug("pool size %d, thread ssn_pool_id %d", PoolThreadSize(ssn_pool), stt->ssn_pool_id);
    }
    SCMutexUnlock(&ssn_pool_mutex);
    if (stt->ssn_pool_id < 0 || ssn_pool == NULL)
        SCReturnInt(TM_ECODE_FAILED);

    SCReturnInt(TM_ECODE_OK);
}

TmEcode StreamTcpThreadDeinit(ThreadVars *tv, void *data)
{
    SCEnter();
    StreamTcpThread *stt = (StreamTcpThread *)data;
    if (stt == NULL) {
        return TM_ECODE_OK;
    }

    /* XXX */

    /* free reassembly ctx */
    StreamTcpReassembleFreeThreadCtx(stt->ra_ctx);

    /* clear memory */
    memset(stt, 0, sizeof(StreamTcpThread));

    SCFree(stt);
    SCReturnInt(TM_ECODE_OK);
}

/**
 *  \brief   Function to check the validity of the RST packets based on the
 *           target OS of the given packet.
 *
 *  \param   ssn    TCP session to which the given packet belongs
 *  \param   p      Packet which has to be checked for its validity
 *
 *  \retval 0 unacceptable RST
 *  \retval 1 acceptable RST
 *
 *  WebSense sends RST packets that are:
 *  - RST flag, win 0, ack 0, seq = nextseq
 *
 模块执行
"StreamTCP"所属的线程使用的slot类型为"var"，其对应的线程执行函数为TmThreadsSlotVar。该函数与TmThreadsSlotPktAcqLoop大同小异，只不过数据包获取是通过tmqh_in，然后会直接调用TmThreadsSlotVarRun把数据包送往每一个slot去处理。这个函数之前已经介绍过，它会依次调用每个slot的SlotFunc，而包含"StreamTCP"的slot的SlotFunc，就是StreamTCP，其流程如下：

获取之前已经初始化好的StreamTcpThread结构体。
若不是TCP包，则直接返回。
若p->flow为空，也直接返回。
若stream_config的CHECKSUM_VALIDATION打开了，则调用StreamTcpValidateChecksum对数据包进行校验和检查，不通过就返回。
将p->flow加上写锁，然后调用StreamTcpPacket，最后解锁并返回。
 */

static int StreamTcpValidateRst(TcpSession *ssn, Packet *p)
{

    uint8_t os_policy;

    if (ssn->flags & STREAMTCP_FLAG_TIMESTAMP) {
        if (!StreamTcpValidateTimestamp(ssn, p)) {
            SCReturnInt(0);
        }
    }

    /* Set up the os_policy to be used in validating the RST packets based on
       target system */
    if (PKT_IS_TOSERVER(p)) {
        if (ssn->server.os_policy == 0)
            StreamTcpSetOSPolicy(&ssn->server, p);

        os_policy = ssn->server.os_policy;

        if (p->tcph->th_flags & TH_ACK &&
                TCP_GET_ACK(p) && StreamTcpValidateAck(ssn, &ssn->server, p) == -1) {
            SCLogDebug("ssn %p: rejecting because of invalid ack value", ssn);
            StreamTcpSetEvent(p, STREAM_RST_INVALID_ACK);
            SCReturnInt(0);
        }

    } else {
        if (ssn->client.os_policy == 0)
            StreamTcpSetOSPolicy(&ssn->client, p);

        os_policy = ssn->client.os_policy;

        if (p->tcph->th_flags & TH_ACK &&
                TCP_GET_ACK(p) && StreamTcpValidateAck(ssn, &ssn->client, p) == -1) {
            SCLogDebug("ssn %p: rejecting because of invalid ack value", ssn);
            StreamTcpSetEvent(p, STREAM_RST_INVALID_ACK);
            SCReturnInt(0);
        }
    }

    switch (os_policy) {
        case OS_POLICY_HPUX11:
            if(PKT_IS_TOSERVER(p)){
                if(SEQ_GEQ(TCP_GET_SEQ(p), ssn->client.next_seq)) {
                    SCLogDebug("reset is Valid! Packet SEQ: %" PRIu32 "",
                                TCP_GET_SEQ(p));
                    return 1;
                } else {
                    SCLogDebug("reset is not Valid! Packet SEQ: %" PRIu32 " "
                               "and server SEQ: %" PRIu32 "", TCP_GET_SEQ(p),
                                ssn->client.next_seq);
                    return 0;
                }
            } else { /* implied to client */
                if(SEQ_GEQ(TCP_GET_SEQ(p), ssn->server.next_seq)) {
                    SCLogDebug("reset is valid! Packet SEQ: %" PRIu32 "",
                                TCP_GET_SEQ(p));
                    return 1;
                } else {
                    SCLogDebug("reset is not valid! Packet SEQ: %" PRIu32 " "
                               "and client SEQ: %" PRIu32 "", TCP_GET_SEQ(p),
                                ssn->server.next_seq);
                    return 0;
                }
            }
            break;
        case OS_POLICY_OLD_LINUX:
        case OS_POLICY_LINUX:
        case OS_POLICY_SOLARIS:
            if(PKT_IS_TOSERVER(p)){
                if(SEQ_GEQ((TCP_GET_SEQ(p)+p->payload_len),
                            ssn->client.last_ack))
                { /*window base is needed !!*/
                    if(SEQ_LT(TCP_GET_SEQ(p),
                              (ssn->client.next_seq + ssn->client.window)))
                    {
                        SCLogDebug("reset is Valid! Packet SEQ: %" PRIu32 "",
                                    TCP_GET_SEQ(p));
                        return 1;
                    }
                } else {
                    SCLogDebug("reset is not valid! Packet SEQ: %" PRIu32 " and"
                               " server SEQ: %" PRIu32 "", TCP_GET_SEQ(p),
                                ssn->client.next_seq);
                    return 0;
                }
            } else { /* implied to client */
                if(SEQ_GEQ((TCP_GET_SEQ(p) + p->payload_len),
                            ssn->server.last_ack))
                { /*window base is needed !!*/
                    if(SEQ_LT(TCP_GET_SEQ(p),
                                (ssn->server.next_seq + ssn->server.window)))
                    {
                        SCLogDebug("reset is Valid! Packet SEQ: %" PRIu32 "",
                                    TCP_GET_SEQ(p));
                        return 1;
                    }
                } else {
                    SCLogDebug("reset is not valid! Packet SEQ: %" PRIu32 " and"
                               " client SEQ: %" PRIu32 "", TCP_GET_SEQ(p),
                                 ssn->server.next_seq);
                    return 0;
                }
            }
            break;
        default:
        case OS_POLICY_BSD:
        case OS_POLICY_FIRST:
        case OS_POLICY_HPUX10:
        case OS_POLICY_IRIX:
        case OS_POLICY_MACOS:
        case OS_POLICY_LAST:
        case OS_POLICY_WINDOWS:
        case OS_POLICY_WINDOWS2K3:
        case OS_POLICY_VISTA:
            if(PKT_IS_TOSERVER(p)) {
                if(SEQ_EQ(TCP_GET_SEQ(p), ssn->client.next_seq)) {
                    SCLogDebug("reset is valid! Packet SEQ: %" PRIu32 "",
                               TCP_GET_SEQ(p));
                    return 1;
                } else {
                    SCLogDebug("reset is not valid! Packet SEQ: %" PRIu32 " "
                               "and server SEQ: %" PRIu32 "", TCP_GET_SEQ(p),
                               ssn->client.next_seq);
                    return 0;
                }
            } else { /* implied to client */
                if(SEQ_EQ(TCP_GET_SEQ(p), ssn->server.next_seq)) {
                    SCLogDebug("reset is valid! Packet SEQ: %" PRIu32 "",
                                TCP_GET_SEQ(p));
                    return 1;
                } else {
                    SCLogDebug("reset is not valid! Packet SEQ: %" PRIu32 " and"
                               " client SEQ: %" PRIu32 "", TCP_GET_SEQ(p),
                                 ssn->server.next_seq);
                    return 0;
                }
            }
            break;
    }
    return 0;
}

/**
 *  \brief Function to check the validity of the received timestamp based on
 *         the target OS of the given stream.
 *
 *  It's passive except for:
 *  1. it sets the os policy on the stream if necessary
 *  2. it sets an event in the packet if necessary
 *
 *  \param ssn TCP session to which the given packet belongs
 *  \param p Packet which has to be checked for its validity
 *
 *  \retval 1 if the timestamp is valid
 *  \retval 0 if the timestamp is invalid
 */
static int StreamTcpValidateTimestamp (TcpSession *ssn, Packet *p)
{
    SCEnter();

    TcpStream *sender_stream;
    TcpStream *receiver_stream;
    uint8_t ret = 1;
    uint8_t check_ts = 1;

    if (PKT_IS_TOSERVER(p)) {
        sender_stream = &ssn->client;
        receiver_stream = &ssn->server;
    } else {
        sender_stream = &ssn->server;
        receiver_stream = &ssn->client;
    }

    /* Set up the os_policy to be used in validating the timestamps based on
       the target system */
    if (receiver_stream->os_policy == 0) {
        StreamTcpSetOSPolicy(receiver_stream, p);
    }

    if (TCP_HAS_TS(p)) {
        uint32_t ts = TCP_GET_TSVAL(p);
        uint32_t last_pkt_ts = sender_stream->last_pkt_ts;
        uint32_t last_ts = sender_stream->last_ts;

        if (sender_stream->flags & STREAMTCP_STREAM_FLAG_ZERO_TIMESTAMP) {
            /* The 3whs used the timestamp with 0 value. */
            switch (receiver_stream->os_policy) {
                case OS_POLICY_LINUX:
                case OS_POLICY_WINDOWS2K3:
                    /* Linux and windows 2003 does not allow the use of 0 as
                     * timestamp in the 3whs. */
                    check_ts = 0;
                    break;

                case OS_POLICY_OLD_LINUX:
                case OS_POLICY_WINDOWS:
                case OS_POLICY_VISTA:
                    if (SEQ_EQ(sender_stream->next_seq, TCP_GET_SEQ(p))) {
                        last_ts = ts;
                        check_ts = 0; /*next packet will be checked for validity
                                        and stream TS has been updated with this
                                        one.*/
                    }
                    break;
            }
        }

        if (receiver_stream->os_policy == OS_POLICY_HPUX11) {
            /* HPUX11 igoners the timestamp of out of order packets */
            if (!SEQ_EQ(sender_stream->next_seq, TCP_GET_SEQ(p)))
                check_ts = 0;
        }

        if (ts == 0) {
            switch (receiver_stream->os_policy) {
                case OS_POLICY_OLD_LINUX:
                case OS_POLICY_WINDOWS:
                case OS_POLICY_WINDOWS2K3:
                case OS_POLICY_VISTA:
                case OS_POLICY_SOLARIS:
                    /* Old Linux and windows allowed packet with 0 timestamp. */
                    break;
                default:
                    /* other OS simply drop the pakcet with 0 timestamp, when
                     * 3whs has valid timestamp*/
                    goto invalid;
            }
        }

        if (check_ts) {
            int32_t result = 0;

            SCLogDebug("ts %"PRIu32", last_ts %"PRIu32"", ts, last_ts);

            if (receiver_stream->os_policy == OS_POLICY_LINUX) {
                /* Linux accepts TS which are off by one.*/
                result = (int32_t) ((ts - last_ts) + 1);
            } else {
                result = (int32_t) (ts - last_ts);
            }

            SCLogDebug("result %"PRIi32", p->ts.tv_sec %"PRIuMAX"", result, (uintmax_t)p->ts.tv_sec);

            if (last_pkt_ts == 0 &&
                    (ssn->flags & STREAMTCP_FLAG_MIDSTREAM))
            {
                last_pkt_ts = p->ts.tv_sec;
            }

            if (result < 0) {
                SCLogDebug("timestamp is not valid last_ts "
                           "%" PRIu32 " p->tcpvars->ts %" PRIu32 " result "
                           "%" PRId32 "", last_ts, ts, result);
                /* candidate for rejection */
                ret = 0;
            } else if ((sender_stream->last_ts != 0) &&
                        (((uint32_t) p->ts.tv_sec) >
                            last_pkt_ts + PAWS_24DAYS))
            {
                SCLogDebug("packet is not valid last_pkt_ts "
                           "%" PRIu32 " p->ts.tv_sec %" PRIu32 "",
                            last_pkt_ts, (uint32_t) p->ts.tv_sec);
                /* candidate for rejection */
                ret = 0;
            }

            if (ret == 0) {
                /* if the timestamp of packet is not valid then, check if the
                 * current stream timestamp is not so old. if so then we need to
                 * accept the packet and update the stream->last_ts (RFC 1323)*/
                if ((SEQ_EQ(sender_stream->next_seq, TCP_GET_SEQ(p))) &&
                        (((uint32_t) p->ts.tv_sec > (last_pkt_ts + PAWS_24DAYS))))
                {
                    SCLogDebug("timestamp considered valid anyway");
                } else {
                    goto invalid;
                }
            }
        }
    }

    SCReturnInt(1);

invalid:
    StreamTcpSetEvent(p, STREAM_PKT_INVALID_TIMESTAMP);
    SCReturnInt(0);
}

/**
 *  \brief Function to check the validity of the received timestamp based on
 *         the target OS of the given stream and update the session.
 *
 *  \param ssn TCP session to which the given packet belongs
 *  \param p Packet which has to be checked for its validity
 *
 *  \retval 1 if the timestamp is valid
 *  \retval 0 if the timestamp is invalid
 */
static int StreamTcpHandleTimestamp (TcpSession *ssn, Packet *p)
{
    SCEnter();

    TcpStream *sender_stream;
    TcpStream *receiver_stream;
    uint8_t ret = 1;
    uint8_t check_ts = 1;

    if (PKT_IS_TOSERVER(p)) {
        sender_stream = &ssn->client;
        receiver_stream = &ssn->server;
    } else {
        sender_stream = &ssn->server;
        receiver_stream = &ssn->client;
    }

    /* Set up the os_policy to be used in validating the timestamps based on
       the target system */
    if (receiver_stream->os_policy == 0) {
        StreamTcpSetOSPolicy(receiver_stream, p);
    }

    if (TCP_HAS_TS(p)) {
        uint32_t ts = TCP_GET_TSVAL(p);

        if (sender_stream->flags & STREAMTCP_STREAM_FLAG_ZERO_TIMESTAMP) {
            /* The 3whs used the timestamp with 0 value. */
            switch (receiver_stream->os_policy) {
                case OS_POLICY_LINUX:
                case OS_POLICY_WINDOWS2K3:
                    /* Linux and windows 2003 does not allow the use of 0 as
                     * timestamp in the 3whs. */
                    ssn->flags &= ~STREAMTCP_FLAG_TIMESTAMP;
                    check_ts = 0;
                    break;

                case OS_POLICY_OLD_LINUX:
                case OS_POLICY_WINDOWS:
                case OS_POLICY_VISTA:
                    sender_stream->flags &= ~STREAMTCP_STREAM_FLAG_ZERO_TIMESTAMP;
                    if (SEQ_EQ(sender_stream->next_seq, TCP_GET_SEQ(p))) {
                        sender_stream->last_ts = ts;
                        check_ts = 0; /*next packet will be checked for validity
                                        and stream TS has been updated with this
                                        one.*/
                    }
                    break;
                default:
                    break;
            }
        }

        if (receiver_stream->os_policy == OS_POLICY_HPUX11) {
            /*HPUX11 igoners the timestamp of out of order packets*/
            if (!SEQ_EQ(sender_stream->next_seq, TCP_GET_SEQ(p)))
                check_ts = 0;
        }

        if (ts == 0) {
            switch (receiver_stream->os_policy) {
                case OS_POLICY_OLD_LINUX:
                case OS_POLICY_WINDOWS:
                case OS_POLICY_WINDOWS2K3:
                case OS_POLICY_VISTA:
                case OS_POLICY_SOLARIS:
                    /* Old Linux and windows allowed packet with 0 timestamp. */
                    break;
                default:
                    /* other OS simply drop the pakcet with 0 timestamp, when
                     * 3whs has valid timestamp*/
                    goto invalid;
            }
        }

        if (check_ts) {
            int32_t result = 0;

            SCLogDebug("ts %"PRIu32", last_ts %"PRIu32"", ts, sender_stream->last_ts);

            if (receiver_stream->os_policy == OS_POLICY_LINUX) {
                /* Linux accepts TS which are off by one.*/
                result = (int32_t) ((ts - sender_stream->last_ts) + 1);
            } else {
                result = (int32_t) (ts - sender_stream->last_ts);
            }

            SCLogDebug("result %"PRIi32", p->ts.tv_sec %"PRIuMAX"", result, (uintmax_t)p->ts.tv_sec);

            if (sender_stream->last_pkt_ts == 0 &&
                    (ssn->flags & STREAMTCP_FLAG_MIDSTREAM))
            {
                sender_stream->last_pkt_ts = p->ts.tv_sec;
            }

            if (result < 0) {
                SCLogDebug("timestamp is not valid sender_stream->last_ts "
                           "%" PRIu32 " p->tcpvars->ts %" PRIu32 " result "
                           "%" PRId32 "", sender_stream->last_ts, ts, result);
                /* candidate for rejection */
                ret = 0;
            } else if ((sender_stream->last_ts != 0) &&
                        (((uint32_t) p->ts.tv_sec) >
                            sender_stream->last_pkt_ts + PAWS_24DAYS))
            {
                SCLogDebug("packet is not valid sender_stream->last_pkt_ts "
                           "%" PRIu32 " p->ts.tv_sec %" PRIu32 "",
                            sender_stream->last_pkt_ts, (uint32_t) p->ts.tv_sec);
                /* candidate for rejection */
                ret = 0;
            }

            if (ret == 1) {
                /* Update the timestamp and last seen packet time for this
                 * stream */
                if (SEQ_EQ(sender_stream->next_seq, TCP_GET_SEQ(p)))
                    sender_stream->last_ts = ts;

                sender_stream->last_pkt_ts = p->ts.tv_sec;

            } else if (ret == 0) {
                /* if the timestamp of packet is not valid then, check if the
                 * current stream timestamp is not so old. if so then we need to
                 * accept the packet and update the stream->last_ts (RFC 1323)*/
                if ((SEQ_EQ(sender_stream->next_seq, TCP_GET_SEQ(p))) &&
                        (((uint32_t) p->ts.tv_sec > (sender_stream->last_pkt_ts + PAWS_24DAYS))))
                {
                    sender_stream->last_ts = ts;
                    sender_stream->last_pkt_ts = p->ts.tv_sec;

                    SCLogDebug("timestamp considered valid anyway");
                } else {
                    goto invalid;
                }
            }
        }
    } else {
        /* Solaris stops using timestamps if a packet is received
           without a timestamp and timestamps were used on that stream. */
        if (receiver_stream->os_policy == OS_POLICY_SOLARIS)
            ssn->flags &= ~STREAMTCP_FLAG_TIMESTAMP;
    }

    SCReturnInt(1);

invalid:
    StreamTcpSetEvent(p, STREAM_PKT_INVALID_TIMESTAMP);
    SCReturnInt(0);
}

/**
 *  \brief  Function to test the received ACK values against the stream window
 *          and previous ack value. ACK values should be higher than previous
 *          ACK value and less than the next_win value.
 *
 *  \param  ssn     TcpSession for state access
 *  \param  stream  TcpStream of which last_ack needs to be tested
 *  \param  p       Packet which is used to test the last_ack
 *
 *  \retval 0  ACK is valid, last_ack is updated if ACK was higher
 *  \retval -1 ACK is invalid
 */
static inline int StreamTcpValidateAck(TcpSession *ssn, TcpStream *stream, Packet *p)
{
    SCEnter();

    uint32_t ack = TCP_GET_ACK(p);

    /* fast track */
    if (SEQ_GT(ack, stream->last_ack) && SEQ_LEQ(ack, stream->next_win))
    {
        SCLogDebug("ACK in bounds");
        SCReturnInt(0);
    }
    /* fast track */
    else if (SEQ_EQ(ack, stream->last_ack)) {
        SCLogDebug("pkt ACK %"PRIu32" == stream last ACK %"PRIu32, TCP_GET_ACK(p), stream->last_ack);
        SCReturnInt(0);
    }

    /* exception handling */
    if (SEQ_LT(ack, stream->last_ack)) {
        SCLogDebug("pkt ACK %"PRIu32" < stream last ACK %"PRIu32, TCP_GET_ACK(p), stream->last_ack);

        /* This is an attempt to get a 'left edge' value that we can check against.
         * It doesn't work when the window is 0, need to think of a better way. */

        if (stream->window != 0 && SEQ_LT(ack, (stream->last_ack - stream->window))) {
            SCLogDebug("ACK %"PRIu32" is before last_ack %"PRIu32" - window "
                    "%"PRIu32" = %"PRIu32, ack, stream->last_ack,
                    stream->window, stream->last_ack - stream->window);
            goto invalid;
        }

        SCReturnInt(0);
    }

    if (ssn->state > TCP_SYN_SENT && SEQ_GT(ack, stream->next_win)) {
        SCLogDebug("ACK %"PRIu32" is after next_win %"PRIu32, ack, stream->next_win);
        goto invalid;
    /* a toclient RST as a reponse to SYN, next_win is 0, ack will be isn+1, just like
     * the syn ack */
    } else if (ssn->state == TCP_SYN_SENT && PKT_IS_TOCLIENT(p) &&
            p->tcph->th_flags & TH_RST &&
            SEQ_EQ(ack, stream->isn + 1)) {
        SCReturnInt(0);
    }

    SCLogDebug("default path leading to invalid: ACK %"PRIu32", last_ack %"PRIu32
        " next_win %"PRIu32, ack, stream->last_ack, stream->next_win);
invalid:
    StreamTcpSetEvent(p, STREAM_PKT_INVALID_ACK);
    SCReturnInt(-1);
}

/** \brief  Set the No reassembly flag for the given direction in given TCP
 *          session.
 *
 * \param ssn TCP Session to set the flag in
 * \param direction direction to set the flag in: 0 toserver, 1 toclient
 */
void StreamTcpSetSessionNoReassemblyFlag (TcpSession *ssn, char direction)
{
    direction ? (ssn->server.flags |= STREAMTCP_STREAM_FLAG_NOREASSEMBLY) :
                (ssn->client.flags |= STREAMTCP_STREAM_FLAG_NOREASSEMBLY);
}

/** \brief  Set the No reassembly flag for the given direction in given TCP
 *          session.
 *
 * \param ssn TCP Session to set the flag in
 * \param direction direction to set the flag in: 0 toserver, 1 toclient
 */
void StreamTcpSetDisableRawReassemblyFlag (TcpSession *ssn, char direction)
{
    direction ? (ssn->server.flags |= STREAMTCP_STREAM_FLAG_NEW_RAW_DISABLED) :
                (ssn->client.flags |= STREAMTCP_STREAM_FLAG_NEW_RAW_DISABLED);
}

#define PSEUDO_PKT_SET_IPV4HDR(nipv4h,ipv4h) do { \
        IPV4_SET_RAW_VER(nipv4h, IPV4_GET_RAW_VER(ipv4h)); \
        IPV4_SET_RAW_HLEN(nipv4h, IPV4_GET_RAW_HLEN(ipv4h)); \
        IPV4_SET_RAW_IPLEN(nipv4h, IPV4_GET_RAW_IPLEN(ipv4h)); \
        IPV4_SET_RAW_IPTOS(nipv4h, IPV4_GET_RAW_IPTOS(ipv4h)); \
        IPV4_SET_RAW_IPPROTO(nipv4h, IPV4_GET_RAW_IPPROTO(ipv4h)); \
        (nipv4h)->s_ip_src = IPV4_GET_RAW_IPDST(ipv4h); \
        (nipv4h)->s_ip_dst = IPV4_GET_RAW_IPSRC(ipv4h); \
    } while (0)

#define PSEUDO_PKT_SET_IPV6HDR(nipv6h,ipv6h) do { \
        (nipv6h)->s_ip6_src[0] = (ipv6h)->s_ip6_dst[0]; \
        (nipv6h)->s_ip6_src[1] = (ipv6h)->s_ip6_dst[1]; \
        (nipv6h)->s_ip6_src[2] = (ipv6h)->s_ip6_dst[2]; \
        (nipv6h)->s_ip6_src[3] = (ipv6h)->s_ip6_dst[3]; \
        (nipv6h)->s_ip6_dst[0] = (ipv6h)->s_ip6_src[0]; \
        (nipv6h)->s_ip6_dst[1] = (ipv6h)->s_ip6_src[1]; \
        (nipv6h)->s_ip6_dst[2] = (ipv6h)->s_ip6_src[2]; \
        (nipv6h)->s_ip6_dst[3] = (ipv6h)->s_ip6_src[3]; \
        IPV6_SET_RAW_NH(nipv6h, IPV6_GET_RAW_NH(ipv6h));    \
    } while (0)

#define PSEUDO_PKT_SET_TCPHDR(ntcph,tcph) do { \
        COPY_PORT((tcph)->th_dport, (ntcph)->th_sport); \
        COPY_PORT((tcph)->th_sport, (ntcph)->th_dport); \
        (ntcph)->th_seq = (tcph)->th_ack; \
        (ntcph)->th_ack = (tcph)->th_seq; \
    } while (0)

/**
 * \brief   Function to fetch a packet from the packet allocation queue for
 *          creation of the pseudo packet from the reassembled stream.
 *
 * @param parent    Pointer to the parent of the pseudo packet
 * @param pkt       pointer to the raw packet of the parent
 * @param len       length of the packet
 * @return          upon success returns the pointer to the new pseudo packet
 *                  otherwise NULL
 */
Packet *StreamTcpPseudoSetup(Packet *parent, uint8_t *pkt, uint32_t len)
{
    SCEnter();

    if (len == 0) {
        SCReturnPtr(NULL, "Packet");
    }

    Packet *p = PacketGetFromQueueOrAlloc();
    if (p == NULL) {
        SCReturnPtr(NULL, "Packet");
    }

    /* set the root ptr to the lowest layer */
    if (parent->root != NULL)
        p->root = parent->root;
    else
        p->root = parent;

    /* copy packet and set lenght, proto */
    p->proto = parent->proto;
    p->datalink = parent->datalink;

    PacketCopyData(p, pkt, len);
    p->recursion_level = parent->recursion_level + 1;
    p->ts.tv_sec = parent->ts.tv_sec;
    p->ts.tv_usec = parent->ts.tv_usec;

    FlowReference(&p->flow, parent->flow);
    /* set tunnel flags */

    /* tell new packet it's part of a tunnel */
    SET_TUNNEL_PKT(p);
    /* tell parent packet it's part of a tunnel */
    SET_TUNNEL_PKT(parent);

    /* increment tunnel packet refcnt in the root packet */
    TUNNEL_INCR_PKT_TPR(p);

    return p;
}

/**
 * \brief   Function to setup the IP and TCP header of the pseudo packet from
 *          the newly copied raw packet contents of the parent.
 *
 * @param np    pointer to the pseudo packet
 * @param p     pointer to the original packet
 */
static void StreamTcpPseudoPacketSetupHeader(Packet *np, Packet *p)
{
    /* Setup the IP header */
    if (PKT_IS_IPV4(p)) {
        np->ip4h = (IPV4Hdr *)((uint8_t *)GET_PKT_DATA(np) + (GET_PKT_LEN(np) - IPV4_GET_IPLEN(p)));
        PSEUDO_PKT_SET_IPV4HDR(np->ip4h, p->ip4h);

        /* Similarly setup the TCP header with ports in opposite direction */
        np->tcph = (TCPHdr *)((uint8_t *)np->ip4h + IPV4_GET_HLEN(np));

        PSEUDO_PKT_SET_TCPHDR(np->tcph, p->tcph);

        /* Setup the adress and port details */
        SET_IPV4_SRC_ADDR(p, &np->dst);
        SET_IPV4_DST_ADDR(p, &np->src);
        SET_TCP_SRC_PORT(p, &np->dp);
        SET_TCP_DST_PORT(p, &np->sp);

    } else if (PKT_IS_IPV6(p)) {
        np->ip6h = (IPV6Hdr *)((uint8_t *)GET_PKT_DATA(np) + (GET_PKT_LEN(np) - IPV6_GET_PLEN(p) - IPV6_HEADER_LEN));
        PSEUDO_PKT_SET_IPV6HDR(np->ip6h, p->ip6h);

        /* Similarly setup the TCP header with ports in opposite direction */
        np->tcph = (TCPHdr *)((uint8_t *)np->ip6h + IPV6_HEADER_LEN);
        PSEUDO_PKT_SET_TCPHDR(np->tcph, p->tcph);

        /* Setup the adress and port details */
        SET_IPV6_SRC_ADDR(p, &np->dst);
        SET_IPV6_DST_ADDR(p, &np->src);
        SET_TCP_SRC_PORT(p, &np->dp);
        SET_TCP_DST_PORT(p, &np->sp);
    }

    /* we don't need a payload (if any) */
    np->payload = NULL;
    np->payload_len = 0;
}

/** \brief Create a pseudo packet injected into the engine to signal the
 *         opposing direction of this stream to wrap up stream reassembly.
 *
 *  \param p real packet
 *  \param pq packet queue to store the new pseudo packet in
 */
void StreamTcpPseudoPacketCreateStreamEndPacket(ThreadVars *tv, StreamTcpThread *stt, Packet *p, TcpSession *ssn, PacketQueue *pq)
{
    SCEnter();

    if (p->flags & PKT_PSEUDO_STREAM_END) {
        SCReturn;
    }

    /* no need for a pseudo packet if there is nothing left to reassemble */
    if (ssn->server.seg_list == NULL && ssn->client.seg_list == NULL) {
        SCReturn;
    }

    Packet *np = StreamTcpPseudoSetup(p, GET_PKT_DATA(p), GET_PKT_LEN(p));
    if (np == NULL) {
        SCLogDebug("The packet received from packet allocation is NULL");
        StatsIncr(tv, stt->counter_tcp_pseudo_failed);
        SCReturn;
    }
    PKT_SET_SRC(np, PKT_SRC_STREAM_TCP_STREAM_END_PSEUDO);

    /* Setup the IP and TCP headers */
    StreamTcpPseudoPacketSetupHeader(np,p);

    np->tenant_id = p->flow->tenant_id;

    np->flowflags = p->flowflags;

    np->flags |= PKT_STREAM_EST;
    np->flags |= PKT_STREAM_EOF;
    np->flags |= PKT_HAS_FLOW;
    np->flags |= PKT_PSEUDO_STREAM_END;

    if (p->flags & PKT_NOPACKET_INSPECTION) {
        DecodeSetNoPacketInspectionFlag(np);
    }
    if (p->flags & PKT_NOPAYLOAD_INSPECTION) {
        DecodeSetNoPayloadInspectionFlag(np);
    }

    if (PKT_IS_TOSERVER(p)) {
        SCLogDebug("original is to_server, so pseudo is to_client");
        np->flowflags &= ~FLOW_PKT_TOSERVER;
        np->flowflags |= FLOW_PKT_TOCLIENT;
#ifdef DEBUG
        BUG_ON(!(PKT_IS_TOCLIENT(np)));
        BUG_ON((PKT_IS_TOSERVER(np)));
#endif
    } else if (PKT_IS_TOCLIENT(p)) {
        SCLogDebug("original is to_client, so pseudo is to_server");
        np->flowflags &= ~FLOW_PKT_TOCLIENT;
        np->flowflags |= FLOW_PKT_TOSERVER;
#ifdef DEBUG
        BUG_ON(!(PKT_IS_TOSERVER(np)));
        BUG_ON((PKT_IS_TOCLIENT(np)));
#endif
    }

    PacketEnqueue(pq, np);

    StatsIncr(tv, stt->counter_tcp_pseudo);
    SCReturn;
}

/**
 * \brief Run callback function on each TCP segment
 *
 * \note when stream engine is running in inline mode all segments are used,
 *       in IDS/non-inline mode only ack'd segments are iterated.
 *
 * \note Must be called under flow lock.
 *
 * \return -1 in case of error, the number of segment in case of success
 *
 */
int StreamTcpSegmentForEach(const Packet *p, uint8_t flag, StreamSegmentCallback CallbackFunc, void *data)
{
    TcpSession *ssn = NULL;
    TcpStream *stream = NULL;
    int ret = 0;
    int cnt = 0;

    if (p->flow == NULL)
        return 0;

    ssn = (TcpSession *)p->flow->protoctx;

    if (ssn == NULL) {
        return 0;
    }

    if (flag & FLOW_PKT_TOSERVER) {
        stream = &(ssn->server);
    } else {
        stream = &(ssn->client);
    }

    /* for IDS, return ack'd segments. For IPS all. */
    TcpSegment *seg = stream->seg_list;
    for (; seg != NULL &&
            (stream_inline || SEQ_LT(seg->seq, stream->last_ack));)
    {
        ret = CallbackFunc(p, data, seg->payload, seg->payload_len);
        if (ret != 1) {
            SCLogDebug("Callback function has failed");
            return -1;
        }
        seg = seg->next;
        cnt++;
    }
    return cnt;
}

int StreamTcpBypassEnabled(void)
{
    return stream_config.bypass;
}

void TcpSessionSetReassemblyDepth(TcpSession *ssn, uint32_t size)
{
    if (size > ssn->reassembly_depth || size == 0) {
        ssn->reassembly_depth = size;
    }

    return;
}

#ifdef UNITTESTS

/**
 *  \test   Test the allocation of TCP session for a given packet from the
 *          ssn_pool.
 *
 *  \retval On success it returns 1 and on failure 0.
 */

static int StreamTcpTest01 (void)
{
    Packet *p = SCMalloc(SIZE_OF_PACKET);
    if (unlikely(p == NULL))
        return 0;
    Flow f;
    memset(p, 0, SIZE_OF_PACKET);
    memset (&f, 0, sizeof(Flow));
    FLOW_INITIALIZE(&f);
    p->flow = &f;
    int ret = 0;

    StreamTcpInitConfig(TRUE);

    TcpSession *ssn = StreamTcpNewSession(p, 0);
    if (ssn == NULL) {
        printf("Session can not be allocated: ");
        goto end;
    }
    f.protoctx = ssn;

    if (f.alparser != NULL) {
        printf("AppLayer field not set to NULL: ");
        goto end;
    }
    if (ssn->state != 0) {
        printf("TCP state field not set to 0: ");
        goto end;
    }

    StreamTcpSessionClear(p->flow->protoctx);

    ret = 1;
end:
    StreamTcpFreeConfig(TRUE);
    SCFree(p);
    FLOW_DESTROY(&f);
    return ret;
}

/**
 *  \test   Test the deallocation of TCP session for a given packet and return
 *          the memory back to ssn_pool and corresponding segments to segment
 *          pool.
 *
 *  \retval On success it returns 1 and on failure 0.
 */

static int StreamTcpTest02 (void)
{
    Packet *p = SCMalloc(SIZE_OF_PACKET);
    if (unlikely(p == NULL))
        return 0;
    Flow f;
    ThreadVars tv;
    StreamTcpThread stt;
    uint8_t payload[4];
    TCPHdr tcph;
    TcpReassemblyThreadCtx ra_ctx;
    PacketQueue pq;
    memset(&pq,0,sizeof(PacketQueue));
    memset(&ra_ctx, 0, sizeof(TcpReassemblyThreadCtx));
    memset(p, 0, SIZE_OF_PACKET);
    memset (&f, 0, sizeof(Flow));
    memset(&tv, 0, sizeof (ThreadVars));
    memset(&stt, 0, sizeof (StreamTcpThread));
    memset(&tcph, 0, sizeof (TCPHdr));
    FLOW_INITIALIZE(&f);
    p->flow = &f;
    tcph.th_win = htons(5480);
    tcph.th_flags = TH_SYN;
    p->tcph = &tcph;
    p->flowflags = FLOW_PKT_TOSERVER;
    int ret = 0;
    stt.ra_ctx = &ra_ctx;

    StreamTcpInitConfig(TRUE);

    FLOWLOCK_WRLOCK(&f);
    if (StreamTcpPacket(&tv, p, &stt, &pq) == -1) {
        goto end;
    }

    p->tcph->th_ack = htonl(1);
    p->tcph->th_flags = TH_SYN | TH_ACK;
    p->flowflags = FLOW_PKT_TOCLIENT;

    if (StreamTcpPacket(&tv, p, &stt, &pq) == -1)
        goto end;

    p->tcph->th_ack = htonl(1);
    p->tcph->th_seq = htonl(1);
    p->tcph->th_flags = TH_ACK;
    p->flowflags = FLOW_PKT_TOSERVER;

    if (StreamTcpPacket(&tv, p, &stt, &pq) == -1)
        goto end;

    p->tcph->th_ack = htonl(1);
    p->tcph->th_seq = htonl(2);
    p->tcph->th_flags = TH_PUSH | TH_ACK;
    p->flowflags = FLOW_PKT_TOSERVER;

    StreamTcpCreateTestPacket(payload, 0x41, 3, 4); /*AAA*/
    p->payload = payload;
    p->payload_len = 3;

    if (StreamTcpPacket(&tv, p, &stt, &pq) == -1)
        goto end;

    p->flowflags = FLOW_PKT_TOCLIENT;
    if (StreamTcpPacket(&tv, p, &stt, &pq) == -1)
        goto end;

    p->tcph->th_ack = htonl(1);
    p->tcph->th_seq = htonl(6);
    p->tcph->th_flags = TH_PUSH | TH_ACK;
    p->flowflags = FLOW_PKT_TOSERVER;

    StreamTcpCreateTestPacket(payload, 0x42, 3, 4); /*BBB*/
    p->payload = payload;
    p->payload_len = 3;

    if (StreamTcpPacket(&tv, p, &stt, &pq) == -1)
        goto end;

    p->flowflags = FLOW_PKT_TOCLIENT;
    if (StreamTcpPacket(&tv, p, &stt, &pq) == -1)
        goto end;

    StreamTcpSessionClear(p->flow->protoctx);

    ret = 1;
end:
    StreamTcpFreeConfig(TRUE);
    FLOWLOCK_UNLOCK(&f);
    SCFree(p);
    FLOW_DESTROY(&f);
    return ret;
}

/**
 *  \test   Test the setting up a TCP session when we missed the intial
 *          SYN packet of the session. The session is setup only if midstream
 *          sessions are allowed to setup.
 *
 *  \retval On success it returns 1 and on failure 0.
 */

static int StreamTcpTest03 (void)
{
    Packet *p = SCMalloc(SIZE_OF_PACKET);
    if (unlikely(p == NULL))
        return 0;
    Flow f;
    ThreadVars tv;
    StreamTcpThread stt;
    TCPHdr tcph;
    memset(p, 0, SIZE_OF_PACKET);
    PacketQueue pq;
    memset(&pq,0,sizeof(PacketQueue));
    memset (&f, 0, sizeof(Flow));
    memset(&tv, 0, sizeof (ThreadVars));
    memset(&stt, 0, sizeof (StreamTcpThread));
    memset(&tcph, 0, sizeof (TCPHdr));
    FLOW_INITIALIZE(&f);
    p->flow = &f;

    StreamTcpInitConfig(TRUE);

    tcph.th_win = htons(5480);
    tcph.th_seq = htonl(10);
    tcph.th_ack = htonl(20);
    tcph.th_flags = TH_SYN|TH_ACK;
    p->tcph = &tcph;
    int ret = 0;

    FLOWLOCK_WRLOCK(&f);
    if (StreamTcpPacket(&tv, p, &stt, &pq) == -1)
        goto end;

    p->tcph->th_seq = htonl(20);
    p->tcph->th_ack = htonl(11);
    p->tcph->th_flags = TH_ACK;
    p->flowflags = FLOW_PKT_TOSERVER;

    if (StreamTcpPacket(&tv, p, &stt, &pq) == -1)
        goto end;

    p->tcph->th_seq = htonl(19);
    p->tcph->th_ack = htonl(11);
    p->tcph->th_flags = TH_ACK|TH_PUSH;
    p->flowflags = FLOW_PKT_TOSERVER;

    if (StreamTcpPacket(&tv, p, &stt, &pq) == -1)
        goto end;

    if (stream_config.midstream != TRUE) {
        ret = 1;
        goto end;
    }
    if (((TcpSession *)(p->flow->protoctx))->state != TCP_ESTABLISHED)
        goto end;

    if (((TcpSession *)(p->flow->protoctx))->client.next_seq != 20 &&
            ((TcpSession *)(p->flow->protoctx))->server.next_seq != 11)
        goto end;

    StreamTcpSessionClear(p->flow->protoctx);

    ret = 1;
end:
    StreamTcpFreeConfig(TRUE);
    FLOWLOCK_UNLOCK(&f);
    SCFree(p);
    FLOW_DESTROY(&f);
    return ret;
}

/**
 *  \test   Test the setting up a TCP session when we missed the intial
 *          SYN/ACK packet of the session. The session is setup only if
 *          midstream sessions are allowed to setup.
 *
 *  \retval On success it returns 1 and on failure 0.
 */

static int StreamTcpTest04 (void)
{
    Packet *p = SCMalloc(SIZE_OF_PACKET);
    if (unlikely(p == NULL))
        return 0;
    Flow f;
    ThreadVars tv;
    StreamTcpThread stt;
    TCPHdr tcph;
    memset(p, 0, SIZE_OF_PACKET);
    PacketQueue pq;
    memset(&pq,0,sizeof(PacketQueue));
    memset (&f, 0, sizeof(Flow));
    memset(&tv, 0, sizeof (ThreadVars));
    memset(&stt, 0, sizeof (StreamTcpThread));
    memset(&tcph, 0, sizeof (TCPHdr));
    FLOW_INITIALIZE(&f);
    p->flow = &f;

    StreamTcpInitConfig(TRUE);

    tcph.th_win = htons(5480);
    tcph.th_seq = htonl(10);
    tcph.th_ack = htonl(20);
    tcph.th_flags = TH_ACK;
    p->tcph = &tcph;

    int ret = 0;

    FLOWLOCK_WRLOCK(&f);
    if (StreamTcpPacket(&tv, p, &stt, &pq) == -1)
        goto end;

    p->tcph->th_seq = htonl(9);
    p->tcph->th_ack = htonl(19);
    p->tcph->th_flags = TH_ACK|TH_PUSH;
    p->flowflags = FLOW_PKT_TOSERVER;

    if (StreamTcpPacket(&tv, p, &stt, &pq) == -1)
        goto end;

    if (stream_config.midstream != TRUE) {
        ret = 1;
        goto end;
    }
    if (((TcpSession *)(p->flow->protoctx))->state != TCP_ESTABLISHED)
        goto end;

    if (((TcpSession *)(p->flow->protoctx))->client.next_seq != 10 &&
            ((TcpSession *)(p->flow->protoctx))->server.next_seq != 20)
        goto end;

    StreamTcpSessionClear(p->flow->protoctx);

    ret = 1;
end:
    StreamTcpFreeConfig(TRUE);
    FLOWLOCK_UNLOCK(&f);
    SCFree(p);
    FLOW_DESTROY(&f);
    return ret;
}

/**
 *  \test   Test the setting up a TCP session when we missed the intial
 *          3WHS packet of the session. The session is setup only if
 *          midstream sessions are allowed to setup.
 *
 *  \retval On success it returns 1 and on failure 0.
 */

static int StreamTcpTest05 (void)
{
    Packet *p = SCMalloc(SIZE_OF_PACKET);
    if (unlikely(p == NULL))
        return 0;
    Flow f;
    ThreadVars tv;
    StreamTcpThread stt;
    TCPHdr tcph;
    uint8_t payload[4];
    memset(p, 0, SIZE_OF_PACKET);
    PacketQueue pq;
    memset(&pq,0,sizeof(PacketQueue));
    memset (&f, 0, sizeof(Flow));
    memset(&tv, 0, sizeof (ThreadVars));
    memset(&stt, 0, sizeof (StreamTcpThread));
    memset(&tcph, 0, sizeof (TCPHdr));
    FLOW_INITIALIZE(&f);
    p->flow = &f;
    int ret = 0;

    StreamTcpInitConfig(TRUE);

    /* prevent L7 from kicking in */
    StreamMsgQueueSetMinChunkLen(FLOW_PKT_TOSERVER, 4096);
    StreamMsgQueueSetMinChunkLen(FLOW_PKT_TOCLIENT, 4096);

    tcph.th_win = htons(5480);
    tcph.th_seq = htonl(10);
    tcph.th_ack = htonl(20);
    tcph.th_flags = TH_ACK|TH_PUSH;
    p->tcph = &tcph;

    StreamTcpCreateTestPacket(payload, 0x41, 3, 4); /*AAA*/
    p->payload = payload;
    p->payload_len = 3;

    FLOWLOCK_WRLOCK(&f);
    if (StreamTcpPacket(&tv, p, &stt, &pq) == -1)
        goto end;

    p->tcph->th_seq = htonl(20);
    p->tcph->th_ack = htonl(13);
    p->tcph->th_flags = TH_ACK|TH_PUSH;
    p->flowflags = FLOW_PKT_TOCLIENT;

    StreamTcpCreateTestPacket(payload, 0x42, 3, 4); /*BBB*/
    p->payload = payload;
    p->payload_len = 3;

    if (StreamTcpPacket(&tv, p, &stt, &pq) == -1)
        goto end;

    p->tcph->th_seq = htonl(13);
    p->tcph->th_ack = htonl(23);
    p->tcph->th_flags = TH_ACK|TH_PUSH;
    p->flowflags = FLOW_PKT_TOSERVER;

    StreamTcpCreateTestPacket(payload, 0x43, 3, 4); /*CCC*/
    p->payload = payload;
    p->payload_len = 3;

    if (StreamTcpPacket(&tv, p, &stt, &pq) == -1)
        goto end;

    p->tcph->th_seq = htonl(19);
    p->tcph->th_ack = htonl(16);
    p->tcph->th_flags = TH_ACK|TH_PUSH;
    p->flowflags = FLOW_PKT_TOCLIENT;

    StreamTcpCreateTestPacket(payload, 0x44, 3, 4); /*DDD*/
    p->payload = payload;
    p->payload_len = 3;

    if (StreamTcpPacket(&tv, p, &stt, &pq) == -1)
        goto end;

    if (stream_config.midstream != TRUE) {
        ret = 1;
        goto end;
    }
    if (((TcpSession *)(p->flow->protoctx))->state != TCP_ESTABLISHED)
        goto end;

    if (((TcpSession *)(p->flow->protoctx))->client.next_seq != 16 &&
            ((TcpSession *)(p->flow->protoctx))->server.next_seq != 23)
        goto end;

    StreamTcpSessionClear(p->flow->protoctx);

    ret = 1;
end:
    StreamTcpFreeConfig(TRUE);
    FLOWLOCK_UNLOCK(&f);
    SCFree(p);
    FLOW_DESTROY(&f);
    return ret;
}

/**
 *  \test   Test the setting up a TCP session when we have seen only the
 *          FIN, RST packets packet of the session. The session is setup only if
 *          midstream sessions are allowed to setup.
 *
 *  \retval On success it returns 1 and on failure 0.
 */

static int StreamTcpTest06 (void)
{
    Packet *p = SCMalloc(SIZE_OF_PACKET);
    if (unlikely(p == NULL))
        return 0;
    Flow f;
    TcpSession ssn;
    ThreadVars tv;
    StreamTcpThread stt;
    TCPHdr tcph;
    memset(p, 0, SIZE_OF_PACKET);
    PacketQueue pq;
    memset(&pq,0,sizeof(PacketQueue));
    memset (&f, 0, sizeof(Flow));
    memset(&ssn, 0, sizeof (TcpSession));
    memset(&tv, 0, sizeof (ThreadVars));
    memset(&stt, 0, sizeof (StreamTcpThread));
    memset(&tcph, 0, sizeof (TCPHdr));
    FLOW_INITIALIZE(&f);
    p->flow = &f;
    int ret = 0;

    StreamTcpInitConfig(TRUE);

    tcph.th_flags = TH_FIN;
    p->tcph = &tcph;

    FLOWLOCK_WRLOCK(&f);
    /* StreamTcpPacket returns -1 on unsolicited FIN */
    if (StreamTcpPacket(&tv, p, &stt, &pq) != -1) {
        printf("StreamTcpPacket failed: ");
        goto end;
    }

    if (((TcpSession *)(p->flow->protoctx)) != NULL) {
        printf("we have a ssn while we shouldn't: ");
        goto end;
    }

    p->tcph->th_flags = TH_RST;
    /* StreamTcpPacket returns -1 on unsolicited RST */
    if (StreamTcpPacket(&tv, p, &stt, &pq) != -1) {
        printf("StreamTcpPacket failed (2): ");
        goto end;
    }

    if (((TcpSession *)(p->flow->protoctx)) != NULL) {
        printf("we have a ssn while we shouldn't (2): ");
        goto end;
    }

    ret = 1;
end:
    StreamTcpFreeConfig(TRUE);
    FLOWLOCK_UNLOCK(&f);
    SCFree(p);
    FLOW_DESTROY(&f);
    return ret;
}

/**
 *  \test   Test the working on PAWS. The packet will be dropped by stream, as
 *          its timestamp is old, although the segment is in the window.
 *
 *  \retval On success it returns 1 and on failure 0.
 */

static int StreamTcpTest07 (void)
{
    Packet *p = SCMalloc(SIZE_OF_PACKET);
    FAIL_IF(unlikely(p == NULL));
    Flow f;
    ThreadVars tv;
    StreamTcpThread stt;
    TCPHdr tcph;
    uint8_t payload[1] = {0x42};
    PacketQueue pq;

    memset(p, 0, SIZE_OF_PACKET);
    memset(&pq,0,sizeof(PacketQueue));
    memset (&f, 0, sizeof(Flow));
    memset(&tv, 0, sizeof (ThreadVars));
    memset(&stt, 0, sizeof(StreamTcpThread));
    memset(&tcph, 0, sizeof(TCPHdr));

    FLOW_INITIALIZE(&f);
    p->flow = &f;

    StreamTcpInitConfig(TRUE);
    stream_config.midstream = TRUE;

    /* prevent L7 from kicking in */
    StreamMsgQueueSetMinChunkLen(FLOW_PKT_TOSERVER, 4096);
    StreamMsgQueueSetMinChunkLen(FLOW_PKT_TOCLIENT, 4096);

    tcph.th_win = htons(5480);
    tcph.th_seq = htonl(10);
    tcph.th_ack = htonl(20);
    tcph.th_flags = TH_ACK|TH_PUSH;
    p->tcph = &tcph;

    p->tcpvars.ts_set = TRUE;
    p->tcpvars.ts_val = 10;
    p->tcpvars.ts_ecr = 11;

    p->payload = payload;
    p->payload_len = 1;

    FLOWLOCK_WRLOCK(&f);
    FAIL_IF(StreamTcpPacket(&tv, p, &stt, &pq) == -1);

    p->tcph->th_seq = htonl(11);
    p->tcph->th_ack = htonl(23);
    p->tcph->th_flags = TH_ACK|TH_PUSH;
    p->flowflags = FLOW_PKT_TOSERVER;

    p->tcpvars.ts_val = 2;

    FAIL_IF(StreamTcpPacket(&tv, p, &stt, &pq) != -1);

    FAIL_IF (((TcpSession *) (p->flow->protoctx))->client.next_seq != 11);

    StreamTcpSessionClear(p->flow->protoctx);
    StreamTcpFreeConfig(TRUE);
    FLOWLOCK_UNLOCK(&f);
    SCFree(p);
    FLOW_DESTROY(&f);
    PASS;
}

/**
 *  \test   Test the working on PAWS. The packet will be accpeted by engine as
 *          the timestamp is valid and it is in window.
 *
 *  \retval On success it returns 1 and on failure 0.
 */

static int StreamTcpTest08 (void)
{
    Packet *p = SCMalloc(SIZE_OF_PACKET);
    FAIL_IF(unlikely(p == NULL));
    Flow f;
    ThreadVars tv;
    StreamTcpThread stt;
    TCPHdr tcph;
    uint8_t payload[1] = {0x42};

    memset(p, 0, SIZE_OF_PACKET);
    PacketQueue pq;
    memset(&pq,0,sizeof(PacketQueue));
    memset (&f, 0, sizeof(Flow));
    memset(&tv, 0, sizeof (ThreadVars));
    memset(&stt, 0, sizeof(StreamTcpThread));
    memset(&tcph, 0, sizeof(TCPHdr));

    FLOW_INITIALIZE(&f);
    p->flow = &f;

    StreamTcpInitConfig(TRUE);
    stream_config.midstream = TRUE;

    /* prevent L7 from kicking in */
    StreamMsgQueueSetMinChunkLen(FLOW_PKT_TOSERVER, 4096);
    StreamMsgQueueSetMinChunkLen(FLOW_PKT_TOCLIENT, 4096);

    tcph.th_win = htons(5480);
    tcph.th_seq = htonl(10);
    tcph.th_ack = htonl(20);
    tcph.th_flags = TH_ACK|TH_PUSH;
    p->tcph = &tcph;

    p->tcpvars.ts_set = TRUE;
    p->tcpvars.ts_val = 10;
    p->tcpvars.ts_ecr = 11;

    p->payload = payload;
    p->payload_len = 1;

    FLOWLOCK_WRLOCK(&f);
    FAIL_IF(StreamTcpPacket(&tv, p, &stt, &pq) == -1);

    p->tcph->th_seq = htonl(11);
    p->tcph->th_ack = htonl(20);
    p->tcph->th_flags = TH_ACK|TH_PUSH;
    p->flowflags = FLOW_PKT_TOSERVER;

    p->tcpvars.ts_val = 12;

    FAIL_IF(StreamTcpPacket(&tv, p, &stt, &pq) == -1);

    FAIL_IF(((TcpSession *) (p->flow->protoctx))->client.next_seq != 12);

    StreamTcpSessionClear(p->flow->protoctx);

    StreamTcpFreeConfig(TRUE);
    FLOWLOCK_UNLOCK(&f);
    SCFree(p);
    FLOW_DESTROY(&f);
    PASS;
}

/**
 *  \test   Test the working of No stream reassembly flag. The stream will not
 *          reassemble the segment if the flag is set.
 *
 *  \retval On success it returns 1 and on failure 0.
 */

static int StreamTcpTest09 (void)
{

    Packet *p = SCMalloc(SIZE_OF_PACKET);
    if (unlikely(p == NULL))
    return 0;
    Flow f;
    ThreadVars tv;
    StreamTcpThread stt;
    TCPHdr tcph;
    uint8_t payload[1] = {0x42};

    memset(p, 0, SIZE_OF_PACKET);
    PacketQueue pq;
    memset(&pq,0,sizeof(PacketQueue));
    memset (&f, 0, sizeof(Flow));
    memset(&tv, 0, sizeof (ThreadVars));
    memset(&stt, 0, sizeof(StreamTcpThread));
    memset(&tcph, 0, sizeof(TCPHdr));

    FLOW_INITIALIZE(&f);
    p->flow = &f;
    int ret = 0;

    StreamTcpInitConfig(TRUE);
    stream_config.midstream = TRUE;

    //prevent L7 from kicking in
    StreamMsgQueueSetMinChunkLen(FLOW_PKT_TOSERVER, 4096);
    StreamMsgQueueSetMinChunkLen(FLOW_PKT_TOCLIENT, 4096);

    tcph.th_win = htons(5480);
    tcph.th_seq = htonl(10);
    tcph.th_ack = htonl(20);
    tcph.th_flags = TH_ACK|TH_PUSH;
    p->tcph = &tcph;

    p->payload = payload;
    p->payload_len = 1;

    FLOWLOCK_WRLOCK(&f);
    if (StreamTcpPacket(&tv, p, &stt, &pq) == -1)
        goto end;

    p->tcph->th_seq = htonl(12);
    p->tcph->th_ack = htonl(23);
    p->tcph->th_flags = TH_ACK|TH_PUSH;
    p->flowflags = FLOW_PKT_TOSERVER;

    StreamTcpSetSessionNoReassemblyFlag(((TcpSession *)(p->flow->protoctx)), 0);

    if (StreamTcpPacket(&tv, p, &stt, &pq) == -1)
        goto end;

    p->tcph->th_seq = htonl(11);
    p->tcph->th_ack = htonl(23);
    p->tcph->th_flags = TH_ACK|TH_PUSH;
    p->flowflags = FLOW_PKT_TOSERVER;

    if (StreamTcpPacket(&tv, p, &stt, &pq) == -1)
        goto end;

    if (((TcpSession *) (p->flow->protoctx))->client.seg_list->next == NULL)
        ret = 1;

    StreamTcpSessionClear(p->flow->protoctx);
end:
    StreamTcpFreeConfig(TRUE);
    FLOWLOCK_UNLOCK(&f);
    SCFree(p);
    FLOW_DESTROY(&f);
    return ret;
}

/**
 *  \test   Test the setting up a TCP session when we are seeing asynchronous
 *          stream, while we see all the packets in that stream from start.
 *
 *  \retval On success it returns 1 and on failure 0.
 */

static int StreamTcpTest10 (void)
{
    Packet *p = SCMalloc(SIZE_OF_PACKET);
    if (unlikely(p == NULL))
        return 0;
    Flow f;
    ThreadVars tv;
    StreamTcpThread stt;
    TCPHdr tcph;
    uint8_t payload[4];
    memset(p, 0, SIZE_OF_PACKET);
    PacketQueue pq;
    memset(&pq,0,sizeof(PacketQueue));
    memset (&f, 0, sizeof(Flow));
    memset(&tv, 0, sizeof (ThreadVars));
    memset(&stt, 0, sizeof (StreamTcpThread));
    memset(&tcph, 0, sizeof (TCPHdr));
    FLOW_INITIALIZE(&f);
    p->flow = &f;

    StreamTcpInitConfig(TRUE);

    tcph.th_win = htons(5480);
    tcph.th_seq = htonl(10);
    tcph.th_ack = htonl(11);
    tcph.th_flags = TH_SYN;
    p->tcph = &tcph;
    int ret = 0;

    FLOWLOCK_WRLOCK(&f);
    if (StreamTcpPacket(&tv, p, &stt, &pq) == -1)
        goto end;

    p->tcph->th_seq = htonl(11);
    p->tcph->th_ack = htonl(11);
    p->tcph->th_flags = TH_ACK;
    p->flowflags = FLOW_PKT_TOSERVER;

    if (StreamTcpPacket(&tv, p, &stt, &pq) == -1)
        goto end;

    p->tcph->th_seq = htonl(11);
    p->tcph->th_ack = htonl(11);
    p->tcph->th_flags = TH_ACK|TH_PUSH;
    p->flowflags = FLOW_PKT_TOSERVER;

    StreamTcpCreateTestPacket(payload, 0x42, 3, 4); /*BBB*/
    p->payload = payload;
    p->payload_len = 3;

    if (StreamTcpPacket(&tv, p, &stt, &pq) == -1)
        goto end;

    p->tcph->th_seq = htonl(6);
    p->tcph->th_ack = htonl(11);
    p->tcph->th_flags = TH_ACK|TH_PUSH;
    p->flowflags = FLOW_PKT_TOSERVER;

    StreamTcpCreateTestPacket(payload, 0x42, 3, 4); /*BBB*/
    p->payload = payload;
    p->payload_len = 3;

    if (StreamTcpPacket(&tv, p, &stt, &pq) == -1)
        goto end;

    if (stream_config.async_oneside != TRUE) {
        ret = 1;
        goto end;
    }
    if (((TcpSession *)(p->flow->protoctx))->state != TCP_ESTABLISHED) {
        printf("failed in setting state\n");
        goto end;
    }

    if (! (((TcpSession *)(p->flow->protoctx))->flags & STREAMTCP_FLAG_ASYNC)) {
        printf("failed in setting asynchronous session\n");
        goto end;
    }

    if (((TcpSession *)(p->flow->protoctx))->client.last_ack != 6 &&
            ((TcpSession *)(p->flow->protoctx))->server.next_seq != 11) {
        printf("failed in seq %"PRIu32" match\n",
                ((TcpSession *)(p->flow->protoctx))->client.last_ack);
        goto end;
    }

    StreamTcpSessionClear(p->flow->protoctx);

    ret = 1;
end:
    StreamTcpFreeConfig(TRUE);
    FLOWLOCK_UNLOCK(&f);
    SCFree(p);
    FLOW_DESTROY(&f);
    return ret;
}

/**
 *  \test   Test the setting up a TCP session when we are seeing asynchronous
 *          stream, while we missed the SYN packet of that stream.
 *
 *  \retval On success it returns 1 and on failure 0.
 */

static int StreamTcpTest11 (void)
{
    Packet *p = SCMalloc(SIZE_OF_PACKET);
    if (unlikely(p == NULL))
        return 0;
    Flow f;
    ThreadVars tv;
    StreamTcpThread stt;
    TCPHdr tcph;
    uint8_t payload[4];
    memset(p, 0, SIZE_OF_PACKET);
    PacketQueue pq;
    memset(&pq,0,sizeof(PacketQueue));
    memset (&f, 0, sizeof(Flow));
    memset(&tv, 0, sizeof (ThreadVars));
    memset(&stt, 0, sizeof (StreamTcpThread));
    memset(&tcph, 0, sizeof (TCPHdr));
    FLOW_INITIALIZE(&f);
    p->flow = &f;

    StreamTcpInitConfig(TRUE);

    tcph.th_win = htons(5480);
    tcph.th_seq = htonl(10);
    tcph.th_ack = htonl(1);
    tcph.th_flags = TH_SYN|TH_ACK;
    p->tcph = &tcph;
    int ret = 0;

    FLOWLOCK_WRLOCK(&f);
    if (StreamTcpPacket(&tv, p, &stt, &pq) == -1)
        goto end;

    p->tcph->th_seq = htonl(11);
    p->tcph->th_ack = htonl(1);
    p->tcph->th_flags = TH_ACK;
    p->flowflags = FLOW_PKT_TOSERVER;

    if (StreamTcpPacket(&tv, p, &stt, &pq) == -1)
        goto end;

    p->tcph->th_seq = htonl(11);
    p->tcph->th_ack = htonl(1);
    p->tcph->th_flags = TH_ACK|TH_PUSH;
    p->flowflags = FLOW_PKT_TOSERVER;

    StreamTcpCreateTestPacket(payload, 0x42, 3, 4); /*BBB*/
    p->payload = payload;
    p->payload_len = 3;

    if (StreamTcpPacket(&tv, p, &stt, &pq) == -1)
        goto end;

    p->tcph->th_seq = htonl(2);
    p->tcph->th_ack = htonl(1);
    p->tcph->th_flags = TH_ACK|TH_PUSH;
    p->flowflags = FLOW_PKT_TOSERVER;

    StreamTcpCreateTestPacket(payload, 0x42, 3, 4); /*BBB*/
    p->payload = payload;
    p->payload_len = 3;

    if (StreamTcpPacket(&tv, p, &stt, &pq) == -1)
        goto end;

    if (stream_config.async_oneside != TRUE) {
        ret = 1;
        goto end;
    }

    if (! (((TcpSession *)(p->flow->protoctx))->flags & STREAMTCP_FLAG_ASYNC)) {
        printf("failed in setting asynchronous session\n");
        goto end;
    }

    if (((TcpSession *)(p->flow->protoctx))->state != TCP_ESTABLISHED) {
        printf("failed in setting state\n");
        goto end;
    }

    if (((TcpSession *)(p->flow->protoctx))->server.last_ack != 2 &&
            ((TcpSession *)(p->flow->protoctx))->client.next_seq != 1) {
        printf("failed in seq %"PRIu32" match\n",
                ((TcpSession *)(p->flow->protoctx))->server.last_ack);
        goto end;
    }

    StreamTcpSessionClear(p->flow->protoctx);

    ret = 1;
end:
    StreamTcpFreeConfig(TRUE);
    FLOWLOCK_UNLOCK(&f);
    SCFree(p);
    FLOW_DESTROY(&f);
    return ret;
}

/**
 *  \test   Test the setting up a TCP session when we are seeing asynchronous
 *          stream, while we missed the SYN and SYN/ACK packets in that stream.
 *
 *  \retval On success it returns 1 and on failure 0.
 */

static int StreamTcpTest12 (void)
{
    Packet *p = SCMalloc(SIZE_OF_PACKET);
    if (unlikely(p == NULL))
        return 0;
    Flow f;
    ThreadVars tv;
    StreamTcpThread stt;
    TCPHdr tcph;
    uint8_t payload[4];
    memset(p, 0, SIZE_OF_PACKET);
    PacketQueue pq;
    memset(&pq,0,sizeof(PacketQueue));
    memset (&f, 0, sizeof(Flow));
    memset(&tv, 0, sizeof (ThreadVars));
    memset(&stt, 0, sizeof (StreamTcpThread));
    memset(&tcph, 0, sizeof (TCPHdr));
    FLOW_INITIALIZE(&f);
    p->flow = &f;

    StreamTcpInitConfig(TRUE);

    tcph.th_win = htons(5480);
    tcph.th_seq = htonl(10);
    tcph.th_ack = htonl(11);
    tcph.th_flags = TH_ACK;
    p->tcph = &tcph;
    int ret = 0;

    FLOWLOCK_WRLOCK(&f);
    if (StreamTcpPacket(&tv, p, &stt, &pq) == -1)
        goto end;

    p->tcph->th_seq = htonl(10);
    p->tcph->th_ack = htonl(11);
    p->tcph->th_flags = TH_ACK|TH_PUSH;
    p->flowflags = FLOW_PKT_TOSERVER;

    StreamTcpCreateTestPacket(payload, 0x42, 3, 4); /*BBB*/
    p->payload = payload;
    p->payload_len = 3;

    if (StreamTcpPacket(&tv, p, &stt, &pq) == -1)
        goto end;

    p->tcph->th_seq = htonl(6);
    p->tcph->th_ack = htonl(11);
    p->tcph->th_flags = TH_ACK|TH_PUSH;
    p->flowflags = FLOW_PKT_TOSERVER;

    StreamTcpCreateTestPacket(payload, 0x42, 3, 4); /*BBB*/
    p->payload = payload;
    p->payload_len = 3;

    if (StreamTcpPacket(&tv, p, &stt, &pq) == -1)
        goto end;

    if (stream_config.async_oneside != TRUE) {
        ret = 1;
        goto end;
    }

    if (! (((TcpSession *)(p->flow->protoctx))->flags & STREAMTCP_FLAG_ASYNC)) {
        printf("failed in setting asynchronous session\n");
        goto end;
    }

    if (((TcpSession *)(p->flow->protoctx))->state != TCP_ESTABLISHED) {
        printf("failed in setting state\n");
        goto end;
    }

    if (((TcpSession *)(p->flow->protoctx))->client.last_ack != 6 &&
            ((TcpSession *)(p->flow->protoctx))->server.next_seq != 11) {
        printf("failed in seq %"PRIu32" match\n",
                ((TcpSession *)(p->flow->protoctx))->client.last_ack);
        goto end;
    }

    StreamTcpSessionClear(p->flow->protoctx);

    ret = 1;
end:
    StreamTcpFreeConfig(TRUE);
    FLOWLOCK_UNLOCK(&f);
    SCFree(p);
    FLOW_DESTROY(&f);
    return ret;
}

/**
 *  \test   Test the setting up a TCP session when we are seeing asynchronous
 *          stream, while we missed the SYN and SYN/ACK packets in that stream.
 *          Later, we start to receive the packet from other end stream too.
 *
 *  \retval On success it returns 1 and on failure 0.
 */

static int StreamTcpTest13 (void)
{
    Packet *p = SCMalloc(SIZE_OF_PACKET);
    if (unlikely(p == NULL))
        return 0;
    Flow f;
    ThreadVars tv;
    StreamTcpThread stt;
    TCPHdr tcph;
    uint8_t payload[4];
    memset(p, 0, SIZE_OF_PACKET);
    PacketQueue pq;
    memset(&pq,0,sizeof(PacketQueue));
    memset (&f, 0, sizeof(Flow));
    memset(&tv, 0, sizeof (ThreadVars));
    memset(&stt, 0, sizeof (StreamTcpThread));
    memset(&tcph, 0, sizeof (TCPHdr));
    FLOW_INITIALIZE(&f);
    p->flow = &f;

    StreamTcpInitConfig(TRUE);

    tcph.th_win = htons(5480);
    tcph.th_seq = htonl(10);
    tcph.th_ack = htonl(11);
    tcph.th_flags = TH_ACK;
    p->tcph = &tcph;
    int ret = 0;

    FLOWLOCK_WRLOCK(&f);
    if (StreamTcpPacket(&tv, p, &stt, &pq) == -1)
        goto end;

    p->tcph->th_seq = htonl(10);
    p->tcph->th_ack = htonl(11);
    p->tcph->th_flags = TH_ACK|TH_PUSH;
    p->flowflags = FLOW_PKT_TOSERVER;

    StreamTcpCreateTestPacket(payload, 0x42, 3, 4); /*BBB*/
    p->payload = payload;
    p->payload_len = 3;

    if (StreamTcpPacket(&tv, p, &stt, &pq) == -1)
        goto end;

    p->tcph->th_seq = htonl(6);
    p->tcph->th_ack = htonl(11);
    p->tcph->th_flags = TH_ACK|TH_PUSH;
    p->flowflags = FLOW_PKT_TOSERVER;

    StreamTcpCreateTestPacket(payload, 0x42, 3, 4); /*BBB*/
    p->payload = payload;
    p->payload_len = 3;

    if (StreamTcpPacket(&tv, p, &stt, &pq) == -1)
        goto end;

    if (stream_config.async_oneside != TRUE) {
        ret = 1;
        goto end;
    }

    if (! (((TcpSession *)(p->flow->protoctx))->flags & STREAMTCP_FLAG_ASYNC)) {
        printf("failed in setting asynchronous session\n");
        goto end;
    }

    if (((TcpSession *)(p->flow->protoctx))->state != TCP_ESTABLISHED) {
        printf("failed in setting state\n");
        goto end;
    }

    p->tcph->th_seq = htonl(11);
    p->tcph->th_ack = htonl(9);
    p->tcph->th_flags = TH_ACK|TH_PUSH;
    p->flowflags = FLOW_PKT_TOCLIENT;

    StreamTcpCreateTestPacket(payload, 0x42, 3, 4); /*BBB*/
    p->payload = payload;
    p->payload_len = 3;

    if (StreamTcpPacket(&tv, p, &stt, &pq) == -1)
        goto end;

    if (((TcpSession *)(p->flow->protoctx))->client.last_ack != 9 &&
            ((TcpSession *)(p->flow->protoctx))->server.next_seq != 14) {
        printf("failed in seq %"PRIu32" match\n",
                ((TcpSession *)(p->flow->protoctx))->client.last_ack);
        goto end;
    }

    StreamTcpSessionPktFree(p);

    ret = 1;
end:
    StreamTcpFreeConfig(TRUE);
    FLOWLOCK_UNLOCK(&f);
    SCFree(p);
    FLOW_DESTROY(&f);
    return ret;
}

/* Dummy conf string to setup the OS policy for unit testing */
static const char *dummy_conf_string =
    "%YAML 1.1\n"
    "---\n"
    "\n"
    "default-log-dir: /var/log/eidps\n"
    "\n"
    "logging:\n"
    "\n"
    "  default-log-level: debug\n"
    "\n"
    "  default-format: \"<%t> - <%l>\"\n"
    "\n"
    "  default-startup-message: Your IDS has started.\n"
    "\n"
    "  default-output-filter:\n"
    "\n"
    "host-os-policy:\n"
    "\n"
    " windows: 192.168.0.1\n"
    "\n"
    " linux: 192.168.0.2\n"
    "\n";
/* Dummy conf string to setup the OS policy for unit testing */
static const char *dummy_conf_string1 =
    "%YAML 1.1\n"
    "---\n"
    "\n"
    "default-log-dir: /var/log/eidps\n"
    "\n"
    "logging:\n"
    "\n"
    "  default-log-level: debug\n"
    "\n"
    "  default-format: \"<%t> - <%l>\"\n"
    "\n"
    "  default-startup-message: Your IDS has started.\n"
    "\n"
    "  default-output-filter:\n"
    "\n"
    "host-os-policy:\n"
    "\n"
    " windows: 192.168.0.0/24," "192.168.1.1\n"
    "\n"
    " linux: 192.168.1.0/24," "192.168.0.1\n"
    "\n";

/**
 *  \brief  Function to parse the dummy conf string and get the value of IP
 *          address for the corresponding OS policy type.
 *
 *  \param  conf_val_name   Name of the OS policy type
 *  \retval returns IP address as string on success and NULL on failure
 */
char *StreamTcpParseOSPolicy (char *conf_var_name)
{
    SCEnter();
    char conf_var_type_name[15] = "host-os-policy";
    char *conf_var_full_name = NULL;
    char *conf_var_value = NULL;

    if (conf_var_name == NULL)
        goto end;

    /* the + 2 is for the '.' and the string termination character '\0' */
    conf_var_full_name = (char *)SCMalloc(strlen(conf_var_type_name) +
                                        strlen(conf_var_name) + 2);
    if (conf_var_full_name == NULL)
        goto end;

    if (snprintf(conf_var_full_name,
                 strlen(conf_var_type_name) + strlen(conf_var_name) + 2, "%s.%s",
                 conf_var_type_name, conf_var_name) < 0) {
        SCLogError(SC_ERR_INVALID_VALUE, "Error in making the conf full name");
        goto end;
    }

    if (ConfGet(conf_var_full_name, &conf_var_value) != 1) {
        SCLogError(SC_ERR_UNKNOWN_VALUE, "Error in getting conf value for conf name %s",
                    conf_var_full_name);
        goto end;
    }

    SCLogDebug("Value obtained from the yaml conf file, for the var "
               "\"%s\" is \"%s\"", conf_var_name, conf_var_value);

 end:
    if (conf_var_full_name != NULL)
        SCFree(conf_var_full_name);
    SCReturnCharPtr(conf_var_value);


}
/**
 *  \test   Test the setting up a OS policy. Te OS policy values are defined in
 *          the config string "dummy_conf_string"
 *
 *  \retval On success it returns 1 and on failure 0
 */

static int StreamTcpTest14 (void)
{
    Packet *p = SCMalloc(SIZE_OF_PACKET);
    if (unlikely(p == NULL))
        return 0;
    Flow f;
    ThreadVars tv;
    StreamTcpThread stt;
    TCPHdr tcph;
    uint8_t payload[4];
    struct in_addr addr;
    IPV4Hdr ipv4h;
    char os_policy_name[10] = "windows";
    char *ip_addr;
    PacketQueue pq;
    memset(&pq,0,sizeof(PacketQueue));

    memset(p, 0, SIZE_OF_PACKET);
    memset (&f, 0, sizeof(Flow));
    memset(&tv, 0, sizeof (ThreadVars));
    memset(&stt, 0, sizeof (StreamTcpThread));
    memset(&tcph, 0, sizeof (TCPHdr));
    memset(&addr, 0, sizeof(addr));
    memset(&ipv4h, 0, sizeof(ipv4h));
    FLOW_INITIALIZE(&f);
    p->flow = &f;
    int ret = 0;

    StreamTcpInitConfig(TRUE);

    /* Load the config string in to parser */
    ConfCreateContextBackup();
    ConfInit();
    ConfYamlLoadString(dummy_conf_string, strlen(dummy_conf_string));

    /* Get the IP address as string and add it to Host info tree for lookups */
    ip_addr = StreamTcpParseOSPolicy(os_policy_name);
    SCHInfoAddHostOSInfo(os_policy_name, ip_addr, -1);
    strlcpy(os_policy_name, "linux\0", sizeof(os_policy_name));
    ip_addr = StreamTcpParseOSPolicy(os_policy_name);
    SCHInfoAddHostOSInfo(os_policy_name, ip_addr, -1);

    /* prevent L7 from kicking in */
    StreamMsgQueueSetMinChunkLen(FLOW_PKT_TOSERVER, 4096);
    StreamMsgQueueSetMinChunkLen(FLOW_PKT_TOCLIENT, 4096);

    addr.s_addr = inet_addr("192.168.0.1");
    tcph.th_win = htons(5480);
    tcph.th_seq = htonl(10);
    tcph.th_ack = htonl(20);
    tcph.th_flags = TH_ACK|TH_PUSH;
    p->tcph = &tcph;
    p->dst.family = AF_INET;
    p->dst.address.address_un_data32[0] = addr.s_addr;
    p->ip4h = &ipv4h;

    StreamTcpCreateTestPacket(payload, 0x41, 3, sizeof(payload)); /*AAA*/
    p->payload = payload;
    p->payload_len = 3;

    FLOWLOCK_WRLOCK(&f);
    if (StreamTcpPacket(&tv, p, &stt, &pq) == -1)
        goto end;

    p->tcph->th_seq = htonl(20);
    p->tcph->th_ack = htonl(13);
    p->tcph->th_flags = TH_ACK|TH_PUSH;
    p->flowflags = FLOW_PKT_TOCLIENT;

    StreamTcpCreateTestPacket(payload, 0x42, 3, sizeof(payload)); /*BBB*/
    p->payload = payload;
    p->payload_len = 3;

    if (StreamTcpPacket(&tv, p, &stt, &pq) == -1)
        goto end;

    p->tcph->th_seq = htonl(15);
    p->tcph->th_ack = htonl(23);
    p->tcph->th_flags = TH_ACK|TH_PUSH;
    p->flowflags = FLOW_PKT_TOSERVER;

    StreamTcpCreateTestPacket(payload, 0x43, 3, sizeof(payload)); /*CCC*/
    p->payload = payload;
    p->payload_len = 3;

    if (StreamTcpPacket(&tv, p, &stt, &pq) == -1)
        goto end;

    p->tcph->th_seq = htonl(14);
    p->tcph->th_ack = htonl(23);
    p->tcph->th_flags = TH_ACK|TH_PUSH;
    p->flowflags = FLOW_PKT_TOSERVER;

    StreamTcpCreateTestPacket(payload, 0x43, 3, sizeof(payload)); /*CCC*/
    p->payload = payload;
    p->payload_len = 3;

    if (StreamTcpPacket(&tv, p, &stt, &pq) == -1)
        goto end;

    addr.s_addr = inet_addr("192.168.0.2");
    p->tcph->th_seq = htonl(25);
    p->tcph->th_ack = htonl(13);
    p->tcph->th_flags = TH_ACK|TH_PUSH;
    p->flowflags = FLOW_PKT_TOCLIENT;
    p->dst.address.address_un_data32[0] = addr.s_addr;

    StreamTcpCreateTestPacket(payload, 0x44, 3, sizeof(payload)); /*DDD*/
    p->payload = payload;
    p->payload_len = 3;

    if (StreamTcpPacket(&tv, p, &stt, &pq) == -1)
        goto end;

    p->tcph->th_seq = htonl(24);
    p->tcph->th_ack = htonl(13);
    p->tcph->th_flags = TH_ACK|TH_PUSH;
    p->flowflags = FLOW_PKT_TOCLIENT;

    StreamTcpCreateTestPacket(payload, 0x44, 3, sizeof(payload)); /*DDD*/
    p->payload = payload;
    p->payload_len = 3;

    if (StreamTcpPacket(&tv, p, &stt, &pq) == -1)
        goto end;

    if (stream_config.midstream != TRUE) {
        ret = 1;
        goto end;
    }
    if (((TcpSession *)(p->flow->protoctx))->state != TCP_ESTABLISHED)
        goto end;

    if (((TcpSession *)(p->flow->protoctx))->client.next_seq != 13 &&
            ((TcpSession *)(p->flow->protoctx))->server.next_seq != 23) {
        printf("failed in next_seq match client.next_seq %"PRIu32""
                " server.next_seq %"PRIu32"\n",
                ((TcpSession *)(p->flow->protoctx))->client.next_seq,
                ((TcpSession *)(p->flow->protoctx))->server.next_seq);
        goto end;
    }

    if (((TcpSession *)(p->flow->protoctx))->client.os_policy !=
            OS_POLICY_WINDOWS && ((TcpSession *)
            (p->flow->protoctx))->server.os_policy != OS_POLICY_LINUX)
    {
        printf("failed in setting up OS policy, client.os_policy: %"PRIu8""
                " should be %"PRIu8" and server.os_policy: %"PRIu8""
                " should be %"PRIu8"\n", ((TcpSession *)
                (p->flow->protoctx))->client.os_policy, (uint8_t)OS_POLICY_WINDOWS,
                ((TcpSession *)(p->flow->protoctx))->server.os_policy,
                (uint8_t)OS_POLICY_LINUX);
        goto end;
    }
    StreamTcpSessionClear(p->flow->protoctx);

    ret = 1;
end:
    StreamTcpFreeConfig(TRUE);
    ConfDeInit();
    ConfRestoreContextBackup();
    FLOWLOCK_UNLOCK(&f);
    SCFree(p);
    FLOW_DESTROY(&f);
    return ret;
}

/**
 *  \test   Test the setting up a TCP session using the 4WHS:
 *          SYN, SYN, SYN/ACK, ACK
 *
 *  \retval On success it returns 1 and on failure 0.
 */

static int StreamTcp4WHSTest01 (void)
{
    int ret = 0;
    Packet *p = SCMalloc(SIZE_OF_PACKET);
    if (unlikely(p == NULL))
        return 0;
    Flow f;
    ThreadVars tv;
    StreamTcpThread stt;
    TCPHdr tcph;
    memset(p, 0, SIZE_OF_PACKET);
    PacketQueue pq;
    memset(&pq,0,sizeof(PacketQueue));
    memset (&f, 0, sizeof(Flow));
    memset(&tv, 0, sizeof (ThreadVars));
    memset(&stt, 0, sizeof (StreamTcpThread));
    memset(&tcph, 0, sizeof (TCPHdr));
    FLOW_INITIALIZE(&f);
    p->flow = &f;

    StreamTcpInitConfig(TRUE);

    tcph.th_win = htons(5480);
    tcph.th_seq = htonl(10);
    tcph.th_ack = 0;
    tcph.th_flags = TH_SYN;
    p->tcph = &tcph;

    FLOWLOCK_WRLOCK(&f);
    if (StreamTcpPacket(&tv, p, &stt, &pq) == -1)
        goto end;

    p->tcph->th_seq = htonl(20);
    p->tcph->th_ack = 0;
    p->tcph->th_flags = TH_SYN;
    p->flowflags = FLOW_PKT_TOCLIENT;

    if (StreamTcpPacket(&tv, p, &stt, &pq) == -1)
        goto end;

    if ((!(((TcpSession *)(p->flow->protoctx))->flags & STREAMTCP_FLAG_4WHS))) {
        printf("STREAMTCP_FLAG_4WHS flag not set: ");
        goto end;
    }

    p->tcph->th_seq = htonl(10);
    p->tcph->th_ack = htonl(21); /* the SYN/ACK uses the SEQ from the first SYN pkt */
    p->tcph->th_flags = TH_SYN|TH_ACK;
    p->flowflags = FLOW_PKT_TOSERVER;

    if (StreamTcpPacket(&tv, p, &stt, &pq) == -1)
        goto end;

    p->tcph->th_seq = htonl(21);
    p->tcph->th_ack = htonl(10);
    p->tcph->th_flags = TH_ACK;
    p->flowflags = FLOW_PKT_TOCLIENT;

    if (StreamTcpPacket(&tv, p, &stt, &pq) == -1)
        goto end;

    if (((TcpSession *)(p->flow->protoctx))->state != TCP_ESTABLISHED) {
        printf("state is not ESTABLISHED: ");
        goto end;
    }

    ret = 1;
end:
    StreamTcpSessionClear(p->flow->protoctx);
    StreamTcpFreeConfig(TRUE);
    FLOWLOCK_UNLOCK(&f);
    SCFree(p);
    FLOW_DESTROY(&f);
    return ret;
}

/**
 *  \test   set up a TCP session using the 4WHS:
 *          SYN, SYN, SYN/ACK, ACK, but the SYN/ACK does
 *          not have the right SEQ
 *
 *  \retval On success it returns 1 and on failure 0.
 */

static int StreamTcp4WHSTest02 (void)
{
    int ret = 0;
    Packet *p = SCMalloc(SIZE_OF_PACKET);
    if (unlikely(p == NULL))
        return 0;
    Flow f;
    ThreadVars tv;
    StreamTcpThread stt;
    TCPHdr tcph;
    memset(p, 0, SIZE_OF_PACKET);
    PacketQueue pq;
    memset(&pq,0,sizeof(PacketQueue));
    memset (&f, 0, sizeof(Flow));
    memset(&tv, 0, sizeof (ThreadVars));
    memset(&stt, 0, sizeof (StreamTcpThread));
    memset(&tcph, 0, sizeof (TCPHdr));
    FLOW_INITIALIZE(&f);
    p->flow = &f;

    StreamTcpInitConfig(TRUE);

    tcph.th_win = htons(5480);
    tcph.th_seq = htonl(10);
    tcph.th_ack = 0;
    tcph.th_flags = TH_SYN;
    p->tcph = &tcph;

    FLOWLOCK_WRLOCK(&f);
    if (StreamTcpPacket(&tv, p, &stt, &pq) == -1)
        goto end;

    p->tcph->th_seq = htonl(20);
    p->tcph->th_ack = 0;
    p->tcph->th_flags = TH_SYN;
    p->flowflags = FLOW_PKT_TOCLIENT;

    if (StreamTcpPacket(&tv, p, &stt, &pq) == -1)
        goto end;

    if ((!(((TcpSession *)(p->flow->protoctx))->flags & STREAMTCP_FLAG_4WHS))) {
        printf("STREAMTCP_FLAG_4WHS flag not set: ");
        goto end;
    }

    p->tcph->th_seq = htonl(30);
    p->tcph->th_ack = htonl(21); /* the SYN/ACK uses the SEQ from the first SYN pkt */
    p->tcph->th_flags = TH_SYN|TH_ACK;
    p->flowflags = FLOW_PKT_TOSERVER;

    if (StreamTcpPacket(&tv, p, &stt, &pq) != -1) {
        printf("SYN/ACK pkt not rejected but it should have: ");
        goto end;
    }

    ret = 1;
end:
    StreamTcpSessionClear(p->flow->protoctx);
    StreamTcpFreeConfig(TRUE);
    FLOWLOCK_UNLOCK(&f);
    SCFree(p);
    FLOW_DESTROY(&f);
    return ret;
}

/**
 *  \test   set up a TCP session using the 4WHS:
 *          SYN, SYN, SYN/ACK, ACK: however the SYN/ACK and ACK
 *          are part of a normal 3WHS
 *
 *  \retval On success it returns 1 and on failure 0.
 */

static int StreamTcp4WHSTest03 (void)
{
    int ret = 0;
    Packet *p = SCMalloc(SIZE_OF_PACKET);
    if (unlikely(p == NULL))
        return 0;
    Flow f;
    ThreadVars tv;
    StreamTcpThread stt;
    TCPHdr tcph;
    memset(p, 0, SIZE_OF_PACKET);
    PacketQueue pq;
    memset(&pq,0,sizeof(PacketQueue));
    memset (&f, 0, sizeof(Flow));
    memset(&tv, 0, sizeof (ThreadVars));
    memset(&stt, 0, sizeof (StreamTcpThread));
    memset(&tcph, 0, sizeof (TCPHdr));
    FLOW_INITIALIZE(&f);
    p->flow = &f;

    StreamTcpInitConfig(TRUE);

    tcph.th_win = htons(5480);
    tcph.th_seq = htonl(10);
    tcph.th_ack = 0;
    tcph.th_flags = TH_SYN;
    p->tcph = &tcph;

    FLOWLOCK_WRLOCK(&f);
    if (StreamTcpPacket(&tv, p, &stt, &pq) == -1)
        goto end;

    p->tcph->th_seq = htonl(20);
    p->tcph->th_ack = 0;
    p->tcph->th_flags = TH_SYN;
    p->flowflags = FLOW_PKT_TOCLIENT;

    if (StreamTcpPacket(&tv, p, &stt, &pq) == -1)
        goto end;

    if ((!(((TcpSession *)(p->flow->protoctx))->flags & STREAMTCP_FLAG_4WHS))) {
        printf("STREAMTCP_FLAG_4WHS flag not set: ");
        goto end;
    }

    p->tcph->th_seq = htonl(30);
    p->tcph->th_ack = htonl(11);
    p->tcph->th_flags = TH_SYN|TH_ACK;
    p->flowflags = FLOW_PKT_TOCLIENT;

    if (StreamTcpPacket(&tv, p, &stt, &pq) == -1)
        goto end;

    p->tcph->th_seq = htonl(11);
    p->tcph->th_ack = htonl(31);
    p->tcph->th_flags = TH_ACK;
    p->flowflags = FLOW_PKT_TOSERVER;

    if (StreamTcpPacket(&tv, p, &stt, &pq) == -1)
        goto end;

    if (((TcpSession *)(p->flow->protoctx))->state != TCP_ESTABLISHED) {
        printf("state is not ESTABLISHED: ");
        goto end;
    }

    ret = 1;
end:
    StreamTcpSessionClear(p->flow->protoctx);
    StreamTcpFreeConfig(TRUE);
    FLOWLOCK_UNLOCK(&f);
    SCFree(p);
    FLOW_DESTROY(&f);
    return ret;
}

/**
 *  \test   Test the setting up a OS policy. Te OS policy values are defined in
 *          the config string "dummy_conf_string1"
 *
 *  \retval On success it returns 1 and on failure 0
 */

static int StreamTcpTest15 (void)
{
    Packet *p = SCMalloc(SIZE_OF_PACKET);
    if (unlikely(p == NULL))
        return 0;
    Flow f;
    ThreadVars tv;
    StreamTcpThread stt;
    TCPHdr tcph;
    uint8_t payload[4];
    struct in_addr addr;
    IPV4Hdr ipv4h;
    char os_policy_name[10] = "windows";
    char *ip_addr;
    PacketQueue pq;
    memset(&pq,0,sizeof(PacketQueue));

    memset(p, 0, SIZE_OF_PACKET);
    memset (&f, 0, sizeof(Flow));
    memset(&tv, 0, sizeof (ThreadVars));
    memset(&stt, 0, sizeof (StreamTcpThread));
    memset(&tcph, 0, sizeof (TCPHdr));
    memset(&addr, 0, sizeof(addr));
    memset(&ipv4h, 0, sizeof(ipv4h));
    FLOW_INITIALIZE(&f);
    p->flow = &f;
    int ret = 0;

    StreamTcpInitConfig(TRUE);

    /* Load the config string in to parser */
    ConfCreateContextBackup();
    ConfInit();
    ConfYamlLoadString(dummy_conf_string1, strlen(dummy_conf_string1));

    /* Get the IP address as string and add it to Host info tree for lookups */
    ip_addr = StreamTcpParseOSPolicy(os_policy_name);
    SCHInfoAddHostOSInfo(os_policy_name, ip_addr, -1);
    strlcpy(os_policy_name, "linux\0", sizeof(os_policy_name));
    ip_addr = StreamTcpParseOSPolicy(os_policy_name);
    SCHInfoAddHostOSInfo(os_policy_name, ip_addr, -1);

    /* prevent L7 from kicking in */
    StreamMsgQueueSetMinChunkLen(FLOW_PKT_TOSERVER, 4096);
    StreamMsgQueueSetMinChunkLen(FLOW_PKT_TOCLIENT, 4096);

    addr.s_addr = inet_addr("192.168.0.20");
    tcph.th_win = htons(5480);
    tcph.th_seq = htonl(10);
    tcph.th_ack = htonl(20);
    tcph.th_flags = TH_ACK|TH_PUSH;
    p->tcph = &tcph;
    p->dst.family = AF_INET;
    p->dst.address.address_un_data32[0] = addr.s_addr;
    p->ip4h = &ipv4h;

    StreamTcpCreateTestPacket(payload, 0x41, 3, sizeof(payload)); /*AAA*/
    p->payload = payload;
    p->payload_len = 3;

    FLOWLOCK_WRLOCK(&f);
    if (StreamTcpPacket(&tv, p, &stt, &pq) == -1)
        goto end;

    p->tcph->th_seq = htonl(20);
    p->tcph->th_ack = htonl(13);
    p->tcph->th_flags = TH_ACK|TH_PUSH;
    p->flowflags = FLOW_PKT_TOCLIENT;

    StreamTcpCreateTestPacket(payload, 0x42, 3, sizeof(payload)); /*BBB*/
    p->payload = payload;
    p->payload_len = 3;

    if (StreamTcpPacket(&tv, p, &stt, &pq) == -1)
        goto end;

    p->tcph->th_seq = htonl(15);
    p->tcph->th_ack = htonl(23);
    p->tcph->th_flags = TH_ACK|TH_PUSH;
    p->flowflags = FLOW_PKT_TOSERVER;

    StreamTcpCreateTestPacket(payload, 0x43, 3, sizeof(payload)); /*CCC*/
    p->payload = payload;
    p->payload_len = 3;

    if (StreamTcpPacket(&tv, p, &stt, &pq) == -1)
        goto end;

    p->tcph->th_seq = htonl(14);
    p->tcph->th_ack = htonl(23);
    p->tcph->th_flags = TH_ACK|TH_PUSH;
    p->flowflags = FLOW_PKT_TOSERVER;

    StreamTcpCreateTestPacket(payload, 0x43, 3, sizeof(payload)); /*CCC*/
    p->payload = payload;
    p->payload_len = 3;

    if (StreamTcpPacket(&tv, p, &stt, &pq) == -1)
        goto end;

    addr.s_addr = inet_addr("192.168.1.20");
    p->tcph->th_seq = htonl(25);
    p->tcph->th_ack = htonl(13);
    p->tcph->th_flags = TH_ACK|TH_PUSH;
    p->flowflags = FLOW_PKT_TOCLIENT;
    p->dst.address.address_un_data32[0] = addr.s_addr;

    StreamTcpCreateTestPacket(payload, 0x44, 3, sizeof(payload)); /*DDD*/
    p->payload = payload;
    p->payload_len = 3;

    if (StreamTcpPacket(&tv, p, &stt, &pq) == -1)
        goto end;

    p->tcph->th_seq = htonl(24);
    p->tcph->th_ack = htonl(13);
    p->tcph->th_flags = TH_ACK|TH_PUSH;
    p->flowflags = FLOW_PKT_TOCLIENT;

    StreamTcpCreateTestPacket(payload, 0x44, 3, sizeof(payload)); /*DDD*/
    p->payload = payload;
    p->payload_len = 3;

    if (StreamTcpPacket(&tv, p, &stt, &pq) == -1)
        goto end;

    if (stream_config.midstream != TRUE) {
        ret = 1;
        goto end;
    }
    if (((TcpSession *)(p->flow->protoctx))->state != TCP_ESTABLISHED)
        goto end;

    if (((TcpSession *)(p->flow->protoctx))->client.next_seq != 13 &&
            ((TcpSession *)(p->flow->protoctx))->server.next_seq != 23) {
        printf("failed in next_seq match client.next_seq %"PRIu32""
                " server.next_seq %"PRIu32"\n",
                ((TcpSession *)(p->flow->protoctx))->client.next_seq,
                ((TcpSession *)(p->flow->protoctx))->server.next_seq);
        goto end;
    }

    if (((TcpSession *)(p->flow->protoctx))->client.os_policy !=
            OS_POLICY_WINDOWS && ((TcpSession *)
            (p->flow->protoctx))->server.os_policy != OS_POLICY_LINUX)
    {
        printf("failed in setting up OS policy, client.os_policy: %"PRIu8""
                " should be %"PRIu8" and server.os_policy: %"PRIu8""
                " should be %"PRIu8"\n", ((TcpSession *)
                (p->flow->protoctx))->client.os_policy, (uint8_t)OS_POLICY_WINDOWS,
                ((TcpSession *)(p->flow->protoctx))->server.os_policy,
                (uint8_t)OS_POLICY_LINUX);
        goto end;
    }
    StreamTcpSessionPktFree(p);

    ret = 1;
end:
    StreamTcpFreeConfig(TRUE);
    ConfDeInit();
    ConfRestoreContextBackup();
    FLOWLOCK_UNLOCK(&f);
    SCFree(p);
    FLOW_DESTROY(&f);
    return ret;
}

/**
 *  \test   Test the setting up a OS policy. Te OS policy values are defined in
 *          the config string "dummy_conf_string1"
 *
 *  \retval On success it returns 1 and on failure 0
 */

static int StreamTcpTest16 (void)
{
    Packet *p = SCMalloc(SIZE_OF_PACKET);
    if (unlikely(p == NULL))
        return 0;
    Flow f;
    ThreadVars tv;
    StreamTcpThread stt;
    TCPHdr tcph;
    uint8_t payload[4];
    struct in_addr addr;
    IPV4Hdr ipv4h;
    char os_policy_name[10] = "windows";
    char *ip_addr;
    PacketQueue pq;
    memset(&pq,0,sizeof(PacketQueue));

    memset(p, 0, SIZE_OF_PACKET);
    memset (&f, 0, sizeof(Flow));
    memset(&tv, 0, sizeof (ThreadVars));
    memset(&stt, 0, sizeof (StreamTcpThread));
    memset(&tcph, 0, sizeof (TCPHdr));
    memset(&addr, 0, sizeof(addr));
    memset(&ipv4h, 0, sizeof(ipv4h));
    FLOW_INITIALIZE(&f);
    p->flow = &f;
    int ret = 0;

    StreamTcpInitConfig(TRUE);

    /* Load the config string in to parser */
    ConfCreateContextBackup();
    ConfInit();
    ConfYamlLoadString(dummy_conf_string1, strlen(dummy_conf_string1));

    /* Get the IP address as string and add it to Host info tree for lookups */
    ip_addr = StreamTcpParseOSPolicy(os_policy_name);
    SCHInfoAddHostOSInfo(os_policy_name, ip_addr, -1);
    strlcpy(os_policy_name, "linux\0", sizeof(os_policy_name));
    ip_addr = StreamTcpParseOSPolicy(os_policy_name);
    SCHInfoAddHostOSInfo(os_policy_name, ip_addr, -1);

    /* prevent L7 from kicking in */
    StreamMsgQueueSetMinChunkLen(FLOW_PKT_TOSERVER, 4096);
    StreamMsgQueueSetMinChunkLen(FLOW_PKT_TOCLIENT, 4096);

    addr.s_addr = inet_addr("192.168.0.1");
    tcph.th_win = htons(5480);
    tcph.th_seq = htonl(10);
    tcph.th_ack = htonl(20);
    tcph.th_flags = TH_ACK|TH_PUSH;
    p->tcph = &tcph;
    p->dst.family = AF_INET;
    p->dst.address.address_un_data32[0] = addr.s_addr;
    p->ip4h = &ipv4h;

    StreamTcpCreateTestPacket(payload, 0x41, 3, sizeof(payload)); /*AAA*/
    p->payload = payload;
    p->payload_len = 3;

    FLOWLOCK_WRLOCK(&f);
    if (StreamTcpPacket(&tv, p, &stt, &pq) == -1)
        goto end;

    p->tcph->th_seq = htonl(20);
    p->tcph->th_ack = htonl(13);
    p->tcph->th_flags = TH_ACK|TH_PUSH;
    p->flowflags = FLOW_PKT_TOCLIENT;

    StreamTcpCreateTestPacket(payload, 0x42, 3, sizeof(payload)); /*BBB*/
    p->payload = payload;
    p->payload_len = 3;

    if (StreamTcpPacket(&tv, p, &stt, &pq) == -1)
        goto end;

    p->tcph->th_seq = htonl(15);
    p->tcph->th_ack = htonl(23);
    p->tcph->th_flags = TH_ACK|TH_PUSH;
    p->flowflags = FLOW_PKT_TOSERVER;

    StreamTcpCreateTestPacket(payload, 0x43, 3, sizeof(payload)); /*CCC*/
    p->payload = payload;
    p->payload_len = 3;

    if (StreamTcpPacket(&tv, p, &stt, &pq) == -1)
        goto end;

    p->tcph->th_seq = htonl(14);
    p->tcph->th_ack = htonl(23);
    p->tcph->th_flags = TH_ACK|TH_PUSH;
    p->flowflags = FLOW_PKT_TOSERVER;

    StreamTcpCreateTestPacket(payload, 0x43, 3, sizeof(payload)); /*CCC*/
    p->payload = payload;
    p->payload_len = 3;

    if (StreamTcpPacket(&tv, p, &stt, &pq) == -1)
        goto end;

    addr.s_addr = inet_addr("192.168.1.1");
    p->tcph->th_seq = htonl(25);
    p->tcph->th_ack = htonl(13);
    p->tcph->th_flags = TH_ACK|TH_PUSH;
    p->flowflags = FLOW_PKT_TOCLIENT;
    p->dst.address.address_un_data32[0] = addr.s_addr;

    StreamTcpCreateTestPacket(payload, 0x44, 3, sizeof(payload)); /*DDD*/
    p->payload = payload;
    p->payload_len = 3;

    if (StreamTcpPacket(&tv, p, &stt, &pq) == -1)
        goto end;

    p->tcph->th_seq = htonl(24);
    p->tcph->th_ack = htonl(13);
    p->tcph->th_flags = TH_ACK|TH_PUSH;
    p->flowflags = FLOW_PKT_TOCLIENT;

    StreamTcpCreateTestPacket(payload, 0x44, 3, sizeof(payload)); /*DDD*/
    p->payload = payload;
    p->payload_len = 3;

    if (StreamTcpPacket(&tv, p, &stt, &pq) == -1)
        goto end;

    if (stream_config.midstream != TRUE) {
        ret = 1;
        goto end;
    }
    if (((TcpSession *)(p->flow->protoctx))->state != TCP_ESTABLISHED)
        goto end;

    if (((TcpSession *)(p->flow->protoctx))->client.next_seq != 13 &&
            ((TcpSession *)(p->flow->protoctx))->server.next_seq != 23) {
        printf("failed in next_seq match client.next_seq %"PRIu32""
                " server.next_seq %"PRIu32"\n",
                ((TcpSession *)(p->flow->protoctx))->client.next_seq,
                ((TcpSession *)(p->flow->protoctx))->server.next_seq);
        goto end;
    }

    if (((TcpSession *)(p->flow->protoctx))->client.os_policy !=
            OS_POLICY_LINUX && ((TcpSession *)
            (p->flow->protoctx))->server.os_policy != OS_POLICY_WINDOWS)
    {
        printf("failed in setting up OS policy, client.os_policy: %"PRIu8""
                " should be %"PRIu8" and server.os_policy: %"PRIu8""
                " should be %"PRIu8"\n", ((TcpSession *)
                (p->flow->protoctx))->client.os_policy, (uint8_t)OS_POLICY_LINUX,
                ((TcpSession *)(p->flow->protoctx))->server.os_policy,
                (uint8_t)OS_POLICY_WINDOWS);
        goto end;
    }
    StreamTcpSessionPktFree(p);

    ret = 1;
end:
    StreamTcpFreeConfig(TRUE);
    ConfDeInit();
    ConfRestoreContextBackup();
    FLOWLOCK_UNLOCK(&f);
    SCFree(p);
    FLOW_DESTROY(&f);
    return ret;
}

/**
 *  \test   Test the setting up a OS policy. Te OS policy values are defined in
 *          the config string "dummy_conf_string1". To check the setting of
 *          Default os policy
 *
 *  \retval On success it returns 1 and on failure 0
 */

static int StreamTcpTest17 (void)
{
    Packet *p = SCMalloc(SIZE_OF_PACKET);
    if (unlikely(p == NULL))
        return 0;
    Flow f;
    ThreadVars tv;
    StreamTcpThread stt;
    TCPHdr tcph;
    uint8_t payload[4];
    struct in_addr addr;
    IPV4Hdr ipv4h;
    char os_policy_name[10] = "windows";
    char *ip_addr;
    PacketQueue pq;
    memset(&pq,0,sizeof(PacketQueue));

    memset(p, 0, SIZE_OF_PACKET);
    memset (&f, 0, sizeof(Flow));
    memset(&tv, 0, sizeof (ThreadVars));
    memset(&stt, 0, sizeof (StreamTcpThread));
    memset(&tcph, 0, sizeof (TCPHdr));
    memset(&addr, 0, sizeof(addr));
    memset(&ipv4h, 0, sizeof(ipv4h));
    FLOW_INITIALIZE(&f);
    p->flow = &f;
    int ret = 0;

    StreamTcpInitConfig(TRUE);

    /* Load the config string in to parser */
    ConfCreateContextBackup();
    ConfInit();
    ConfYamlLoadString(dummy_conf_string1, strlen(dummy_conf_string1));

    /* Get the IP address as string and add it to Host info tree for lookups */
    ip_addr = StreamTcpParseOSPolicy(os_policy_name);
    SCHInfoAddHostOSInfo(os_policy_name, ip_addr, -1);
    strlcpy(os_policy_name, "linux\0", sizeof(os_policy_name));
    ip_addr = StreamTcpParseOSPolicy(os_policy_name);
    SCHInfoAddHostOSInfo(os_policy_name, ip_addr, -1);

    /* prevent L7 from kicking in */
    StreamMsgQueueSetMinChunkLen(FLOW_PKT_TOSERVER, 4096);
    StreamMsgQueueSetMinChunkLen(FLOW_PKT_TOCLIENT, 4096);

    addr.s_addr = inet_addr("192.168.0.1");
    tcph.th_win = htons(5480);
    tcph.th_seq = htonl(10);
    tcph.th_ack = htonl(20);
    tcph.th_flags = TH_ACK|TH_PUSH;
    p->tcph = &tcph;
    p->dst.family = AF_INET;
    p->dst.address.address_un_data32[0] = addr.s_addr;
    p->ip4h = &ipv4h;

    StreamTcpCreateTestPacket(payload, 0x41, 3, sizeof(payload)); /*AAA*/
    p->payload = payload;
    p->payload_len = 3;

    FLOWLOCK_WRLOCK(&f);
    if (StreamTcpPacket(&tv, p, &stt, &pq) == -1)
        goto end;

    p->tcph->th_seq = htonl(20);
    p->tcph->th_ack = htonl(13);
    p->tcph->th_flags = TH_ACK|TH_PUSH;
    p->flowflags = FLOW_PKT_TOCLIENT;

    StreamTcpCreateTestPacket(payload, 0x42, 3, sizeof(payload)); /*BBB*/
    p->payload = payload;
    p->payload_len = 3;

    if (StreamTcpPacket(&tv, p, &stt, &pq) == -1)
        goto end;

    p->tcph->th_seq = htonl(15);
    p->tcph->th_ack = htonl(23);
    p->tcph->th_flags = TH_ACK|TH_PUSH;
    p->flowflags = FLOW_PKT_TOSERVER;

    StreamTcpCreateTestPacket(payload, 0x43, 3, sizeof(payload)); /*CCC*/
    p->payload = payload;
    p->payload_len = 3;

    if (StreamTcpPacket(&tv, p, &stt, &pq) == -1)
        goto end;

    p->tcph->th_seq = htonl(14);
    p->tcph->th_ack = htonl(23);
    p->tcph->th_flags = TH_ACK|TH_PUSH;
    p->flowflags = FLOW_PKT_TOSERVER;

    StreamTcpCreateTestPacket(payload, 0x43, 3, sizeof(payload)); /*CCC*/
    p->payload = payload;
    p->payload_len = 3;

    if (StreamTcpPacket(&tv, p, &stt, &pq) == -1)
        goto end;

    addr.s_addr = inet_addr("10.1.1.1");
    p->tcph->th_seq = htonl(25);
    p->tcph->th_ack = htonl(13);
    p->tcph->th_flags = TH_ACK|TH_PUSH;
    p->flowflags = FLOW_PKT_TOCLIENT;
    p->dst.address.address_un_data32[0] = addr.s_addr;

    StreamTcpCreateTestPacket(payload, 0x44, 3, sizeof(payload)); /*DDD*/
    p->payload = payload;
    p->payload_len = 3;

    if (StreamTcpPacket(&tv, p, &stt, &pq) == -1)
        goto end;

    p->tcph->th_seq = htonl(24);
    p->tcph->th_ack = htonl(13);
    p->tcph->th_flags = TH_ACK|TH_PUSH;
    p->flowflags = FLOW_PKT_TOCLIENT;

    StreamTcpCreateTestPacket(payload, 0x44, 3, sizeof(payload)); /*DDD*/
    p->payload = payload;
    p->payload_len = 3;

    if (StreamTcpPacket(&tv, p, &stt, &pq) == -1)
        goto end;

    if (stream_config.midstream != TRUE) {
        ret = 1;
        goto end;
    }
    if (((TcpSession *)(p->flow->protoctx))->state != TCP_ESTABLISHED)
        goto end;

    if (((TcpSession *)(p->flow->protoctx))->client.next_seq != 13 &&
            ((TcpSession *)(p->flow->protoctx))->server.next_seq != 23) {
        printf("failed in next_seq match client.next_seq %"PRIu32""
                " server.next_seq %"PRIu32"\n",
                ((TcpSession *)(p->flow->protoctx))->client.next_seq,
                ((TcpSession *)(p->flow->protoctx))->server.next_seq);
        goto end;
    }

    if (((TcpSession *)(p->flow->protoctx))->client.os_policy !=
            OS_POLICY_LINUX && ((TcpSession *)
            (p->flow->protoctx))->server.os_policy != OS_POLICY_DEFAULT)
    {
        printf("failed in setting up OS policy, client.os_policy: %"PRIu8""
                " should be %"PRIu8" and server.os_policy: %"PRIu8""
                " should be %"PRIu8"\n", ((TcpSession *)
                (p->flow->protoctx))->client.os_policy, (uint8_t)OS_POLICY_LINUX,
                ((TcpSession *)(p->flow->protoctx))->server.os_policy,
                (uint8_t)OS_POLICY_DEFAULT);
        goto end;
    }
    StreamTcpSessionPktFree(p);

    ret = 1;
end:
    StreamTcpFreeConfig(TRUE);
    ConfDeInit();
    ConfRestoreContextBackup();
    FLOWLOCK_UNLOCK(&f);
    SCFree(p);
    FLOW_DESTROY(&f);
    return ret;
}

/** \test   Test the various OS policies based on different IP addresses from
            confuguration defined in 'dummy_conf_string1' */
static int StreamTcpTest18 (void)
{

    struct in_addr addr;
    char os_policy_name[10] = "windows";
    char *ip_addr;
    TcpStream stream;
    Packet *p = SCMalloc(SIZE_OF_PACKET);
    if (unlikely(p == NULL))
    return 0;
    IPV4Hdr ipv4h;
    int ret = 0;

    memset(&addr, 0, sizeof(addr));
    memset(&stream, 0, sizeof(stream));
    memset(p, 0, SIZE_OF_PACKET);
    memset(&ipv4h, 0, sizeof(ipv4h));

    StreamTcpInitConfig(TRUE);
    SCHInfoCleanResources();

    /* Load the config string in to parser */
    ConfCreateContextBackup();
    ConfInit();
    ConfYamlLoadString(dummy_conf_string1, strlen(dummy_conf_string1));

    /* Get the IP address as string and add it to Host info tree for lookups */
    ip_addr = StreamTcpParseOSPolicy(os_policy_name);
    SCHInfoAddHostOSInfo(os_policy_name, ip_addr, -1);

    p->dst.family = AF_INET;
    p->ip4h = &ipv4h;
    addr.s_addr = inet_addr("192.168.1.1");
    p->dst.address.address_un_data32[0] = addr.s_addr;
    StreamTcpSetOSPolicy(&stream, p);

    if (stream.os_policy != OS_POLICY_WINDOWS)
        goto end;

    ret = 1;
end:
    StreamTcpFreeConfig(TRUE);
    ConfDeInit();
    ConfRestoreContextBackup();
    SCFree(p);
    return ret;
}
/** \test   Test the various OS policies based on different IP addresses from
            confuguration defined in 'dummy_conf_string1' */
static int StreamTcpTest19 (void)
{

    struct in_addr addr;
    char os_policy_name[10] = "windows";
    char *ip_addr;
    TcpStream stream;
    Packet *p = SCMalloc(SIZE_OF_PACKET);
    if (unlikely(p == NULL))
    return 0;
    IPV4Hdr ipv4h;
    int ret = 0;

    memset(&addr, 0, sizeof(addr));
    memset(&stream, 0, sizeof(stream));
    memset(p, 0, SIZE_OF_PACKET);
    memset(&ipv4h, 0, sizeof(ipv4h));

    StreamTcpInitConfig(TRUE);
    SCHInfoCleanResources();

    /* Load the config string in to parser */
    ConfCreateContextBackup();
    ConfInit();
    ConfYamlLoadString(dummy_conf_string1, strlen(dummy_conf_string1));

    /* Get the IP address as string and add it to Host info tree for lookups */
    ip_addr = StreamTcpParseOSPolicy(os_policy_name);
    SCHInfoAddHostOSInfo(os_policy_name, ip_addr, -1);

    p->dst.family = AF_INET;
    p->ip4h = &ipv4h;
    addr.s_addr = inet_addr("192.168.0.30");
    p->dst.address.address_un_data32[0] = addr.s_addr;
    StreamTcpSetOSPolicy(&stream, p);

    if (stream.os_policy != OS_POLICY_WINDOWS) {
        printf("expected os_policy: %"PRIu8" but received %"PRIu8": ",
                (uint8_t)OS_POLICY_WINDOWS, stream.os_policy);
        goto end;
    }

    ret = 1;
end:
    StreamTcpFreeConfig(TRUE);
    ConfDeInit();
    ConfRestoreContextBackup();
    SCFree(p);
    return ret;
}
/** \test   Test the various OS policies based on different IP addresses from
            confuguration defined in 'dummy_conf_string1' */
static int StreamTcpTest20 (void)
{

    struct in_addr addr;
    char os_policy_name[10] = "linux";
    char *ip_addr;
    TcpStream stream;
    Packet *p = SCMalloc(SIZE_OF_PACKET);
    if (unlikely(p == NULL))
    return 0;
    IPV4Hdr ipv4h;
    int ret = 0;

    memset(&addr, 0, sizeof(addr));
    memset(&stream, 0, sizeof(stream));
    memset(p, 0, SIZE_OF_PACKET);
    memset(&ipv4h, 0, sizeof(ipv4h));

    StreamTcpInitConfig(TRUE);
    SCHInfoCleanResources();

    /* Load the config string in to parser */
    ConfCreateContextBackup();
    ConfInit();
    ConfYamlLoadString(dummy_conf_string1, strlen(dummy_conf_string1));

    /* Get the IP address as string and add it to Host info tree for lookups */
    ip_addr = StreamTcpParseOSPolicy(os_policy_name);
    SCHInfoAddHostOSInfo(os_policy_name, ip_addr, -1);

    p->dst.family = AF_INET;
    p->ip4h = &ipv4h;
    addr.s_addr = inet_addr("192.168.0.1");
    p->dst.address.address_un_data32[0] = addr.s_addr;
    StreamTcpSetOSPolicy(&stream, p);

    if (stream.os_policy != OS_POLICY_LINUX) {
        printf("expected os_policy: %"PRIu8" but received %"PRIu8"\n",
                (uint8_t)OS_POLICY_LINUX, stream.os_policy);
        goto end;
    }

    ret = 1;
end:
    StreamTcpFreeConfig(TRUE);
    ConfDeInit();
    ConfRestoreContextBackup();
    SCFree(p);
    return ret;
}
/** \test   Test the various OS policies based on different IP addresses from
            confuguration defined in 'dummy_conf_string1' */
static int StreamTcpTest21 (void)
{

    struct in_addr addr;
    char os_policy_name[10] = "linux";
    char *ip_addr;
    TcpStream stream;
    Packet *p = SCMalloc(SIZE_OF_PACKET);
    if (unlikely(p == NULL))
    return 0;
    IPV4Hdr ipv4h;
    int ret = 0;

    memset(&addr, 0, sizeof(addr));
    memset(&stream, 0, sizeof(stream));
    memset(p, 0, SIZE_OF_PACKET);
    memset(&ipv4h, 0, sizeof(ipv4h));

    StreamTcpInitConfig(TRUE);
    SCHInfoCleanResources();

    /* Load the config string in to parser */
    ConfCreateContextBackup();
    ConfInit();
    ConfYamlLoadString(dummy_conf_string1, strlen(dummy_conf_string1));

    /* Get the IP address as string and add it to Host info tree for lookups */
    ip_addr = StreamTcpParseOSPolicy(os_policy_name);
    SCHInfoAddHostOSInfo(os_policy_name, ip_addr, -1);

    p->dst.family = AF_INET;
    p->ip4h = &ipv4h;
    addr.s_addr = inet_addr("192.168.1.30");
    p->dst.address.address_un_data32[0] = addr.s_addr;
    StreamTcpSetOSPolicy(&stream, p);

    if (stream.os_policy != OS_POLICY_LINUX) {
        printf("expected os_policy: %"PRIu8" but received %"PRIu8"\n",
                (uint8_t)OS_POLICY_LINUX, stream.os_policy);
        goto end;
    }

    ret = 1;
end:
    StreamTcpFreeConfig(TRUE);
    ConfDeInit();
    ConfRestoreContextBackup();
    SCFree(p);
    return ret;
}
/** \test   Test the various OS policies based on different IP addresses from
            confuguration defined in 'dummy_conf_string1' */
static int StreamTcpTest22 (void)
{

    struct in_addr addr;
    char os_policy_name[10] = "windows";
    char *ip_addr;
    TcpStream stream;
    Packet *p = SCMalloc(SIZE_OF_PACKET);
    if (unlikely(p == NULL))
    return 0;
    IPV4Hdr ipv4h;
    int ret = 0;

    memset(&addr, 0, sizeof(addr));
    memset(&stream, 0, sizeof(stream));
    memset(p, 0, SIZE_OF_PACKET);
    memset(&ipv4h, 0, sizeof(ipv4h));

    StreamTcpInitConfig(TRUE);
    SCHInfoCleanResources();

    /* Load the config string in to parser */
    ConfCreateContextBackup();
    ConfInit();
    ConfYamlLoadString(dummy_conf_string1, strlen(dummy_conf_string1));

    /* Get the IP address as string and add it to Host info tree for lookups */
    ip_addr = StreamTcpParseOSPolicy(os_policy_name);
    SCHInfoAddHostOSInfo(os_policy_name, ip_addr, -1);

    p->dst.family = AF_INET;
    p->ip4h = &ipv4h;
    addr.s_addr = inet_addr("123.231.2.1");
    p->dst.address.address_un_data32[0] = addr.s_addr;
    StreamTcpSetOSPolicy(&stream, p);

    if (stream.os_policy != OS_POLICY_DEFAULT) {
        printf("expected os_policy: %"PRIu8" but received %"PRIu8"\n",
                (uint8_t)OS_POLICY_DEFAULT, stream.os_policy);
        goto end;
    }

    ret = 1;
end:
    StreamTcpFreeConfig(TRUE);
    ConfDeInit();
    ConfRestoreContextBackup();
    SCFree(p);
    return ret;
}

/** \test   Test the stream mem leaks conditions. */
static int StreamTcpTest23(void)
{
    TcpSession ssn;
    Flow f;
    TCPHdr tcph;
    TcpReassemblyThreadCtx *ra_ctx = StreamTcpReassembleInitThreadCtx(NULL);
    uint8_t packet[1460] = "";
    ThreadVars tv;
    int result = 1;
    PacketQueue pq;

    Packet *p = SCMalloc(SIZE_OF_PACKET);
    if (unlikely(p == NULL))
        return 0;

    memset(&pq,0,sizeof(PacketQueue));
    memset(&ssn, 0, sizeof (TcpSession));
    memset(p, 0, SIZE_OF_PACKET);
    memset(&f, 0, sizeof (Flow));
    memset(&tcph, 0, sizeof (TCPHdr));
    memset(&tv, 0, sizeof (ThreadVars));

    StreamTcpInitConfig(TRUE);

    /* prevent L7 from kicking in */
    StreamMsgQueueSetMinChunkLen(FLOW_PKT_TOSERVER, 4096);
    StreamMsgQueueSetMinChunkLen(FLOW_PKT_TOCLIENT, 4096);

    FLOW_INITIALIZE(&f);
    ssn.client.os_policy = OS_POLICY_BSD;
    f.protoctx = &ssn;
    p->src.family = AF_INET;
    p->dst.family = AF_INET;
    p->proto = IPPROTO_TCP;
    p->flow = &f;
    tcph.th_win = 5480;
    tcph.th_flags = TH_PUSH | TH_ACK;
    p->tcph = &tcph;
    p->flowflags = FLOW_PKT_TOSERVER;
    p->payload = packet;
    ssn.client.ra_app_base_seq = ssn.client.ra_raw_base_seq = ssn.client.last_ack = 3184324453UL;

    p->tcph->th_seq = htonl(3184324453UL);
    p->tcph->th_ack = htonl(3373419609UL);
    p->payload_len = 2;

    if (StreamTcpReassembleHandleSegment(&tv, ra_ctx,&ssn, &ssn.client, p, &pq) == -1) {
        printf("failed in segment reassmebling: ");
        result &= 0;
        goto end;
    }

    p->tcph->th_seq = htonl(3184324455UL);
    p->tcph->th_ack = htonl(3373419621UL);
    p->payload_len = 2;

    if (StreamTcpReassembleHandleSegment(&tv, ra_ctx,&ssn, &ssn.client, p, &pq) == -1) {
        printf("failed in segment reassmebling: ");
        result &= 0;
        goto end;
    }

    p->tcph->th_seq = htonl(3184324453UL);
    p->tcph->th_ack = htonl(3373419621UL);
    p->payload_len = 6;

    if (StreamTcpReassembleHandleSegment(&tv, ra_ctx,&ssn, &ssn.client, p, &pq) == -1) {
        printf("failed in segment reassmebling: ");
        result &= 0;
//        goto end;
    }

    if(ssn.client.seg_list_tail != NULL && ssn.client.seg_list_tail->payload_len != 4) {
        printf("failed in segment reassmebling: ");
        result &= 0;
    }

end:
    StreamTcpReturnStreamSegments(&ssn.client);
    StreamTcpFreeConfig(TRUE);
    if (SC_ATOMIC_GET(st_memuse) == 0) {
        result &= 1;
    } else {
        printf("smemuse.stream_memuse %"PRIu64"\n", SC_ATOMIC_GET(st_memuse));
    }
    SCFree(p);
    FLOW_DESTROY(&f);
    return result;
}

/** \test   Test the stream mem leaks conditions. */
static int StreamTcpTest24(void)
{
    TcpSession ssn;
    Packet *p = SCMalloc(SIZE_OF_PACKET);
    if (unlikely(p == NULL))
        return 0;
    Flow f;
    TCPHdr tcph;
    TcpReassemblyThreadCtx *ra_ctx = StreamTcpReassembleInitThreadCtx(NULL);
    uint8_t packet[1460] = "";
    ThreadVars tv;
    int result = 1;
    PacketQueue pq;
    memset(&pq,0,sizeof(PacketQueue));

    StreamTcpInitConfig(TRUE);

    /* prevent L7 from kicking in */
    StreamMsgQueueSetMinChunkLen(FLOW_PKT_TOSERVER, 4096);
    StreamMsgQueueSetMinChunkLen(FLOW_PKT_TOCLIENT, 4096);

    memset(&ssn, 0, sizeof (TcpSession));
    memset(p, 0, SIZE_OF_PACKET);
    memset(&f, 0, sizeof (Flow));
    memset(&tv, 0, sizeof (ThreadVars));
    memset(&tcph, 0, sizeof (TCPHdr));
    FLOW_INITIALIZE(&f);
    ssn.client.os_policy = OS_POLICY_BSD;
    f.protoctx = &ssn;
    p->src.family = AF_INET;
    p->dst.family = AF_INET;
    p->proto = IPPROTO_TCP;
    p->flow = &f;
    tcph.th_win = 5480;
    tcph.th_flags = TH_PUSH | TH_ACK;
    p->tcph = &tcph;
    p->flowflags = FLOW_PKT_TOSERVER;
    p->payload = packet;
    ssn.client.ra_app_base_seq = ssn.client.ra_raw_base_seq = ssn.client.last_ack = 3184324453UL;

    p->tcph->th_seq = htonl(3184324455UL);
    p->tcph->th_ack = htonl(3373419621UL);
    p->payload_len = 4;

    if (StreamTcpReassembleHandleSegment(&tv, ra_ctx,&ssn, &ssn.client, p, &pq) == -1) {
        printf("failed in segment reassmebling\n");
        result &= 0;
        goto end;
    }

    p->tcph->th_seq = htonl(3184324459UL);
    p->tcph->th_ack = htonl(3373419633UL);
    p->payload_len = 2;

    if (StreamTcpReassembleHandleSegment(&tv, ra_ctx,&ssn, &ssn.client, p, &pq) == -1) {
        printf("failed in segment reassmebling\n");
        result &= 0;
        goto end;
    }

    p->tcph->th_seq = htonl(3184324459UL);
    p->tcph->th_ack = htonl(3373419657UL);
    p->payload_len = 4;

    if (StreamTcpReassembleHandleSegment(&tv, ra_ctx,&ssn, &ssn.client, p, &pq) == -1) {
        printf("failed in segment reassmebling\n");
        result &= 0;
        goto end;
    }

    if(ssn.client.seg_list_tail != NULL && ssn.client.seg_list_tail->payload_len != 2) {
        printf("failed in segment reassmebling\n");
        result &= 0;
    }

end:
    StreamTcpReturnStreamSegments(&ssn.client);
    StreamTcpFreeConfig(TRUE);
    if (SC_ATOMIC_GET(st_memuse) == 0) {
        result &= 1;
    } else {
        printf("smemuse.stream_memuse %"PRIu64"\n", SC_ATOMIC_GET(st_memuse));
    }
    SCFree(p);
    FLOW_DESTROY(&f);
    return result;
}

/**
 *  \test   Test the initialization of tcp streams with congestion flags
 *
 *  \retval On success it returns 1 and on failure 0.
 */
static int StreamTcpTest25(void)
{
    Packet *p = SCMalloc(SIZE_OF_PACKET);
    if (unlikely(p == NULL))
        return 0;
    Flow f;
    ThreadVars tv;
    StreamTcpThread stt;
    uint8_t payload[4];
    TCPHdr tcph;
    TcpReassemblyThreadCtx *ra_ctx = StreamTcpReassembleInitThreadCtx(NULL);
    int ret = 0;
    PacketQueue pq;
    memset(&pq,0,sizeof(PacketQueue));

    memset(p, 0, SIZE_OF_PACKET);
    memset (&f, 0, sizeof(Flow));
    memset(&tv, 0, sizeof (ThreadVars));
    memset(&stt, 0, sizeof (StreamTcpThread));
    memset(&tcph, 0, sizeof (TCPHdr));

    FLOW_INITIALIZE(&f);
    stt.ra_ctx = ra_ctx;
    p->flow = &f;
    tcph.th_win = htons(5480);
    tcph.th_flags = TH_SYN | TH_CWR;
    p->tcph = &tcph;
    p->flowflags = FLOW_PKT_TOSERVER;

    /* prevent L7 from kicking in */
    StreamMsgQueueSetMinChunkLen(FLOW_PKT_TOSERVER, 4096);
    StreamMsgQueueSetMinChunkLen(FLOW_PKT_TOCLIENT, 4096);

    StreamTcpInitConfig(TRUE);

    FLOWLOCK_WRLOCK(&f);
    if (StreamTcpPacket(&tv, p, &stt, &pq) == -1)
        goto end;

    p->tcph->th_ack = htonl(1);
    p->tcph->th_flags = TH_SYN | TH_ACK;
    p->flowflags = FLOW_PKT_TOCLIENT;

    if (StreamTcpPacket(&tv, p, &stt, &pq) == -1 || (TcpSession *)p->flow->protoctx == NULL)
        goto end;

    p->tcph->th_ack = htonl(1);
    p->tcph->th_seq = htonl(1);
    p->tcph->th_flags = TH_ACK;
    p->flowflags = FLOW_PKT_TOSERVER;

    if (StreamTcpPacket(&tv, p, &stt, &pq) == -1 || (TcpSession *)p->flow->protoctx == NULL)
        goto end;

    p->tcph->th_ack = htonl(1);
    p->tcph->th_seq = htonl(2);
    p->tcph->th_flags = TH_PUSH | TH_ACK;
    p->flowflags = FLOW_PKT_TOSERVER;

    StreamTcpCreateTestPacket(payload, 0x41, 3, 4); /*AAA*/
    p->payload = payload;
    p->payload_len = 3;

    if (StreamTcpPacket(&tv, p, &stt, &pq) == -1 || (TcpSession *)p->flow->protoctx == NULL)
        goto end;

    p->flowflags = FLOW_PKT_TOCLIENT;
    if (StreamTcpPacket(&tv, p, &stt, &pq) == -1 || (TcpSession *)p->flow->protoctx == NULL)
        goto end;

    p->tcph->th_ack = htonl(1);
    p->tcph->th_seq = htonl(6);
    p->tcph->th_flags = TH_PUSH | TH_ACK;
    p->flowflags = FLOW_PKT_TOSERVER;

    StreamTcpCreateTestPacket(payload, 0x42, 3, 4); /*BBB*/
    p->payload = payload;
    p->payload_len = 3;

    if (StreamTcpPacket(&tv, p, &stt, &pq) == -1 || (TcpSession *)p->flow->protoctx == NULL)
        goto end;

    p->flowflags = FLOW_PKT_TOCLIENT;
    if (StreamTcpPacket(&tv, p, &stt, &pq) == -1 || (TcpSession *)p->flow->protoctx == NULL)
        goto end;

    StreamTcpSessionClear(p->flow->protoctx);

    ret = 1;
end:
    StreamTcpFreeConfig(TRUE);
    FLOWLOCK_UNLOCK(&f);
    SCFree(p);
    FLOW_DESTROY(&f);
    return ret;
}

/**
 *  \test   Test the initialization of tcp streams with congestion flags
 *
 *  \retval On success it returns 1 and on failure 0.
 */
static int StreamTcpTest26(void)
{
    Packet *p = SCMalloc(SIZE_OF_PACKET);
    if (unlikely(p == NULL))
        return 0;
    Flow f;
    ThreadVars tv;
    StreamTcpThread stt;
    uint8_t payload[4];
    TCPHdr tcph;
    TcpReassemblyThreadCtx *ra_ctx = StreamTcpReassembleInitThreadCtx(NULL);
    int ret = 0;
    PacketQueue pq;
    memset(&pq,0,sizeof(PacketQueue));

    memset(p, 0, SIZE_OF_PACKET);
    memset (&f, 0, sizeof(Flow));
    memset(&tv, 0, sizeof (ThreadVars));
    memset(&stt, 0, sizeof (StreamTcpThread));
    memset(&tcph, 0, sizeof (TCPHdr));

    FLOW_INITIALIZE(&f);
    stt.ra_ctx = ra_ctx;
    p->flow = &f;
    tcph.th_win = htons(5480);
    tcph.th_flags = TH_SYN | TH_ECN;
    p->tcph = &tcph;
    p->flowflags = FLOW_PKT_TOSERVER;

    StreamTcpInitConfig(TRUE);

    FLOWLOCK_WRLOCK(&f);
    if (StreamTcpPacket(&tv, p, &stt, &pq) == -1)
        goto end;

    p->tcph->th_ack = htonl(1);
    p->tcph->th_flags = TH_SYN | TH_ACK;
    p->flowflags = FLOW_PKT_TOCLIENT;

    if (StreamTcpPacket(&tv, p, &stt, &pq) == -1 || (TcpSession *)p->flow->protoctx == NULL)
        goto end;

    p->tcph->th_ack = htonl(1);
    p->tcph->th_seq = htonl(1);
    p->tcph->th_flags = TH_ACK;
    p->flowflags = FLOW_PKT_TOSERVER;

    if (StreamTcpPacket(&tv, p, &stt, &pq) == -1 || (TcpSession *)p->flow->protoctx == NULL)
        goto end;

    p->tcph->th_ack = htonl(1);
    p->tcph->th_seq = htonl(2);
    p->tcph->th_flags = TH_PUSH | TH_ACK;
    p->flowflags = FLOW_PKT_TOSERVER;

    StreamTcpCreateTestPacket(payload, 0x41, 3, 4); /*AAA*/
    p->payload = payload;
    p->payload_len = 3;

    if (StreamTcpPacket(&tv, p, &stt, &pq) == -1 || (TcpSession *)p->flow->protoctx == NULL)
        goto end;

    p->flowflags = FLOW_PKT_TOCLIENT;
    if (StreamTcpPacket(&tv, p, &stt, &pq) == -1 || (TcpSession *)p->flow->protoctx == NULL)
        goto end;

    p->tcph->th_ack = htonl(1);
    p->tcph->th_seq = htonl(6);
    p->tcph->th_flags = TH_PUSH | TH_ACK;
    p->flowflags = FLOW_PKT_TOSERVER;

    StreamTcpCreateTestPacket(payload, 0x42, 3, 4); /*BBB*/
    p->payload = payload;
    p->payload_len = 3;

    if (StreamTcpPacket(&tv, p, &stt, &pq) == -1 || (TcpSession *)p->flow->protoctx == NULL)
        goto end;

    p->flowflags = FLOW_PKT_TOCLIENT;
    if (StreamTcpPacket(&tv, p, &stt, &pq) == -1 || (TcpSession *)p->flow->protoctx == NULL)
        goto end;

    StreamTcpSessionClear(p->flow->protoctx);

    ret = 1;
end:
    StreamTcpFreeConfig(TRUE);
    FLOWLOCK_UNLOCK(&f);
    SCFree(p);
    FLOW_DESTROY(&f);
    return ret;
}

/**
 *  \test   Test the initialization of tcp streams with congestion flags
 *
 *  \retval On success it returns 1 and on failure 0.
 */
static int StreamTcpTest27(void)
{
    Packet *p = SCMalloc(SIZE_OF_PACKET);
    if (unlikely(p == NULL))
        return 0;
    Flow f;
    ThreadVars tv;
    StreamTcpThread stt;
    uint8_t payload[4];
    TCPHdr tcph;
    TcpReassemblyThreadCtx *ra_ctx = StreamTcpReassembleInitThreadCtx(NULL);
    int ret = 0;
    PacketQueue pq;
    memset(&pq,0,sizeof(PacketQueue));

    memset(p, 0, SIZE_OF_PACKET);
    memset (&f, 0, sizeof(Flow));
    memset(&tv, 0, sizeof (ThreadVars));
    memset(&stt, 0, sizeof (StreamTcpThread));
    memset(&tcph, 0, sizeof (TCPHdr));

    FLOW_INITIALIZE(&f);
    stt.ra_ctx = ra_ctx;
    p->flow = &f;
    tcph.th_win = htons(5480);
    tcph.th_flags = TH_SYN | TH_CWR | TH_ECN;
    p->tcph = &tcph;
    p->flowflags = FLOW_PKT_TOSERVER;

    StreamTcpInitConfig(TRUE);

    FLOWLOCK_WRLOCK(&f);
    if (StreamTcpPacket(&tv, p, &stt, &pq) == -1)
        goto end;

    p->tcph->th_ack = htonl(1);
    p->tcph->th_flags = TH_SYN | TH_ACK;
    p->flowflags = FLOW_PKT_TOCLIENT;

    if (StreamTcpPacket(&tv, p, &stt, &pq) == -1 || (TcpSession *)p->flow->protoctx == NULL)
        goto end;

    p->tcph->th_ack = htonl(1);
    p->tcph->th_seq = htonl(1);
    p->tcph->th_flags = TH_ACK;
    p->flowflags = FLOW_PKT_TOSERVER;

    if (StreamTcpPacket(&tv, p, &stt, &pq) == -1 || (TcpSession *)p->flow->protoctx == NULL)
        goto end;

    p->tcph->th_ack = htonl(1);
    p->tcph->th_seq = htonl(2);
    p->tcph->th_flags = TH_PUSH | TH_ACK;
    p->flowflags = FLOW_PKT_TOSERVER;

    StreamTcpCreateTestPacket(payload, 0x41, 3, 4); /*AAA*/
    p->payload = payload;
    p->payload_len = 3;

    if (StreamTcpPacket(&tv, p, &stt, &pq) == -1 || (TcpSession *)p->flow->protoctx == NULL)
        goto end;

    p->flowflags = FLOW_PKT_TOCLIENT;
    if (StreamTcpPacket(&tv, p, &stt, &pq) == -1 || (TcpSession *)p->flow->protoctx == NULL)
        goto end;

    p->tcph->th_ack = htonl(1);
    p->tcph->th_seq = htonl(6);
    p->tcph->th_flags = TH_PUSH | TH_ACK;
    p->flowflags = FLOW_PKT_TOSERVER;

    StreamTcpCreateTestPacket(payload, 0x42, 3, 4); /*BBB*/
    p->payload = payload;
    p->payload_len = 3;

    if (StreamTcpPacket(&tv, p, &stt, &pq) == -1 || (TcpSession *)p->flow->protoctx == NULL)
        goto end;

    p->flowflags = FLOW_PKT_TOCLIENT;
    if (StreamTcpPacket(&tv, p, &stt, &pq) == -1 || (TcpSession *)p->flow->protoctx == NULL)
        goto end;

    StreamTcpSessionClear(p->flow->protoctx);

    ret = 1;
end:
    StreamTcpFreeConfig(TRUE);
    FLOWLOCK_UNLOCK(&f);
    SCFree(p);
    FLOW_DESTROY(&f);
    return ret;
}

/** \test   Test the memcap incrementing/decrementing and memcap check */
static int StreamTcpTest28(void)
{
    uint8_t ret = 0;
    StreamTcpInitConfig(TRUE);
    uint32_t memuse = SC_ATOMIC_GET(st_memuse);

    StreamTcpIncrMemuse(500);
    if (SC_ATOMIC_GET(st_memuse) != (memuse+500)) {
        printf("failed in incrementing the memory");
        goto end;
    }

    StreamTcpDecrMemuse(500);
    if (SC_ATOMIC_GET(st_memuse) != memuse) {
        printf("failed in decrementing the memory");
        goto end;
    }

    if (StreamTcpCheckMemcap(500) != 1) {
        printf("failed in validating the memcap");
        goto end;
    }

    if (StreamTcpCheckMemcap((memuse + stream_config.memcap)) != 0) {
        printf("failed in validating the overflowed memcap");
        goto end;
    }

    StreamTcpFreeConfig(TRUE);

    if (SC_ATOMIC_GET(st_memuse) != 0) {
        printf("failed in clearing the memory");
        goto end;
    }

    ret = 1;
    return ret;
end:
    StreamTcpFreeConfig(TRUE);
    return ret;
}

#if 0
/**
 *  \test   Test the resetting of the sesison with bad checksum packet and later
 *          send the malicious contents on the session. Engine should drop the
 *          packet with the bad checksum.
 *
 *  \retval On success it returns 1 and on failure 0.
 */
static int StreamTcpTest29(void)
{
    Packet p;
    Flow f;
    ThreadVars tv;
    StreamTcpThread stt;
    TCPHdr tcph;
    TcpSession ssn;
    IPV4Hdr ipv4h;
    TcpReassemblyThreadCtx *ra_ctx = StreamTcpReassembleInitThreadCtx(NULL);
    struct in_addr addr;
    struct in_addr addr1;
    TCPCache tcpc;
    TCPVars tcpvars;
    TcpStream server;
    TcpStream client;

    memset (&p, 0, SIZE_OF_PACKET);
    memset (&f, 0, sizeof(Flow));
    memset(&tv, 0, sizeof (ThreadVars));
    memset(&stt, 0, sizeof (StreamTcpThread));
    memset(&tcph, 0, sizeof (TCPHdr));
    memset (&ipv4h, 0, sizeof(IPV4Hdr));
    memset (&addr, 0, sizeof(addr));
    memset (&addr1, 0, sizeof(addr1));
    memset (&tcpc, 0, sizeof(tcpc));
    memset (&tcpvars, 0, sizeof(tcpvars));
    memset(&ssn, 0, sizeof (TcpSession));
    memset(&server, 0, sizeof (TcpStream));
    memset(&client, 0, sizeof (TcpStream));
    uint8_t packet[1460] = "";
    int result = 1;

    FLOW_INITIALIZE(&f);
    StreamTcpInitConfig(TRUE);

    /* prevent L7 from kicking in */

    ssn.client.os_policy = OS_POLICY_BSD;
    p.src.family = AF_INET;
    p.dst.family = AF_INET;
    p.proto = IPPROTO_TCP;
    p.flow = &f;
    tcph.th_win = 5480;
    p.tcph = &tcph;
    p.payload = packet;
    p.ip4h = &ipv4h;
    p.tcpc = tcpc;
    p.tcpc.level4_comp_csum = -1;
    tcpvars.hlen = 20;
    p.tcpvars = tcpvars;
    ssn.state = TCP_ESTABLISHED;
    addr.s_addr = inet_addr("10.1.3.53");
    p.dst.address.address_un_data32[0] = addr.s_addr;
    addr1.s_addr = inet_addr("10.1.3.7");
    p.src.address.address_un_data32[0] = addr1.s_addr;
    f.protoctx = &ssn;
    stt.ra_ctx = ra_ctx;
    ssn.server = server;
    ssn.client = client;
    ssn.client.isn = 10;
    ssn.client.window = 5184;
    ssn.client.last_ack = 10;
    ssn.client.ra_base_seq = 10;
    ssn.client.next_win = 5184;
    ssn.server.isn = 119197101;
    ssn.server.window = 5184;
    ssn.server.next_win = 5184;
    ssn.server.last_ack = 119197101;
    ssn.server.ra_base_seq = 119197101;

    tcph.th_flags = TH_PUSH | TH_ACK;
    p.flowflags = FLOW_PKT_TOSERVER;
    p.tcph->th_seq = htonl(11);
    p.tcph->th_ack = htonl(119197102);
    p.payload_len = 4;
    p.ip4h->ip_src = addr1;
    p.tcph->th_sum = TCPCalculateChecksum((uint16_t *)&(p.ip4h->ip_src),
                                          (uint16_t *)p.tcph,
                                          (p.payload_len +
                                           p.tcpvars.hlen) );

    if (StreamTcp(&tv, &p, (void *)&stt, NULL, NULL) != TM_ECODE_OK) {
        printf("failed in segment reassmebling\n");
        result &= 0;
        goto end;
    }

    tcph.th_flags = TH_ACK;
    p.flowflags = FLOW_PKT_TOCLIENT;
    p.tcph->th_seq = htonl(119197102);
    p.tcph->th_ack = htonl(15);
    p.payload_len = 0;
    p.ip4h->ip_src = addr;
    p.tcph->th_sum = TCPCalculateChecksum((uint16_t *)&(p.ip4h->ip_src),
                                                 (uint16_t *)p.tcph,
                                                 (p.payload_len +
                                                  p.tcpvars.hlen) );

    if (StreamTcp(&tv, &p, (void *)&stt, NULL, NULL) != TM_ECODE_OK) {
        printf("failed in segment reassmebling\n");
        result &= 0;
        goto end;
    }

    tcph.th_flags = TH_RST | TH_ACK;
    p.flowflags = FLOW_PKT_TOSERVER;
    p.tcph->th_seq = htonl(15);
    p.tcph->th_ack = htonl(119197102);
    p.payload_len = 0;
    p.ip4h->ip_src = addr1;
    p.tcph->th_sum = 12345;

    if (StreamTcp(&tv, &p, (void *)&stt, NULL, NULL) != TM_ECODE_OK) {
        printf("failed in segment reassmebling\n");
        result &= 0;
        goto end;
    }

    if (ssn.state != TCP_ESTABLISHED) {
        printf("the ssn.state should be TCP_ESTABLISHED(%"PRIu8"), not %"PRIu8""
                "\n", TCP_ESTABLISHED, ssn.state);
        result &= 0;
        goto end;
    }

end:
    StreamTcpReturnStreamSegments(&ssn.client);
    StreamTcpFreeConfig(TRUE);
    return result;
}

/**
 *  \test   Test the overlapping of the packet with bad checksum packet and later
 *          send the malicious contents on the session. Engine should drop the
 *          packet with the bad checksum.
 *
 *  \retval On success it returns 1 and on failure 0.
 */
static int StreamTcpTest30(void)
{
    Packet p;
    Flow f;
    ThreadVars tv;
    StreamTcpThread stt;
    TCPHdr tcph;
    TcpSession ssn;
    IPV4Hdr ipv4h;
    TcpReassemblyThreadCtx *ra_ctx = StreamTcpReassembleInitThreadCtx(NULL);
    struct in_addr addr;
    struct in_addr addr1;
    TCPCache tcpc;
    TCPVars tcpvars;
    TcpStream server;
    TcpStream client;

    memset (&p, 0, SIZE_OF_PACKET);
    memset (&f, 0, sizeof(Flow));
    memset(&tv, 0, sizeof (ThreadVars));
    memset(&stt, 0, sizeof (StreamTcpThread));
    memset(&tcph, 0, sizeof (TCPHdr));
    memset (&ipv4h, 0, sizeof(IPV4Hdr));
    memset (&addr, 0, sizeof(addr));
    memset (&addr1, 0, sizeof(addr1));
    memset (&tcpc, 0, sizeof(tcpc));
    memset (&tcpvars, 0, sizeof(tcpvars));
    memset(&ssn, 0, sizeof (TcpSession));
    memset(&server, 0, sizeof (TcpStream));
    memset(&client, 0, sizeof (TcpStream));
    uint8_t payload[9] = "AAAAAAAAA";
    uint8_t payload1[9] = "GET /EVIL";
    uint8_t expected_content[9] = { 0x47, 0x45, 0x54, 0x20, 0x2f, 0x45, 0x56,
                                    0x49, 0x4c };
    int result = 1;

    FLOW_INITIALIZE(&f);
    StreamTcpInitConfig(TRUE);

    /* prevent L7 from kicking in */

    ssn.client.os_policy = OS_POLICY_BSD;
    p.src.family = AF_INET;
    p.dst.family = AF_INET;
    p.proto = IPPROTO_TCP;
    p.flow = &f;
    tcph.th_win = 5480;
    p.tcph = &tcph;
    p.payload = payload;
    p.ip4h = &ipv4h;
    p.tcpc = tcpc;
    p.tcpc.level4_comp_csum = -1;
    p.tcpvars = tcpvars;
    ssn.state = TCP_ESTABLISHED;
    addr.s_addr = inet_addr("10.1.3.53");
    p.dst.address.address_un_data32[0] = addr.s_addr;
    addr1.s_addr = inet_addr("10.1.3.7");
    p.src.address.address_un_data32[0] = addr1.s_addr;
    f.protoctx = &ssn;
    stt.ra_ctx = ra_ctx;
    ssn.server = server;
    ssn.client = client;
    ssn.client.isn = 10;
    ssn.client.window = 5184;
    ssn.client.last_ack = 10;
    ssn.client.ra_base_seq = 10;
    ssn.client.next_win = 5184;
    ssn.server.isn = 1351079940;
    ssn.server.window = 5184;
    ssn.server.next_win = 1351088132;
    ssn.server.last_ack = 1351079940;
    ssn.server.ra_base_seq = 1351079940;

    tcph.th_flags = TH_PUSH | TH_ACK;
    p.flowflags = FLOW_PKT_TOSERVER;
    p.tcph->th_seq = htonl(11);
    p.tcph->th_ack = htonl(1351079940);
    p.payload_len = 9;
    p.ip4h->ip_src = addr1;
    p.tcph->th_sum = 12345;

    if (StreamTcp(&tv, &p, (void *)&stt, NULL, NULL) != TM_ECODE_OK) {
        printf("failed in segment reassmebling\n");
        result &= 0;
        goto end;
    }

    tcph.th_flags = TH_PUSH | TH_ACK;
    p.flowflags = FLOW_PKT_TOSERVER;
    p.tcph->th_seq = htonl(11);
    p.tcph->th_ack = htonl(1351079940);
    p.payload = payload1;
    p.payload_len = 9;
    p.ip4h->ip_src = addr1;
    p.tcph->th_sum = TCPCalculateChecksum((uint16_t *)&(p.ip4h->ip_src),
                                                 (uint16_t *)p.tcph,
                                                 (p.payload_len +
                                                  p.tcpvars.hlen) );

    if (StreamTcp(&tv, &p, (void *)&stt, NULL, NULL) != TM_ECODE_OK) {
        printf("failed in segment reassmebling\n");
        result &= 0;
        goto end;
    }

    tcph.th_flags = TH_ACK;
    p.flowflags = FLOW_PKT_TOCLIENT;
    p.tcph->th_seq = htonl(1351079940);
    p.tcph->th_ack = htonl(20);
    p.payload_len = 0;
    p.ip4h->ip_src = addr;
    p.tcph->th_sum = TCPCalculateChecksum((uint16_t *)&(p.ip4h->ip_src),
                                                 (uint16_t *)p.tcph,
                                                 (p.payload_len +
                                                  p.tcpvars.hlen) );

    if (StreamTcp(&tv, &p, (void *)&stt, NULL, NULL) != TM_ECODE_OK) {
        printf("failed in segment reassmebling\n");
        result &= 0;
        goto end;
    }

    if (StreamTcpCheckStreamContents(expected_content, 9, &ssn.client) != 1) {
        printf("the contents are not as expected(GET /EVIL), contents are: ");
        PrintRawDataFp(stdout, ssn.client.seg_list->payload, 9);
        result &= 0;
        goto end;
    }

end:
    StreamTcpReturnStreamSegments(&ssn.client);
    StreamTcpFreeConfig(TRUE);
    return result;
}

/**
 *  \test   Test the multiple SYN packet handling with bad checksum and timestamp
 *          value. Engine should drop the bad checksum packet and establish
 *          TCP session correctly.
 *
 *  \retval On success it returns 1 and on failure 0.
 */
static int StreamTcpTest31(void)
{
    Packet p;
    Flow f;
    ThreadVars tv;
    StreamTcpThread stt;
    TCPHdr tcph;
    TcpSession ssn;
    IPV4Hdr ipv4h;
    TcpReassemblyThreadCtx *ra_ctx = StreamTcpReassembleInitThreadCtx(NULL);
    struct in_addr addr;
    struct in_addr addr1;
    TCPCache tcpc;
    TCPVars tcpvars;
    TcpStream server;
    TcpStream client;
    TCPOpt tcpopt;

    memset (&p, 0, SIZE_OF_PACKET);
    memset (&f, 0, sizeof(Flow));
    memset(&tv, 0, sizeof (ThreadVars));
    memset(&stt, 0, sizeof (StreamTcpThread));
    memset(&tcph, 0, sizeof (TCPHdr));
    memset (&ipv4h, 0, sizeof(IPV4Hdr));
    memset (&addr, 0, sizeof(addr));
    memset (&addr1, 0, sizeof(addr1));
    memset (&tcpc, 0, sizeof(tcpc));
    memset (&tcpvars, 0, sizeof(tcpvars));
    memset(&ssn, 0, sizeof (TcpSession));
    memset(&server, 0, sizeof (TcpStream));
    memset(&client, 0, sizeof (TcpStream));
    memset(&tcpopt, 0, sizeof (TCPOpt));
    int result = 1;

    StreamTcpInitConfig(TRUE);

    FLOW_INITIALIZE(&f);
    /* prevent L7 from kicking in */

    ssn.client.os_policy = OS_POLICY_LINUX;
    p.src.family = AF_INET;
    p.dst.family = AF_INET;
    p.proto = IPPROTO_TCP;
    p.flow = &f;
    tcph.th_win = 5480;
    p.tcph = &tcph;
    p.ip4h = &ipv4h;
    p.tcpc = tcpc;
    p.tcpc.level4_comp_csum = -1;
    p.tcpvars = tcpvars;
    p.tcpvars.ts = &tcpopt;
    addr.s_addr = inet_addr("10.1.3.53");
    p.dst.address.address_un_data32[0] = addr.s_addr;
    addr1.s_addr = inet_addr("10.1.3.7");
    p.src.address.address_un_data32[0] = addr1.s_addr;
    f.protoctx = &ssn;
    stt.ra_ctx = ra_ctx;
    ssn.server = server;
    ssn.client = client;
    ssn.client.isn = 10;
    ssn.client.window = 5184;
    ssn.client.last_ack = 10;
    ssn.client.ra_base_seq = 10;
    ssn.client.next_win = 5184;
    ssn.server.isn = 1351079940;
    ssn.server.window = 5184;
    ssn.server.next_win = 1351088132;
    ssn.server.last_ack = 1351079940;
    ssn.server.ra_base_seq = 1351079940;

    tcph.th_flags = TH_SYN;
    p.flowflags = FLOW_PKT_TOSERVER;
    p.tcph->th_seq = htonl(10);
    p.payload_len = 0;
    p.ip4h->ip_src = addr1;
    p.tcpc.ts1 = 100;
    p.tcph->th_sum = 12345;

    if (StreamTcp(&tv, &p, (void *)&stt, NULL, NULL) != TM_ECODE_OK) {
        printf("failed in segment reassmebling\n");
        result &= 0;
        goto end;
    }

    tcph.th_flags = TH_SYN;
    p.flowflags = FLOW_PKT_TOSERVER;
    p.tcph->th_seq = htonl(10);
    p.payload_len = 0;
    p.ip4h->ip_src = addr1;
    p.tcpc.ts1 = 10;
    p.tcpc.level4_comp_csum = -1;
    p.tcph->th_sum = TCPCalculateChecksum((uint16_t *)&(p.ip4h->ip_src),
                                          (uint16_t *)p.tcph,
                                          (p.payload_len +
                                           p.tcpvars.hlen) );

    if (StreamTcp(&tv, &p, (void *)&stt, NULL, NULL) != TM_ECODE_OK) {
        printf("failed in segment reassmebling\n");
        result &= 0;
        goto end;
    }

    ssn.flags |= STREAMTCP_FLAG_TIMESTAMP;
    tcph.th_flags = TH_SYN | TH_ACK;
    p.flowflags = FLOW_PKT_TOCLIENT;
    p.tcph->th_seq = htonl(1351079940);
    p.tcph->th_ack = htonl(11);
    p.payload_len = 0;
    p.tcpc.ts1 = 10;
    p.ip4h->ip_src = addr;
    p.tcpc.level4_comp_csum = -1;
    p.tcph->th_sum = TCPCalculateChecksum((uint16_t *)&(p.ip4h->ip_src),
                                          (uint16_t *)p.tcph,
                                          (p.payload_len +
                                           p.tcpvars.hlen) );

    if (StreamTcp(&tv, &p, (void *)&stt, NULL, NULL) != TM_ECODE_OK) {
        printf("failed in segment reassmebling\n");
        result &= 0;
        goto end;
    }

    tcph.th_flags = TH_ACK;
    p.flowflags = FLOW_PKT_TOSERVER;
    p.tcph->th_seq = htonl(11);
    p.tcph->th_ack = htonl(1351079941);
    p.payload_len = 0;
    p.tcpc.ts1 = 10;
    p.ip4h->ip_src = addr1;
    p.tcpc.level4_comp_csum = -1;
    p.tcph->th_sum = TCPCalculateChecksum((uint16_t *)&(p.ip4h->ip_src),
                                          (uint16_t *)p.tcph,
                                          (p.payload_len +
                                           p.tcpvars.hlen) );

    if (StreamTcp(&tv, &p, (void *)&stt, NULL, NULL) != TM_ECODE_OK) {
        printf("failed in segment reassmebling\n");
        result &= 0;
        goto end;
    }

    if (ssn.state != TCP_ESTABLISHED) {
        printf("the should have been changed to TCP_ESTABLISHED!!\n ");
        result &= 0;
        goto end;
    }

end:
    StreamTcpReturnStreamSegments(&ssn.client);
    StreamTcpFreeConfig(TRUE);
    return result;
}

/**
 *  \test   Test the initialization of tcp streams with ECN & CWR flags
 *
 *  \retval On success it returns 1 and on failure 0.
 */
static int StreamTcpTest32(void)
{
    Packet p;
    Flow f;
    ThreadVars tv;
    StreamTcpThread stt;
    uint8_t payload[4];
    TCPHdr tcph;
    TcpReassemblyThreadCtx *ra_ctx = StreamTcpReassembleInitThreadCtx(NULL);
    int ret = 0;
    PacketQueue pq;
    memset(&pq,0,sizeof(PacketQueue));

    memset (&p, 0, SIZE_OF_PACKET);
    memset (&f, 0, sizeof(Flow));
    memset(&tv, 0, sizeof (ThreadVars));
    memset(&stt, 0, sizeof (StreamTcpThread));
    memset(&tcph, 0, sizeof (TCPHdr));

    FLOW_INITIALIZE(&f);
    stt.ra_ctx = ra_ctx;
    p.flow = &f;
    tcph.th_win = htons(5480);
    tcph.th_flags = TH_SYN | TH_CWR | TH_ECN;
    p.tcph = &tcph;
    p.flowflags = FLOW_PKT_TOSERVER;

    StreamTcpInitConfig(TRUE);

    if (StreamTcpPacket(&tv, &p, &stt, &pq) == -1)
        goto end;

    p.tcph->th_ack = htonl(1);
    p.tcph->th_flags = TH_SYN | TH_ACK | TH_ECN;
    p.flowflags = FLOW_PKT_TOCLIENT;

    if (StreamTcpPacket(&tv, &p, &stt, &pq) == -1 || (TcpSession *)p.flow->protoctx == NULL) {
        printf("failed in processing packet\n");
        goto end;
    }

    p.tcph->th_ack = htonl(1);
    p.tcph->th_seq = htonl(1);
    p.tcph->th_flags = TH_ACK | TH_ECN | TH_CWR;
    p.flowflags = FLOW_PKT_TOSERVER;

    if (StreamTcpPacket(&tv, &p, &stt, &pq) == -1 || (TcpSession *)p.flow->protoctx == NULL) {
        printf("failed in processing packet\n");
        goto end;
    }

    p.tcph->th_ack = htonl(1);
    p.tcph->th_seq = htonl(2);
    p.tcph->th_flags = TH_PUSH | TH_ACK | TH_ECN | TH_CWR;
    p.flowflags = FLOW_PKT_TOSERVER;

    StreamTcpCreateTestPacket(payload, 0x41, 3, 4); /*AAA*/
    p.payload = payload;
    p.payload_len = 3;

    if (StreamTcpPacket(&tv, &p, &stt, &pq) == -1 || (TcpSession *)p.flow->protoctx == NULL) {
        printf("failed in processing packet\n");
        goto end;
    }

    p.flowflags = FLOW_PKT_TOCLIENT;
    p.tcph->th_flags = TH_ACK;
    if (StreamTcpPacket(&tv, &p, &stt, &pq) == -1 || (TcpSession *)p.flow->protoctx == NULL) {
        printf("failed in processing packet\n");
        goto end;
    }

    if (((TcpSession *)p.flow->protoctx)->state != TCP_ESTABLISHED) {
        printf("the TCP state should be TCP_ESTABLISEHD\n");
        goto end;
    }
    StreamTcpSessionClear(p.flow->protoctx);

    ret = 1;
end:
    StreamTcpFreeConfig(TRUE);
    return ret;
}

/**
 *  \test   Test the allocation of TCP session for a given packet when the same
 *          ports have been used to start the new session after resetting the
 *          previous session.
 *
 *  \retval On success it returns 1 and on failure 0.
 */

static int StreamTcpTest33 (void)
{
    Packet p;
    Flow f;
    ThreadVars tv;
    StreamTcpThread stt;
    TCPHdr tcph;
    TcpReassemblyThreadCtx ra_ctx;
    StreamMsgQueue stream_q;
    PacketQueue pq;
    memset(&pq,0,sizeof(PacketQueue));
    memset(&stream_q, 0, sizeof(StreamMsgQueue));
    memset(&ra_ctx, 0, sizeof(TcpReassemblyThreadCtx));
    memset (&p, 0, SIZE_OF_PACKET);
    memset (&f, 0, sizeof(Flow));
    memset(&tv, 0, sizeof (ThreadVars));
    memset(&stt, 0, sizeof (StreamTcpThread));
    memset(&tcph, 0, sizeof (TCPHdr));

    FLOW_INITIALIZE(&f);
    p.flow = &f;
    tcph.th_win = htons(5480);
    tcph.th_flags = TH_SYN;
    p.tcph = &tcph;
    p.flowflags = FLOW_PKT_TOSERVER;
    int ret = 0;
    ra_ctx.stream_q = &stream_q;
    stt.ra_ctx = &ra_ctx;

    StreamTcpInitConfig(TRUE);

    if (StreamTcpPacket(&tv, &p, &stt, &pq) == -1)
        goto end;

    p.tcph->th_ack = htonl(1);
    p.tcph->th_flags = TH_SYN | TH_ACK;
    p.flowflags = FLOW_PKT_TOCLIENT;

    if (StreamTcpPacket(&tv, &p, &stt, &pq) == -1)
        goto end;

    p.tcph->th_ack = htonl(1);
    p.tcph->th_seq = htonl(1);
    p.tcph->th_flags = TH_ACK;
    p.flowflags = FLOW_PKT_TOSERVER;

    if (StreamTcpPacket(&tv, &p, &stt, &pq) == -1)
        goto end;

    p.tcph->th_ack = htonl(1);
    p.tcph->th_seq = htonl(1);
    p.tcph->th_flags = TH_RST | TH_ACK;
    p.flowflags = FLOW_PKT_TOSERVER;

    if (StreamTcpPacket(&tv, &p, &stt, &pq) == -1)
        goto end;

    if (((TcpSession *)(p.flow->protoctx))->state != TCP_CLOSED) {
        printf("Tcp session should have been closed\n");
        goto end;
    }

    p.tcph->th_seq = htonl(1);
    p.tcph->th_flags = TH_SYN;
    p.flowflags = FLOW_PKT_TOSERVER;

    if (StreamTcpPacket(&tv, &p, &stt, &pq) == -1)
        goto end;

    p.tcph->th_seq = htonl(1);
    p.tcph->th_ack = htonl(2);
    p.tcph->th_flags = TH_SYN | TH_ACK;
    p.flowflags = FLOW_PKT_TOCLIENT;

    if (StreamTcpPacket(&tv, &p, &stt, &pq) == -1)
        goto end;

    p.tcph->th_ack = htonl(2);
    p.tcph->th_seq = htonl(2);
    p.tcph->th_flags = TH_ACK;
    p.flowflags = FLOW_PKT_TOSERVER;

    if (StreamTcpPacket(&tv, &p, &stt, &pq) == -1)
        goto end;

    if (((TcpSession *)(p.flow->protoctx))->state != TCP_ESTABLISHED) {
        printf("Tcp session should have been ESTABLISHED\n");
        goto end;
    }

    ret = 1;
end:
    StreamTcpSessionClear(p.flow->protoctx);
    StreamTcpFreeConfig(TRUE);
    return ret;
}

/**
 *  \test   Test the allocation of TCP session for a given packet when the SYN
 *          packet is sent with the PUSH flag set.
 *
 *  \retval On success it returns 1 and on failure 0.
 */

static int StreamTcpTest34 (void)
{
    Packet p;
    Flow f;
    ThreadVars tv;
    StreamTcpThread stt;
    TCPHdr tcph;
    TcpReassemblyThreadCtx ra_ctx;
    StreamMsgQueue stream_q;
    PacketQueue pq;
    memset(&pq,0,sizeof(PacketQueue));
    memset(&stream_q, 0, sizeof(StreamMsgQueue));
    memset(&ra_ctx, 0, sizeof(TcpReassemblyThreadCtx));
    memset (&p, 0, SIZE_OF_PACKET);
    memset (&f, 0, sizeof(Flow));
    memset(&tv, 0, sizeof (ThreadVars));
    memset(&stt, 0, sizeof (StreamTcpThread));
    memset(&tcph, 0, sizeof (TCPHdr));

    FLOW_INITIALIZE(&f);
    p.flow = &f;
    tcph.th_win = htons(5480);
    tcph.th_flags = TH_SYN|TH_PUSH;
    p.tcph = &tcph;
    p.flowflags = FLOW_PKT_TOSERVER;
    int ret = 0;
    ra_ctx.stream_q = &stream_q;
    stt.ra_ctx = &ra_ctx;

    StreamTcpInitConfig(TRUE);

    if (StreamTcpPacket(&tv, &p, &stt, &pq) == -1)
        goto end;

    p.tcph->th_ack = htonl(1);
    p.tcph->th_flags = TH_SYN | TH_ACK;
    p.flowflags = FLOW_PKT_TOCLIENT;

    if (StreamTcpPacket(&tv, &p, &stt, &pq) == -1)
        goto end;

    p.tcph->th_ack = htonl(1);
    p.tcph->th_seq = htonl(1);
    p.tcph->th_flags = TH_ACK;
    p.flowflags = FLOW_PKT_TOSERVER;

    if (StreamTcpPacket(&tv, &p, &stt, &pq) == -1)
        goto end;

    if (((TcpSession *)(p.flow->protoctx))->state != TCP_ESTABLISHED) {
        printf("Tcp session should have been establisehd\n");
        goto end;
    }

    ret = 1;
end:
    StreamTcpSessionClear(p.flow->protoctx);
    StreamTcpFreeConfig(TRUE);
    return ret;
}

/**
 *  \test   Test the allocation of TCP session for a given packet when the SYN
 *          packet is sent with the URG flag set.
 *
 *  \retval On success it returns 1 and on failure 0.
 */

static int StreamTcpTest35 (void)
{
    Packet p;
    Flow f;
    ThreadVars tv;
    StreamTcpThread stt;
    TCPHdr tcph;
    TcpReassemblyThreadCtx ra_ctx;
    StreamMsgQueue stream_q;
    PacketQueue pq;
    memset(&pq,0,sizeof(PacketQueue));
    memset(&stream_q, 0, sizeof(StreamMsgQueue));
    memset(&ra_ctx, 0, sizeof(TcpReassemblyThreadCtx));
    memset (&p, 0, SIZE_OF_PACKET);
    memset (&f, 0, sizeof(Flow));
    memset(&tv, 0, sizeof (ThreadVars));
    memset(&stt, 0, sizeof (StreamTcpThread));
    memset(&tcph, 0, sizeof (TCPHdr));

    FLOW_INITIALIZE(&f);
    p.flow = &f;
    tcph.th_win = htons(5480);
    tcph.th_flags = TH_SYN|TH_URG;
    p.tcph = &tcph;
    p.flowflags = FLOW_PKT_TOSERVER;
    int ret = 0;
    ra_ctx.stream_q = &stream_q;
    stt.ra_ctx = &ra_ctx;

    StreamTcpInitConfig(TRUE);

    if (StreamTcpPacket(&tv, &p, &stt, &pq) == -1)
        goto end;

    p.tcph->th_ack = htonl(1);
    p.tcph->th_flags = TH_SYN | TH_ACK;
    p.flowflags = FLOW_PKT_TOCLIENT;

    if (StreamTcpPacket(&tv, &p, &stt, &pq) == -1)
        goto end;

    p.tcph->th_ack = htonl(1);
    p.tcph->th_seq = htonl(1);
    p.tcph->th_flags = TH_ACK;
    p.flowflags = FLOW_PKT_TOSERVER;

    if (StreamTcpPacket(&tv, &p, &stt, &pq) == -1)
        goto end;

    if (((TcpSession *)(p.flow->protoctx))->state != TCP_ESTABLISHED) {
        printf("Tcp session should have been establisehd\n");
        goto end;
    }

    ret = 1;
end:
    StreamTcpSessionClear(p.flow->protoctx);
    StreamTcpFreeConfig(TRUE);
    return ret;
}

/**
 *  \test   Test the processing of PSH and URG flag in tcp session.
 *
 *  \retval On success it returns 1 and on failure 0.
 */
static int StreamTcpTest36(void)
{
    Packet p;
    Flow f;
    ThreadVars tv;
    StreamTcpThread stt;
    uint8_t payload[4];
    TCPHdr tcph;
    TcpReassemblyThreadCtx *ra_ctx = StreamTcpReassembleInitThreadCtx(NULL);
    int ret = 0;
    PacketQueue pq;
    memset(&pq,0,sizeof(PacketQueue));

    memset (&p, 0, SIZE_OF_PACKET);
    memset (&f, 0, sizeof(Flow));
    memset(&tv, 0, sizeof (ThreadVars));
    memset(&stt, 0, sizeof (StreamTcpThread));
    memset(&tcph, 0, sizeof (TCPHdr));

    FLOW_INITIALIZE(&f);
    stt.ra_ctx = ra_ctx;
    p.flow = &f;
    tcph.th_win = htons(5480);
    tcph.th_flags = TH_SYN;
    p.tcph = &tcph;
    p.flowflags = FLOW_PKT_TOSERVER;

    StreamTcpInitConfig(TRUE);

    if (StreamTcpPacket(&tv, &p, &stt, &pq) == -1) {
        printf("failed in processing packet\n");
        goto end;
    }

    p.tcph->th_ack = htonl(1);
    p.tcph->th_flags = TH_SYN | TH_ACK;
    p.flowflags = FLOW_PKT_TOCLIENT;

    if (StreamTcpPacket(&tv, &p, &stt, &pq) == -1 || (TcpSession *)p.flow->protoctx == NULL) {
        printf("failed in processing packet\n");
        goto end;
    }

    p.tcph->th_ack = htonl(1);
    p.tcph->th_seq = htonl(1);
    p.tcph->th_flags = TH_ACK;
    p.flowflags = FLOW_PKT_TOSERVER;

    if (StreamTcpPacket(&tv, &p, &stt, &pq) == -1 || (TcpSession *)p.flow->protoctx == NULL) {
        printf("failed in processing packet\n");
        goto end;
    }

    if (((TcpSession *)p.flow->protoctx)->state != TCP_ESTABLISHED) {
        printf("the TCP state should be TCP_ESTABLISEHD\n");
        goto end;
    }

    p.tcph->th_ack = htonl(2);
    p.tcph->th_seq = htonl(1);
    p.tcph->th_flags = TH_PUSH | TH_ACK | TH_URG;
    p.flowflags = FLOW_PKT_TOSERVER;

    StreamTcpCreateTestPacket(payload, 0x41, 3, 4); /*AAA*/
    p.payload = payload;
    p.payload_len = 3;

    if (StreamTcpPacket(&tv, &p, &stt, &pq) == -1 || (TcpSession *)p.flow->protoctx == NULL) {
        printf("failed in processing packet\n");
        goto end;
    }

    if (((TcpSession *)p.flow->protoctx)->client.next_seq != 4) {
        printf("the ssn->client.next_seq should be 4, but it is %"PRIu32"\n",
                ((TcpSession *)p.flow->protoctx)->client.next_seq);
        goto end;
    }

    StreamTcpSessionClear(p.flow->protoctx);

    ret = 1;
end:
    StreamTcpFreeConfig(TRUE);
    return ret;
}
#endif

/**
 *  \test   Test the processing of out of order FIN packets in tcp session.
 *
 *  \retval On success it returns 1 and on failure 0.
 */
static int StreamTcpTest37(void)
{
    Packet *p = SCMalloc(SIZE_OF_PACKET);
    if (unlikely(p == NULL))
        return 0;
    Flow f;
    ThreadVars tv;
    StreamTcpThread stt;
    uint8_t payload[4];
    TCPHdr tcph;
    TcpReassemblyThreadCtx *ra_ctx = StreamTcpReassembleInitThreadCtx(NULL);
    int ret = 0;
    PacketQueue pq;
    memset(&pq,0,sizeof(PacketQueue));

    memset(p, 0, SIZE_OF_PACKET);
    memset (&f, 0, sizeof(Flow));
    memset(&tv, 0, sizeof (ThreadVars));
    memset(&stt, 0, sizeof (StreamTcpThread));
    memset(&tcph, 0, sizeof (TCPHdr));

    FLOW_INITIALIZE(&f);

    stt.ra_ctx = ra_ctx;
    p->flow = &f;
    tcph.th_win = htons(5480);
    tcph.th_flags = TH_SYN;
    p->tcph = &tcph;
    p->flowflags = FLOW_PKT_TOSERVER;

    StreamTcpInitConfig(TRUE);

    FLOWLOCK_WRLOCK(&f);
    if (StreamTcpPacket(&tv, p, &stt, &pq) == -1) {
        printf("failed in processing packet\n");
        goto end;
    }

    p->tcph->th_ack = htonl(1);
    p->tcph->th_flags = TH_SYN | TH_ACK;
    p->flowflags = FLOW_PKT_TOCLIENT;

    if (StreamTcpPacket(&tv, p, &stt, &pq) == -1 || (TcpSession *)p->flow->protoctx == NULL) {
        printf("failed in processing packet\n");
        goto end;
    }

    p->tcph->th_ack = htonl(1);
    p->tcph->th_seq = htonl(1);
    p->tcph->th_flags = TH_ACK;
    p->flowflags = FLOW_PKT_TOSERVER;

    if (StreamTcpPacket(&tv, p, &stt, &pq) == -1 || (TcpSession *)p->flow->protoctx == NULL) {
        printf("failed in processing packet\n");
        goto end;
    }

    if (((TcpSession *)p->flow->protoctx)->state != TCP_ESTABLISHED) {
        printf("the TCP state should be TCP_ESTABLISEHD\n");
        goto end;
    }

    p->tcph->th_ack = htonl(2);
    p->tcph->th_seq = htonl(4);
    p->tcph->th_flags = TH_ACK|TH_FIN;
    p->flowflags = FLOW_PKT_TOSERVER;

    if (StreamTcpPacket(&tv, p, &stt, &pq) == -1 || (TcpSession *)p->flow->protoctx == NULL) {
        printf("failed in processing packet\n");
        goto end;
    }

    if (((TcpSession *)p->flow->protoctx)->state != TCP_CLOSE_WAIT) {
        printf("the TCP state should be TCP_CLOSE_WAIT\n");
        goto end;
    }

    p->tcph->th_ack = htonl(1);
    p->tcph->th_seq = htonl(1);
    p->tcph->th_flags = TH_PUSH | TH_ACK;
    p->flowflags = FLOW_PKT_TOSERVER;

    StreamTcpCreateTestPacket(payload, 0x41, 3, 4); /*AAA*/
    p->payload = payload;
    p->payload_len = 3;

    if (StreamTcpPacket(&tv, p, &stt, &pq) == -1 || (TcpSession *)p->flow->protoctx == NULL) {
        printf("failed in processing packet\n");
        goto end;
    }

    p->tcph->th_ack = htonl(4);
    p->tcph->th_seq = htonl(2);
    p->tcph->th_flags = TH_ACK;
    p->payload_len = 0;
    p->flowflags = FLOW_PKT_TOCLIENT;

    if (StreamTcpPacket(&tv, p, &stt, &pq) == -1 || (TcpSession *)p->flow->protoctx == NULL) {
        printf("failed in processing packet\n");
        goto end;
    }

    if (((TcpSession *)p->flow->protoctx)->client.ra_raw_base_seq != 3) {
        printf("the ssn->client.next_seq should be 3, but it is %"PRIu32"\n",
                ((TcpSession *)p->flow->protoctx)->client.ra_raw_base_seq);
        goto end;
    }

    StreamTcpSessionClear(p->flow->protoctx);

    ret = 1;
end:
    StreamTcpFreeConfig(TRUE);
    FLOWLOCK_UNLOCK(&f);
    SCFree(p);
    FLOW_DESTROY(&f);
    return ret;
}

/**
 *  \test   Test the validation of the ACK number before setting up the
 *          stream.last_ack.
 *
 *  \retval On success it returns 1 and on failure 0.
 */

static int StreamTcpTest38 (void)
{
    int ret = 0;
    Flow f;
    ThreadVars tv;
    StreamTcpThread stt;
    uint8_t payload[128];
    TCPHdr tcph;
    PacketQueue pq;

    TcpReassemblyThreadCtx *ra_ctx = StreamTcpReassembleInitThreadCtx(NULL);
    memset (&f, 0, sizeof(Flow));
    memset(&tv, 0, sizeof (ThreadVars));
    memset(&stt, 0, sizeof (StreamTcpThread));
    memset(&tcph, 0, sizeof (TCPHdr));
    memset(&pq,0,sizeof(PacketQueue));

    Packet *p = SCMalloc(SIZE_OF_PACKET);
    if (unlikely(p == NULL))
        return 0;
    memset(p, 0, SIZE_OF_PACKET);

    FLOW_INITIALIZE(&f);
    p->flow = &f;
    tcph.th_win = htons(5480);
    tcph.th_flags = TH_SYN;
    p->tcph = &tcph;
    p->flowflags = FLOW_PKT_TOSERVER;
    stt.ra_ctx = ra_ctx;

    StreamTcpInitConfig(TRUE);
    FLOWLOCK_WRLOCK(&f);
    if (StreamTcpPacket(&tv, p, &stt, &pq) == -1) {
        printf("failed in processing packet in StreamTcpPacket\n");
        goto end;
    }

    p->tcph->th_ack = htonl(1);
    p->tcph->th_flags = TH_SYN | TH_ACK;
    p->flowflags = FLOW_PKT_TOCLIENT;

    if (StreamTcpPacket(&tv, p, &stt, &pq) == -1) {
        printf("failed in processing packet in StreamTcpPacket\n");
        goto end;
    }

    p->tcph->th_ack = htonl(1);
    p->tcph->th_seq = htonl(1);
    p->tcph->th_flags = TH_ACK;
    p->flowflags = FLOW_PKT_TOSERVER;

    if (StreamTcpPacket(&tv, p, &stt, &pq) == -1) {
        printf("failed in processing packet in StreamTcpPacket\n");
        goto end;
    }

    p->tcph->th_ack = htonl(29847);
    p->tcph->th_seq = htonl(2);
    p->tcph->th_flags = TH_PUSH | TH_ACK;
    p->flowflags = FLOW_PKT_TOSERVER;

    StreamTcpCreateTestPacket(payload, 0x41, 3, 4); /*AAA*/
    p->payload = payload;
    p->payload_len = 3;

    if (StreamTcpPacket(&tv, p, &stt, &pq) == -1) {
        printf("failed in processing packet in StreamTcpPacket\n");
        goto end;
    }

    /* last_ack value should be 1 as the previous sent ACK value is out of
       window */
    if (((TcpSession *)(p->flow->protoctx))->server.last_ack != 1) {
        printf("the server.last_ack should be 1, but it is %"PRIu32"\n",
                ((TcpSession *)(p->flow->protoctx))->server.last_ack);
        goto end;
    }

    p->tcph->th_ack = htonl(1);
    p->tcph->th_seq = htonl(1);
    p->tcph->th_flags = TH_PUSH | TH_ACK;
    p->flowflags = FLOW_PKT_TOCLIENT;

    StreamTcpCreateTestPacket(payload, 0x41, 127, 128); /*AAA*/
    p->payload = payload;
    p->payload_len = 127;

    if (StreamTcpPacket(&tv, p, &stt, &pq) == -1) {
        printf("failed in processing packet in StreamTcpPacket\n");
        goto end;
    }

    if (((TcpSession *)(p->flow->protoctx))->server.next_seq != 128) {
        printf("the server.next_seq should be 128, but it is %"PRIu32"\n",
                ((TcpSession *)(p->flow->protoctx))->server.next_seq);
        goto end;
    }

    p->tcph->th_ack = htonl(256); // in window, but beyond next_seq
    p->tcph->th_seq = htonl(5);
    p->tcph->th_flags = TH_PUSH | TH_ACK;
    p->flowflags = FLOW_PKT_TOSERVER;

    StreamTcpCreateTestPacket(payload, 0x41, 3, 4); /*AAA*/
    p->payload = payload;
    p->payload_len = 3;

    if (StreamTcpPacket(&tv, p, &stt, &pq) == -1) {
        printf("failed in processing packet in StreamTcpPacket\n");
        goto end;
    }

    /* last_ack value should be 256, as the previous sent ACK value
       is inside window */
    if (((TcpSession *)(p->flow->protoctx))->server.last_ack != 256) {
        printf("the server.last_ack should be 1, but it is %"PRIu32"\n",
                ((TcpSession *)(p->flow->protoctx))->server.last_ack);
        goto end;
    }

    p->tcph->th_ack = htonl(128);
    p->tcph->th_seq = htonl(8);
    p->tcph->th_flags = TH_PUSH | TH_ACK;
    p->flowflags = FLOW_PKT_TOSERVER;

    StreamTcpCreateTestPacket(payload, 0x41, 3, 4); /*AAA*/
    p->payload = payload;
    p->payload_len = 3;

    if (StreamTcpPacket(&tv, p, &stt, &pq) == -1) {
        printf("failed in processing packet in StreamTcpPacket\n");
        goto end;
    }

    /* last_ack value should be 256 as the previous sent ACK value is inside
       window */
    if (((TcpSession *)(p->flow->protoctx))->server.last_ack != 256) {
        printf("the server.last_ack should be 256, but it is %"PRIu32"\n",
                ((TcpSession *)(p->flow->protoctx))->server.last_ack);
        goto end;
    }

    ret = 1;

end:
    StreamTcpSessionClear(p->flow->protoctx);
    StreamTcpFreeConfig(TRUE);
    FLOWLOCK_UNLOCK(&f);
    SCFree(p);
    FLOW_DESTROY(&f);
    if (stt.ra_ctx != NULL)
        StreamTcpReassembleFreeThreadCtx(stt.ra_ctx);
    return ret;
}

/**
 *  \test   Test the validation of the ACK number before setting up the
 *          stream.last_ack and update the next_seq after loosing the .
 *
 *  \retval On success it returns 1 and on failure 0.
 */

static int StreamTcpTest39 (void)
{
    Flow f;
    ThreadVars tv;
    StreamTcpThread stt;
    uint8_t payload[4];
    TCPHdr tcph;
    PacketQueue pq;

    TcpReassemblyThreadCtx *ra_ctx = StreamTcpReassembleInitThreadCtx(NULL);
    memset (&f, 0, sizeof(Flow));
    memset(&tv, 0, sizeof (ThreadVars));
    memset(&stt, 0, sizeof (StreamTcpThread));
    memset(&tcph, 0, sizeof (TCPHdr));
    memset(&pq,0,sizeof(PacketQueue));

    Packet *p = SCMalloc(SIZE_OF_PACKET);
    if (unlikely(p == NULL))
        return 0;
    memset(p, 0, SIZE_OF_PACKET);

    FLOW_INITIALIZE(&f);
    p->flow = &f;
    tcph.th_win = htons(5480);
    tcph.th_flags = TH_SYN;
    p->tcph = &tcph;
    p->flowflags = FLOW_PKT_TOSERVER;
    int ret = 0;
    stt.ra_ctx = ra_ctx;

    StreamTcpInitConfig(TRUE);

    FLOWLOCK_WRLOCK(&f);
    if (StreamTcpPacket(&tv, p, &stt, &pq) == -1) {
        printf("failed in processing packet in StreamTcpPacket\n");
        goto end;
    }

    p->tcph->th_ack = htonl(1);
    p->tcph->th_flags = TH_SYN | TH_ACK;
    p->flowflags = FLOW_PKT_TOCLIENT;

    if (StreamTcpPacket(&tv, p, &stt, &pq) == -1) {
        printf("failed in processing packet in StreamTcpPacket\n");
        goto end;
    }

    p->tcph->th_ack = htonl(1);
    p->tcph->th_seq = htonl(1);
    p->tcph->th_flags = TH_ACK;
    p->flowflags = FLOW_PKT_TOSERVER;

    if (StreamTcpPacket(&tv, p, &stt, &pq) == -1) {
        printf("failed in processing packet in StreamTcpPacket\n");
        goto end;
    }

    p->tcph->th_ack = htonl(1);
    p->tcph->th_seq = htonl(1);
    p->tcph->th_flags = TH_PUSH | TH_ACK;
    p->flowflags = FLOW_PKT_TOCLIENT;

    StreamTcpCreateTestPacket(payload, 0x41, 3, 4); /*AAA*/
    p->payload = payload;
    p->payload_len = 3;

    if (StreamTcpPacket(&tv, p, &stt, &pq) == -1) {
        printf("failed in processing packet in StreamTcpPacket\n");
        goto end;
    }

    if (((TcpSession *)(p->flow->protoctx))->server.next_seq != 4) {
        printf("the server.next_seq should be 4, but it is %"PRIu32"\n",
                ((TcpSession *)(p->flow->protoctx))->server.next_seq);
        goto end;
    }

    p->tcph->th_ack = htonl(4);
    p->tcph->th_seq = htonl(2);
    p->tcph->th_flags = TH_PUSH | TH_ACK;
    p->flowflags = FLOW_PKT_TOSERVER;

    StreamTcpCreateTestPacket(payload, 0x41, 3, 4); /*AAA*/
    p->payload = payload;
    p->payload_len = 3;

    if (StreamTcpPacket(&tv, p, &stt, &pq) == -1) {
        printf("failed in processing packet in StreamTcpPacket\n");
        goto end;
    }

    /* last_ack value should be 4 as the previous sent ACK value is inside
       window */
    if (((TcpSession *)(p->flow->protoctx))->server.last_ack != 4) {
        printf("the server.last_ack should be 4, but it is %"PRIu32"\n",
                ((TcpSession *)(p->flow->protoctx))->server.last_ack);
        goto end;
    }

    p->tcph->th_seq = htonl(4);
    p->tcph->th_ack = htonl(5);
    p->tcph->th_flags = TH_PUSH | TH_ACK;
    p->flowflags = FLOW_PKT_TOCLIENT;

    StreamTcpCreateTestPacket(payload, 0x41, 3, 4); /*AAA*/
    p->payload = payload;
    p->payload_len = 3;

    if (StreamTcpPacket(&tv, p, &stt, &pq) == -1) {
        printf("failed in processing packet in StreamTcpPacket\n");
        goto end;
    }

    /* next_seq value should be 2987 as the previous sent ACK value is inside
       window */
    if (((TcpSession *)(p->flow->protoctx))->server.next_seq != 7) {
        printf("the server.next_seq should be 7, but it is %"PRIu32"\n",
                ((TcpSession *)(p->flow->protoctx))->server.next_seq);
        goto end;
    }

    ret = 1;

end:
    StreamTcpSessionClear(p->flow->protoctx);
    StreamTcpFreeConfig(TRUE);
    FLOWLOCK_UNLOCK(&f);
    SCFree(p);
    FLOW_DESTROY(&f);
    if (stt.ra_ctx != NULL)
        StreamTcpReassembleFreeThreadCtx(stt.ra_ctx);
    return ret;
}

static int StreamTcpTest40(void)
{
    uint8_t raw_vlan[] = {
        0x00, 0x20, 0x08, 0x00, 0x45, 0x00, 0x00, 0x34,
        0x3b, 0x36, 0x40, 0x00, 0x40, 0x06, 0xb7, 0xc9,
        0x83, 0x97, 0x20, 0x81, 0x83, 0x97, 0x20, 0x15,
        0x04, 0x8a, 0x17, 0x70, 0x4e, 0x14, 0xdf, 0x55,
        0x4d, 0x3d, 0x5a, 0x61, 0x80, 0x10, 0x6b, 0x50,
        0x3c, 0x4c, 0x00, 0x00, 0x01, 0x01, 0x08, 0x0a,
        0x00, 0x04, 0xf0, 0xc8, 0x01, 0x99, 0xa3, 0xf3
    };
    Packet *p = SCMalloc(SIZE_OF_PACKET);
    if (unlikely(p == NULL))
        return 0;
    ThreadVars tv;
    DecodeThreadVars dtv;

    memset(&tv, 0, sizeof(ThreadVars));
    memset(p, 0, SIZE_OF_PACKET);
    PACKET_INITIALIZE(p);

    SET_PKT_LEN(p, sizeof(raw_vlan));
    memcpy(GET_PKT_DATA(p), raw_vlan, sizeof(raw_vlan));
    memset(&dtv, 0, sizeof(DecodeThreadVars));

    FlowInitConfig(FLOW_QUIET);

    DecodeVLAN(&tv, &dtv, p, GET_PKT_DATA(p), GET_PKT_LEN(p), NULL);

    if(p->vlanh[0] == NULL) {
        SCFree(p);
        return 0;
    }

    if(p->tcph == NULL) {
        SCFree(p);
        return 0;
    }

    Packet *np = StreamTcpPseudoSetup(p, GET_PKT_DATA(p), GET_PKT_LEN(p));
    if (np == NULL) {
        printf("the packet received from packet allocation is NULL: ");
        return 0;
    }

    StreamTcpPseudoPacketSetupHeader(np,p);

    if (((uint8_t *)p->tcph - (uint8_t *)p->ip4h) != ((uint8_t *)np->tcph - (uint8_t *)np->ip4h)) {
        return 0;
    }

    PACKET_RECYCLE(np);
    PACKET_RECYCLE(p);
    FlowShutdown();

    return 1;
}

static int StreamTcpTest41(void)
{
    /* IPV6/TCP/no eth header */
    uint8_t raw_ip[] = {
        0x60, 0x00, 0x00, 0x00, 0x00, 0x28, 0x06, 0x40,
        0x20, 0x01, 0x06, 0x18, 0x04, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x51, 0x99, 0xcc, 0x70,
        0x20, 0x01, 0x06, 0x18, 0x00, 0x01, 0x80, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x05,
        0x8c, 0x9b, 0x00, 0x50, 0x6a, 0xe7, 0x07, 0x36,
        0x00, 0x00, 0x00, 0x00, 0xa0, 0x02, 0x16, 0x30,
        0x29, 0x9c, 0x00, 0x00, 0x02, 0x04, 0x05, 0x8c,
        0x04, 0x02, 0x08, 0x0a, 0x00, 0xdd, 0x1a, 0x39,
        0x00, 0x00, 0x00, 0x00, 0x01, 0x03, 0x03, 0x02 };
    Packet *p = SCMalloc(SIZE_OF_PACKET);
    if (unlikely(p == NULL))
        return 0;
    ThreadVars tv;
    DecodeThreadVars dtv;

    memset(&dtv, 0, sizeof(DecodeThreadVars));
    memset(&tv,  0, sizeof(ThreadVars));
    memset(p, 0, SIZE_OF_PACKET);
    PACKET_INITIALIZE(p);

    if (PacketCopyData(p, raw_ip, sizeof(raw_ip)) == -1) {
        PacketFree(p);
        return 1;
    }

    FlowInitConfig(FLOW_QUIET);

    DecodeRaw(&tv, &dtv, p, raw_ip, GET_PKT_LEN(p), NULL);

    if (p->ip6h == NULL) {
        printf("expected a valid ipv6 header but it was NULL: ");
        FlowShutdown();
        SCFree(p);
        return 1;
    }

    if(p->tcph == NULL) {
        SCFree(p);
        return 0;
    }

    Packet *np = StreamTcpPseudoSetup(p, GET_PKT_DATA(p), GET_PKT_LEN(p));
    if (np == NULL) {
        printf("the packet received from packet allocation is NULL: ");
        return 0;
    }

    StreamTcpPseudoPacketSetupHeader(np,p);

    if (((uint8_t *)p->tcph - (uint8_t *)p->ip6h) != ((uint8_t *)np->tcph - (uint8_t *)np->ip6h)) {
        return 0;
    }

    PACKET_RECYCLE(np);
    PACKET_RECYCLE(p);
    SCFree(p);
    FlowShutdown();

    return 1;
}

/** \test multiple different SYN/ACK, pick first */
static int StreamTcpTest42 (void)
{
    int ret = 0;
    Flow f;
    ThreadVars tv;
    StreamTcpThread stt;
    TCPHdr tcph;
    PacketQueue pq;
    Packet *p = SCMalloc(SIZE_OF_PACKET);
    TcpSession *ssn;

    if (unlikely(p == NULL))
        return 0;
    memset(p, 0, SIZE_OF_PACKET);

    memset(&pq,0,sizeof(PacketQueue));
    memset (&f, 0, sizeof(Flow));
    memset(&tv, 0, sizeof (ThreadVars));
    memset(&stt, 0, sizeof (StreamTcpThread));
    memset(&tcph, 0, sizeof (TCPHdr));

    StreamTcpInitConfig(TRUE);

    FLOW_INITIALIZE(&f);
    p->tcph = &tcph;
    tcph.th_win = htons(5480);
    p->flow = &f;

    /* SYN pkt */
    tcph.th_flags = TH_SYN;
    tcph.th_seq = htonl(100);
    p->flowflags = FLOW_PKT_TOSERVER;

    FLOWLOCK_WRLOCK(&f);
    if (StreamTcpPacket(&tv, p, &stt, &pq) == -1)
        goto end;

    /* SYN/ACK */
    p->tcph->th_seq = htonl(500);
    p->tcph->th_ack = htonl(101);
    p->tcph->th_flags = TH_SYN | TH_ACK;
    p->flowflags = FLOW_PKT_TOCLIENT;

    if (StreamTcpPacket(&tv, p, &stt, &pq) == -1)
        goto end;

    /* SYN/ACK */
    p->tcph->th_seq = htonl(1000);
    p->tcph->th_ack = htonl(101);
    p->tcph->th_flags = TH_SYN | TH_ACK;
    p->flowflags = FLOW_PKT_TOCLIENT;

    if (StreamTcpPacket(&tv, p, &stt, &pq) == -1)
        goto end;

    /* ACK */
    p->tcph->th_ack = htonl(501);
    p->tcph->th_seq = htonl(101);
    p->tcph->th_flags = TH_ACK;
    p->flowflags = FLOW_PKT_TOSERVER;

    if (StreamTcpPacket(&tv, p, &stt, &pq) == -1)
        goto end;

    ssn = p->flow->protoctx;

    if (ssn->state != TCP_ESTABLISHED) {
        printf("state not TCP_ESTABLISHED: ");
        goto end;
    }

    if (ssn->server.isn != 500) {
        SCLogDebug("ssn->server.isn %"PRIu32" != %"PRIu32"",
            ssn->server.isn, 500);
        goto end;
    }
    if (ssn->client.isn != 100) {
        SCLogDebug("ssn->client.isn %"PRIu32" != %"PRIu32"",
            ssn->client.isn, 100);
        goto end;
    }

    StreamTcpSessionClear(p->flow->protoctx);

    ret = 1;
end:
    StreamTcpFreeConfig(TRUE);
    FLOWLOCK_UNLOCK(&f);
    SCFree(p);
    FLOW_DESTROY(&f);
    return ret;
}

/** \test multiple different SYN/ACK, pick second */
static int StreamTcpTest43 (void)
{
    int ret = 0;
    Flow f;
    ThreadVars tv;
    StreamTcpThread stt;
    TCPHdr tcph;
    PacketQueue pq;
    Packet *p = SCMalloc(SIZE_OF_PACKET);
    TcpSession *ssn;

    if (unlikely(p == NULL))
        return 0;
    memset(p, 0, SIZE_OF_PACKET);

    memset(&pq,0,sizeof(PacketQueue));
    memset (&f, 0, sizeof(Flow));
    memset(&tv, 0, sizeof (ThreadVars));
    memset(&stt, 0, sizeof (StreamTcpThread));
    memset(&tcph, 0, sizeof (TCPHdr));

    StreamTcpInitConfig(TRUE);

    FLOW_INITIALIZE(&f);
    p->tcph = &tcph;
    tcph.th_win = htons(5480);
    p->flow = &f;

    /* SYN pkt */
    tcph.th_flags = TH_SYN;
    tcph.th_seq = htonl(100);
    p->flowflags = FLOW_PKT_TOSERVER;

    FLOWLOCK_WRLOCK(&f);
    if (StreamTcpPacket(&tv, p, &stt, &pq) == -1)
        goto end;

    /* SYN/ACK */
    p->tcph->th_seq = htonl(500);
    p->tcph->th_ack = htonl(101);
    p->tcph->th_flags = TH_SYN | TH_ACK;
    p->flowflags = FLOW_PKT_TOCLIENT;

    if (StreamTcpPacket(&tv, p, &stt, &pq) == -1)
        goto end;

    /* SYN/ACK */
    p->tcph->th_seq = htonl(1000);
    p->tcph->th_ack = htonl(101);
    p->tcph->th_flags = TH_SYN | TH_ACK;
    p->flowflags = FLOW_PKT_TOCLIENT;

    if (StreamTcpPacket(&tv, p, &stt, &pq) == -1)
        goto end;

    /* ACK */
    p->tcph->th_ack = htonl(1001);
    p->tcph->th_seq = htonl(101);
    p->tcph->th_flags = TH_ACK;
    p->flowflags = FLOW_PKT_TOSERVER;

    if (StreamTcpPacket(&tv, p, &stt, &pq) == -1)
        goto end;

    ssn = p->flow->protoctx;

    if (ssn->state != TCP_ESTABLISHED) {
        printf("state not TCP_ESTABLISHED: ");
        goto end;
    }

    if (ssn->server.isn != 1000) {
        SCLogDebug("ssn->server.isn %"PRIu32" != %"PRIu32"",
            ssn->server.isn, 1000);
        goto end;
    }
    if (ssn->client.isn != 100) {
        SCLogDebug("ssn->client.isn %"PRIu32" != %"PRIu32"",
            ssn->client.isn, 100);
        goto end;
    }

    StreamTcpSessionClear(p->flow->protoctx);

    ret = 1;
end:
    StreamTcpFreeConfig(TRUE);
    FLOWLOCK_UNLOCK(&f);
    SCFree(p);
    FLOW_DESTROY(&f);
    return ret;
}

/** \test multiple different SYN/ACK, pick neither */
static int StreamTcpTest44 (void)
{
    int ret = 0;
    Flow f;
    ThreadVars tv;
    StreamTcpThread stt;
    TCPHdr tcph;
    PacketQueue pq;
    Packet *p = SCMalloc(SIZE_OF_PACKET);
    TcpSession *ssn;

    if (unlikely(p == NULL))
        return 0;
    memset(p, 0, SIZE_OF_PACKET);

    memset(&pq,0,sizeof(PacketQueue));
    memset (&f, 0, sizeof(Flow));
    memset(&tv, 0, sizeof (ThreadVars));
    memset(&stt, 0, sizeof (StreamTcpThread));
    memset(&tcph, 0, sizeof (TCPHdr));

    StreamTcpInitConfig(TRUE);

    FLOW_INITIALIZE(&f);
    p->tcph = &tcph;
    tcph.th_win = htons(5480);
    p->flow = &f;

    /* SYN pkt */
    tcph.th_flags = TH_SYN;
    tcph.th_seq = htonl(100);
    p->flowflags = FLOW_PKT_TOSERVER;

    FLOWLOCK_WRLOCK(&f);
    if (StreamTcpPacket(&tv, p, &stt, &pq) == -1)
        goto end;

    /* SYN/ACK */
    p->tcph->th_seq = htonl(500);
    p->tcph->th_ack = htonl(101);
    p->tcph->th_flags = TH_SYN | TH_ACK;
    p->flowflags = FLOW_PKT_TOCLIENT;

    if (StreamTcpPacket(&tv, p, &stt, &pq) == -1)
        goto end;

    /* SYN/ACK */
    p->tcph->th_seq = htonl(1000);
    p->tcph->th_ack = htonl(101);
    p->tcph->th_flags = TH_SYN | TH_ACK;
    p->flowflags = FLOW_PKT_TOCLIENT;

    if (StreamTcpPacket(&tv, p, &stt, &pq) == -1)
        goto end;

    /* ACK */
    p->tcph->th_ack = htonl(3001);
    p->tcph->th_seq = htonl(101);
    p->tcph->th_flags = TH_ACK;
    p->flowflags = FLOW_PKT_TOSERVER;

    if (StreamTcpPacket(&tv, p, &stt, &pq) != -1)
        goto end;

    ssn = p->flow->protoctx;

    if (ssn->state != TCP_SYN_RECV) {
        SCLogDebug("state not TCP_SYN_RECV");
        goto end;
    }

    if (ssn->client.isn != 100) {
        SCLogDebug("ssn->client.isn %"PRIu32" != %"PRIu32"",
            ssn->client.isn, 100);
        goto end;
    }

    StreamTcpSessionClear(p->flow->protoctx);

    ret = 1;
end:
    StreamTcpFreeConfig(TRUE);
    FLOWLOCK_UNLOCK(&f);
    SCFree(p);
    FLOW_DESTROY(&f);
    return ret;
}

/** \test multiple different SYN/ACK, over the limit */
static int StreamTcpTest45 (void)
{
    int ret = 0;
    Flow f;
    ThreadVars tv;
    StreamTcpThread stt;
    TCPHdr tcph;
    PacketQueue pq;
    Packet *p = SCMalloc(SIZE_OF_PACKET);
    TcpSession *ssn;

    if (unlikely(p == NULL))
        return 0;
    memset(p, 0, SIZE_OF_PACKET);

    memset(&pq,0,sizeof(PacketQueue));
    memset (&f, 0, sizeof(Flow));
    memset(&tv, 0, sizeof (ThreadVars));
    memset(&stt, 0, sizeof (StreamTcpThread));
    memset(&tcph, 0, sizeof (TCPHdr));

    StreamTcpInitConfig(TRUE);
    stream_config.max_synack_queued = 2;

    FLOW_INITIALIZE(&f);
    p->tcph = &tcph;
    tcph.th_win = htons(5480);
    p->flow = &f;

    /* SYN pkt */
    tcph.th_flags = TH_SYN;
    tcph.th_seq = htonl(100);
    p->flowflags = FLOW_PKT_TOSERVER;

    FLOWLOCK_WRLOCK(&f);
    if (StreamTcpPacket(&tv, p, &stt, &pq) == -1)
        goto end;

    /* SYN/ACK */
    p->tcph->th_seq = htonl(500);
    p->tcph->th_ack = htonl(101);
    p->tcph->th_flags = TH_SYN | TH_ACK;
    p->flowflags = FLOW_PKT_TOCLIENT;

    if (StreamTcpPacket(&tv, p, &stt, &pq) == -1)
        goto end;

    /* SYN/ACK */
    p->tcph->th_seq = htonl(1000);
    p->tcph->th_ack = htonl(101);
    p->tcph->th_flags = TH_SYN | TH_ACK;
    p->flowflags = FLOW_PKT_TOCLIENT;

    if (StreamTcpPacket(&tv, p, &stt, &pq) == -1)
        goto end;

    /* SYN/ACK */
    p->tcph->th_seq = htonl(2000);
    p->tcph->th_ack = htonl(101);
    p->tcph->th_flags = TH_SYN | TH_ACK;
    p->flowflags = FLOW_PKT_TOCLIENT;

    if (StreamTcpPacket(&tv, p, &stt, &pq) == -1)
        goto end;

    /* SYN/ACK */
    p->tcph->th_seq = htonl(3000);
    p->tcph->th_ack = htonl(101);
    p->tcph->th_flags = TH_SYN | TH_ACK;
    p->flowflags = FLOW_PKT_TOCLIENT;

    if (StreamTcpPacket(&tv, p, &stt, &pq) != -1)
        goto end;

    /* ACK */
    p->tcph->th_ack = htonl(1001);
    p->tcph->th_seq = htonl(101);
    p->tcph->th_flags = TH_ACK;
    p->flowflags = FLOW_PKT_TOSERVER;

    if (StreamTcpPacket(&tv, p, &stt, &pq) == -1)
        goto end;

    ssn = p->flow->protoctx;

    if (ssn->state != TCP_ESTABLISHED) {
        printf("state not TCP_ESTABLISHED: ");
        goto end;
    }

    if (ssn->server.isn != 1000) {
        SCLogDebug("ssn->server.isn %"PRIu32" != %"PRIu32"",
            ssn->server.isn, 1000);
        goto end;
    }
    if (ssn->client.isn != 100) {
        SCLogDebug("ssn->client.isn %"PRIu32" != %"PRIu32"",
            ssn->client.isn, 100);
        goto end;
    }

    StreamTcpSessionClear(p->flow->protoctx);

    ret = 1;
end:
    StreamTcpFreeConfig(TRUE);
    FLOWLOCK_UNLOCK(&f);
    SCFree(p);
    return ret;
}

#endif /* UNITTESTS */

void StreamTcpRegisterTests (void)
{
#ifdef UNITTESTS
    UtRegisterTest("StreamTcpTest01 -- TCP session allocation",
                   StreamTcpTest01);
    UtRegisterTest("StreamTcpTest02 -- TCP session deallocation",
                   StreamTcpTest02);
    UtRegisterTest("StreamTcpTest03 -- SYN missed MidStream session",
                   StreamTcpTest03);
    UtRegisterTest("StreamTcpTest04 -- SYN/ACK missed MidStream session",
                   StreamTcpTest04);
    UtRegisterTest("StreamTcpTest05 -- 3WHS missed MidStream session",
                   StreamTcpTest05);
    UtRegisterTest("StreamTcpTest06 -- FIN, RST message MidStream session",
                   StreamTcpTest06);
    UtRegisterTest("StreamTcpTest07 -- PAWS invalid timestamp",
                   StreamTcpTest07);
    UtRegisterTest("StreamTcpTest08 -- PAWS valid timestamp", StreamTcpTest08);
    UtRegisterTest("StreamTcpTest09 -- No Client Reassembly", StreamTcpTest09);
    UtRegisterTest("StreamTcpTest10 -- No missed packet Async stream",
                   StreamTcpTest10);
    UtRegisterTest("StreamTcpTest11 -- SYN missed Async stream",
                   StreamTcpTest11);
    UtRegisterTest("StreamTcpTest12 -- SYN/ACK missed Async stream",
                   StreamTcpTest12);
    UtRegisterTest("StreamTcpTest13 -- opposite stream packets for Async " "stream",
                   StreamTcpTest13);
    UtRegisterTest("StreamTcp4WHSTest01", StreamTcp4WHSTest01);
    UtRegisterTest("StreamTcp4WHSTest02", StreamTcp4WHSTest02);
    UtRegisterTest("StreamTcp4WHSTest03", StreamTcp4WHSTest03);
    UtRegisterTest("StreamTcpTest14 -- setup OS policy", StreamTcpTest14);
    UtRegisterTest("StreamTcpTest15 -- setup OS policy", StreamTcpTest15);
    UtRegisterTest("StreamTcpTest16 -- setup OS policy", StreamTcpTest16);
    UtRegisterTest("StreamTcpTest17 -- setup OS policy", StreamTcpTest17);
    UtRegisterTest("StreamTcpTest18 -- setup OS policy", StreamTcpTest18);
    UtRegisterTest("StreamTcpTest19 -- setup OS policy", StreamTcpTest19);
    UtRegisterTest("StreamTcpTest20 -- setup OS policy", StreamTcpTest20);
    UtRegisterTest("StreamTcpTest21 -- setup OS policy", StreamTcpTest21);
    UtRegisterTest("StreamTcpTest22 -- setup OS policy", StreamTcpTest22);
    UtRegisterTest("StreamTcpTest23 -- stream memory leaks", StreamTcpTest23);
    UtRegisterTest("StreamTcpTest24 -- stream memory leaks", StreamTcpTest24);
    UtRegisterTest("StreamTcpTest25 -- test ecn/cwr sessions",
                   StreamTcpTest25);
    UtRegisterTest("StreamTcpTest26 -- test ecn/cwr sessions",
                   StreamTcpTest26);
    UtRegisterTest("StreamTcpTest27 -- test ecn/cwr sessions",
                   StreamTcpTest27);
    UtRegisterTest("StreamTcpTest28 -- Memcap Test", StreamTcpTest28);

#if 0 /* VJ 2010/09/01 disabled since they blow up on Fedora and Fedora is
       * right about blowing up. The checksum functions are not used properly
       * in the tests. */
    UtRegisterTest("StreamTcpTest29 -- Badchecksum Reset Test", StreamTcpTest29, 1);
    UtRegisterTest("StreamTcpTest30 -- Badchecksum Overlap Test", StreamTcpTest30, 1);
    UtRegisterTest("StreamTcpTest31 -- MultipleSyns Test", StreamTcpTest31, 1);
    UtRegisterTest("StreamTcpTest32 -- Bogus CWR Test", StreamTcpTest32, 1);
    UtRegisterTest("StreamTcpTest33 -- RST-SYN Again Test", StreamTcpTest33, 1);
    UtRegisterTest("StreamTcpTest34 -- SYN-PUSH Test", StreamTcpTest34, 1);
    UtRegisterTest("StreamTcpTest35 -- SYN-URG Test", StreamTcpTest35, 1);
    UtRegisterTest("StreamTcpTest36 -- PUSH-URG Test", StreamTcpTest36, 1);
#endif
    UtRegisterTest("StreamTcpTest37 -- Out of order FIN Test",
                   StreamTcpTest37);

    UtRegisterTest("StreamTcpTest38 -- validate ACK", StreamTcpTest38);
    UtRegisterTest("StreamTcpTest39 -- update next_seq", StreamTcpTest39);

    UtRegisterTest("StreamTcpTest40 -- pseudo setup", StreamTcpTest40);
    UtRegisterTest("StreamTcpTest41 -- pseudo setup", StreamTcpTest41);

    UtRegisterTest("StreamTcpTest42 -- SYN/ACK queue", StreamTcpTest42);
    UtRegisterTest("StreamTcpTest43 -- SYN/ACK queue", StreamTcpTest43);
    UtRegisterTest("StreamTcpTest44 -- SYN/ACK queue", StreamTcpTest44);
    UtRegisterTest("StreamTcpTest45 -- SYN/ACK queue", StreamTcpTest45);

    /* set up the reassembly tests as well */
    StreamTcpReassembleRegisterTests();

    StreamTcpSackRegisterTests ();
#endif /* UNITTESTS */
}

