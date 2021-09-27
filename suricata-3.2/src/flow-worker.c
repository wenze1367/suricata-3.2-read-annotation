/* Copyright (C) 2016 Open Information Security Foundation
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
 * Flow Workers are single thread modules taking care of (almost)
 * everything related to packets with flows:
 *
 * - Lookup/creation
 * - Stream tracking, reassembly
 * - Applayer update
 * - Detection
 *
 * This all while holding the flow lock.
 */

#include "suricata-common.h"
#include "suricata.h"

#include "decode.h"
#include "stream-tcp.h"
#include "app-layer.h"
#include "detect-engine.h"
#include "output.h"

#include "util-validate.h"

#include "flow-util.h"

typedef DetectEngineThreadCtx *DetectEngineThreadCtxPtr;

typedef struct FlowWorkerThreadData_ {
    DecodeThreadVars *dtv;

    union {
        StreamTcpThread *stream_thread;
        void *stream_thread_ptr;
    };

    SC_ATOMIC_DECLARE(DetectEngineThreadCtxPtr, detect_thread);

    void *output_thread; /* Output thread data. */

    PacketQueue pq;

} FlowWorkerThreadData;

/** \brief handle flow for packet
 *
 *  Handle flow creation/lookup
 */
static inline TmEcode FlowUpdate(Packet *p)
{
    FlowHandlePacketUpdate(p->flow, p);

    int state = SC_ATOMIC_GET(p->flow->flow_state);
    switch (state) {
        case FLOW_STATE_CAPTURE_BYPASSED:
        case FLOW_STATE_LOCAL_BYPASSED:
            return TM_ECODE_DONE;
        default:
            return TM_ECODE_OK;
    }
}

static TmEcode FlowWorkerThreadInit(ThreadVars *tv, void *initdata, void **data)
{
    FlowWorkerThreadData *fw = SCCalloc(1, sizeof(*fw));
    BUG_ON(fw == NULL);
    SC_ATOMIC_INIT(fw->detect_thread);
    SC_ATOMIC_SET(fw->detect_thread, NULL);

    fw->dtv = DecodeThreadVarsAlloc(tv);
    if (fw->dtv == NULL) {
        SC_ATOMIC_DESTROY(fw->detect_thread);
        SCFree(fw);
        return TM_ECODE_FAILED;
    }

    /* setup TCP */
    BUG_ON(StreamTcpThreadInit(tv, NULL, &fw->stream_thread_ptr) != TM_ECODE_OK);

    if (DetectEngineEnabled()) {
        /* setup DETECT */
        void *detect_thread = NULL;
        BUG_ON(DetectEngineThreadCtxInit(tv, NULL, &detect_thread) != TM_ECODE_OK);
        SC_ATOMIC_SET(fw->detect_thread, detect_thread);
    }

    /* Setup outputs for this thread. */
    if (OutputLoggerThreadInit(tv, initdata, &fw->output_thread) != TM_ECODE_OK) {
        return TM_ECODE_FAILED;
    }
 
    AppLayerRegisterThreadCounters(tv);

    /* setup pq for stream end pkts */
    memset(&fw->pq, 0, sizeof(PacketQueue));
    SCMutexInit(&fw->pq.mutex_q, NULL);

    *data = fw;
    return TM_ECODE_OK;
}

static TmEcode FlowWorkerThreadDeinit(ThreadVars *tv, void *data)
{
    FlowWorkerThreadData *fw = data;

    DecodeThreadVarsFree(tv, fw->dtv);

    /* free TCP */
    StreamTcpThreadDeinit(tv, (void *)fw->stream_thread);

    /* free DETECT */
    void *detect_thread = SC_ATOMIC_GET(fw->detect_thread);
    if (detect_thread != NULL) {
        DetectEngineThreadCtxDeinit(tv, detect_thread);
        SC_ATOMIC_SET(fw->detect_thread, NULL);
    }

    /* Free output. */
    OutputLoggerThreadDeinit(tv, fw->output_thread);

    /* free pq */
    BUG_ON(fw->pq.len);
    SCMutexDestroy(&fw->pq.mutex_q);

    SCFree(fw);
    return TM_ECODE_OK;
}

TmEcode Detect(ThreadVars *tv, Packet *p, void *data, PacketQueue *pq, PacketQueue *postpq);
TmEcode StreamTcp (ThreadVars *, Packet *, void *, PacketQueue *, PacketQueue *);

TmEcode FlowWorker(ThreadVars *tv, Packet *p, void *data, PacketQueue *preq, PacketQueue *unused)
{
	/*FlowWorkerThreadInit中初始化，包含大量stats统计指标,decode指标在DecodeThreadVars中，
	tcp指标在StreamTcpThread中*/
    FlowWorkerThreadData *fw = data;

	//获取detect线程(3.1中的worker线程)的数据;
    void *detect_thread = SC_ATOMIC_GET(fw->detect_thread);

    SCLogDebug("packet %"PRIu64, p->pcap_cnt);

    /* update time */
    if (!(PKT_IS_PSEUDOPKT(p))) {
        TimeSetByThread(tv->id, &p->ts);
    }

    /* handle Flow */
	/*如果p->flags被置了PKT_WANTS_FLOW（tcp的包一定会被置PKT_WANTS_FLOW）,
说明这是一条流中的一个包，需要更新其对应的流信息*/
    if (p->flags & PKT_WANTS_FLOW) {
        FLOWWORKER_PROFILING_START(p, PROFILE_FLOWWORKER_FLOW);

        FlowHandlePacket(tv, fw->dtv, p);
        if (likely(p->flow != NULL)) {
            DEBUG_ASSERT_FLOW_LOCKED(p->flow);
            if (FlowUpdate(p) == TM_ECODE_DONE) {
                FLOWLOCK_UNLOCK(p->flow);
                return TM_ECODE_OK;
            }
        }
        /* Flow is now LOCKED */

        FLOWWORKER_PROFILING_END(p, PROFILE_FLOWWORKER_FLOW);

    /* if PKT_WANTS_FLOW is not set, but PKT_HAS_FLOW is, then this is a
     * pseudo packet created by the flow manager. */
    } else if (p->flags & PKT_HAS_FLOW) {
	    /*此时流是被锁住的*/
        FLOWLOCK_WRLOCK(p->flow);
    }

    SCLogDebug("packet %"PRIu64" has flow? %s", p->pcap_cnt, p->flow ? "yes" : "no");

    /* handle TCP and app layer */
    if (PKT_IS_TCP(p)) {
        SCLogDebug("packet %"PRIu64" is TCP", p->pcap_cnt);
        DEBUG_ASSERT_FLOW_LOCKED(p->flow);

        FLOWWORKER_PROFILING_START(p, PROFILE_FLOWWORKER_STREAM);

		//主要的流操作都在这里，后面会详细分析;
        StreamTcp(tv, p, fw->stream_thread, &fw->pq, NULL);
		
        FLOWWORKER_PROFILING_END(p, PROFILE_FLOWWORKER_STREAM);

        /* Packets here can safely access p->flow as it's locked */
        SCLogDebug("packet %"PRIu64": extra packets %u", p->pcap_cnt, fw->pq.len);
        Packet *x;
        while ((x = PacketDequeue(&fw->pq))) {
            SCLogDebug("packet %"PRIu64" extra packet %p", p->pcap_cnt, x);

            // TODO do we need to call StreamTcp on these pseudo packets or not?
            //StreamTcp(tv, x, fw->stream_thread, &fw->pq, NULL);
            if (detect_thread != NULL) {
                FLOWWORKER_PROFILING_START(x, PROFILE_FLOWWORKER_DETECT);
				
			//detect操作太过复杂，至今没有理出头绪，先放在这里，后续再补全;
                Detect(tv, x, detect_thread, NULL, NULL);
                FLOWWORKER_PROFILING_END(x, PROFILE_FLOWWORKER_DETECT);
            }

            //  Outputs
            OutputLoggerLog(tv, x, fw->output_thread);

            /* put these packets in the preq queue so that they are
             * by the other thread modules before packet 'p'. */
            PacketEnqueue(preq, x);
        }

    /* handle the app layer part of the UDP packet payload */
    } else if (p->flow && p->proto == IPPROTO_UDP) {
        FLOWWORKER_PROFILING_START(p, PROFILE_FLOWWORKER_APPLAYERUDP);
        AppLayerHandleUdp(tv, fw->stream_thread->ra_ctx->app_tctx, p, p->flow);

		//同上，暂不分析，留待以后补全;
        FLOWWORKER_PROFILING_END(p, PROFILE_FLOWWORKER_APPLAYERUDP);
    }

    /* handle Detect */
    DEBUG_ASSERT_FLOW_LOCKED(p->flow);
    SCLogDebug("packet %"PRIu64" calling Detect", p->pcap_cnt);

    if (detect_thread != NULL) {
        FLOWWORKER_PROFILING_START(p, PROFILE_FLOWWORKER_DETECT);
        Detect(tv, p, detect_thread, NULL, NULL);
        FLOWWORKER_PROFILING_END(p, PROFILE_FLOWWORKER_DETECT);
    }

    // Outputs.
    OutputLoggerLog(tv, p, fw->output_thread);

    /*  Release tcp segments. Done here after alerting can use them. */
    if (p->flow != NULL && p->proto == IPPROTO_TCP) {
        StreamTcpPruneSession(p->flow, p->flowflags & FLOW_PKT_TOSERVER ?
                STREAM_TOSERVER : STREAM_TOCLIENT);
    }

    if (p->flow) {
        DEBUG_ASSERT_FLOW_LOCKED(p->flow);

		//解锁对应的流;
        FLOWLOCK_UNLOCK(p->flow);
    }

    return TM_ECODE_OK;
}

void FlowWorkerReplaceDetectCtx(void *flow_worker, void *detect_ctx)
{
    FlowWorkerThreadData *fw = flow_worker;

    SC_ATOMIC_SET(fw->detect_thread, detect_ctx);
}

void *FlowWorkerGetDetectCtxPtr(void *flow_worker)
{
    FlowWorkerThreadData *fw = flow_worker;

    return SC_ATOMIC_GET(fw->detect_thread);
}

const char *ProfileFlowWorkerIdToString(enum ProfileFlowWorkerId fwi)
{
    switch (fwi) {
        case PROFILE_FLOWWORKER_FLOW:
            return "flow";
        case PROFILE_FLOWWORKER_STREAM:
            return "stream";
        case PROFILE_FLOWWORKER_APPLAYERUDP:
            return "app-layer";
        case PROFILE_FLOWWORKER_DETECT:
            return "detect";
        case PROFILE_FLOWWORKER_SIZE:
            return "size";
    }
    return "error";
}

static void FlowWorkerExitPrintStats(ThreadVars *tv, void *data)
{
    FlowWorkerThreadData *fw = data;
    OutputLoggerExitPrintStats(tv, fw->output_thread);
}

void TmModuleFlowWorkerRegister (void)
{
    tmm_modules[TMM_FLOWWORKER].name = "FlowWorker";
    tmm_modules[TMM_FLOWWORKER].ThreadInit = FlowWorkerThreadInit;
    tmm_modules[TMM_FLOWWORKER].Func = FlowWorker;
    tmm_modules[TMM_FLOWWORKER].ThreadDeinit = FlowWorkerThreadDeinit;
    tmm_modules[TMM_FLOWWORKER].ThreadExitPrintStats = FlowWorkerExitPrintStats;
    tmm_modules[TMM_FLOWWORKER].cap_flags = 0;
    tmm_modules[TMM_FLOWWORKER].flags = TM_FLAG_STREAM_TM|TM_FLAG_DETECT_TM;
}
