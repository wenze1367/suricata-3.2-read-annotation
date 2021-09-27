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
 * Live pcap packet acquisition support
 */

#include "suricata-common.h"
#include "suricata.h"
#include "decode.h"
#include "packet-queue.h"
#include "threads.h"
#include "threadvars.h"
#include "tm-queuehandlers.h"
#include "tm-threads.h"
#include "source-pcap.h"
#include "conf.h"
#include "util-debug.h"
#include "util-error.h"
#include "util-privs.h"
#include "util-device.h"
#include "util-optimize.h"
#include "util-checksum.h"
#include "util-ioctl.h"
#include "tmqh-packetpool.h"

#ifdef __SC_CUDA_SUPPORT__

#include "util-cuda.h"
#include "util-cuda-buffer.h"
#include "util-mpm-ac.h"
#include "util-cuda-handlers.h"
#include "detect-engine.h"
#include "detect-engine-mpm.h"
#include "util-cuda-vars.h"

#endif /* __SC_CUDA_SUPPORT__ */

#define PCAP_STATE_DOWN 0
#define PCAP_STATE_UP 1

#define PCAP_RECONNECT_TIMEOUT 500000

/**
 * \brief Structure to hold thread specific variables.
 */
typedef struct PcapThreadVars_
{
    /* thread specific handle */
    pcap_t *pcap_handle;
    /* handle state */
    unsigned char pcap_state;
    /* thread specific bpf */
    struct bpf_program filter;
    /* ptr to string from config */
    char *bpf_filter;

    time_t last_stats_dump;

    /* data link type for the thread */
    int datalink;

    /* counters */
    uint32_t pkts;
    uint64_t bytes;
    uint32_t errs;

    uint16_t capture_kernel_packets;
    uint16_t capture_kernel_drops;
    uint16_t capture_kernel_ifdrops;

    ThreadVars *tv;
    TmSlot *slot;

    /** callback result -- set if one of the thread module failed. */
    int cb_result;

    /* pcap buffer size */
    int pcap_buffer_size;
    int pcap_snaplen;

    ChecksumValidationMode checksum_mode;

#if LIBPCAP_VERSION_MAJOR == 0
    char iface[PCAP_IFACE_NAME_LENGTH];
#endif
    LiveDevice *livedev;
} PcapThreadVars;

TmEcode ReceivePcapThreadInit(ThreadVars *, void *, void **);
void ReceivePcapThreadExitStats(ThreadVars *, void *);
TmEcode ReceivePcapThreadDeinit(ThreadVars *, void *);
TmEcode ReceivePcapLoop(ThreadVars *tv, void *data, void *slot);

TmEcode DecodePcapThreadInit(ThreadVars *, void *, void **);
TmEcode DecodePcapThreadDeinit(ThreadVars *tv, void *data);
TmEcode DecodePcap(ThreadVars *, Packet *, void *, PacketQueue *, PacketQueue *);

/** protect pcap_compile and pcap_setfilter, as they are not thread safe:
 *  http://seclists.org/tcpdump/2009/q1/62 */
static SCMutex pcap_bpf_compile_lock = SCMUTEX_INITIALIZER;

/**
 * \brief Registration Function for RecievePcap.
 * \todo Unit tests are needed for this module.
 Suricata支持多种数据包源：pcap（实时/文件）、nfq、ipfw、mpipe、af-packet、pfring、dag（实时/文件）、napatech。 
每种数据包源的支持都对应于一个线程模块（Thread Module），得益于这种其模块化的架构，增加一个新的数据源支持只需要添加一个新的线程模块即可。 
这里，我将主要记录最常见的pcap实时数据源的实现细节，包括相关数据结构、运行流程，以及与主框架和其他模块的交互等。 
模块注册 
TmModuleReceivePcapRegister函数用于实现pcap实时数据源的线程模块的注册，该函数在系统初始化阶段由RegisterAllModules函数所调用。函数内部唯一的工作就是填充TmModule类型的结构体变量：tmm_modules[TMM_RECEIVEPCAP]。下面是各字段的填充内容：
 name	 “ReceivePcap”	 线程名字：目前没有看到代码中有对这个变量的使用。
 ThreadInit  ReceivePcapThreadInit	 初始化函数：在_TmSlotSetFuncAppend中被传递给其所嵌入的slot的SlotThreadInit函数，而该函数将在线程执行函数（如TmThreadsSlotVar）中被调用。
 Func	 NULL	 模块执行函数：对于数据源模块，其执行函数为下面的PktAcqLoop。
 PktAcqLoop  ReceivePcapLoop 数据包获取函数：在TmThreadsSlotPktAcqLoop中被调用。
 ThreadExitPrintStats	 ReceivePcapThreadExitStats  退出打印函数：用于打印模块统计信息，同样被赋给slot对应函数，然后在线程执行函数的退出阶段被调用。
 ThreadDeinit	 NULL	 清理函数：这里设成NULL可能是个BUG，因为存在一个正好用于这个目的却没有被引用过的函数：ReceivePcapThreadDeinit，其中调用pcap_close进行了清理。
 RegisterTests	 NULL	 注册测试函数：用来注册模块内部所编写的单元测试，在单元测试模式下，运行所有测试前将调用TmModuleRegisterTests函数先注册所有线程模块的单元测试函数。
 cap_flags	 SC_CAP_NET_RAW  能力标志（capability flags）：标志这个线程模块所需要的能力，以确定能让整个系统正常运行所需要的最小权限。SC_CAP_NET_RAW应该是表示需要获取原始数据包的能力。
 flags	 TM_FLAG_RECEIVE_TM  其他标志：TM_FLAG_RECEIVE_TM表示这个模块的用途是收包（其他还有解码、检测等）。
 */
void TmModuleReceivePcapRegister (void)
{
    tmm_modules[TMM_RECEIVEPCAP].name = "ReceivePcap";
    tmm_modules[TMM_RECEIVEPCAP].ThreadInit = ReceivePcapThreadInit;
    tmm_modules[TMM_RECEIVEPCAP].Func = NULL;
    tmm_modules[TMM_RECEIVEPCAP].PktAcqLoop = ReceivePcapLoop;
    tmm_modules[TMM_RECEIVEPCAP].PktAcqBreakLoop = NULL;
    tmm_modules[TMM_RECEIVEPCAP].ThreadExitPrintStats = ReceivePcapThreadExitStats;
    tmm_modules[TMM_RECEIVEPCAP].ThreadDeinit = NULL;
    tmm_modules[TMM_RECEIVEPCAP].RegisterTests = NULL;
    tmm_modules[TMM_RECEIVEPCAP].cap_flags = SC_CAP_NET_RAW;
    tmm_modules[TMM_RECEIVEPCAP].flags = TM_FLAG_RECEIVE_TM;
}

/**
 * \brief Registration Function for DecodePcap.
 * \todo Unit tests are needed for this module.
 */
void TmModuleDecodePcapRegister (void)
{
    tmm_modules[TMM_DECODEPCAP].name = "DecodePcap";
    tmm_modules[TMM_DECODEPCAP].ThreadInit = DecodePcapThreadInit;
    tmm_modules[TMM_DECODEPCAP].Func = DecodePcap;
    tmm_modules[TMM_DECODEPCAP].ThreadExitPrintStats = NULL;
    tmm_modules[TMM_DECODEPCAP].ThreadDeinit = DecodePcapThreadDeinit;
    tmm_modules[TMM_DECODEPCAP].RegisterTests = NULL;
    tmm_modules[TMM_DECODEPCAP].cap_flags = 0;
    tmm_modules[TMM_DECODEPCAP].flags = TM_FLAG_DECODE_TM;
}

static inline void PcapDumpCounters(PcapThreadVars *ptv)
{
    struct pcap_stat pcap_s;
    if (likely((pcap_stats(ptv->pcap_handle, &pcap_s) >= 0))) {
        StatsSetUI64(ptv->tv, ptv->capture_kernel_packets, pcap_s.ps_recv);
        StatsSetUI64(ptv->tv, ptv->capture_kernel_drops, pcap_s.ps_drop);
        (void) SC_ATOMIC_SET(ptv->livedev->drop, pcap_s.ps_drop);
        StatsSetUI64(ptv->tv, ptv->capture_kernel_ifdrops, pcap_s.ps_ifdrop);
    }
}


#if LIBPCAP_VERSION_MAJOR == 1
static int PcapTryReopen(PcapThreadVars *ptv)
{
    int pcap_activate_r;

    ptv->pcap_state = PCAP_STATE_DOWN;
    pcap_activate_r = pcap_activate(ptv->pcap_handle);
    if (pcap_activate_r != 0) {
        return pcap_activate_r;
    }
    /* set bpf filter if we have one */
    if (ptv->bpf_filter != NULL) {
        if(pcap_compile(ptv->pcap_handle,&ptv->filter,ptv->bpf_filter,1,0) < 0) {
            SCLogError(SC_ERR_BPF,"bpf compilation error %s",pcap_geterr(ptv->pcap_handle));
            return -1;
        }

        if(pcap_setfilter(ptv->pcap_handle,&ptv->filter) < 0) {
            SCLogError(SC_ERR_BPF,"could not set bpf filter %s",pcap_geterr(ptv->pcap_handle));
            return -1;
        }
    }

    SCLogInfo("Recovering interface listening");
    ptv->pcap_state = PCAP_STATE_UP;
    return 0;
}
#else /* implied LIBPCAP_VERSION_MAJOR == 0 */
static int PcapTryReopen(PcapThreadVars *ptv)
{
    char errbuf[PCAP_ERRBUF_SIZE] = "";

    ptv->pcap_state = PCAP_STATE_DOWN;
    pcap_close(ptv->pcap_handle);

    ptv->pcap_handle = pcap_open_live((char *)ptv->iface, ptv->pcap_snaplen,
            LIBPCAP_PROMISC, LIBPCAP_COPYWAIT, errbuf);
    if (ptv->pcap_handle == NULL) {
        SCLogError(SC_ERR_PCAP_OPEN_LIVE, "Problem creating pcap handler for live mode, error %s", errbuf);
        return -1;
    }

    /* set bpf filter if we have one */
    if (ptv->bpf_filter != NULL) {
        SCLogInfo("using bpf-filter \"%s\"", ptv->bpf_filter);

        if(pcap_compile(ptv->pcap_handle,&ptv->filter,ptv->bpf_filter,1,0) < 0) {
            SCLogError(SC_ERR_BPF,"bpf compilation error %s",pcap_geterr(ptv->pcap_handle));
            return -1;
        }

        if(pcap_setfilter(ptv->pcap_handle,&ptv->filter) < 0) {
            SCLogError(SC_ERR_BPF,"could not set bpf filter %s",pcap_geterr(ptv->pcap_handle));
            return -1;
        }
    }

    SCLogInfo("Recovering interface listening");
    ptv->pcap_state = PCAP_STATE_UP;
    return 0;
}

#endif

/*
数据包封装
在Suricata中，用来封装数据包的结构体为Packet，核心字段如下：

字段	                        含义
src/dst、sp/dp、proto	    五元组信息：源/目的地址，源/目的端口号，传输层协议（TCP/UDP/…）。
flow	                数据包所属的流指针（类型为Flow_ *）。
ip4h、ip6h	            网络层数据指针。
tcph、udph、sctph、icmpv4/6h   	传输层数据指针。
payload、payload_len	        应用层负载指针及长度。
next、prev	               前一个/后一个数据包指针，用于组成双向链表。
PcapCallbackLoop函数中第一步就是完成对数据包的封装。其函数原型如下：

*其中，user为用户数据，即之前传入的PcapThreadVars，h为pcap包结构体头，pkt为包数据指针。函数流程如下：

调用PacketGetFromQueueOrAlloc获取一个Packet结构。该函数会首先尝试调用PacketPoolGetPacket从packet pool中直接获取，如果失败（已经用完了），那么就调用PacketGetFromAlloc新分配一个。
注：与pool中取出的数据包最终可以回收不同，这种使用malloc动态分配的数据包最后需要free，因此为了区分会在其flags中打上标记PKT_ALLOC。

填充Packet结构体的部分字段：数据包源（PKT_SRC_WIRE）、时间戳、所属数据链路/设备。
调用PacketCopyData复制数据包内容到pkt字段中，并设置pktlen为相应的长度。
注：为什么需要做复制这种开销大的操作呢？man pcap_dispatch给出了答案：The struct pcap_pkthdr… are not guaranteed to be valid after the callback routine returns; if the code needs them to be valid after the callback, it must make a copy of them. 而由于Suricata的多线程和异步特性，
数据包在callback中会送入outq中等待后续线程继续处理，因此这里必须进行复制。
1.校验和相关的处理。若checksum_mode为DISABLE，将会给包的flags打上PKT_IGNORE_CHECKSUM标志，
表示后续不再对其进行校验和验证。若checksum_mode为AUTO，则调用ChecksumAutoModeCheck进行统计分析，
满足条件则后续该设备的数据包都会关闭校验和验证。目前是的关闭条件是：
1000个包中若有超过10%的包校验和不正确，则认为网卡开启了checksum offloading，因而关闭检验和验证。
2.调用TmThreadsSlotProcessPkt让本线程中包含的其他slot中的模块对数据包进行后续处理。
若处理返回失败，则调用pcap_breakloop中断抓包。
3.调用PcapDumpCounters打印抓包统计信息。这个打印保证每秒只触发一次，机制是：获取当前时间，
只有当前秒数与上一次记录的秒数不同时才调用。
*
*/
void PcapCallbackLoop(char *user, struct pcap_pkthdr *h, u_char *pkt)
{
    SCEnter();

    PcapThreadVars *ptv = (PcapThreadVars *)user;
    Packet *p = PacketGetFromQueueOrAlloc();
    struct timeval current_time;

    if (unlikely(p == NULL)) {
        SCReturn;
    }

    PKT_SET_SRC(p, PKT_SRC_WIRE);
    p->ts.tv_sec = h->ts.tv_sec;
    p->ts.tv_usec = h->ts.tv_usec;
    SCLogDebug("p->ts.tv_sec %"PRIuMAX"", (uintmax_t)p->ts.tv_sec);
    p->datalink = ptv->datalink;

    ptv->pkts++;
    ptv->bytes += h->caplen;
    (void) SC_ATOMIC_ADD(ptv->livedev->pkts, 1);
    p->livedev = ptv->livedev;

    if (unlikely(PacketCopyData(p, pkt, h->caplen))) {
        TmqhOutputPacketpool(ptv->tv, p);
        SCReturn;
    }

    switch (ptv->checksum_mode) {
        case CHECKSUM_VALIDATION_AUTO:
            if (ptv->livedev->ignore_checksum) {
                p->flags |= PKT_IGNORE_CHECKSUM;
            } else if (ChecksumAutoModeCheck(ptv->pkts,
                        SC_ATOMIC_GET(ptv->livedev->pkts),
                        SC_ATOMIC_GET(ptv->livedev->invalid_checksums))) {
                ptv->livedev->ignore_checksum = 1;
                p->flags |= PKT_IGNORE_CHECKSUM;
            }
            break;
        case CHECKSUM_VALIDATION_DISABLE:
            p->flags |= PKT_IGNORE_CHECKSUM;
            break;
        default:
            break;
    }

    if (TmThreadsSlotProcessPkt(ptv->tv, ptv->slot, p) != TM_ECODE_OK) {
        pcap_breakloop(ptv->pcap_handle);
        ptv->cb_result = TM_ECODE_FAILED;
    }

    /* Trigger one dump of stats every second */
    TimeGet(&current_time);
    if (current_time.tv_sec != ptv->last_stats_dump) {
        PcapDumpCounters(ptv);
        ptv->last_stats_dump = current_time.tv_sec;
    }

    SCReturn;
}

/**
 *  \brief Main PCAP reading Loop function.
 数据包获取
初始化完成后，TmThreadsSlotPktAcqLoop函数将进入一个while循环，调用slot的PktAcqLoop函数获取并处理数据包。对应的模块函数原型为：

        TmEcode ReceivePcapLoop(ThreadVars *tv, void *data, void *slot)

其中，data即为初始化阶段生成的PcapThreadVars结构体，而slot就是包含该模块的那个slot，传入进来的目的主要是获取线程中后续的slot（这里对应DecodePcap），以调用后续的数据包处理流程。

函数内部的核心是一个while(1)循环，流程如下：

检查suricata_ctl_flags是否包含STOP或KILL标志，即Suricata是否需要退出，若是的话则立即返回。
这里让子线程去检查全局控制标志的处理方式感觉的不是很优雅，最好是只检查自己的线程标志。
等待packet pool中有空闲数据包结构（通过cond或sleep实现）。
调用pcap_dispatch获取并处理数据包。其中，第2个参数表示最多处理的数据包个数，
传入的值packet_q_len为packet pool的当前大小；第3个参数为包处理回调函数PcapCallbackLoop；
最后一个参数为传给前面的回调函数的用户数据，这里传入的是PcapThreadVars结构体。
检查返回值，若出错则调用pcap_geterr获取错误信息，然后尝试不断调用PcapTryReopen重新开启抓包。
此后，pcap库内部会对每一个原始数据包，都调用PcapCallbackLoop函数进行进一步处理。
 */
TmEcode ReceivePcapLoop(ThreadVars *tv, void *data, void *slot)
{
    SCEnter();

    int packet_q_len = 64;
    PcapThreadVars *ptv = (PcapThreadVars *)data;
    int r;
    TmSlot *s = (TmSlot *)slot;

    ptv->slot = s->slot_next;
    ptv->cb_result = TM_ECODE_OK;

    while (1) {
        if (suricata_ctl_flags & SURICATA_STOP) {
            SCReturnInt(TM_ECODE_OK);
        }

        /* make sure we have at least one packet in the packet pool, to prevent
         * us from alloc'ing packets at line rate */
        PacketPoolWait();

        /* Right now we just support reading packets one at a time. */
        r = pcap_dispatch(ptv->pcap_handle, packet_q_len,
                          (pcap_handler)PcapCallbackLoop, (u_char *)ptv);
        if (unlikely(r < 0)) {
            int dbreak = 0;
            SCLogError(SC_ERR_PCAP_DISPATCH, "error code %" PRId32 " %s",
                       r, pcap_geterr(ptv->pcap_handle));
#ifdef PCAP_ERROR_BREAK
            if (r == PCAP_ERROR_BREAK) {
                SCReturnInt(ptv->cb_result);
            }
#endif
            do {
                usleep(PCAP_RECONNECT_TIMEOUT);
                if (suricata_ctl_flags != 0) {
                    dbreak = 1;
                    break;
                }
                r = PcapTryReopen(ptv);
            } while (r < 0);
            if (dbreak) {
                break;
            }
        } else if (ptv->cb_result == TM_ECODE_FAILED) {
            SCLogError(SC_ERR_PCAP_DISPATCH, "Pcap callback PcapCallbackLoop failed");
            SCReturnInt(TM_ECODE_FAILED);
        } else if (unlikely(r == 0)) {
            TmThreadsCaptureInjectPacket(tv, ptv->slot, NULL);
        }

        StatsSyncCountersIfSignalled(tv);
    }

    PcapDumpCounters(ptv);
    StatsSyncCountersIfSignalled(tv);
    SCReturnInt(TM_ECODE_OK);
}

/**
 * \brief Init function for ReceivePcap.
 *
 * This is a setup function for recieving packets
 * via libpcap. There are two versions of this function
 * depending on the major version of libpcap used.
 * For versions prior to 1.x we use open_pcap_live,
 * for versions 1.x and greater we use pcap_create + pcap_activate.
 *
 * \param tv pointer to ThreadVars
 * \param initdata pointer to the interface passed from the user
 * \param data pointer gets populated with PcapThreadVars
 *
 * \todo Create a general pcap setup function.
 其中，tv参数对应该模块所嵌入的线程的ThreadVars，在使用某些与线程相关的函数时需要使用。
 
 initdata   参数是模块的初始化数据，在使用TmSlotSetFuncAppend向线程中嵌入模块时传入。对于这个模块，其初始数据是一个PcapIfaceConfig类型的结构体指针，而这个结构体是由运行模式（对应于这个模块的运行模式类型为RUNMODE_PCAP_DEV）初始化函数（例如如RunModeIdsPcapAutoFp）中的ParsePcapConfig通过查询配置节点树下的pcap节点信息所填充的。具体的一些重要配置信息包括：
 
 字段                含义
 iface	       设备接口名字，如linux下的"eth0"。
 threads       抓包线程数量，默认为1。
 buffer_size   接收缓冲大小，通过pcap_set_buffer_size设置。
 snaplen       抓取长度，通过pcap_set_snaplen设置。
 promisc       是否开启混杂模式，通过pcap_set_promisc设置。注意：如果要打开混杂模式，那么网卡必须也要打开（ifconfig eth0 promisc）。
 bpf_filter    BPF过滤器表达式，通过pcap_compile编译成bpf_program后再通过pcap_setfilter设置。
 checksum_mode	 校验和验证模式，设置为auto表示使用统计方式确定当前是否有checksum off-loading，若有，则关闭后续的校验和验证。
 ref, DerefFunc  实现对配置结构体的引用计数。ref初始为当前使用该接口的线程（threads），因为这些线程都会在ReceivePcapThreadInit中引用这个配置结构。当用完配置结构体后（或出错需要退出时），就调用DerefFunc（PcapDerefConfig）减少引用计数，并在引用计数值为0时调用SCFree回收内存。
 最后一个data参数，是该初始化函数的结果输出。函数内部会新建一个PcapThreadVars结构体，作为本模块的内部上下文，其中部分字段是直接copy的PcapIfaceConfig，另一些重要字段包括：
 
 字段                含义
 livedev       当前设备结构体（LiveDevice类型），记录设备统计信息（收包、丢包、校验和验证失败的包），通过iface调用LiveGetDevice查找得到。
 pcap_handle   pcap句柄，通过pcap_open_live获得，后续使用pcap库函数时都会用到。
 pcap_state    pcap状态，UP或DOWN，在使用PcapTryReopen重新打开pcap时用到。
 在初始化函数返回时，填充好的PcapThreadVars结构体便传递给了包含该模块的slot的slot_data字段，该字段将做为参数传入后续的模块函数。

 
 */
#if LIBPCAP_VERSION_MAJOR == 1
TmEcode ReceivePcapThreadInit(ThreadVars *tv, void *initdata, void **data)
{
    SCEnter();
    PcapIfaceConfig *pcapconfig = initdata;

    if (initdata == NULL) {
        SCLogError(SC_ERR_INVALID_ARGUMENT, "initdata == NULL");
        SCReturnInt(TM_ECODE_FAILED);
    }

    PcapThreadVars *ptv = SCMalloc(sizeof(PcapThreadVars));
    if (unlikely(ptv == NULL)) {
        pcapconfig->DerefFunc(pcapconfig);
        SCReturnInt(TM_ECODE_FAILED);
    }
    memset(ptv, 0, sizeof(PcapThreadVars));

    ptv->tv = tv;

    ptv->livedev = LiveGetDevice(pcapconfig->iface);
    if (ptv->livedev == NULL) {
        SCLogError(SC_ERR_INVALID_VALUE, "Unable to find Live device");
        SCFree(ptv);
        SCReturnInt(TM_ECODE_FAILED);
    }

    SCLogInfo("using interface %s", (char *)pcapconfig->iface);

    if (LiveGetOffload() == 0) {
        (void)GetIfaceOffloading((char *)pcapconfig->iface, 1, 1);
    } else {
        DisableIfaceOffloading(ptv->livedev, 1, 1);
    }

    ptv->checksum_mode = pcapconfig->checksum_mode;
    if (ptv->checksum_mode == CHECKSUM_VALIDATION_AUTO) {
        SCLogInfo("Running in 'auto' checksum mode. Detection of interface state will require "
                  xstr(CHECKSUM_SAMPLE_COUNT) " packets.");
    }

    /* XXX create a general pcap setup function */
    char errbuf[PCAP_ERRBUF_SIZE];
    ptv->pcap_handle = pcap_create((char *)pcapconfig->iface, errbuf);
    if (ptv->pcap_handle == NULL) {
        if (strlen(errbuf)) {
            SCLogError(SC_ERR_PCAP_CREATE, "Couldn't create a new pcap handler for %s, error %s",
                    (char *)pcapconfig->iface, errbuf);
        } else {
            SCLogError(SC_ERR_PCAP_CREATE, "Couldn't create a new pcap handler for %s",
                    (char *)pcapconfig->iface);
        }
        SCFree(ptv);
        pcapconfig->DerefFunc(pcapconfig);
        SCReturnInt(TM_ECODE_FAILED);
    }

    if (pcapconfig->snaplen == 0) {
        /* We set snaplen if we can get the MTU */
        ptv->pcap_snaplen = GetIfaceMaxPacketSize(pcapconfig->iface);
    } else {
        ptv->pcap_snaplen = pcapconfig->snaplen;
    }
    if (ptv->pcap_snaplen > 0) {
        /* set Snaplen. Must be called before pcap_activate */
        int pcap_set_snaplen_r = pcap_set_snaplen(ptv->pcap_handle, ptv->pcap_snaplen);
        if (pcap_set_snaplen_r != 0) {
            SCLogError(SC_ERR_PCAP_SET_SNAPLEN, "Couldn't set snaplen, error: %s", pcap_geterr(ptv->pcap_handle));
            SCFree(ptv);
            pcapconfig->DerefFunc(pcapconfig);
            SCReturnInt(TM_ECODE_FAILED);
        }
        SCLogInfo("Set snaplen to %d for '%s'", ptv->pcap_snaplen,
                  pcapconfig->iface);
    }

    /* set Promisc, and Timeout. Must be called before pcap_activate */
    int pcap_set_promisc_r = pcap_set_promisc(ptv->pcap_handle, pcapconfig->promisc);
    //printf("ReceivePcapThreadInit: pcap_set_promisc(%p) returned %" PRId32 "\n", ptv->pcap_handle, pcap_set_promisc_r);
    if (pcap_set_promisc_r != 0) {
        SCLogError(SC_ERR_PCAP_SET_PROMISC, "Couldn't set promisc mode, error %s", pcap_geterr(ptv->pcap_handle));
        SCFree(ptv);
        pcapconfig->DerefFunc(pcapconfig);
        SCReturnInt(TM_ECODE_FAILED);
    }

    int pcap_set_timeout_r = pcap_set_timeout(ptv->pcap_handle,LIBPCAP_COPYWAIT);
    //printf("ReceivePcapThreadInit: pcap_set_timeout(%p) returned %" PRId32 "\n", ptv->pcap_handle, pcap_set_timeout_r);
    if (pcap_set_timeout_r != 0) {
        SCLogError(SC_ERR_PCAP_SET_TIMEOUT, "Problems setting timeout, error %s", pcap_geterr(ptv->pcap_handle));
        SCFree(ptv);
        pcapconfig->DerefFunc(pcapconfig);
        SCReturnInt(TM_ECODE_FAILED);
    }
#ifdef HAVE_PCAP_SET_BUFF
    ptv->pcap_buffer_size = pcapconfig->buffer_size;
    if (ptv->pcap_buffer_size >= 0 && ptv->pcap_buffer_size <= INT_MAX) {
        if (ptv->pcap_buffer_size > 0)
            SCLogInfo("Going to use pcap buffer size of %" PRId32 "", ptv->pcap_buffer_size);

        int pcap_set_buffer_size_r = pcap_set_buffer_size(ptv->pcap_handle,ptv->pcap_buffer_size);
        //printf("ReceivePcapThreadInit: pcap_set_timeout(%p) returned %" PRId32 "\n", ptv->pcap_handle, pcap_set_buffer_size_r);
        if (pcap_set_buffer_size_r != 0) {
            SCLogError(SC_ERR_PCAP_SET_BUFF_SIZE, "Problems setting pcap buffer size, error %s", pcap_geterr(ptv->pcap_handle));
            SCFree(ptv);
            pcapconfig->DerefFunc(pcapconfig);
            SCReturnInt(TM_ECODE_FAILED);
        }
    }
#endif /* HAVE_PCAP_SET_BUFF */

    /* activate the handle */
    int pcap_activate_r = pcap_activate(ptv->pcap_handle);
    //printf("ReceivePcapThreadInit: pcap_activate(%p) returned %" PRId32 "\n", ptv->pcap_handle, pcap_activate_r);
    if (pcap_activate_r != 0) {
        SCLogError(SC_ERR_PCAP_ACTIVATE_HANDLE, "Couldn't activate the pcap handler, error %s", pcap_geterr(ptv->pcap_handle));
        SCFree(ptv);
        pcapconfig->DerefFunc(pcapconfig);
        SCReturnInt(TM_ECODE_FAILED);
    } else {
        ptv->pcap_state = PCAP_STATE_UP;
    }

    /* set bpf filter if we have one */
    if (pcapconfig->bpf_filter) {
        SCMutexLock(&pcap_bpf_compile_lock);

        ptv->bpf_filter = pcapconfig->bpf_filter;

        if (pcap_compile(ptv->pcap_handle,&ptv->filter,ptv->bpf_filter,1,0) < 0) {
            SCLogError(SC_ERR_BPF, "bpf compilation error %s", pcap_geterr(ptv->pcap_handle));

            SCMutexUnlock(&pcap_bpf_compile_lock);
            SCFree(ptv);
            pcapconfig->DerefFunc(pcapconfig);
            return TM_ECODE_FAILED;
        }

        if (pcap_setfilter(ptv->pcap_handle,&ptv->filter) < 0) {
            SCLogError(SC_ERR_BPF, "could not set bpf filter %s", pcap_geterr(ptv->pcap_handle));

            SCMutexUnlock(&pcap_bpf_compile_lock);
            SCFree(ptv);
            pcapconfig->DerefFunc(pcapconfig);
            return TM_ECODE_FAILED;
        }

        SCMutexUnlock(&pcap_bpf_compile_lock);
    }

    /* no offloading supported at all */
    (void)GetIfaceOffloading(pcapconfig->iface, 1, 1);

    ptv->datalink = pcap_datalink(ptv->pcap_handle);

    pcapconfig->DerefFunc(pcapconfig);

    ptv->capture_kernel_packets = StatsRegisterCounter("capture.kernel_packets",
            ptv->tv);
    ptv->capture_kernel_drops = StatsRegisterCounter("capture.kernel_drops",
            ptv->tv);
    ptv->capture_kernel_ifdrops = StatsRegisterCounter("capture.kernel_ifdrops",
            ptv->tv);

    *data = (void *)ptv;
    SCReturnInt(TM_ECODE_OK);
}
#else 
/* implied LIBPCAP_VERSION_MAJOR == 0 
模块初始化 
如上表所示，模块初始化由ReceivePcapThreadInit函数完成，其函数原型为： 

TmEcode ReceivePcapThreadInit(ThreadVars *tv, void *initdata, void **data) 

其中，tv参数对应该模块所嵌入的线程的ThreadVars，在使用某些与线程相关的函数时需要使用。 
initdata参数是模块的初始化数据，在使用TmSlotSetFuncAppend向线程中嵌入模块时传入。对于这个模块，其初始数据是一个PcapIfaceConfig类型的结构体指针，而这个结构体是由运行模式（对应于这个模块的运行模式类型为RUNMODE_PCAP_DEV）初始化函数（例如如RunModeIdsPcapAutoFp）中的ParsePcapConfig通过查询配置节点树下的pcap节点信息所填充的。具体的一些重要配置信息包括：
threads	抓包线程数量，默认为1。
buffer_size	接收缓冲大小，通过pcap_set_buffer_size设置。
snaplen	抓取长度，通过pcap_set_snaplen设置。
promisc	是否开启混杂模式，通过pcap_set_promisc设置。注意：如果要打开混杂模式，那么网卡必须也要打开（ifconfig eth0 promisc）。
bpf_filter	BPF过滤器表达式，通过pcap_compile编译成bpf_program后再通过pcap_setfilter设置。
checksum_mode	校验和验证模式，设置为auto表示使用统计方式确定当前是否有checksum off-loading，若有，则关闭后续的校验和验证。
ref, DerefFunc	实现对配置结构体的引用计数。ref初始为当前使用该接口的线程（threads），因为这些线程都会在ReceivePcapThreadInit中引用这个配置结构。当用完配置结构体后（或出错需要退出时），就调用DerefFunc（PcapDerefConfig）减少引用计数，并在引用计数值为0时调用SCFree回收内存。

最后一个data参数，是该初始化函数的结果输出。函数内部会新建一个PcapThreadVars结构体，作为本模块的内部上下文，其中部分字段是直接copy的PcapIfaceConfig，另一些重要字段包括：
livedev	当前设备结构体（LiveDevice类型），记录设备统计信息（收包、丢包、校验和验证失败的包），通过iface调用LiveGetDevice查找得到。
pcap_handle	pcap句柄，通过pcap_open_live获得，后续使用pcap库函数时都会用到。
pcap_state	pcap状态，UP或DOWN，在使用PcapTryReopen重新打开pcap时用到。
在初始化函数返回时，填充好的PcapThreadVars结构体便传递给了包含该模块的slot的slot_data字段，该字段将做为参数传入后续的模块函数。

*/
TmEcode ReceivePcapThreadInit(ThreadVars *tv, void *initdata, void **data)
{
    SCEnter();
    PcapIfaceConfig *pcapconfig = initdata;

    if (initdata == NULL) {
        SCLogError(SC_ERR_INVALID_ARGUMENT, "initdata == NULL");
        SCReturnInt(TM_ECODE_FAILED);
    }

    PcapThreadVars *ptv = SCMalloc(sizeof(PcapThreadVars));
    if (unlikely(ptv == NULL)) {
        pcapconfig->DerefFunc(pcapconfig);
        SCReturnInt(TM_ECODE_FAILED);
    }
    memset(ptv, 0, sizeof(PcapThreadVars));

    ptv->tv = tv;

    ptv->livedev = LiveGetDevice(pcapconfig->iface);
    if (ptv->livedev == NULL) {
        SCLogError(SC_ERR_INVALID_VALUE, "Unable to find Live device");
        SCFree(ptv);
        SCReturnInt(TM_ECODE_FAILED);
    }

    SCLogInfo("using interface %s", pcapconfig->iface);
    if (strlen(pcapconfig->iface) > PCAP_IFACE_NAME_LENGTH) {
        SCFree(ptv);
        /* Dereference config */
        pcapconfig->DerefFunc(pcapconfig);
        SCReturnInt(TM_ECODE_FAILED);
    }
    strlcpy(ptv->iface, pcapconfig->iface, PCAP_IFACE_NAME_LENGTH);

    if (pcapconfig->snaplen == 0) {
        /* We try to set snaplen from MTU value */
        ptv->pcap_snaplen = GetIfaceMaxPacketSize(pcapconfig->iface);
        /* be conservative with old pcap lib to mimic old tcpdump behavior
           when MTU was not available. */
        if (ptv->pcap_snaplen <= 0)
            ptv->pcap_snaplen = LIBPCAP_SNAPLEN;
    } else {
        ptv->pcap_snaplen = pcapconfig->snaplen;
    }

    char errbuf[PCAP_ERRBUF_SIZE] = "";
    ptv->pcap_handle = pcap_open_live(ptv->iface, ptv->pcap_snaplen,
                                        LIBPCAP_PROMISC, LIBPCAP_COPYWAIT, errbuf);
    if (ptv->pcap_handle == NULL) {
        SCLogError(SC_ERR_PCAP_OPEN_LIVE, "Problem creating pcap handler for live mode, error %s", errbuf);
        SCFree(ptv);
        /* Dereference config */
        pcapconfig->DerefFunc(pcapconfig);
        SCReturnInt(TM_ECODE_FAILED);
    }

    /* set bpf filter if we have one */
    if (pcapconfig->bpf_filter) {
        SCMutexLock(&pcap_bpf_compile_lock);

        ptv->bpf_filter = pcapconfig->bpf_filter;
        SCLogInfo("using bpf-filter \"%s\"", ptv->bpf_filter);

        if(pcap_compile(ptv->pcap_handle,&ptv->filter, ptv->bpf_filter,1,0) < 0) {
            SCLogError(SC_ERR_BPF,"bpf compilation error %s",pcap_geterr(ptv->pcap_handle));

            SCMutexUnlock(&pcap_bpf_compile_lock);
            SCFree(ptv);
            /* Dereference config */
            pcapconfig->DerefFunc(pcapconfig);
            return TM_ECODE_FAILED;
        }

        if(pcap_setfilter(ptv->pcap_handle,&ptv->filter) < 0) {
            SCLogError(SC_ERR_BPF,"could not set bpf filter %s",pcap_geterr(ptv->pcap_handle));

            SCMutexUnlock(&pcap_bpf_compile_lock);
            SCFree(ptv);
            /* Dereference config */
            pcapconfig->DerefFunc(pcapconfig);
            return TM_ECODE_FAILED;
        }

        SCMutexUnlock(&pcap_bpf_compile_lock);
    }

    ptv->datalink = pcap_datalink(ptv->pcap_handle);

    ptv->capture_kernel_packets = StatsRegisterCounter("capture.kernel_packets",
            ptv->tv);
    ptv->capture_kernel_drops = StatsRegisterCounter("capture.kernel_drops",
            ptv->tv);
    ptv->capture_kernel_ifdrops = StatsRegisterCounter("capture.kernel_ifdrops",
            ptv->tv);

    *data = (void *)ptv;

    /* Dereference config */
    pcapconfig->DerefFunc(pcapconfig);
    SCReturnInt(TM_ECODE_OK);
}
#endif /* LIBPCAP_VERSION_MAJOR */

/**
 * \brief This function prints stats to the screen at exit.
 * \param tv pointer to ThreadVars
 * \param data pointer that gets cast into PcapThreadVars for ptv
 */
void ReceivePcapThreadExitStats(ThreadVars *tv, void *data)
{
    SCEnter();
    PcapThreadVars *ptv = (PcapThreadVars *)data;
    struct pcap_stat pcap_s;

    if (pcap_stats(ptv->pcap_handle, &pcap_s) < 0) {
        SCLogError(SC_ERR_STAT,"(%s) Failed to get pcap_stats: %s", tv->name, pcap_geterr(ptv->pcap_handle));
        SCLogInfo("(%s) Packets %" PRIu32 ", bytes %" PRIu64 "", tv->name, ptv->pkts, ptv->bytes);

        return;
    } else {
        SCLogInfo("(%s) Packets %" PRIu32 ", bytes %" PRIu64 "", tv->name, ptv->pkts, ptv->bytes);

       /* these numbers are not entirely accurate as ps_recv contains packets that are still waiting to be processed at exit.
        * ps_drop only contains packets dropped by the driver and not any packets dropped by the interface.
        * Additionally see http://tracker.icir.org/bro/ticket/18
        *
        * Note: ps_recv includes dropped packets and should be considered total.
        * Unless we start to look at ps_ifdrop which isn't supported everywhere.
        */
        SCLogInfo("(%s) Pcap Total:%" PRIu64 " Recv:%" PRIu64 " Drop:%" PRIu64 " (%02.1f%%).", tv->name,
        (uint64_t)pcap_s.ps_recv, (uint64_t)pcap_s.ps_recv - (uint64_t)pcap_s.ps_drop, (uint64_t)pcap_s.ps_drop,
        (((float)(uint64_t)pcap_s.ps_drop)/(float)(uint64_t)pcap_s.ps_recv)*100);

        return;
    }
}

/**
 * \brief DeInit function closes pcap_handle at exit.
 * \param tv pointer to ThreadVars
 * \param data pointer that gets cast into PcapThreadVars for ptv
 */
TmEcode ReceivePcapThreadDeinit(ThreadVars *tv, void *data)
{
    PcapThreadVars *ptv = (PcapThreadVars *)data;

    pcap_close(ptv->pcap_handle);
    SCReturnInt(TM_ECODE_OK);
}

/**
 * \brief This function passes off to link type decoders.
 *
 * DecodePcap reads packets from the PacketQueue and passes
 * them off to the proper link type decoder.
 *
 * \param t pointer to ThreadVars
 * \param p pointer to the current packet
 * \param data pointer that gets cast into PcapThreadVars for ptv
 * \param pq pointer to the current PacketQueue
 */
 /*data为初始化时填充的DecodeThreadVars，pq为解码模块所嵌入的slot的slot_pre_pq，
postpq则为slot_post_pq（可能为NULL）。
注：按照注释，Suricata中是想套用libpcap中的link type定义，完整的列表可参见：LINK-LAYER HEADER TYPES。

*/
TmEcode DecodePcap(ThreadVars *tv, Packet *p, void *data, PacketQueue *pq, PacketQueue *postpq)
{
    SCEnter();
    DecodeThreadVars *dtv = (DecodeThreadVars *)data;

    /* XXX HACK: flow timeout can call us for injected pseudo packets
     *           see bug: https://redmine.openinfosecfoundation.org/issues/1107 */
    if (p->flags & PKT_PSEUDO_STREAM_END)
        return TM_ECODE_OK;

    /* update counters */
    DecodeUpdatePacketCounters(tv, dtv, p);

    /* call the decoder */
    switch(p->datalink) {
        case LINKTYPE_LINUX_SLL:
			/*libpcap使用的伪协议头，用于从"any"设备抓包或某些链路层头无法获取的情况，
详见：Linux cooked-mode capture (SLL) 。*/
            DecodeSll(tv, dtv, p, GET_PKT_DATA(p), GET_PKT_LEN(p), pq);
            break;
        case LINKTYPE_ETHERNET:
			/*以太网协议包。LINKTYPE_ETHERNET宏定义为pcap中的DLT_EN10MB
（10Mb命名是历史原因，参考下面的列表）*/
            DecodeEthernet(tv, dtv, p,GET_PKT_DATA(p), GET_PKT_LEN(p), pq);
            break;
        case LINKTYPE_PPP:
			/*PPP协议包。参见：RFC 1661 - The Point-to-Point Protocol (PPP)。*/
            DecodePPP(tv, dtv, p, GET_PKT_DATA(p), GET_PKT_LEN(p), pq);
            break;
        case LINKTYPE_RAW:
			/*原始IP数据包。即直接以IPv4或IPv6头开始。LINKTYPE_RAW宏定义为pcap中的DLT_RAW。*/
            DecodeRaw(tv, dtv, p, GET_PKT_DATA(p), GET_PKT_LEN(p), pq);
            break;
        case LINKTYPE_NULL:
            DecodeNull(tv, dtv, p, GET_PKT_DATA(p), GET_PKT_LEN(p), pq);
            break;
        default:
            SCLogError(SC_ERR_DATALINK_UNIMPLEMENTED, "Error: datalink type %" PRId32 " not yet supported in module DecodePcap", p->datalink);
            break;
    }

    PacketDecodeFinalize(tv, dtv, p);

    SCReturnInt(TM_ECODE_OK);
}

TmEcode DecodePcapThreadInit(ThreadVars *tv, void *initdata, void **data)
{
    SCEnter();
    DecodeThreadVars *dtv = NULL;

    dtv = DecodeThreadVarsAlloc(tv);

    if (dtv == NULL)
        SCReturnInt(TM_ECODE_FAILED);

    DecodeRegisterPerfCounters(dtv, tv);

#ifdef __SC_CUDA_SUPPORT__
    if (CudaThreadVarsInit(&dtv->cuda_vars) < 0)
        SCReturnInt(TM_ECODE_FAILED);
#endif

    *data = (void *)dtv;

    SCReturnInt(TM_ECODE_OK);
}

TmEcode DecodePcapThreadDeinit(ThreadVars *tv, void *data)
{
    if (data != NULL)
        DecodeThreadVarsFree(tv, data);
    SCReturnInt(TM_ECODE_OK);
}

void PcapTranslateIPToDevice(char *pcap_dev, size_t len)
{
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_if_t *alldevsp = NULL;
    pcap_if_t *devsp = NULL;

    struct addrinfo aiHints;
    struct addrinfo *aiList = NULL;
    int retVal = 0;

    memset(&aiHints, 0, sizeof(aiHints));
    aiHints.ai_family = AF_UNSPEC;
    aiHints.ai_flags = AI_NUMERICHOST;

    /* try to translate IP */
    if ((retVal = getaddrinfo(pcap_dev, NULL, &aiHints, &aiList)) != 0) {
        return;
    }

    if (pcap_findalldevs(&alldevsp, errbuf)) {
        freeaddrinfo(aiList);
        return;
    }

    for (devsp = alldevsp; devsp ; devsp = devsp->next) {
        pcap_addr_t *ip = NULL;

        for (ip = devsp->addresses; ip ; ip = ip->next) {

            if (aiList->ai_family != ip->addr->sa_family) {
                continue;
            }

            if (ip->addr->sa_family == AF_INET) {
                if (memcmp(&((struct sockaddr_in*)aiList->ai_addr)->sin_addr, &((struct sockaddr_in*)ip->addr)->sin_addr, sizeof(struct in_addr))) {
                    continue;
                }
            } else if (ip->addr->sa_family == AF_INET6) {
                if (memcmp(&((struct sockaddr_in6*)aiList->ai_addr)->sin6_addr, &((struct sockaddr_in6*)ip->addr)->sin6_addr, sizeof(struct in6_addr))) {
                    continue;
                }
            } else {
                continue;
            }

            freeaddrinfo(aiList);

            memset(pcap_dev, 0, len);
            strlcpy(pcap_dev, devsp->name, len);

            pcap_freealldevs(alldevsp);
            return;
        }
    }

    freeaddrinfo(aiList);

    pcap_freealldevs(alldevsp);
}

/* eof */

