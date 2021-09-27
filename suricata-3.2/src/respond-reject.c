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
 * \author William Metcalf <william.metcalf@gmail.com>
 *
 * RespondReject is a threaded wrapper for sending Rejects
 *
 * \todo RespondRejectFunc returns 1 on error, 0 on ok... why? For now it should
 *   just return 0 always, error handling is a TODO in the threading model (VJ)
 */

#include "suricata-common.h"
#include "decode.h"
#include "packet-queue.h"
#include "threads.h"
#include "threadvars.h"
#include "tm-queuehandlers.h"
#include "tm-threads.h"
#include "action-globals.h"

#include "respond-reject.h"
#include "respond-reject-libnet11.h"

#include "util-debug.h"
#include "util-privs.h"

int RejectSendIPv4TCP(ThreadVars *, Packet *, void *);
int RejectSendIPv4ICMP(ThreadVars *, Packet *, void *);
int RejectSendIPv6TCP(ThreadVars *, Packet *, void *);
int RejectSendIPv6ICMP(ThreadVars *, Packet *, void *);

void TmModuleRespondRejectRegister (void)
{
    tmm_modules[TMM_RESPONDREJECT].name = "RespondReject";
    tmm_modules[TMM_RESPONDREJECT].ThreadInit = NULL;
    tmm_modules[TMM_RESPONDREJECT].Func = RespondRejectFunc;
    tmm_modules[TMM_RESPONDREJECT].ThreadDeinit = NULL;
    tmm_modules[TMM_RESPONDREJECT].RegisterTests = NULL;
    tmm_modules[TMM_RESPONDREJECT].cap_flags = 0; /* libnet is not compat with caps */
}

/*
*简介
RespondReject工作在worker线程，在FlowWorker模块之后对数据包进行处理。此处主要的作用是直接对符合过滤规则的数据包进行阻断并回复，从而使得数据包不会流入后续的操作模块。个人理解这点在IPS模式时会十分有用，可以阻断网络攻击、爬虫等。

原码分析
函数RespondRejectFunc只支持IPv4和IPv6的数据包回复，因此其中只调用了4个函数：RejectSendIPv4TCP、RejectSendIPv4ICMP、RejectSendIPv6TCP、RejectSendIPv6ICMP。
下面主要分析一下RejectSendIPv4TCP函数。
*/
TmEcode RespondRejectFunc(ThreadVars *tv, Packet *p, void *data, PacketQueue *pq, PacketQueue *postpq)
{
    int ret = 0;

    /* ACTION_REJECT defaults to rejecting the SRC */
    if (!(PACKET_TEST_ACTION(p, ACTION_REJECT)) &&
        !(PACKET_TEST_ACTION(p, ACTION_REJECT_DST)) &&
        !(PACKET_TEST_ACTION(p, ACTION_REJECT_BOTH))) {
        return TM_ECODE_OK;
    }

    if (PKT_IS_IPV4(p)) {
        if (PKT_IS_TCP(p)) {
            ret = RejectSendIPv4TCP(tv, p, data);
        } else {
            ret = RejectSendIPv4ICMP(tv, p, data);
        }
    } else if (PKT_IS_IPV6(p)) {
        if (PKT_IS_TCP(p)) {
            ret = RejectSendIPv6TCP(tv, p, data);
        } else {
            ret = RejectSendIPv6ICMP(tv, p, data);
        }
    } else {
        /* we're only supporting IPv4 and IPv6 */
        return TM_ECODE_OK;
    }

    if (ret)
        return TM_ECODE_FAILED;
    else
        return TM_ECODE_OK;
}

/*
*注：这里有一个我开始不是很明白。对原端来的数据包进行回复很好理解，对阻断的包做一个响应，仅仅是通知一下对方“我收到你的包了”。
可对目的端发送数据包就有点不好理解了，如果在我们阻断之前原端
和目地端已经建立了连接，那么单方面阻断原端数据会使得目地端长时间处于等待数据包的状态，
占用系统资源，这时我们给上地端发送数据，告诉目地端“现在连接结束，可以释放资源了”，
这样就能够减少系统的资源占用。
后续3处分支都调用RejectSendLibnet11L3IPv4TCP函数，这个函数就是通过libnet进行组包，
然后发出，当然其中会对需要发关到的地址进行编辑。
*/
int RejectSendIPv4TCP(ThreadVars *tv, Packet *p, void *data)
{
    SCEnter();
    int r = 0;
	
    if (PACKET_TEST_ACTION(p, ACTION_REJECT)) {
		//将数据发送回原端;
        r = RejectSendLibnet11L3IPv4TCP(tv, p, data, REJECT_DIR_SRC);
        SCReturnInt(r);
    } else if (PACKET_TEST_ACTION(p, ACTION_REJECT_DST)) {
		//将数据发送到目地端;
        r = RejectSendLibnet11L3IPv4TCP(tv, p, data, REJECT_DIR_DST);
        SCReturnInt(r);
    } else if(PACKET_TEST_ACTION(p, ACTION_REJECT_BOTH)) {
        int ret;
		//同时对原端和目地端进行回复;
        ret = RejectSendLibnet11L3IPv4TCP(tv, p, data, REJECT_DIR_SRC);
        if (RejectSendLibnet11L3IPv4TCP(tv, p, data, REJECT_DIR_DST) == 0) {
            SCReturnInt(0);
        } else {
            SCReturnInt(ret);
        }
    }
    SCReturnInt(0);
}

int RejectSendIPv4ICMP(ThreadVars *tv, Packet *p, void *data)
{
    SCEnter();
    int r = 0;
    if (PACKET_TEST_ACTION(p, ACTION_REJECT)) {
        r = RejectSendLibnet11L3IPv4ICMP(tv, p, data, REJECT_DIR_SRC);
        SCReturnInt(r);
    } else if (PACKET_TEST_ACTION(p, ACTION_REJECT_DST)) {
        r = RejectSendLibnet11L3IPv4ICMP(tv, p, data, REJECT_DIR_DST);
        SCReturnInt(r);
    } else if(PACKET_TEST_ACTION(p, ACTION_REJECT_BOTH)) {
        int ret;
        ret = RejectSendLibnet11L3IPv4ICMP(tv, p, data, REJECT_DIR_SRC);
        if (RejectSendLibnet11L3IPv4ICMP(tv, p, data, REJECT_DIR_DST) == 0) {
            SCReturnInt(0);
        } else {
            SCReturnInt(ret);
        }
    }
    SCReturnInt(0);
}

int RejectSendIPv6TCP(ThreadVars *tv, Packet *p, void *data)
{
    SCEnter();
    int r = 0;
    if (PACKET_TEST_ACTION(p, ACTION_REJECT)) {
        r = RejectSendLibnet11L3IPv6TCP(tv, p, data, REJECT_DIR_SRC);
        SCReturnInt(r);
    } else if (PACKET_TEST_ACTION(p, ACTION_REJECT_DST)) {
        r = RejectSendLibnet11L3IPv6TCP(tv, p, data, REJECT_DIR_DST);
        SCReturnInt(r);
    } else if(PACKET_TEST_ACTION(p, ACTION_REJECT_BOTH)) {
        int ret;
        ret = RejectSendLibnet11L3IPv6TCP(tv, p, data, REJECT_DIR_SRC);
        if (RejectSendLibnet11L3IPv6TCP(tv, p, data, REJECT_DIR_DST) == 0) {
            SCReturnInt(0);
        } else {
            SCReturnInt(ret);
        }
    }
    SCReturnInt(0);
}

int RejectSendIPv6ICMP(ThreadVars *tv, Packet *p, void *data)
{
    SCEnter();
    int r = 0;
    if (PACKET_TEST_ACTION(p, ACTION_REJECT)) {
        r = RejectSendLibnet11L3IPv6ICMP(tv, p, data, REJECT_DIR_SRC);
        SCReturnInt(r);
    } else if (PACKET_TEST_ACTION(p, ACTION_REJECT_DST)) {
        r = RejectSendLibnet11L3IPv6ICMP(tv, p, data, REJECT_DIR_DST);
        SCReturnInt(r);
    } else if(PACKET_TEST_ACTION(p, ACTION_REJECT_BOTH)) {
        int ret;
        ret = RejectSendLibnet11L3IPv6ICMP(tv, p, data, REJECT_DIR_SRC);
        if (RejectSendLibnet11L3IPv6ICMP(tv, p, data, REJECT_DIR_DST) == 0) {
            SCReturnInt(0);
        } else {
            SCReturnInt(ret);
        }
    }
    SCReturnInt(0);
}

