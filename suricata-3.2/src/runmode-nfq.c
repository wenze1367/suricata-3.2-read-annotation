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
 * \author Anoop Saldanha <anoopsaldanha@gmail.com>
 * \author Eric Leblond <eric@regit.org>
 *
 * Handling of NFQ runmodes.
 */


#include "suricata-common.h"
#include "tm-threads.h"
#include "conf.h"
#include "runmodes.h"
#include "runmode-nfq.h"
#include "output.h"

#include "util-debug.h"
#include "util-time.h"
#include "util-cpu.h"
#include "util-affinity.h"
#include "util-runmodes.h"
#include "util-device.h"

static const char *default_mode;

const char *RunModeIpsNFQGetDefaultMode(void)
{
    return default_mode;
}

/*
*里面注册了3个回调函数，这个3个回调函数主要针对的是auto模式、autofp模式和workers模式。
其中我要说的是workers模式下的情况，而在RunModeIpsNFQWorker(这个函数在runmode-nfq.c)
这个函数中主要调用了函数RunModeSetIPSWorker。
*/
void RunModeIpsNFQRegister(void)
{
    default_mode = "autofp";
    RunModeRegisterNewRunMode(RUNMODE_NFQ, "autofp",
                              "Multi threaded NFQ IPS mode with respect to flow",
                              RunModeIpsNFQAutoFp);

    RunModeRegisterNewRunMode(RUNMODE_NFQ, "workers",
                              "Multi queue NFQ IPS mode with one thread per queue",
                              RunModeIpsNFQWorker);
    return;
}

int RunModeIpsNFQAutoFp(void)
{
    SCEnter();
    int ret = 0;
#ifdef NFQ

    RunModeInitialize();

    TimeModeSetLive();

    LiveDeviceHasNoStats();

    ret = RunModeSetIPSAutoFp(NFQGetThread,
            "ReceiveNFQ",
            "VerdictNFQ",
            "DecodeNFQ");
#endif /* NFQ */
    return ret;
}

int RunModeIpsNFQWorker(void)
{
    SCEnter();
    int ret = 0;
#ifdef NFQ

    RunModeInitialize();

    TimeModeSetLive();

    LiveDeviceHasNoStats();

	/*
	*其中我要说的是workers模式下的情况，而在RunModeIpsNFQWorker(这个函数在runmode-nfq.c)
	这个函数中主要调用了函数RunModeSetIPSWorker。
	在RunModeSetIPSWorker中就完成将所有的模块连接起来。包括了ReceiveNFQ模块(主要进行数据包的接受)、
	Decode模块(主要是对数据包的协议进行分析)、StreamTcp模块(主要是将对应的数据包组成stream的形式)、
	Detect模块(主要是使用DetectEngineCtx里面的特征对数据进行匹配)、Verdict模块以及RespondReject模块。
	*/
    ret = RunModeSetIPSWorker(NFQGetThread,
            "ReceiveNFQ",
            "VerdictNFQ",
            "DecodeNFQ");
#endif /* NFQ */
    return ret;
}
