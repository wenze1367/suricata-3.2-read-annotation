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

/** \mainpage Doxygen documentation
 *
 * \section intro_sec Introduction
 *
 * The Suricata Engine is an Open Source Next Generation Intrusion Detection
 * and Prevention Engine. This engine is not intended to just replace or
 * emulate the existing tools in the industry, but will bring new ideas and
 * technologies to the field.
 *
 * \section dev_doc Developer documentation
 *
 * You've reach the automically generated documentation of Suricata. This
 * document contains information about architecture and code structure. It
 * is attended for developers wanting to understand or contribute to Suricata.
 *
 * \subsection modules Modules
 *
 * Documentation is generate from comments placed in all parts of the code.
 * But you will also find some groups describing specific functional parts:
 *  - \ref decode
 *  - \ref httplayer
 *  - \ref sigstate
 *  - \ref threshold
 *
 * \section archi Architecture
 *
 * \subsection datastruct Data structures
 *
 * Regarding matching, there is three main data structures which are:
 *  - ::Packet: Data relative to an individual packet with information about
 *  linked structure such as the ::Flow the ::Packet belongs to.
 *  - ::Flow: Information about a flow for example a TCP session
 *  - ::StreamMsg: structure containing the reassembled data
 *
 *  \subsection runmode Running mode
 *
 *  Suricata is multithreaded and running modes define how the different
 *  threads are working together. You can see util-runmodes.c for example
 *  of running mode.
 */

/**
 * \file
 *
 * \author Victor Julien <victor@inliniac.net>
 */

#ifndef __SURICATA_H__
#define __SURICATA_H__

#include "suricata-common.h"
#include "packet-queue.h"
#include "data-queue.h"

/* the name of our binary */
#define PROG_NAME "Suricata"
#define PROG_VER "3.2"

/* workaround SPlint error (don't know __gnuc_va_list) */
#ifdef S_SPLINT_S
#  include <err.h>
#  define CONFIG_DIR "/etc/suricata"
#endif

#define DEFAULT_CONF_FILE CONFIG_DIR "/suricata.yaml"

#define DEFAULT_PID_DIR LOCAL_STATE_DIR "/run/"
#define DEFAULT_PID_BASENAME "suricata.pid"
#define DEFAULT_PID_FILENAME DEFAULT_PID_DIR DEFAULT_PID_BASENAME

#define DOC_URL "http://suricata.readthedocs.io/en/"

#if defined RELEASE
#define DOC_VERSION PROG_VER
#else
#define DOC_VERSION "latest"
#endif

/* runtime engine control flags */
#define SURICATA_STOP    (1 << 0)   /**< gracefully stop the engine: process all
                                     outstanding packets first */
#define SURICATA_DONE    (1 << 2)   /**< packets capture ended */

/* Engine stage/status*/
enum {
    SURICATA_INIT = 0,
    SURICATA_RUNTIME,
    SURICATA_DEINIT
};

/* Engine is acting as */
enum EngineMode {
    ENGINE_MODE_IDS,
    ENGINE_MODE_IPS,
};

void EngineModeSetIPS(void);
void EngineModeSetIDS(void);
int EngineModeIsIPS(void);
int EngineModeIsIDS(void);

/* Box is acting as router */
enum {
    SURI_HOST_IS_SNIFFER_ONLY,
    SURI_HOST_IS_ROUTER,
};

#define IS_SURI_HOST_MODE_SNIFFER_ONLY(host_mode)  ((host_mode) == SURI_HOST_IS_SNIFFER_ONLY)
#define IS_SURI_HOST_MODE_ROUTER(host_mode)  ((host_mode) == SURI_HOST_IS_ROUTER)

#include "runmodes.h"

/* queue's between various other threads
 * XXX move to the TmQueue structure later
 Suricata中使用了一个全局数组作为所有的线程间队列的存储，
 定义为:
 这里为什么使用全局静态数组，而不是更直观更省内存的在运行时按需动态分配呢？
 主要是出于性能考虑。按需动态分配，就要求将队列组织为链表（当然，动态数组也行，
 但实现相对复杂，且完全没有必要），而为了支持队列负载均衡，需要将数据包在各个数据包之间进行分配，
 像hash这种分配方式是需要能够按照队列索引进行随机访问的。
 并且，由于所需队列个数在编译时就已经确定，因此使用全局静态数据是最合适的了。
 */
PacketQueue trans_q[256];

SCDQDataQueue data_queues[256];

typedef struct SCInstance_ {
    enum RunModes run_mode;

    char pcap_dev[128];
    char *sig_file;
    int sig_file_exclusive;
    char *pid_filename;
    char *regex_arg;

    char *keyword_info;
    char *runmode_custom_mode;
#ifndef OS_WIN32
    char *user_name;
    char *group_name;
    uint8_t do_setuid;
    uint8_t do_setgid;
    uint32_t userid;
    uint32_t groupid;
#endif /* OS_WIN32 */
    int delayed_detect;
    int disabled_detect;
    int daemon;
    int offline;
    int verbose;
    int checksum_validation;

    struct timeval start_time;

    char *log_dir;
    const char *progname; /**< pointer to argv[0] */
    const char *conf_filename;
} SCInstance;


/* memset to zeros, and mutex init! */
void GlobalInits();

extern volatile uint8_t suricata_ctl_flags;

/* uppercase to lowercase conversion lookup table */
uint8_t g_u8_lowercasetable[256];

/* marco to do the actual lookup */
//#define u8_tolower(c) g_u8_lowercasetable[(c)]
// these 2 are slower:
//#define u8_tolower(c) ((c) >= 'A' && (c) <= 'Z') ? g_u8_lowercasetable[(c)] : (c)
//#define u8_tolower(c) (((c) >= 'A' && (c) <= 'Z') ? ((c) + ('a' - 'A')) : (c))

/* this is faster than the table lookup */
#include <ctype.h>
#define u8_tolower(c) tolower((uint8_t)(c))

void EngineStop(void);
void EngineDone(void);

int RunmodeIsUnittests(void);
int RunmodeGetCurrent(void);
int IsRuleReloadSet(int quiet);

extern int run_mode;

#endif /* __SURICATA_H__ */

