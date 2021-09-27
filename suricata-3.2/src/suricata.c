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
 */

#include "suricata-common.h"
#include "config.h"

#if HAVE_GETOPT_H
#include <getopt.h>
#endif

#if HAVE_SIGNAL_H
#include <signal.h>
#endif

#ifdef HAVE_NSS
#include <prinit.h>
#include <nss.h>
#endif

#include "suricata.h"
#include "decode.h"
#include "detect.h"
#include "packet-queue.h"
#include "threads.h"
#include "threadvars.h"
#include "flow-worker.h"

#include "util-atomic.h"
#include "util-spm.h"
#include "util-cpu.h"
#include "util-action.h"
#include "util-pidfile.h"
#include "util-ioctl.h"
#include "util-device.h"
#include "util-misc.h"
#include "util-running-modes.h"

#include "detect-engine.h"
#include "detect-parse.h"
#include "detect-fast-pattern.h"
#include "detect-engine-tag.h"
#include "detect-engine-threshold.h"
#include "detect-engine-address.h"
#include "detect-engine-port.h"
#include "detect-engine-mpm.h"

#include "tm-queuehandlers.h"
#include "tm-queues.h"
#include "tm-threads.h"

#include "tmqh-flow.h"

#include "conf.h"
#include "conf-yaml-loader.h"

#include "stream-tcp.h"

#include "source-nfq.h"
#include "source-nfq-prototypes.h"

#include "source-nflog.h"

#include "source-ipfw.h"

#include "source-pcap.h"
#include "source-pcap-file.h"

#include "source-pfring.h"

#include "source-erf-file.h"
#include "source-erf-dag.h"
#include "source-napatech.h"

#include "source-af-packet.h"
#include "source-netmap.h"
#include "source-mpipe.h"

#include "respond-reject.h"

#include "flow.h"
#include "flow-timeout.h"
#include "flow-manager.h"
#include "flow-var.h"
#include "flow-bit.h"
#include "pkt-var.h"
#include "host-bit.h"

#include "ippair.h"
#include "ippair-bit.h"

#include "host.h"
#include "unix-manager.h"

#include "app-layer.h"
#include "app-layer-parser.h"
#include "app-layer-htp.h"
#include "app-layer-ssl.h"
#include "app-layer-dns-tcp.h"
#include "app-layer-ssh.h"
#include "app-layer-ftp.h"
#include "app-layer-smtp.h"
#include "app-layer-smb.h"
#include "app-layer-modbus.h"
#include "app-layer-enip.h"
#include "app-layer-dnp3.h"

#include "util-decode-der.h"
#include "util-radix-tree.h"
#include "util-host-os-info.h"
#include "util-cidr.h"
#include "util-unittest.h"
#include "util-unittest-helper.h"
#include "util-time.h"
#include "util-rule-vars.h"
#include "util-classification-config.h"
#include "util-threshold-config.h"
#include "util-reference-config.h"
#include "util-profiling.h"
#include "util-magic.h"
#include "util-signal.h"

#include "util-coredump-config.h"

#include "util-decode-mime.h"

#include "defrag.h"

#include "runmodes.h"
#include "runmode-unittests.h"

#include "util-cuda.h"
#include "util-decode-asn1.h"
#include "util-debug.h"
#include "util-error.h"
#include "util-daemon.h"
#include "reputation.h"

#include "output.h"

#include "util-privs.h"

#include "tmqh-packetpool.h"

#include "util-proto-name.h"
#ifdef __SC_CUDA_SUPPORT__
#include "util-cuda-buffer.h"
#include "util-mpm-ac.h"
#endif
#include "util-mpm-hs.h"
#include "util-storage.h"
#include "host-storage.h"

#include "util-lua.h"

/*
 * we put this here, because we only use it here in main.
 */
volatile sig_atomic_t sigint_count = 0;
volatile sig_atomic_t sighup_count = 0;
volatile sig_atomic_t sigterm_count = 0;
volatile sig_atomic_t sigusr2_count = 0;

/*
 * Flag to indicate if the engine is at the initialization
 * or already processing packets. 3 stages: SURICATA_INIT,
 * SURICATA_RUNTIME and SURICATA_FINALIZE
 */
SC_ATOMIC_DECLARE(unsigned int, engine_stage);

/* Max packets processed simultaniously per thread. */
#define DEFAULT_MAX_PENDING_PACKETS 1024

/** suricata engine control flags */
volatile uint8_t suricata_ctl_flags = 0;

/** Run mode selected */
int run_mode = RUNMODE_UNKNOWN;

/** Engine mode: inline (ENGINE_MODE_IPS) or just
  * detection mode (ENGINE_MODE_IDS by default) */
static enum EngineMode g_engine_mode = ENGINE_MODE_IDS;

/** Host mode: set if box is sniffing only
 * or is a router */
uint8_t host_mode = SURI_HOST_IS_SNIFFER_ONLY;

/** Maximum packets to simultaneously process. */
intmax_t max_pending_packets;

/** global indicating if detection is enabled */
int g_detect_disabled = 0;

/** set caps or not */
int sc_set_caps;

int EngineModeIsIPS(void)
{
    return (g_engine_mode == ENGINE_MODE_IPS);
}

int EngineModeIsIDS(void)
{
    return (g_engine_mode == ENGINE_MODE_IDS);
}

void EngineModeSetIPS(void)
{
    g_engine_mode = ENGINE_MODE_IPS;
}

void EngineModeSetIDS(void)
{
    g_engine_mode = ENGINE_MODE_IDS;
}

int RunmodeIsUnittests(void)
{
    if (run_mode == RUNMODE_UNITTEST)
        return 1;

    return 0;
}

int RunmodeGetCurrent(void)
{
    return run_mode;
}

/** signal handlers
 *
 *  WARNING: don't use the SCLog* API in the handlers. The API is complex
 *  with memory allocation possibly happening, calls to syslog, json message
 *  construction, etc.
 */

static void SignalHandlerSigint(/*@unused@*/ int sig)
{
    sigint_count = 1;
}
static void SignalHandlerSigterm(/*@unused@*/ int sig)
{
    sigterm_count = 1;
}

/**
 * SIGUSR2 handler.  Just set sigusr2_count.  The main loop will act on
 * it.
 */
static void SignalHandlerSigusr2(int sig)
{
    if (sigusr2_count < 16) {
        sigusr2_count++;
    } else {
        SCLogWarning(SC_ERR_LIVE_RULE_SWAP, "Too many USR2 signals pending, ignoring new ones!");
    }
}

/**
 * SIGHUP handler.  Just set sighup_count.  The main loop will act on
 * it.
 */
static void SignalHandlerSigHup(/*@unused@*/ int sig)
{
    sighup_count = 1;
}

#ifdef DBG_MEM_ALLOC
#ifndef _GLOBAL_MEM_
#define _GLOBAL_MEM_
/* This counter doesn't complain realloc's(), it's gives
 * an aproximation for the startup */
size_t global_mem = 0;
#ifdef DBG_MEM_ALLOC_SKIP_STARTUP
uint8_t print_mem_flag = 0;
#else
uint8_t print_mem_flag = 1;
#endif
#endif
#endif

void CreateLowercaseTable()
{
    /* create table for O(1) lowercase conversion lookup.  It was removed, but
     * we still need it for cuda.  So resintalling it back into the codebase */
    int c = 0;
    memset(g_u8_lowercasetable, 0x00, sizeof(g_u8_lowercasetable));
    for ( ; c < 256; c++) {
        if (c >= 'A' && c <= 'Z')
            g_u8_lowercasetable[c] = (c + ('a' - 'A'));
        else
            g_u8_lowercasetable[c] = c;
    }
}

void GlobalInits()
{
    memset(trans_q, 0, sizeof(trans_q));
    memset(data_queues, 0, sizeof(data_queues));

    /* Initialize the trans_q mutex */
    int blah;
    int r = 0;
    for(blah=0;blah<256;blah++) {
        r |= SCMutexInit(&trans_q[blah].mutex_q, NULL);
        r |= SCCondInit(&trans_q[blah].cond_q, NULL);

        r |= SCMutexInit(&data_queues[blah].mutex_q, NULL);
        r |= SCCondInit(&data_queues[blah].cond_q, NULL);
   }

    if (r != 0) {
        SCLogInfo("Trans_Q Mutex not initialized correctly");
        exit(EXIT_FAILURE);
    }

    CreateLowercaseTable();
}

/** \brief make sure threads can stop the engine by calling this
 *  function. Purpose: pcap file mode needs to be able to tell the
 *  engine the file eof is reached. */
void EngineStop(void)
{
    suricata_ctl_flags |= SURICATA_STOP;
}

/**
 * \brief Used to indicate that the current task is done.
 *
 * This is mainly used by pcap-file to tell it has finished
 * to treat a pcap files when running in unix-socket mode.
 */
void EngineDone(void)
{
    suricata_ctl_flags |= SURICATA_DONE;
}

static int SetBpfString(int argc, char *argv[])
{
    char *bpf_filter = NULL;
    uint32_t bpf_len = 0;
    int tmpindex = 0;

    /* attempt to parse remaining args as bpf filter */
    tmpindex = argc;
    while(argv[tmpindex] != NULL) {
        bpf_len+=strlen(argv[tmpindex]) + 1;
        tmpindex++;
    }

    if (bpf_len == 0)
        return TM_ECODE_OK;

    if (EngineModeIsIPS()) {
        SCLogError(SC_ERR_NOT_SUPPORTED,
                   "BPF filter not available in IPS mode."
                   " Use firewall filtering if possible.");
        return TM_ECODE_FAILED;
    }

    bpf_filter = SCMalloc(bpf_len);
    if (unlikely(bpf_filter == NULL))
        return TM_ECODE_OK;
    memset(bpf_filter, 0x00, bpf_len);

    tmpindex = optind;
    while(argv[tmpindex] != NULL) {
        strlcat(bpf_filter, argv[tmpindex],bpf_len);
        if(argv[tmpindex + 1] != NULL) {
            strlcat(bpf_filter," ", bpf_len);
        }
        tmpindex++;
    }

    if(strlen(bpf_filter) > 0) {
        if (ConfSetFinal("bpf-filter", bpf_filter) != 1) {
            SCLogError(SC_ERR_FATAL, "Failed to set bpf filter.");
            SCFree(bpf_filter);
            return TM_ECODE_FAILED;
        }
    }
    SCFree(bpf_filter);

    return TM_ECODE_OK;
}

static void SetBpfStringFromFile(char *filename)
{
    char *bpf_filter = NULL;
    char *bpf_comment_tmp = NULL;
    char *bpf_comment_start =  NULL;
    uint32_t bpf_len = 0;
#ifdef OS_WIN32
    struct _stat st;
#else
    struct stat st;
#endif /* OS_WIN32 */
    FILE *fp = NULL;
    size_t nm = 0;

    if (EngineModeIsIPS()) {
        SCLogError(SC_ERR_NOT_SUPPORTED,
                   "BPF filter not available in IPS mode."
                   " Use firewall filtering if possible.");
        exit(EXIT_FAILURE);
    }

#ifdef OS_WIN32
    if(_stat(filename, &st) != 0) {
#else
    if(stat(filename, &st) != 0) {
#endif /* OS_WIN32 */
        SCLogError(SC_ERR_FOPEN, "Failed to stat file %s", filename);
        exit(EXIT_FAILURE);
    }
    bpf_len = st.st_size + 1;

    fp = fopen(filename,"r");
    if (fp == NULL) {
        SCLogError(SC_ERR_FOPEN, "Failed to open file %s", filename);
        exit(EXIT_FAILURE);
    }

    bpf_filter = SCMalloc(bpf_len * sizeof(char));
    if (unlikely(bpf_filter == NULL)) {
        SCLogError(SC_ERR_MEM_ALLOC, "Failed to allocate buffer for bpf filter in file %s", filename);
        exit(EXIT_FAILURE);
    }
    memset(bpf_filter, 0x00, bpf_len);

    nm = fread(bpf_filter, 1, bpf_len - 1, fp);
    if ((ferror(fp) != 0) || (nm != (bpf_len - 1))) {
        SCLogError(SC_ERR_BPF, "Failed to read complete BPF file %s", filename);
        SCFree(bpf_filter);
        fclose(fp);
        exit(EXIT_FAILURE);
    }
    fclose(fp);
    bpf_filter[nm] = '\0';

    if(strlen(bpf_filter) > 0) {
        /*replace comments with space*/
        bpf_comment_start = bpf_filter;
        while((bpf_comment_tmp = strchr(bpf_comment_start, '#')) != NULL) {
            while((*bpf_comment_tmp !='\0') &&
                (*bpf_comment_tmp != '\r') && (*bpf_comment_tmp != '\n'))
            {
                *bpf_comment_tmp++ = ' ';
            }
            bpf_comment_start = bpf_comment_tmp;
        }
        /*remove remaining '\r' and '\n' */
        while((bpf_comment_tmp = strchr(bpf_filter, '\r')) != NULL) {
            *bpf_comment_tmp = ' ';
        }
        while((bpf_comment_tmp = strchr(bpf_filter, '\n')) != NULL) {
            *bpf_comment_tmp = ' ';
        }
        /* cut trailing spaces */
        while (strlen(bpf_filter) > 0 &&
                bpf_filter[strlen(bpf_filter)-1] == ' ')
        {
            bpf_filter[strlen(bpf_filter)-1] = '\0';
        }
        if (strlen(bpf_filter) > 0) {
            if(ConfSetFinal("bpf-filter", bpf_filter) != 1) {
                SCLogError(SC_ERR_FOPEN, "ERROR: Failed to set bpf filter!");
                SCFree(bpf_filter);
                exit(EXIT_FAILURE);
            }
        }
    }
    SCFree(bpf_filter);
}

void usage(const char *progname)
{
#ifdef REVISION
    printf("%s %s (rev %s)\n", PROG_NAME, PROG_VER, xstr(REVISION));
#else
    printf("%s %s\n", PROG_NAME, PROG_VER);
#endif
    printf("USAGE: %s [OPTIONS] [BPF FILTER]\n\n", progname);
    printf("\t-c <path>                            : path to configuration file\n");
    printf("\t-T                                   : test configuration file (use with -c)\n");
    printf("\t-i <dev or ip>                       : run in pcap live mode\n");
    printf("\t-F <bpf filter file>                 : bpf filter file\n");
    printf("\t-r <path>                            : run in pcap file/offline mode\n");
#ifdef NFQ
    printf("\t-q <qid>                             : run in inline nfqueue mode\n");
#endif /* NFQ */
#ifdef IPFW
    printf("\t-d <divert port>                     : run in inline ipfw divert mode\n");
#endif /* IPFW */
    printf("\t-s <path>                            : path to signature file loaded in addition to suricata.yaml settings (optional)\n");
    printf("\t-S <path>                            : path to signature file loaded exclusively (optional)\n");
    printf("\t-l <dir>                             : default log directory\n");
#ifndef OS_WIN32
    printf("\t-D                                   : run as daemon\n");
#else
    printf("\t--service-install                    : install as service\n");
    printf("\t--service-remove                     : remove service\n");
    printf("\t--service-change-params              : change service startup parameters\n");
#endif /* OS_WIN32 */
    printf("\t-k [all|none]                        : force checksum check (all) or disabled it (none)\n");
    printf("\t-V                                   : display Suricata version\n");
    printf("\t-v[v]                                : increase default Suricata verbosity\n");
#ifdef UNITTESTS
    printf("\t-u                                   : run the unittests and exit\n");
    printf("\t-U, --unittest-filter=REGEX          : filter unittests with a regex\n");
    printf("\t--list-unittests                     : list unit tests\n");
    printf("\t--fatal-unittests                    : enable fatal failure on unittest error\n");
    printf("\t--unittests-coverage                 : display unittest coverage report\n");
#endif /* UNITTESTS */
    printf("\t--list-app-layer-protos              : list supported app layer protocols\n");
    printf("\t--list-keywords[=all|csv|<kword>]    : list keywords implemented by the engine\n");
#ifdef __SC_CUDA_SUPPORT__
    printf("\t--list-cuda-cards                    : list cuda supported cards\n");
#endif
    printf("\t--list-runmodes                      : list supported runmodes\n");
    printf("\t--runmode <runmode_id>               : specific runmode modification the engine should run.  The argument\n"
           "\t                                       supplied should be the id for the runmode obtained by running\n"
           "\t                                       --list-runmodes\n");
    printf("\t--engine-analysis                    : print reports on analysis of different sections in the engine and exit.\n"
           "\t                                       Please have a look at the conf parameter engine-analysis on what reports\n"
           "\t                                       can be printed\n");
    printf("\t--pidfile <file>                     : write pid to this file\n");
    printf("\t--init-errors-fatal                  : enable fatal failure on signature init error\n");
    printf("\t--disable-detection                  : disable detection engine\n");
    printf("\t--dump-config                        : show the running configuration\n");
    printf("\t--build-info                         : display build information\n");
    printf("\t--pcap[=<dev>]                       : run in pcap mode, no value select interfaces from suricata.yaml\n");
#ifdef HAVE_PCAP_SET_BUFF
    printf("\t--pcap-buffer-size                   : size of the pcap buffer value from 0 - %i\n",INT_MAX);
#endif /* HAVE_SET_PCAP_BUFF */
#ifdef HAVE_AF_PACKET
    printf("\t--af-packet[=<dev>]                  : run in af-packet mode, no value select interfaces from suricata.yaml\n");
#endif
#ifdef HAVE_NETMAP
    printf("\t--netmap[=<dev>]                     : run in netmap mode, no value select interfaces from suricata.yaml\n");
#endif
#ifdef HAVE_PFRING
    printf("\t--pfring[=<dev>]                     : run in pfring mode, use interfaces from suricata.yaml\n");
    printf("\t--pfring-int <dev>                   : run in pfring mode, use interface <dev>\n");
    printf("\t--pfring-cluster-id <id>             : pfring cluster id \n");
    printf("\t--pfring-cluster-type <type>         : pfring cluster type for PF_RING 4.1.2 and later cluster_round_robin|cluster_flow\n");
#endif /* HAVE_PFRING */
    printf("\t--simulate-ips                       : force engine into IPS mode. Useful for QA\n");
#ifdef HAVE_LIBCAP_NG
    printf("\t--user <user>                        : run suricata as this user after init\n");
    printf("\t--group <group>                      : run suricata as this group after init\n");
#endif /* HAVE_LIBCAP_NG */
    printf("\t--erf-in <path>                      : process an ERF file\n");
#ifdef HAVE_DAG
    printf("\t--dag <dagX:Y>                       : process ERF records from DAG interface X, stream Y\n");
#endif
#ifdef HAVE_NAPATECH
    printf("\t--napatech                           : run Napatech Streams using the API\n");
#endif
#ifdef BUILD_UNIX_SOCKET
    printf("\t--unix-socket[=<file>]               : use unix socket to control suricata work\n");
#endif
#ifdef HAVE_MPIPE
    printf("\t--mpipe                              : run with tilegx mpipe interface(s)\n");
#endif
    printf("\t--set name=value                     : set a configuration value\n");
    printf("\n");
    printf("\nTo run the engine with default configuration on "
            "interface eth0 with signature file \"signatures.rules\", run the "
            "command as:\n\n%s -c suricata.yaml -s signatures.rules -i eth0 \n\n",
            progname);
}

void SCPrintBuildInfo(void)
{
    char *bits = "<unknown>-bits";
    char *endian = "<unknown>-endian";
    char features[2048] = "";
    char *tls = "pthread key";

#ifdef REVISION
    printf("This is %s version %s (rev %s)\n", PROG_NAME, PROG_VER, xstr(REVISION));
#elif defined RELEASE
    printf("This is %s version %s RELEASE\n", PROG_NAME, PROG_VER);
#else
    printf("This is %s version %s\n", PROG_NAME, PROG_VER);
#endif

#ifdef DEBUG
    strlcat(features, "DEBUG ", sizeof(features));
#endif
#ifdef DEBUG_VALIDATION
    strlcat(features, "DEBUG_VALIDATION ", sizeof(features));
#endif
#ifdef UNITTESTS
    strlcat(features, "UNITTESTS ", sizeof(features));
#endif
#ifdef NFQ
    strlcat(features, "NFQ ", sizeof(features));
#endif
#ifdef IPFW
    strlcat(features, "IPFW ", sizeof(features));
#endif
#ifdef HAVE_PCAP_SET_BUFF
    strlcat(features, "PCAP_SET_BUFF ", sizeof(features));
#endif
#if LIBPCAP_VERSION_MAJOR == 1
    strlcat(features, "LIBPCAP_VERSION_MAJOR=1 ", sizeof(features));
#elif LIBPCAP_VERSION_MAJOR == 0
    strlcat(features, "LIBPCAP_VERSION_MAJOR=0 ", sizeof(features));
#endif
#ifdef __SC_CUDA_SUPPORT__
    strlcat(features, "CUDA ", sizeof(features));
#endif
#ifdef HAVE_PFRING
    strlcat(features, "PF_RING ", sizeof(features));
#endif
#ifdef HAVE_AF_PACKET
    strlcat(features, "AF_PACKET ", sizeof(features));
#endif
#ifdef HAVE_NETMAP
    strlcat(features, "NETMAP ", sizeof(features));
#endif
#ifdef HAVE_PACKET_FANOUT
    strlcat(features, "HAVE_PACKET_FANOUT ", sizeof(features));
#endif
#ifdef HAVE_DAG
    strlcat(features, "DAG ", sizeof(features));
#endif
#ifdef HAVE_LIBCAP_NG
    strlcat(features, "LIBCAP_NG ", sizeof(features));
#endif
#ifdef HAVE_LIBNET11
    strlcat(features, "LIBNET1.1 ", sizeof(features));
#endif
#ifdef HAVE_HTP_URI_NORMALIZE_HOOK
    strlcat(features, "HAVE_HTP_URI_NORMALIZE_HOOK ", sizeof(features));
#endif
#ifdef PCRE_HAVE_JIT
    strlcat(features, "PCRE_JIT ", sizeof(features));
#endif
#ifdef HAVE_NSS
    strlcat(features, "HAVE_NSS ", sizeof(features));
#endif
#ifdef HAVE_LUA
    strlcat(features, "HAVE_LUA ", sizeof(features));
#endif
#ifdef HAVE_LUAJIT
    strlcat(features, "HAVE_LUAJIT ", sizeof(features));
#endif
#ifdef HAVE_LIBJANSSON
    strlcat(features, "HAVE_LIBJANSSON ", sizeof(features));
#endif
#ifdef PROFILING
    strlcat(features, "PROFILING ", sizeof(features));
#endif
#ifdef PROFILE_LOCKING
    strlcat(features, "PROFILE_LOCKING ", sizeof(features));
#endif
#ifdef TLS
    strlcat(features, "TLS ", sizeof(features));
#endif
    if (strlen(features) == 0) {
        strlcat(features, "none", sizeof(features));
    }

    printf("Features: %s\n", features);

    /* SIMD stuff */
    memset(features, 0x00, sizeof(features));
#if defined(__SSE4_2__)
    strlcat(features, "SSE_4_2 ", sizeof(features));
#endif
#if defined(__SSE4_1__)
    strlcat(features, "SSE_4_1 ", sizeof(features));
#endif
#if defined(__SSE3__)
    strlcat(features, "SSE_3 ", sizeof(features));
#endif
#if defined(__tile__)
    strlcat(features, "Tilera ", sizeof(features));
#endif
    if (strlen(features) == 0) {
        strlcat(features, "none", sizeof(features));
    }
    printf("SIMD support: %s\n", features);

    /* atomics stuff */
    memset(features, 0x00, sizeof(features));
#if defined(__GCC_HAVE_SYNC_COMPARE_AND_SWAP_1)
    strlcat(features, "1 ", sizeof(features));
#endif
#if defined(__GCC_HAVE_SYNC_COMPARE_AND_SWAP_2)
    strlcat(features, "2 ", sizeof(features));
#endif
#if defined(__GCC_HAVE_SYNC_COMPARE_AND_SWAP_4)
    strlcat(features, "4 ", sizeof(features));
#endif
#if defined(__GCC_HAVE_SYNC_COMPARE_AND_SWAP_8)
    strlcat(features, "8 ", sizeof(features));
#endif
#if defined(__GCC_HAVE_SYNC_COMPARE_AND_SWAP_16)
    strlcat(features, "16 ", sizeof(features));
#endif
    if (strlen(features) == 0) {
        strlcat(features, "none", sizeof(features));
    } else {
        strlcat(features, "byte(s)", sizeof(features));
    }
    printf("Atomic intrisics: %s\n", features);

#if __WORDSIZE == 64
    bits = "64-bits";
#elif __WORDSIZE == 32
    bits = "32-bits";
#endif

#if __BYTE_ORDER == __BIG_ENDIAN
    endian = "Big-endian";
#elif __BYTE_ORDER == __LITTLE_ENDIAN
    endian = "Little-endian";
#endif

    printf("%s, %s architecture\n", bits, endian);
#ifdef __GNUC__
    printf("GCC version %s, C version %"PRIiMAX"\n", __VERSION__, (intmax_t)__STDC_VERSION__);
#else
    printf("C version %"PRIiMAX"\n", (intmax_t)__STDC_VERSION__);
#endif

#if __SSP__ == 1
    printf("compiled with -fstack-protector\n");
#endif
#if __SSP_ALL__ == 2
    printf("compiled with -fstack-protector-all\n");
#endif
/*
 * Workaround for special defines of _FORTIFY_SOURCE like
 * FORTIFY_SOURCE=((defined __OPTIMIZE && OPTIMIZE > 0) ? 2 : 0)
 * which is used by Gentoo for example and would result in the error
 * 'defined' undeclared when _FORTIFY_SOURCE used via %d in printf func
 *
 */
#if _FORTIFY_SOURCE == 2
    printf("compiled with _FORTIFY_SOURCE=2\n");
#elif _FORTIFY_SOURCE == 1
    printf("compiled with _FORTIFY_SOURCE=1\n");
#elif _FORTIFY_SOURCE == 0
    printf("compiled with _FORTIFY_SOURCE=0\n");
#endif
#ifdef CLS
    printf("L1 cache line size (CLS)=%d\n", CLS);
#endif
#ifdef TLS
    tls = "__thread";
#endif
    printf("thread local storage method: %s\n", tls);

    printf("compiled with %s, linked against %s\n",
           HTP_VERSION_STRING_FULL, htp_get_version());
    printf("\n");
#include "build-info.h"
}

int coverage_unittests;
int g_ut_modules;
int g_ut_covered;

void RegisterAllModules()
{
    /* commanders */
    TmModuleUnixManagerRegister();
    /* managers */
    TmModuleFlowManagerRegister();
    TmModuleFlowRecyclerRegister();
    /* nfq */
    TmModuleReceiveNFQRegister();
    TmModuleVerdictNFQRegister();
    TmModuleDecodeNFQRegister();
    /* ipfw */
    TmModuleReceiveIPFWRegister();
    TmModuleVerdictIPFWRegister();
    TmModuleDecodeIPFWRegister();
    /* pcap live */
    TmModuleReceivePcapRegister();
    TmModuleDecodePcapRegister();
    /* pcap file */
    TmModuleReceivePcapFileRegister();
    TmModuleDecodePcapFileRegister();
#ifdef HAVE_MPIPE
    /* mpipe */
    TmModuleReceiveMpipeRegister();
    TmModuleDecodeMpipeRegister();
#endif
    /* af-packet */
    TmModuleReceiveAFPRegister();
    TmModuleDecodeAFPRegister();
    /* netmap */
    TmModuleReceiveNetmapRegister();
    TmModuleDecodeNetmapRegister();
    /* pfring */
    TmModuleReceivePfringRegister();
    TmModuleDecodePfringRegister();
    /* dag file */
    TmModuleReceiveErfFileRegister();
    TmModuleDecodeErfFileRegister();
    /* dag live */
    TmModuleReceiveErfDagRegister();
    TmModuleDecodeErfDagRegister();
    /* napatech */
    TmModuleNapatechStreamRegister();
    TmModuleNapatechDecodeRegister();

    /* flow worker */
    TmModuleFlowWorkerRegister();
    /* respond-reject */
    TmModuleRespondRejectRegister();

    /* log api */
    TmModuleLoggerRegister();
    TmModuleStatsLoggerRegister();

    TmModuleDebugList();
    /* nflog */
    TmModuleReceiveNFLOGRegister();
    TmModuleDecodeNFLOGRegister();
}

static TmEcode LoadYamlConfig(SCInstance *suri)
{
    SCEnter();

    if (suri->conf_filename == NULL)
        suri->conf_filename = DEFAULT_CONF_FILE;

    if (ConfYamlLoadFile(suri->conf_filename) != 0) {
        /* Error already displayed. */
        SCReturnInt(TM_ECODE_FAILED);
    }

    SCReturnInt(TM_ECODE_OK);
}

static TmEcode ParseInterfacesList(int runmode, char *pcap_dev)
{
    SCEnter();

    /* run the selected runmode */
    if (runmode == RUNMODE_PCAP_DEV) {
        if (strlen(pcap_dev) == 0) {
            int ret = LiveBuildDeviceList("pcap");
            if (ret == 0) {
                SCLogError(SC_ERR_INITIALIZATION, "No interface found in config for pcap");
                SCReturnInt(TM_ECODE_FAILED);
            }
        }
#ifdef HAVE_MPIPE
    } else if (runmode == RUNMODE_TILERA_MPIPE) {
        if (strlen(pcap_dev)) {
            if (ConfSetFinal("mpipe.single_mpipe_dev", pcap_dev) != 1) {
                fprintf(stderr, "ERROR: Failed to set mpipe.single_mpipe_dev\n");
                SCReturnInt(TM_ECODE_FAILED);
            }
        } else {
            int ret = LiveBuildDeviceList("mpipe.inputs");
            if (ret == 0) {
                fprintf(stderr, "ERROR: No interface found in config for mpipe\n");
                SCReturnInt(TM_ECODE_FAILED);
            }
        }
#endif
    } else if (runmode == RUNMODE_PFRING) {
        /* FIXME add backward compat support */
        /* iface has been set on command line */
        if (strlen(pcap_dev)) {
            if (ConfSetFinal("pfring.live-interface", pcap_dev) != 1) {
                SCLogError(SC_ERR_INITIALIZATION, "Failed to set pfring.live-interface");
                SCReturnInt(TM_ECODE_FAILED);
            }
        } else {
            /* not an error condition if we have a 1.0 config */
            LiveBuildDeviceList("pfring");
        }
#ifdef HAVE_AF_PACKET
    } else if (runmode == RUNMODE_AFP_DEV) {
        /* iface has been set on command line */
        if (strlen(pcap_dev)) {
            if (ConfSetFinal("af-packet.live-interface", pcap_dev) != 1) {
                SCLogError(SC_ERR_INITIALIZATION, "Failed to set af-packet.live-interface");
                SCReturnInt(TM_ECODE_FAILED);
            }
        } else {
            int ret = LiveBuildDeviceList("af-packet");
            if (ret == 0) {
                SCLogError(SC_ERR_INITIALIZATION, "No interface found in config for af-packet");
                SCReturnInt(TM_ECODE_FAILED);
            }
            if (AFPRunModeIsIPS()) {
                SCLogInfo("AF_PACKET: Setting IPS mode");
                EngineModeSetIPS();
            }
        }
#endif
#ifdef HAVE_NETMAP
    } else if (runmode == RUNMODE_NETMAP) {
        /* iface has been set on command line */
        if (strlen(pcap_dev)) {
            if (ConfSetFinal("netmap.live-interface", pcap_dev) != 1) {
                SCLogError(SC_ERR_INITIALIZATION, "Failed to set netmap.live-interface");
                SCReturnInt(TM_ECODE_FAILED);
            }
        } else {
            int ret = LiveBuildDeviceList("netmap");
            if (ret == 0) {
                SCLogError(SC_ERR_INITIALIZATION, "No interface found in config for netmap");
                SCReturnInt(TM_ECODE_FAILED);
            }
            if (NetmapRunModeIsIPS()) {
                SCLogInfo("Netmap: Setting IPS mode");
                EngineModeSetIPS();
            }
        }
#endif
#ifdef HAVE_NFLOG
    } else if (runmode == RUNMODE_NFLOG) {
        int ret = LiveBuildDeviceListCustom("nflog", "group");
        if (ret == 0) {
            SCLogError(SC_ERR_INITIALIZATION, "No group found in config for nflog");
            SCReturnInt(TM_ECODE_FAILED);
        }
#endif
    }

    SCReturnInt(TM_ECODE_OK);
}

static void SCInstanceInit(SCInstance *suri)
{
    memset(suri, 0x00, sizeof(*suri));

    suri->run_mode = RUNMODE_UNKNOWN;

    memset(suri->pcap_dev, 0, sizeof(suri->pcap_dev));
    suri->sig_file = NULL;
    suri->sig_file_exclusive = FALSE;
    suri->pid_filename = NULL;
    suri->regex_arg = NULL;

    suri->keyword_info = NULL;
    suri->runmode_custom_mode = NULL;
#ifndef OS_WIN32
    suri->user_name = NULL;
    suri->group_name = NULL;
    suri->do_setuid = FALSE;
    suri->do_setgid = FALSE;
    suri->userid = 0;
    suri->groupid = 0;
#endif /* OS_WIN32 */
    suri->delayed_detect = 0;
    suri->daemon = 0;
    suri->offline = 0;
    suri->verbose = 0;
    /* use -1 as unknown */
    suri->checksum_validation = -1;
#if HAVE_DETECT_DISABLED==1
    g_detect_disabled = suri->disabled_detect = 1;
#else
    g_detect_disabled = suri->disabled_detect = 0;
#endif
}

static TmEcode PrintVersion()
{
#ifdef REVISION
    printf("This is %s version %s (rev %s)\n", PROG_NAME, PROG_VER, xstr(REVISION));
#elif defined RELEASE
    printf("This is %s version %s RELEASE\n", PROG_NAME, PROG_VER);
#else
    printf("This is %s version %s\n", PROG_NAME, PROG_VER);
#endif
    return TM_ECODE_OK;
}

static TmEcode SCPrintVersion()
{
#ifdef REVISION
    SCLogNotice("This is %s version %s (rev %s)", PROG_NAME, PROG_VER, xstr(REVISION));
#elif defined RELEASE
    SCLogNotice("This is %s version %s RELEASE", PROG_NAME, PROG_VER);
#else
    SCLogNotice("This is %s version %s", PROG_NAME, PROG_VER);
#endif
    return TM_ECODE_OK;
}

static void SCSetStartTime(SCInstance *suri)
{
    memset(&suri->start_time, 0, sizeof(suri->start_time));
    gettimeofday(&suri->start_time, NULL);
}

static void SCPrintElapsedTime(SCInstance *suri)
{
    struct timeval end_time;
    memset(&end_time, 0, sizeof(end_time));
    gettimeofday(&end_time, NULL);
    uint64_t milliseconds = ((end_time.tv_sec - suri->start_time.tv_sec) * 1000) +
        (((1000000 + end_time.tv_usec - suri->start_time.tv_usec) / 1000) - 1000);
    SCLogInfo("time elapsed %.3fs", (float)milliseconds/(float)1000);
}

static int ParseCommandLineAfpacket(SCInstance *suri, const char *in_arg)
{
#ifdef HAVE_AF_PACKET
    if (suri->run_mode == RUNMODE_UNKNOWN) {
        suri->run_mode = RUNMODE_AFP_DEV;
        if (in_arg) {
            LiveRegisterDevice(in_arg);
            memset(suri->pcap_dev, 0, sizeof(suri->pcap_dev));
            strlcpy(suri->pcap_dev, in_arg, sizeof(suri->pcap_dev));
        }
    } else if (suri->run_mode == RUNMODE_AFP_DEV) {
        SCLogWarning(SC_WARN_PCAP_MULTI_DEV_EXPERIMENTAL, "using "
                "multiple devices to get packets is experimental.");
        if (in_arg) {
            LiveRegisterDevice(in_arg);
        } else {
            SCLogInfo("Multiple af-packet option without interface on each is useless");
        }
    } else {
        SCLogError(SC_ERR_MULTIPLE_RUN_MODE, "more than one run mode "
                "has been specified");
        usage(suri->progname);
        return TM_ECODE_FAILED;
    }
    return TM_ECODE_OK;
#else
    SCLogError(SC_ERR_NO_AF_PACKET,"AF_PACKET not enabled. On Linux "
            "host, make sure to pass --enable-af-packet to "
            "configure when building.");
    return TM_ECODE_FAILED;
#endif
}

static int ParseCommandLinePcapLive(SCInstance *suri, const char *in_arg)
{
    memset(suri->pcap_dev, 0, sizeof(suri->pcap_dev));

    if (in_arg != NULL) {
        /* some windows shells require escaping of the \ in \Device. Otherwise
         * the backslashes are stripped. We put them back here. */
        if (strlen(in_arg) > 9 && strncmp(in_arg, "DeviceNPF", 9) == 0) {
            snprintf(suri->pcap_dev, sizeof(suri->pcap_dev), "\\Device\\NPF%s", in_arg+9);
        } else {
            strlcpy(suri->pcap_dev, in_arg, sizeof(suri->pcap_dev));
            PcapTranslateIPToDevice(suri->pcap_dev, sizeof(suri->pcap_dev));
        }

        if (strcmp(suri->pcap_dev, in_arg) != 0) {
            SCLogInfo("translated %s to pcap device %s", in_arg, suri->pcap_dev);
        } else if (strlen(suri->pcap_dev) > 0 && isdigit((unsigned char)suri->pcap_dev[0])) {
            SCLogError(SC_ERR_PCAP_TRANSLATE, "failed to find a pcap device for IP %s", in_arg);
            return TM_ECODE_FAILED;
        }
    }

    if (suri->run_mode == RUNMODE_UNKNOWN) {
        suri->run_mode = RUNMODE_PCAP_DEV;
        if (in_arg) {
            LiveRegisterDevice(suri->pcap_dev);
        }
    } else if (suri->run_mode == RUNMODE_PCAP_DEV) {
#ifdef OS_WIN32
        SCLogError(SC_ERR_PCAP_MULTI_DEV_NO_SUPPORT, "pcap multi dev "
                "support is not (yet) supported on Windows.");
        return TM_ECODE_FAILED;
#else
        SCLogWarning(SC_WARN_PCAP_MULTI_DEV_EXPERIMENTAL, "using "
                "multiple pcap devices to get packets is experimental.");
        LiveRegisterDevice(suri->pcap_dev);
#endif
    } else {
        SCLogError(SC_ERR_MULTIPLE_RUN_MODE, "more than one run mode "
                "has been specified");
        usage(suri->progname);
        return TM_ECODE_FAILED;
    }
    return TM_ECODE_OK;
}

static TmEcode ParseCommandLine(int argc, char** argv, SCInstance *suri)
{
    int opt;

    int dump_config = 0;
    int list_app_layer_protocols = 0;
    int list_unittests = 0;
    int list_cuda_cards = 0;
    int list_runmodes = 0;
    int list_keywords = 0;
    int build_info = 0;
    int conf_test = 0;
#ifdef AFLFUZZ_CONF_TEST
    int conf_test_force_success = 0;
#endif
    int engine_analysis = 0;
    int set_log_directory = 0;
    int ret = TM_ECODE_OK;

#ifdef UNITTESTS
    coverage_unittests = 0;
    g_ut_modules = 0;
    g_ut_covered = 0;
#endif

    struct option long_opts[] = {
        {"dump-config", 0, &dump_config, 1},
        {"pfring", optional_argument, 0, 0},
        {"pfring-int", required_argument, 0, 0},
        {"pfring-cluster-id", required_argument, 0, 0},
        {"pfring-cluster-type", required_argument, 0, 0},
        {"af-packet", optional_argument, 0, 0},
        {"netmap", optional_argument, 0, 0},
        {"pcap", optional_argument, 0, 0},
        {"simulate-ips", 0, 0 , 0},

        /* AFL app-layer options. */
        {"afl-http-request", required_argument, 0 , 0},
        {"afl-http", required_argument, 0 , 0},
        {"afl-tls-request", required_argument, 0 , 0},
        {"afl-tls", required_argument, 0 , 0},
        {"afl-dns-request", required_argument, 0 , 0},
        {"afl-dns", required_argument, 0 , 0},
        {"afl-ssh-request", required_argument, 0 , 0},
        {"afl-ssh", required_argument, 0 , 0},
        {"afl-ftp-request", required_argument, 0 , 0},
        {"afl-ftp", required_argument, 0 , 0},
        {"afl-smtp-request", required_argument, 0 , 0},
        {"afl-smtp", required_argument, 0 , 0},
        {"afl-smb-request", required_argument, 0 , 0},
        {"afl-smb", required_argument, 0 , 0},
        {"afl-modbus-request", required_argument, 0 , 0},
        {"afl-modbus", required_argument, 0 , 0},
        {"afl-enip-request", required_argument, 0 , 0},
        {"afl-enip", required_argument, 0 , 0},
        {"afl-mime", required_argument, 0 , 0},
        {"afl-dnp3-request", required_argument, 0, 0},
        {"afl-dnp3", required_argument, 0, 0},

        /* Other AFL options. */
        {"afl-rules", required_argument, 0 , 0},
        {"afl-mime", required_argument, 0 , 0},
        {"afl-decoder-ppp", required_argument, 0 , 0},
        {"afl-der", required_argument, 0, 0},

#ifdef BUILD_UNIX_SOCKET
        {"unix-socket", optional_argument, 0, 0},
#endif
        {"pcap-buffer-size", required_argument, 0, 0},
        {"unittest-filter", required_argument, 0, 'U'},
        {"list-app-layer-protos", 0, &list_app_layer_protocols, 1},
        {"list-unittests", 0, &list_unittests, 1},
        {"list-cuda-cards", 0, &list_cuda_cards, 1},
        {"list-runmodes", 0, &list_runmodes, 1},
        {"list-keywords", optional_argument, &list_keywords, 1},
        {"runmode", required_argument, NULL, 0},
        {"engine-analysis", 0, &engine_analysis, 1},
#ifdef OS_WIN32
		{"service-install", 0, 0, 0},
		{"service-remove", 0, 0, 0},
		{"service-change-params", 0, 0, 0},
#endif /* OS_WIN32 */
        {"pidfile", required_argument, 0, 0},
        {"init-errors-fatal", 0, 0, 0},
        {"disable-detection", 0, 0, 0},
        {"fatal-unittests", 0, 0, 0},
        {"unittests-coverage", 0, &coverage_unittests, 1},
        {"user", required_argument, 0, 0},
        {"group", required_argument, 0, 0},
        {"erf-in", required_argument, 0, 0},
        {"dag", required_argument, 0, 0},
        {"napatech", 0, 0, 0},
        {"build-info", 0, &build_info, 1},
#ifdef HAVE_MPIPE
        {"mpipe", optional_argument, 0, 0},
#endif
        {"set", required_argument, 0, 0},
#ifdef HAVE_NFLOG
        {"nflog", optional_argument, 0, 0},
#endif
#ifdef AFLFUZZ_CONF_TEST
        {"afl-parse-rules", 0, &conf_test_force_success, 1},
#endif
        {NULL, 0, NULL, 0}
    };

    /* getopt_long stores the option index here. */
    int option_index = 0;

    char short_opts[] = "c:TDhi:l:q:d:r:us:S:U:VF:vk:";

    while ((opt = getopt_long(argc, argv, short_opts, long_opts, &option_index)) != -1) {
        switch (opt) {
        case 0:
            if (strcmp((long_opts[option_index]).name , "pfring") == 0 ||
                strcmp((long_opts[option_index]).name , "pfring-int") == 0) {
#ifdef HAVE_PFRING
                suri->run_mode = RUNMODE_PFRING;
                if (optarg != NULL) {
                    memset(suri->pcap_dev, 0, sizeof(suri->pcap_dev));
                    strlcpy(suri->pcap_dev, optarg,
                            ((strlen(optarg) < sizeof(suri->pcap_dev)) ?
                             (strlen(optarg) + 1) : sizeof(suri->pcap_dev)));
                    LiveRegisterDevice(optarg);
                }
#else
                SCLogError(SC_ERR_NO_PF_RING,"PF_RING not enabled. Make sure "
                        "to pass --enable-pfring to configure when building.");
                return TM_ECODE_FAILED;
#endif /* HAVE_PFRING */
            }
            else if(strcmp((long_opts[option_index]).name , "pfring-cluster-id") == 0){
#ifdef HAVE_PFRING
                if (ConfSetFinal("pfring.cluster-id", optarg) != 1) {
                    fprintf(stderr, "ERROR: Failed to set pfring.cluster-id.\n");
                    return TM_ECODE_FAILED;
                }
#else
                SCLogError(SC_ERR_NO_PF_RING,"PF_RING not enabled. Make sure "
                        "to pass --enable-pfring to configure when building.");
                return TM_ECODE_FAILED;
#endif /* HAVE_PFRING */
            }
            else if(strcmp((long_opts[option_index]).name , "pfring-cluster-type") == 0){
#ifdef HAVE_PFRING
                if (ConfSetFinal("pfring.cluster-type", optarg) != 1) {
                    fprintf(stderr, "ERROR: Failed to set pfring.cluster-type.\n");
                    return TM_ECODE_FAILED;
                }
#else
                SCLogError(SC_ERR_NO_PF_RING,"PF_RING not enabled. Make sure "
                        "to pass --enable-pfring to configure when building.");
                return TM_ECODE_FAILED;
#endif /* HAVE_PFRING */
            }
            else if (strcmp((long_opts[option_index]).name , "af-packet") == 0)
            {
                if (ParseCommandLineAfpacket(suri, optarg) != TM_ECODE_OK) {
                    return TM_ECODE_FAILED;
                }
            } else if (strcmp((long_opts[option_index]).name , "netmap") == 0){
#ifdef HAVE_NETMAP
                if (suri->run_mode == RUNMODE_UNKNOWN) {
                    suri->run_mode = RUNMODE_NETMAP;
                    if (optarg) {
                        LiveRegisterDevice(optarg);
                        memset(suri->pcap_dev, 0, sizeof(suri->pcap_dev));
                        strlcpy(suri->pcap_dev, optarg,
                                ((strlen(optarg) < sizeof(suri->pcap_dev)) ?
                                 (strlen(optarg) + 1) : sizeof(suri->pcap_dev)));
                    }
                } else if (suri->run_mode == RUNMODE_NETMAP) {
                    SCLogWarning(SC_WARN_PCAP_MULTI_DEV_EXPERIMENTAL, "using "
                            "multiple devices to get packets is experimental.");
                    if (optarg) {
                        LiveRegisterDevice(optarg);
                    } else {
                        SCLogInfo("Multiple netmap option without interface on each is useless");
                        break;
                    }
                } else {
                    SCLogError(SC_ERR_MULTIPLE_RUN_MODE, "more than one run mode "
                            "has been specified");
                    usage(argv[0]);
                    return TM_ECODE_FAILED;
                }
#else
                    SCLogError(SC_ERR_NO_NETMAP, "NETMAP not enabled.");
                    return TM_ECODE_FAILED;
#endif
            } else if (strcmp((long_opts[option_index]).name, "nflog") == 0) {
#ifdef HAVE_NFLOG
                if (suri->run_mode == RUNMODE_UNKNOWN) {
                    suri->run_mode = RUNMODE_NFLOG;
                    LiveBuildDeviceListCustom("nflog", "group");
                }
#else
                SCLogError(SC_ERR_NFLOG_NOSUPPORT, "NFLOG not enabled.");
                return TM_ECODE_FAILED;
#endif /* HAVE_NFLOG */
            } else if (strcmp((long_opts[option_index]).name , "pcap") == 0) {
                if (ParseCommandLinePcapLive(suri, optarg) != TM_ECODE_OK) {
                    return TM_ECODE_FAILED;
                }
#ifdef AFLFUZZ_RULES
            } else if(strcmp((long_opts[option_index]).name, "afl-rules") == 0) {
                MpmTableSetup();
                SpmTableSetup();
                exit(RuleParseDataFromFile(optarg));
#endif
#ifdef AFLFUZZ_APPLAYER
            } else if(strcmp((long_opts[option_index]).name, "afl-http-request") == 0) {
                //printf("arg: //%s\n", optarg);
                MpmTableSetup();
                SpmTableSetup();
                AppLayerProtoDetectSetup();
                AppLayerParserSetup();
                RegisterHTPParsers();
                exit(AppLayerParserRequestFromFile(ALPROTO_HTTP, optarg));
            } else if(strcmp((long_opts[option_index]).name, "afl-http") == 0) {
                //printf("arg: //%s\n", optarg);
                MpmTableSetup();
                SpmTableSetup();
                AppLayerProtoDetectSetup();
                AppLayerParserSetup();
                RegisterHTPParsers();
                exit(AppLayerParserFromFile(ALPROTO_HTTP, optarg));

            } else if(strcmp((long_opts[option_index]).name, "afl-tls-request") == 0) {
                //printf("arg: //%s\n", optarg);
                MpmTableSetup();
                SpmTableSetup();
                AppLayerProtoDetectSetup();
                AppLayerParserSetup();
                RegisterSSLParsers();
                exit(AppLayerParserRequestFromFile(ALPROTO_TLS, optarg));
            } else if(strcmp((long_opts[option_index]).name, "afl-tls") == 0) {
                //printf("arg: //%s\n", optarg);
                MpmTableSetup();
                SpmTableSetup();
                AppLayerProtoDetectSetup();
                AppLayerParserSetup();
                RegisterSSLParsers();
                exit(AppLayerParserFromFile(ALPROTO_TLS, optarg));

            } else if(strcmp((long_opts[option_index]).name, "afl-dns-request") == 0) {
                //printf("arg: //%s\n", optarg);
                RegisterDNSTCPParsers();
                exit(AppLayerParserRequestFromFile(ALPROTO_DNS, optarg));
            } else if(strcmp((long_opts[option_index]).name, "afl-dns") == 0) {
                //printf("arg: //%s\n", optarg);
                AppLayerParserSetup();
                RegisterDNSTCPParsers();
                exit(AppLayerParserFromFile(ALPROTO_DNS, optarg));

            } else if(strcmp((long_opts[option_index]).name, "afl-ssh-request") == 0) {
                //printf("arg: //%s\n", optarg);
                MpmTableSetup();
                SpmTableSetup();
                AppLayerProtoDetectSetup();
                RegisterSSHParsers();
                exit(AppLayerParserRequestFromFile(ALPROTO_SSH, optarg));
            } else if(strcmp((long_opts[option_index]).name, "afl-ssh") == 0) {
                //printf("arg: //%s\n", optarg);
                MpmTableSetup();
                SpmTableSetup();
                AppLayerProtoDetectSetup();
                AppLayerParserSetup();
                RegisterSSHParsers();
                exit(AppLayerParserFromFile(ALPROTO_SSH, optarg));

            } else if(strcmp((long_opts[option_index]).name, "afl-ftp-request") == 0) {
                //printf("arg: //%s\n", optarg);
                MpmTableSetup();
                SpmTableSetup();
                AppLayerProtoDetectSetup();
                AppLayerParserSetup();
                RegisterFTPParsers();
                exit(AppLayerParserRequestFromFile(ALPROTO_FTP, optarg));
            } else if(strcmp((long_opts[option_index]).name, "afl-ftp") == 0) {
                //printf("arg: //%s\n", optarg);
                MpmTableSetup();
                SpmTableSetup();
                AppLayerProtoDetectSetup();
                AppLayerParserSetup();
                RegisterFTPParsers();
                exit(AppLayerParserFromFile(ALPROTO_FTP, optarg));

            } else if(strcmp((long_opts[option_index]).name, "afl-smtp-request") == 0) {
                //printf("arg: //%s\n", optarg);
                MpmTableSetup();
                SpmTableSetup();
                AppLayerProtoDetectSetup();
                AppLayerParserSetup();
                RegisterSMTPParsers();
                exit(AppLayerParserRequestFromFile(ALPROTO_SMTP, optarg));
            } else if(strcmp((long_opts[option_index]).name, "afl-smtp") == 0) {
                //printf("arg: //%s\n", optarg);
                MpmTableSetup();
                SpmTableSetup();
                AppLayerProtoDetectSetup();
                AppLayerParserSetup();
                RegisterSMTPParsers();
                exit(AppLayerParserFromFile(ALPROTO_SMTP, optarg));

            } else if(strcmp((long_opts[option_index]).name, "afl-smb-request") == 0) {
                //printf("arg: //%s\n", optarg);
                MpmTableSetup();
                SpmTableSetup();
                AppLayerProtoDetectSetup();
                RegisterSMBParsers();
                exit(AppLayerParserRequestFromFile(ALPROTO_SMB, optarg));
            } else if(strcmp((long_opts[option_index]).name, "afl-smb") == 0) {
                //printf("arg: //%s\n", optarg);
                MpmTableSetup();
                SpmTableSetup();
                AppLayerProtoDetectSetup();
                AppLayerParserSetup();
                RegisterSMBParsers();
                exit(AppLayerParserFromFile(ALPROTO_SMB, optarg));

            } else if(strcmp((long_opts[option_index]).name, "afl-modbus-request") == 0) {
                //printf("arg: //%s\n", optarg);
                AppLayerParserSetup();
                RegisterModbusParsers();
                exit(AppLayerParserRequestFromFile(ALPROTO_MODBUS, optarg));
            } else if(strcmp((long_opts[option_index]).name, "afl-modbus") == 0) {
                //printf("arg: //%s\n", optarg);
                AppLayerParserSetup();
                RegisterModbusParsers();
                exit(AppLayerParserFromFile(ALPROTO_MODBUS, optarg));
            } else if(strcmp((long_opts[option_index]).name, "afl-enip-request") == 0) {
                //printf("arg: //%s\n", optarg);
                AppLayerParserSetup();
                RegisterENIPTCPParsers();
                exit(AppLayerParserRequestFromFile(ALPROTO_ENIP, optarg));
            } else if(strcmp((long_opts[option_index]).name, "afl-enip") == 0) {
                //printf("arg: //%s\n", optarg);
                AppLayerParserSetup();
                RegisterENIPTCPParsers();
                exit(AppLayerParserFromFile(ALPROTO_ENIP, optarg));
            } else if(strcmp((long_opts[option_index]).name, "afl-dnp3-request") == 0) {
                AppLayerParserSetup();
                RegisterDNP3Parsers();
                exit(AppLayerParserRequestFromFile(ALPROTO_DNP3, optarg));
            } else if(strcmp((long_opts[option_index]).name, "afl-dnp3") == 0) {
                AppLayerParserSetup();
                RegisterDNP3Parsers();
                exit(AppLayerParserFromFile(ALPROTO_DNP3, optarg));
#endif
#ifdef AFLFUZZ_MIME
            } else if(strcmp((long_opts[option_index]).name, "afl-mime") == 0) {
                //printf("arg: //%s\n", optarg);
                exit(MimeParserDataFromFile(optarg));
#endif
#ifdef AFLFUZZ_DECODER
            } else if(strcmp((long_opts[option_index]).name, "afl-decoder-ppp") == 0) {
                StatsInit();
                MpmTableSetup();
                SpmTableSetup();
                AppLayerProtoDetectSetup();
                DefragInit();
                FlowInitConfig(FLOW_QUIET);
                //printf("arg: //%s\n", optarg);
                exit(DecoderParseDataFromFile(optarg, DecodePPP));
#endif
#ifdef AFLFUZZ_DER
            } else if(strcmp((long_opts[option_index]).name, "afl-der") == 0) {
                //printf("arg: //%s\n", optarg);
                exit(DerParseDataFromFile(optarg));
#endif
            } else if(strcmp((long_opts[option_index]).name, "simulate-ips") == 0) {
                SCLogInfo("Setting IPS mode");
                EngineModeSetIPS();
            } else if(strcmp((long_opts[option_index]).name, "init-errors-fatal") == 0) {
                if (ConfSetFinal("engine.init-failure-fatal", "1") != 1) {
                    fprintf(stderr, "ERROR: Failed to set engine init-failure-fatal.\n");
                    return TM_ECODE_FAILED;
                }
#ifdef BUILD_UNIX_SOCKET
            } else if (strcmp((long_opts[option_index]).name , "unix-socket") == 0) {
                if (suri->run_mode == RUNMODE_UNKNOWN) {
                    suri->run_mode = RUNMODE_UNIX_SOCKET;
                    if (optarg) {
                        if (ConfSetFinal("unix-command.filename", optarg) != 1) {
                            fprintf(stderr, "ERROR: Failed to set unix-command.filename.\n");
                            return TM_ECODE_FAILED;
                        }

                    }
                } else {
                    SCLogError(SC_ERR_MULTIPLE_RUN_MODE, "more than one run mode "
                            "has been specified");
                    usage(argv[0]);
                    return TM_ECODE_FAILED;
                }
#endif
            }
            else if(strcmp((long_opts[option_index]).name, "list-app-layer-protocols") == 0) {
                /* listing all supported app layer protocols */
            }
            else if(strcmp((long_opts[option_index]).name, "list-unittests") == 0) {
#ifdef UNITTESTS
                suri->run_mode = RUNMODE_LIST_UNITTEST;
#else
                fprintf(stderr, "ERROR: Unit tests not enabled. Make sure to pass --enable-unittests to configure when building.\n");
                return TM_ECODE_FAILED;
#endif /* UNITTESTS */
            } else if(strcmp((long_opts[option_index]).name, "list-cuda-cards") == 0) {
#ifndef __SC_CUDA_SUPPORT__
                fprintf(stderr, "ERROR: Cuda not enabled. Make sure to pass "
                        "--enable-cuda to configure when building.\n");
                return TM_ECODE_FAILED;
#endif /* UNITTESTS */
            } else if (strcmp((long_opts[option_index]).name, "list-runmodes") == 0) {
                suri->run_mode = RUNMODE_LIST_RUNMODES;
                return TM_ECODE_OK;
            } else if (strcmp((long_opts[option_index]).name, "list-keywords") == 0) {
                if (optarg) {
                    if (strcmp("short",optarg)) {
                        suri->keyword_info = optarg;
                    }
                }
            } else if (strcmp((long_opts[option_index]).name, "runmode") == 0) {
                suri->runmode_custom_mode = optarg;
            } else if(strcmp((long_opts[option_index]).name, "engine-analysis") == 0) {
                // do nothing for now
            }
#ifdef OS_WIN32
            else if(strcmp((long_opts[option_index]).name, "service-install") == 0) {
                suri->run_mode = RUNMODE_INSTALL_SERVICE;
                return TM_ECODE_OK;
            }
            else if(strcmp((long_opts[option_index]).name, "service-remove") == 0) {
                suri->run_mode = RUNMODE_REMOVE_SERVICE;
                return TM_ECODE_OK;
            }
            else if(strcmp((long_opts[option_index]).name, "service-change-params") == 0) {
                suri->run_mode = RUNMODE_CHANGE_SERVICE_PARAMS;
                return TM_ECODE_OK;
            }
#endif /* OS_WIN32 */
            else if(strcmp((long_opts[option_index]).name, "pidfile") == 0) {
                suri->pid_filename = optarg;
            }
            else if(strcmp((long_opts[option_index]).name, "disable-detection") == 0) {
                g_detect_disabled = suri->disabled_detect = 1;
                SCLogInfo("detection engine disabled");
            }
            else if(strcmp((long_opts[option_index]).name, "fatal-unittests") == 0) {
#ifdef UNITTESTS
                unittests_fatal = 1;
#else
                fprintf(stderr, "ERROR: Unit tests not enabled. Make sure to pass --enable-unittests to configure when building.\n");
                return TM_ECODE_FAILED;
#endif /* UNITTESTS */
            }
            else if(strcmp((long_opts[option_index]).name, "user") == 0) {
#ifndef HAVE_LIBCAP_NG
                SCLogError(SC_ERR_LIBCAP_NG_REQUIRED, "libcap-ng is required to"
                        " drop privileges, but it was not compiled into Suricata.");
                return TM_ECODE_FAILED;
#else
                suri->user_name = optarg;
                suri->do_setuid = TRUE;
#endif /* HAVE_LIBCAP_NG */
            }
            else if(strcmp((long_opts[option_index]).name, "group") == 0) {
#ifndef HAVE_LIBCAP_NG
                SCLogError(SC_ERR_LIBCAP_NG_REQUIRED, "libcap-ng is required to"
                        " drop privileges, but it was not compiled into Suricata.");
                return TM_ECODE_FAILED;
#else
                suri->group_name = optarg;
                suri->do_setgid = TRUE;
#endif /* HAVE_LIBCAP_NG */
            }
            else if (strcmp((long_opts[option_index]).name, "erf-in") == 0) {
                suri->run_mode = RUNMODE_ERF_FILE;
                if (ConfSetFinal("erf-file.file", optarg) != 1) {
                    fprintf(stderr, "ERROR: Failed to set erf-file.file\n");
                    return TM_ECODE_FAILED;
                }
            }
            else if (strcmp((long_opts[option_index]).name, "dag") == 0) {
#ifdef HAVE_DAG
                if (suri->run_mode == RUNMODE_UNKNOWN) {
                    suri->run_mode = RUNMODE_DAG;
                }
                else if (suri->run_mode != RUNMODE_DAG) {
                    SCLogError(SC_ERR_MULTIPLE_RUN_MODE,
                        "more than one run mode has been specified");
                    usage(argv[0]);
                    return TM_ECODE_FAILED;
                }
                LiveRegisterDevice(optarg);
#else
                SCLogError(SC_ERR_DAG_REQUIRED, "libdag and a DAG card are required"
						" to receive packets using --dag.");
                return TM_ECODE_FAILED;
#endif /* HAVE_DAG */
		}
        else if (strcmp((long_opts[option_index]).name, "napatech") == 0) {
#ifdef HAVE_NAPATECH
            suri->run_mode = RUNMODE_NAPATECH;
#else
            SCLogError(SC_ERR_NAPATECH_REQUIRED, "libntapi and a Napatech adapter are required"
                                                 " to capture packets using --napatech.");
            return TM_ECODE_FAILED;
#endif /* HAVE_NAPATECH */
			}
            else if(strcmp((long_opts[option_index]).name, "pcap-buffer-size") == 0) {
#ifdef HAVE_PCAP_SET_BUFF
                if (ConfSetFinal("pcap.buffer-size", optarg) != 1) {
                    fprintf(stderr, "ERROR: Failed to set pcap-buffer-size.\n");
                    return TM_ECODE_FAILED;
                }
#else
                SCLogError(SC_ERR_NO_PCAP_SET_BUFFER_SIZE, "The version of libpcap you have"
                        " doesn't support setting buffer size.");
#endif /* HAVE_PCAP_SET_BUFF */
            }
            else if(strcmp((long_opts[option_index]).name, "build-info") == 0) {
                suri->run_mode = RUNMODE_PRINT_BUILDINFO;
                return TM_ECODE_OK;
            }
#ifdef HAVE_MPIPE
            else if(strcmp((long_opts[option_index]).name , "mpipe") == 0) {
                if (suri->run_mode == RUNMODE_UNKNOWN) {
                    suri->run_mode = RUNMODE_TILERA_MPIPE;
                    if (optarg != NULL) {
                        memset(suri->pcap_dev, 0, sizeof(suri->pcap_dev));
                        strlcpy(suri->pcap_dev, optarg,
                                ((strlen(optarg) < sizeof(suri->pcap_dev)) ?
                                 (strlen(optarg) + 1) : sizeof(suri->pcap_dev)));
                        LiveRegisterDevice(optarg);
                    }
                } else {
                    SCLogError(SC_ERR_MULTIPLE_RUN_MODE,
                               "more than one run mode has been specified");
                    usage(argv[0]);
                    exit(EXIT_FAILURE);
                }
            }
#endif
            else if (strcmp((long_opts[option_index]).name, "set") == 0) {
                if (optarg != NULL) {
                    /* Quick validation. */
                    char *val = strchr(optarg, '=');
                    if (val == NULL) {
                        SCLogError(SC_ERR_CMD_LINE,
                                "Invalid argument for --set, must be key=val.");
                        exit(EXIT_FAILURE);
                    }
                    if (!ConfSetFromString(optarg, 1)) {
                        fprintf(stderr, "Failed to set configuration value %s.",
                                optarg);
                        exit(EXIT_FAILURE);
                    }
                }
            }
            break;
        case 'c':
            suri->conf_filename = optarg;
            break;
        case 'T':
            SCLogInfo("Running suricata under test mode");
            conf_test = 1;
            if (ConfSetFinal("engine.init-failure-fatal", "1") != 1) {
                fprintf(stderr, "ERROR: Failed to set engine init-failure-fatal.\n");
                return TM_ECODE_FAILED;
            }
            break;
#ifndef OS_WIN32
        case 'D':
            suri->daemon = 1;
            break;
#endif /* OS_WIN32 */
        case 'h':
            suri->run_mode = RUNMODE_PRINT_USAGE;
            return TM_ECODE_OK;
        case 'i':
            if (optarg == NULL) {
                SCLogError(SC_ERR_INITIALIZATION, "no option argument (optarg) for -i");
                return TM_ECODE_FAILED;
            }
#ifdef HAVE_AF_PACKET
            if (ParseCommandLineAfpacket(suri, optarg) != TM_ECODE_OK) {
                return TM_ECODE_FAILED;
            }
#else /* not afpacket */
            /* warn user if netmap or pf-ring are available */
#if defined HAVE_PFRING || HAVE_NETMAP
            int i = 0;
#ifdef HAVE_PFRING
            i++;
#endif
#ifdef HAVE_NETMAP
            i++;
#endif
            SCLogWarning(SC_WARN_FASTER_CAPTURE_AVAILABLE, "faster capture "
                    "option%s %s available:"
#ifdef HAVE_PFRING
                    " PF_RING (--pfring-int=%s)"
#endif
#ifdef HAVE_NETMAP
                    " NETMAP (--netmap=%s)"
#endif
                    ". Use --pcap=%s to suppress this warning",
                    i == 1 ? "" : "s", i == 1 ? "is" : "are"
#ifdef HAVE_PFRING
                    , optarg
#endif
#ifdef HAVE_NETMAP
                    , optarg
#endif
                    , optarg
                    );
#endif /* have faster methods */
            if (ParseCommandLinePcapLive(suri, optarg) != TM_ECODE_OK) {
                return TM_ECODE_FAILED;
            }
#endif
            break;
        case 'l':
            if (optarg == NULL) {
                SCLogError(SC_ERR_INITIALIZATION, "no option argument (optarg) for -l");
                return TM_ECODE_FAILED;
            }

            if (ConfigSetLogDirectory(optarg) != TM_ECODE_OK) {
                SCLogError(SC_ERR_FATAL, "Failed to set log directory.\n");
                return TM_ECODE_FAILED;
            }
            if (ConfigCheckLogDirectory(optarg) != TM_ECODE_OK) {
                SCLogError(SC_ERR_LOGDIR_CMDLINE, "The logging directory \"%s\""
                        " supplied at the commandline (-l %s) doesn't "
                        "exist. Shutting down the engine.", optarg, optarg);
                return TM_ECODE_FAILED;
            }
            set_log_directory = 1;

            break;
        case 'q':
#ifdef NFQ
            if (suri->run_mode == RUNMODE_UNKNOWN) {
                suri->run_mode = RUNMODE_NFQ;
                EngineModeSetIPS();
                if (NFQRegisterQueue(optarg) == -1)
                    return TM_ECODE_FAILED;
            } else if (suri->run_mode == RUNMODE_NFQ) {
                if (NFQRegisterQueue(optarg) == -1)
                    return TM_ECODE_FAILED;
            } else {
                SCLogError(SC_ERR_MULTIPLE_RUN_MODE, "more than one run mode "
                                                     "has been specified");
                usage(argv[0]);
                return TM_ECODE_FAILED;
            }
#else
            SCLogError(SC_ERR_NFQ_NOSUPPORT,"NFQUEUE not enabled. Make sure to pass --enable-nfqueue to configure when building.");
            return TM_ECODE_FAILED;
#endif /* NFQ */
            break;
        case 'd':
#ifdef IPFW
            if (suri->run_mode == RUNMODE_UNKNOWN) {
                suri->run_mode = RUNMODE_IPFW;
                EngineModeSetIPS();
                if (IPFWRegisterQueue(optarg) == -1)
                    return TM_ECODE_FAILED;
            } else if (suri->run_mode == RUNMODE_IPFW) {
                if (IPFWRegisterQueue(optarg) == -1)
                    return TM_ECODE_FAILED;
            } else {
                SCLogError(SC_ERR_MULTIPLE_RUN_MODE, "more than one run mode "
                                                     "has been specified");
                usage(argv[0]);
                return TM_ECODE_FAILED;
            }
#else
            SCLogError(SC_ERR_IPFW_NOSUPPORT,"IPFW not enabled. Make sure to pass --enable-ipfw to configure when building.");
            return TM_ECODE_FAILED;
#endif /* IPFW */
            break;
        case 'r':
            if (suri->run_mode == RUNMODE_UNKNOWN) {
                suri->run_mode = RUNMODE_PCAP_FILE;
            } else {
                SCLogError(SC_ERR_MULTIPLE_RUN_MODE, "more than one run mode "
                                                     "has been specified");
                usage(argv[0]);
                return TM_ECODE_FAILED;
            }
            if (ConfSetFinal("pcap-file.file", optarg) != 1) {
                fprintf(stderr, "ERROR: Failed to set pcap-file.file\n");
                return TM_ECODE_FAILED;
            }
            break;
        case 's':
            if (suri->sig_file != NULL) {
                SCLogError(SC_ERR_CMD_LINE, "can't have multiple -s options or mix -s and -S.");
                return TM_ECODE_FAILED;
            }
            suri->sig_file = optarg;
            break;
        case 'S':
            if (suri->sig_file != NULL) {
                SCLogError(SC_ERR_CMD_LINE, "can't have multiple -S options or mix -s and -S.");
                return TM_ECODE_FAILED;
            }
            suri->sig_file = optarg;
            suri->sig_file_exclusive = TRUE;
            break;
        case 'u':
#ifdef UNITTESTS
            if (suri->run_mode == RUNMODE_UNKNOWN) {
                suri->run_mode = RUNMODE_UNITTEST;
            } else {
                SCLogError(SC_ERR_MULTIPLE_RUN_MODE, "more than one run mode has"
                                                     " been specified");
                usage(argv[0]);
                return TM_ECODE_FAILED;
            }
#else
            fprintf(stderr, "ERROR: Unit tests not enabled. Make sure to pass --enable-unittests to configure when building.\n");
            return TM_ECODE_FAILED;
#endif /* UNITTESTS */
            break;
        case 'U':
#ifdef UNITTESTS
            suri->regex_arg = optarg;

            if(strlen(suri->regex_arg) == 0)
                suri->regex_arg = NULL;
#endif
            break;
        case 'V':
            suri->run_mode = RUNMODE_PRINT_VERSION;
            return TM_ECODE_OK;
        case 'F':
            if (optarg == NULL) {
                SCLogError(SC_ERR_INITIALIZATION, "no option argument (optarg) for -F");
                return TM_ECODE_FAILED;
            }

            SetBpfStringFromFile(optarg);
            break;
        case 'v':
            suri->verbose++;
            break;
        case 'k':
            if (optarg == NULL) {
                SCLogError(SC_ERR_INITIALIZATION, "no option argument (optarg) for -k");
                return TM_ECODE_FAILED;
            }
            if (!strcmp("all", optarg))
                suri->checksum_validation = 1;
            else if (!strcmp("none", optarg))
                suri->checksum_validation = 0;
            else {
                SCLogError(SC_ERR_INITIALIZATION, "option '%s' invalid for -k", optarg);
                return TM_ECODE_FAILED;
            }
            break;
        default:
            usage(argv[0]);
            return TM_ECODE_FAILED;
        }
    }

    if (suri->disabled_detect && suri->sig_file != NULL) {
        SCLogError(SC_ERR_INITIALIZATION, "can't use -s/-S when detection is disabled");
        return TM_ECODE_FAILED;
    }
#ifdef AFLFUZZ_CONF_TEST
    if (conf_test && conf_test_force_success) {
        (void)ConfSetFinal("engine.init-failure-fatal", "0");
    }
#endif

    if ((suri->run_mode == RUNMODE_UNIX_SOCKET) && set_log_directory) {
        SCLogError(SC_ERR_INITIALIZATION, "can't use -l and unix socket runmode at the same time");
        return TM_ECODE_FAILED;
    }

    if (list_app_layer_protocols)
        suri->run_mode = RUNMODE_LIST_APP_LAYERS;
    if (list_cuda_cards)
        suri->run_mode = RUNMODE_LIST_CUDA_CARDS;
    if (list_keywords)
        suri->run_mode = RUNMODE_LIST_KEYWORDS;
    if (list_unittests)
        suri->run_mode = RUNMODE_LIST_UNITTEST;
    if (dump_config)
        suri->run_mode = RUNMODE_DUMP_CONFIG;
    if (conf_test)
        suri->run_mode = RUNMODE_CONF_TEST;
    if (engine_analysis)
        suri->run_mode = RUNMODE_ENGINE_ANALYSIS;

    ret = SetBpfString(optind, argv);
    if (ret != TM_ECODE_OK)
        return ret;

    return TM_ECODE_OK;
}

#ifdef OS_WIN32
static int WindowsInitService(int argc, char **argv)
{
    if (SCRunningAsService()) {
        char path[MAX_PATH];
        char *p = NULL;
        strlcpy(path, argv[0], MAX_PATH);
        if ((p = strrchr(path, '\\'))) {
            *p = '\0';
        }
        if (!SetCurrentDirectory(path)) {
            SCLogError(SC_ERR_FATAL, "Can't set current directory to: %s", path);
            return -1;
        }
        SCLogInfo("Current directory is set to: %s", path);
        daemon = 1;
        SCServiceInit(argc, argv);
    }

    /* Windows socket subsystem initialization */
    WSADATA wsaData;
    if (0 != WSAStartup(MAKEWORD(2, 2), &wsaData)) {
        SCLogError(SC_ERR_FATAL, "Can't initialize Windows sockets: %d", WSAGetLastError());
        return -1;
    }

    return 0;
}
#endif /* OS_WIN32 */

static int MayDaemonize(SCInstance *suri)
{
    if (suri->daemon == 1 && suri->pid_filename == NULL) {
        if (ConfGet("pid-file", &suri->pid_filename) == 1) {
            SCLogInfo("Use pid file %s from config file.", suri->pid_filename);
        } else {
            suri->pid_filename = DEFAULT_PID_FILENAME;
        }
    }

    if (suri->pid_filename != NULL && SCPidfileTestRunning(suri->pid_filename) != 0) {
        suri->pid_filename = NULL;
        return TM_ECODE_FAILED;
    }

    if (suri->daemon == 1) {
        Daemonize();
    }

    if (suri->pid_filename != NULL) {
        if (SCPidfileCreate(suri->pid_filename) != 0) {
            suri->pid_filename = NULL;
            SCLogError(SC_ERR_PIDFILE_DAEMON,
                    "Unable to create PID file, concurrent run of"
                    " Suricata can occur.");
            SCLogError(SC_ERR_PIDFILE_DAEMON,
                    "PID file creation WILL be mandatory for daemon mode"
                    " in future version");
        }
    }

    return TM_ECODE_OK;
}

static int InitSignalHandler(SCInstance *suri)
{
    /* registering signals we use */
    UtilSignalHandlerSetup(SIGINT, SignalHandlerSigint);
    UtilSignalHandlerSetup(SIGUSR2, SignalHandlerSigusr2);
    UtilSignalHandlerSetup(SIGTERM, SignalHandlerSigterm);
    UtilSignalHandlerSetup(SIGPIPE, SIG_IGN);
    UtilSignalHandlerSetup(SIGSYS, SIG_IGN);

#ifndef OS_WIN32
    /* SIGHUP is not implemented on WIN32 */
    UtilSignalHandlerSetup(SIGHUP, SignalHandlerSigHup);

    /* Try to get user/group to run suricata as if
       command line as not decide of that */
    if (suri->do_setuid == FALSE && suri->do_setgid == FALSE) {
        char *id;
        if (ConfGet("run-as.user", &id) == 1) {
            suri->do_setuid = TRUE;
            suri->user_name = id;
        }
        if (ConfGet("run-as.group", &id) == 1) {
            suri->do_setgid = TRUE;
            suri->group_name = id;
        }
    }
    /* Get the suricata user ID to given user ID */
    if (suri->do_setuid == TRUE) {
        if (SCGetUserID(suri->user_name, suri->group_name,
                        &suri->userid, &suri->groupid) != 0) {
            SCLogError(SC_ERR_UID_FAILED, "failed in getting user ID");
            return TM_ECODE_FAILED;
        }

        sc_set_caps = TRUE;
    /* Get the suricata group ID to given group ID */
    } else if (suri->do_setgid == TRUE) {
        if (SCGetGroupID(suri->group_name, &suri->groupid) != 0) {
            SCLogError(SC_ERR_GID_FAILED, "failed in getting group ID");
            return TM_ECODE_FAILED;
        }

        sc_set_caps = TRUE;
    }
#endif /* OS_WIN32 */

    return TM_ECODE_OK;
}

int StartInternalRunMode(SCInstance *suri, int argc, char **argv)
{
    /* Treat internal running mode */
    switch(suri->run_mode) {
        case RUNMODE_LIST_KEYWORDS:
            ListKeywords(suri->keyword_info);
            return TM_ECODE_DONE;
        case RUNMODE_LIST_APP_LAYERS:
            ListAppLayerProtocols();
            return TM_ECODE_DONE;
        case RUNMODE_PRINT_VERSION:
            PrintVersion();
            return TM_ECODE_DONE;
        case RUNMODE_PRINT_BUILDINFO:
            SCPrintBuildInfo();
            return TM_ECODE_DONE;
        case RUNMODE_PRINT_USAGE:
            usage(argv[0]);
            return TM_ECODE_DONE;
#ifdef __SC_CUDA_SUPPORT__
        case RUNMODE_LIST_CUDA_CARDS:
            return ListCudaCards();
#endif
        case RUNMODE_LIST_RUNMODES:
            RunModeListRunmodes();
            return TM_ECODE_DONE;
        case RUNMODE_LIST_UNITTEST:
            RunUnittests(1, suri->regex_arg);
        case RUNMODE_UNITTEST:
            RunUnittests(0, suri->regex_arg);
#ifdef OS_WIN32
        case RUNMODE_INSTALL_SERVICE:
            if (SCServiceInstall(argc, argv)) {
                return TM_ECODE_FAILED;
            }
            SCLogInfo("Suricata service has been successfuly installed.");
            return TM_ECODE_DONE;
        case RUNMODE_REMOVE_SERVICE:
            if (SCServiceRemove(argc, argv)) {
                return TM_ECODE_FAILED;
            }
            SCLogInfo("Suricata service has been successfuly removed.");
            return TM_ECODE_DONE;
        case RUNMODE_CHANGE_SERVICE_PARAMS:
            if (SCServiceChangeParams(argc, argv)) {
                return TM_ECODE_FAILED;
            }
            SCLogInfo("Suricata service startup parameters has been successfuly changed.");
            return TM_ECODE_DONE;
#endif /* OS_WIN32 */
        default:
            /* simply continue for other running mode */
            break;
    }
    return TM_ECODE_OK;
}

static int FinalizeRunMode(SCInstance *suri, char **argv)
{
    switch (suri->run_mode) {
        case RUNMODE_PCAP_FILE:
        case RUNMODE_ERF_FILE:
        case RUNMODE_ENGINE_ANALYSIS:
            suri->offline = 1;
            break;
        case RUNMODE_UNKNOWN:
            usage(argv[0]);
            return TM_ECODE_FAILED;
        default:
            break;
    }
    /* Set the global run mode */
    run_mode = suri->run_mode;

    if (!CheckValidDaemonModes(suri->daemon, suri->run_mode)) {
        return TM_ECODE_FAILED;
    }

    return TM_ECODE_OK;
}

static void SetupDelayedDetect(SCInstance *suri)
{
    /* In offline mode delayed init of detect is a bad idea */
    if (suri->offline) {
        suri->delayed_detect = 0;
    } else {
        if (ConfGetBool("detect.delayed-detect", &suri->delayed_detect) != 1) {
            ConfNode *denode = NULL;
            ConfNode *decnf = ConfGetNode("detect-engine");
            if (decnf != NULL) {
                TAILQ_FOREACH(denode, &decnf->head, next) {
                    if (strcmp(denode->val, "delayed-detect") == 0) {
                        (void)ConfGetChildValueBool(denode, "delayed-detect", &suri->delayed_detect);
                    }
                }
            }
        }
    }

    SCLogConfig("Delayed detect %s", suri->delayed_detect ? "enabled" : "disabled");
    if (suri->delayed_detect) {
        SCLogInfo("Packets will start being processed before signatures are active.");
    }

}

static int LoadSignatures(DetectEngineCtx *de_ctx, SCInstance *suri)
{
    if (SigLoadSignatures(de_ctx, suri->sig_file, suri->sig_file_exclusive) < 0) {
        SCLogError(SC_ERR_NO_RULES_LOADED, "Loading signatures failed.");
        if (de_ctx->failure_fatal)
            return TM_ECODE_FAILED;
    }

    SCThresholdConfInitContext(de_ctx, NULL);
    return TM_ECODE_OK;
}

static int ConfigGetCaptureValue(SCInstance *suri)
{
    /* Pull the max pending packets from the config, if not found fall
     * back on a sane default. */
    if (ConfGetInt("max-pending-packets", &max_pending_packets) != 1)
        max_pending_packets = DEFAULT_MAX_PENDING_PACKETS;
    if (max_pending_packets >= 65535) {
        SCLogError(SC_ERR_INVALID_YAML_CONF_ENTRY,
                "Maximum max-pending-packets setting is 65534. "
                "Please check %s for errors", suri->conf_filename);
        return TM_ECODE_FAILED;
    }

    SCLogDebug("Max pending packets set to %"PRIiMAX, max_pending_packets);

    /* Pull the default packet size from the config, if not found fall
     * back on a sane default. */
    char *temp_default_packet_size;
    if ((ConfGet("default-packet-size", &temp_default_packet_size)) != 1) {
        int lthread;
        int nlive;
        int strip_trailing_plus = 0;
        switch (suri->run_mode) {
            case RUNMODE_PCAP_DEV:
            case RUNMODE_AFP_DEV:
            case RUNMODE_NETMAP:
                /* in netmap igb0+ has a special meaning, however the
                 * interface really is igb0 */
                strip_trailing_plus = 1;
                /* fall through */
            case RUNMODE_PFRING:
                nlive = LiveGetDeviceCount();
                for (lthread = 0; lthread < nlive; lthread++) {
                    const char *live_dev = LiveGetDeviceName(lthread);
                    char dev[32];
                    (void)strlcpy(dev, live_dev, sizeof(dev));

                    if (strip_trailing_plus) {
                        size_t len = strlen(dev);
                        if (len && dev[len-1] == '+') {
                            dev[len-1] = '\0';
                        }
                    }

                    unsigned int iface_max_packet_size = GetIfaceMaxPacketSize(dev);
                    if (iface_max_packet_size > default_packet_size)
                        default_packet_size = iface_max_packet_size;
                }
                if (default_packet_size)
                    break;
                /* fall through */
            default:
                default_packet_size = DEFAULT_PACKET_SIZE;
        }
    } else {
        if (ParseSizeStringU32(temp_default_packet_size, &default_packet_size) < 0) {
            SCLogError(SC_ERR_SIZE_PARSE, "Error parsing max-pending-packets "
                       "from conf file - %s.  Killing engine",
                       temp_default_packet_size);
            return TM_ECODE_FAILED;
        }
    }

    SCLogDebug("Default packet size set to %"PRIu32, default_packet_size);

    return TM_ECODE_OK;
}
/**
 * This function is meant to contain code that needs
 * to be run once the configuration has been loaded.
 */
static int PostConfLoadedSetup(SCInstance *suri)
{
    char *hostmode = NULL;

    /* do this as early as possible #1577 #1955 */
#ifdef HAVE_LUAJIT
    if (LuajitSetupStatesPool() != 0) {
        SCReturnInt(TM_ECODE_FAILED);
    }
#endif

    /* load the pattern matchers */
    MpmTableSetup();
#ifdef __SC_CUDA_SUPPORT__
    MpmCudaEnvironmentSetup();
#endif
    SpmTableSetup();

    int disable_offloading;
    if (ConfGetBool("capture.disable-offloading", &disable_offloading) == 0)
        disable_offloading = 1;
    if (disable_offloading) {
        LiveSetOffloadDisable();
    } else {
        LiveSetOffloadWarn();
    }

    if (suri->checksum_validation == -1) {
        char *cv = NULL;
        if (ConfGet("capture.checksum-validation", &cv) == 1) {
            if (strcmp(cv, "none") == 0) {
                suri->checksum_validation = 0;
            } else if (strcmp(cv, "all") == 0) {
                suri->checksum_validation = 1;
            }
        }
    }
    switch (suri->checksum_validation) {
        case 0:
            ConfSet("stream.checksum-validation", "0");
            break;
        case 1:
            ConfSet("stream.checksum-validation", "1");
            break;
    }

    AppLayerSetup();

    /* Check for the existance of the default logging directory which we pick
     * from suricata.yaml.  If not found, shut the engine down */
    suri->log_dir = ConfigGetLogDirectory();

    if (ConfigCheckLogDirectory(suri->log_dir) != TM_ECODE_OK) {
        SCLogError(SC_ERR_LOGDIR_CONFIG, "The logging directory \"%s\" "
                "supplied by %s (default-log-dir) doesn't exist. "
                "Shutting down the engine", suri->log_dir, suri->conf_filename);
        SCReturnInt(TM_ECODE_FAILED);
    }

    if (ConfigGetCaptureValue(suri) != TM_ECODE_OK) {
        SCReturnInt(TM_ECODE_FAILED);
    }

    if (ConfGet("host-mode", &hostmode) == 1) {
        if (!strcmp(hostmode, "router")) {
            host_mode = SURI_HOST_IS_ROUTER;
        } else if (!strcmp(hostmode, "sniffer-only")) {
            host_mode = SURI_HOST_IS_SNIFFER_ONLY;
        } else {
            if (strcmp(hostmode, "auto") != 0) {
                WarnInvalidConfEntry("host-mode", "%s", "auto");
            }
            if (EngineModeIsIPS()) {
                host_mode = SURI_HOST_IS_ROUTER;
            } else {
                host_mode = SURI_HOST_IS_SNIFFER_ONLY;
            }
        }
    } else {
        if (EngineModeIsIPS()) {
            host_mode = SURI_HOST_IS_ROUTER;
            SCLogInfo("No 'host-mode': suricata is in IPS mode, using "
                      "default setting 'router'");
        } else {
            host_mode = SURI_HOST_IS_SNIFFER_ONLY;
            SCLogInfo("No 'host-mode': suricata is in IDS mode, using "
                      "default setting 'sniffer-only'");
        }
    }

#ifdef NFQ
    if (suri->run_mode == RUNMODE_NFQ)
        NFQInitConfig(FALSE);
#endif

    /* Load the Host-OS lookup. */
    SCHInfoLoadFromConfig();
    if (suri->run_mode != RUNMODE_UNIX_SOCKET) {
        DefragInit();
    }

    if (suri->run_mode == RUNMODE_ENGINE_ANALYSIS) {
        SCLogInfo("== Carrying out Engine Analysis ==");
        char *temp = NULL;
        if (ConfGet("engine-analysis", &temp) == 0) {
            SCLogInfo("no engine-analysis parameter(s) defined in conf file.  "
                      "Please define/enable them in the conf to use this "
                      "feature.");
            SCReturnInt(TM_ECODE_FAILED);
        }
    }

    /* hardcoded initialization code */
    SigTableSetup(); /* load the rule keywords */
    TmqhSetup();

    StorageInit();
    CIDRInit();
    SigParsePrepare();
#ifdef PROFILING
    if (suri->run_mode != RUNMODE_UNIX_SOCKET) {
        SCProfilingRulesGlobalInit();
        SCProfilingKeywordsGlobalInit();
        SCProfilingSghsGlobalInit();
        SCProfilingInit();
    }
#endif /* PROFILING */
    SCReputationInitCtx();
    SCProtoNameInit();

    TagInitCtx();
    PacketAlertTagInit();
    ThresholdInit();
    HostBitInitCtx();
    IPPairBitInitCtx();

    if (DetectAddressTestConfVars() < 0) {
        SCLogError(SC_ERR_INVALID_YAML_CONF_ENTRY,
                "basic address vars test failed. Please check %s for errors",
                suri->conf_filename);
        SCReturnInt(TM_ECODE_FAILED);
    }
    if (DetectPortTestConfVars() < 0) {
        SCLogError(SC_ERR_INVALID_YAML_CONF_ENTRY,
                "basic port vars test failed. Please check %s for errors",
                suri->conf_filename);
        SCReturnInt(TM_ECODE_FAILED);
    }

    RegisterAllModules();

    AppLayerHtpNeedFileInspection();

    StorageFinalize();

    TmModuleRunInit();

    if (MayDaemonize(suri) != TM_ECODE_OK)
        SCReturnInt(TM_ECODE_FAILED);

    if (InitSignalHandler(suri) != TM_ECODE_OK)
        SCReturnInt(TM_ECODE_FAILED);


#ifdef HAVE_NSS
    if (suri->run_mode != RUNMODE_CONF_TEST) {
        /* init NSS for hashing */
        PR_Init(PR_USER_THREAD, PR_PRIORITY_NORMAL, 0);
        NSS_NoDB_Init(NULL);
    }
#endif

    if (suri->disabled_detect) {
        /* disable raw reassembly */
        (void)ConfSetFinal("stream.reassembly.raw", "false");
    }

    HostInitConfig(HOST_VERBOSE);

    if (MagicInit() != 0)
        SCReturnInt(TM_ECODE_FAILED);

    SCAsn1LoadConfig();

    CoredumpLoadConfig();

    SCReturnInt(TM_ECODE_OK);
}

/*
*main()函数位于suricata.c文件，其主要流程如下：

1. 定义并初始化程序的全局实例变量。

SCInstance类型的suri变量用来保存程序当前的一些状态、标志等上下文环境，通常是用来作为参数传递给各个模块的子函数，因此为了更好的封装性而放到一个结构体变量中，而不是使用零散的长串参数或一堆全局变量。
SCInstanceInit函数，顾名思义，即是对suri中各个字段进行初始化。注意，这里对所有字段都进行了显示初始化，因为虽然一个memset清零已经基本达到目的了，但显示地将各个成员设成0/NULL/FALSE对于可读性来说还是有好处的，可以明确地说明各个字段的初始值，且对扩展性也会有好处，例如若后续初始化需要设置一些非0值（如用-1表示无效值），直接更改就好了。
2. 初始化sc_set_caps为FALSE –> 标识是否对主线程进行特权去除（drop privilege），主要是出于安全性考虑。

3. 初始化原子变量engine_stage –> 记录程序当前的运行阶段：SURICATA_INIT、SURICATA_RUNTIME、SURICATA_FINALIZE

4. 初始化日志模块，因为后续的执行流程中将使用日志输出，所以需要最先初始化该模块。

5. 设置当前主线程名字为“Suricata-Main”。线程名字还是挺重要的，至少在gdb调试时info threads可以看到各个线程名，从而可以精确地找到想要查看的线程。另外，在top -H时，也能够显示出线程名字（然而ps -efL时貌似还是只是显示进程名）。

6. 初始化ParserSize模块 –> 使用正则表达式来解析类似“10Mb”这种大小参数，其中正则引擎用的是pcre，因此初始化时就是调用pcre_compile、pcre_study对已经写好的正则表达式进行编译和预处理。

7. 注册各种运行模式。Suricata对“运行模式”这个概念也进行了封装。运行模式存储在runmodes数组中，定义为RunModes runmodes[RUNMODE_USER_MAX]。

首先，数组中每一项（例如runmodes[RUNMODE_PCAP_DEV]），对应一组运行模式，模式组包括（RunModes类型）：“IDS+Pcap”模式组、“File+Pcap”模式组、“UnixSocket”模式组等（另外还有其他一些内部模式，如：“列出关键字”模式、“打印版本号”模式等，这些没有存储在runmodes数组中）。
然后，每一个模式组，其中可以包含若干个运行模式（RunMode类型），例如：single、auto、autofp、workers。
运行模式的注册，则是为各个模式组（如RunModeIdsPcapRegister）添加其所支持的运行模式（通过调用RunModeRegisterNewRunMode），并定义改组的默认运行模式，以及非常重要的：注册各个模式下的初始化函数（如RunModeIdsPcapSingle），等后续初始化阶段确定了具体的运行模式后，就会调用这里注册的对应的初始化函数，对该模式下的运行环境进行进一步配置。
8. 初始化引擎模式为IDS模式。引擎模式只有两种：IDS、IPS，初始默认为IDS，而在nfq或ipfw启用时，就会切换成IPS模式，该模式下能够执行“Drop”操作，即拦截数据包。

9. 初始化配置模块，为配置节点树建立root节点。

10. 解析命令行参数。其中，与包捕获相关的选项（如“-i”）都会调用LiveRegisterDevice，以注册一个数据包捕获设备接口（如eth0）。全局的所有已注册的设备接口存储在变量live_devices中，类型为LiveDevice。注意，用多设备同时捕获数据包这个特性在Suricata中目前还只是实验性的。“-v”选项可多次使用，每个v都能将当前日志等级提升一级。

11. 若运行模式为内部模式，则进入该模式执行，完毕后退出程序。

12. FinalizeRunMode，即为运行模式的处理划上句号。主要是设置offline标志、对unknown运行模式进行报错，以及设置全局的run_mode变量。

13. 若运行模式为单元测试模式，则跑（用户通过正则表达式指定的）单元测试，并输出测试结果。

14. 检查当前模式是否与daemon标志冲突。Pcap文件模式及单元测试模式都不能在daemon开启下进行。

15. 初始化全局变量。包括：数据包队列trans_q、数据队列data_queues（干嘛的？）、对应的mutex和cond、建立小写字母表。

16. 初始化时间。包括：获取当前时间所用的spin lock，以及设置时区（调用tzset()即可）。

17. 为快速模式匹配注册关键字。调用SupportFastPatternForSigMatchList函数，按照优先级大小插入到sm_fp_support_smlist_list链表中。

18. 若用户未在输入参数中指定配置文件，则使用默认配置文件（/etc/suricata/suricata.yaml）。

19. 调用LoadYamlConfig读取Yaml格式配置文件。Yaml格式解析是通过libyaml库来完成的，解析的结果存储在配置节点树（见conf.c）中。对include机制的支持：在第一遍调用ConfYamlLoadFile载入主配置文件后，将在当前配置节点树中搜寻“include”节点，并对其每个子节点的值（即通过include语句所指定的子配置文件路径），同样调用ConfYamlLoadFile进行载入。

20. 再次初始化日志模块。这次，程序将会根据配置文件中日志输出配置（logging.outputs）填充SCLogInitData类型的结构体，调用SCLogInitLogModule重新初始化日志模块。

21. 打印版本信息。这是Suricata启动开始后第一条打印信息。

22. 打印当前机器的CPU/核个数，这些信息是通过sysconf系统函数获取的。

23. 若运行模式为DUMP_CONFIG，则调用ConfDump打印出当前的所有配置信息。ConfDump通过递归调用ConfNodeDump函数实现对配置节点树的DFS（深度优先遍历）。

24. 执行PostConfLoadedSetup，即运行那些需要在配置载入完成后就立马执行的函数。这里面涉及的流程和函数非常多：

MpmTableSetup：设置多模式匹配表，该表中每一项就是一个实现了某种多模式匹配算法（如WuManber、AC）的匹配器。以注册AC匹配器为例，MpmTableSetup会调用MpmACRegister函数实现AC注册，函数内部其实只是填充mpm_table中对应AC的那一项（mpm_table[MPM_AC]）的各个字段，如：匹配器名称（"ac"）、初始化函数（SCACInitCtx）、增加模式函数（SCACAddPatternCS）、实际的搜索执行函数（SCACSearch）。
设置rule_reload标志。如果配置文件中对应选项打开，则会设置该标志，表示可以进行“规则热重载”，即能够在程序运行时载入或替换规则集。
AppLayerDetectProtoThreadInit：初始化应用层协议检测模块。其中，AlpProtoInit函数初始化该模块所用到的多模式匹配器，RegisterAppLayerParsers函数注册各种应用层协议的解析器（如RegisterHTPParsers函数对应HTTP协议），而AlpProtoFinalizeGlobal函数完成一些收尾工作，包括调用匹配器的预处理（Prepare）函数、建立模式ID和规则签名之间的映射等。
AppLayerParsersInitPostProcess：这个函数内部建立了一个解析器之间的映射，还不太懂其用途。
设置并验证日志存储目录是否存在。若配置文件中未指定，则使用默认目录，linux下默认为/var/log/suricata。
获取与包捕获相关的一些配置参数，目前包括：max-pending-packets、default-packet-size。
设置host_mode（主机模式），两种模式：router和sniffer-only，而如果设置为“auto”，则会进行自动选择：IPS模式下运行为router，否则为sniffer-only。
SCHInfoLoadFromConfig：从配置文件中载入host os policy(主机OS策略)信息。网络入侵通常是针对某些特定OS的漏洞，因此如果能够获取部署环境中主机的OS信息，肯定对入侵检测大有裨益。具体这些信息是怎么使用的，暂时也还不清楚。
DefragInit：初始化IP分片重组模块。
SigTableSetup：初始化检测引擎，主要是注册检测引擎所支持的规则格式（跟Snort规则基本一致）中的关键字，比如sid、priority、msg、within、distance等等。
TmqhSetup：初始化queue handler（队列处理函数），这个是衔接线程模块和数据包队列之间的桥梁，目前共有5类handler：simple, nfq, packetpool, flow, ringbuffer。每类handler内部都有一个InHandler和OutHandler，一个用于从上一级队列中获取数据包，另一个用于处理完毕后将数据包送入下一级队列。
StorageInit：初始化存储模块，这个模块可以用来临时存储一些数据，数据类型目前有两种：host、flow。具体在何种场景下用，目前未知。
CIDRInit：初始化CIDR掩码数组，cidrs[i]对应前i位为1的掩码。
SigParsePrepare：为规则签名解析器的正则表达式进行编译(pcre_compile)和预处理(pcre_study)。
SCPerfInitCounterApi：初始化性能计数器模块。这个模块实现了累加计数器（例如统计收到的数据包个数、字节数）、平均值计数器（统计平均包长、处理时间）、最大计数器（最大包长、处理时间）、基于时间间隔的计数器（当前流量速率）等，默认输出到日志目录下的stats.log文件。
几个Profiling模块的初始化函数。Profiling模块提供内建的模块性能分析功能，可以用来分析模块性能、各种锁的实际使用情况（竞争时间）、规则的性能等。
SCReputationInitCtx：初始化IP声望模块。IP声望数据在内部是以Radix tree的形式存储的，但目前还不知道数据源是从哪来的，而且也没看到这个模块的函数在哪调用。
SCProtoNameInit：读取/etc/protocols文件，建立IP层所承载的上层协议号和协议名的映射（如6-> ”TCP”,17-> ”UDP“）。
TagInitCtx、ThresholdInit：与规则中的tag、threshould关键字的实现相关，这里用到了Storage模块，调用HostStorageRegister和FlowStorageRegister注册了几个（与流/主机绑定的？）存储区域。
DetectAddressTestConfVars、DetectPortTestConfVars：检查配置文件中"vars"选项下所预定义的一些IP地址（如局域网地址块）、端口变量（如HTTP端口号）是否符合格式要求。
RegisterAllModules：这是个非常重要的函数！里面注册了Suricata所支持的所有线程模块（Thread Module）。以pcap相关模块为例，TmModuleReceivePcapRegister函数注册了Pcap捕获模块，而TmModuleDecodePcapRegister函数注册了Pcap数据包解码模块。所谓注册，就是在tmm_modules模块数组中对应的那项中填充TmModule结构的所有字段，这些字段包括：模块名字、线程初始化函数、包处理或包获取函数、线程退出清理函数、一些标志位等等。
AppLayerHtpNeedFileInspection：设置suricata内部模块与libhtp（HTTP处理库）对接关系的函数，具体细节暂时不管。
DetectEngineRegisterAppInspectionEngines：名字都这么长了，肯定很复杂。。。暂时不管。
若设置了rule_reload标志，则注册相应的信号处理函数（目前设置的函数都是些提示函数，没有做实际重载）。这里用的是比较惯用的SIGUSR2信号来触发rule reload。
StorageFinalize：关闭storage模块的注册，为已注册的storage实际分配存储空间。
TmModuleRunInit：调用之前注册的线程模块的初始化函数进行初始化。
25. 检查是否进入Daemon模式。若需要进入Daemon模式，则会检测pidfile是否已经存在（daemon下只能有一个实例运行），然后进行Daemonize，最后创建一个pidfile。Daemonize的主要思路是：fork->子进程调用setsid创建一个新的session，关闭stdin、stdout、stderr，并告诉父进程 –> 父进程等待子进程通知，然后退出 –> 子进程继续执行。

26. 初始化信号handler。首先为SIGINT（ctrl-c触发）和SIGTERM（不带参数kill时触发）这两个常规退出信号分别注册handler，对SIGINT的处理是设置程序的状态标志为STOP，即让程序优雅地退出；而对SIGTERM是设置为KILL，即强杀。接着，程序会忽略SIGPIPE（这个信号通常是在Socket通信时向已关闭的连接另一端发送数据时收到）和SIGSYS（当进程尝试执行一个不存在的系统调用时收到）信号，以加强程序的容错性和健壮性。

27. 获取配置文件中指定的Suricata运行时的user和group，如果命令行中没有指定的话。然后，将指定的user和group通过getpwuid、getpwnam、getgrnam等函数转换为uid和gid，为后续的实际设置uid和gid做准备。注意，这段代码也是在InitSignalHandler中执行的，不知道为什么放这里，跟信号有关系么。。。

28. 初始化Packet pool，即预分配一些Packet结构体，分配的数目由之前配置的max_pending_packets确定，而数据包的数据大小由default_packet_size确定（一个包的总占用空间为default_packet_size+sizeof(Packet)）。在调用PacketGetFromAlloc新建并初始化一个数据包后，再调用PacketPoolStorePacket将该数据包存入ringbuffer。Suricata中用于数据包池的Ring Buffer类型为RingBuffer16，即容量为2^16=65536（但为什么max_pending_packets的最大值被限定为65534呢？）。

29. 初始化Host engine。这货好像跟之前的host类型的storage有关系，具体怎么用后面再看看吧。

30. 初始化Flow engine。跟前面的host engine类似，不过这个的用处就很明显了，就是用来表示一条TCP/UDP/ICMP/SCTP流的，程序当前所记录的所有流便组成了流表，在flow引擎中，流表为flow_hash这个全局变量，其类型为FlowBucket *，而FlowBucket中则能够存储一个Flow链表，典型的一张chained hash Table。在初始化函数FlowInitConfig中，首先会使用配置文件信息填充flow_config，然后会按照配置中的hash_size为流表实际分配内存，接着按照prealloc进行流的预分配（FlowAlloc->FlowEnqueue，存储在flow_spare_q这个FlowQueue类型的队列中），最后调用FlowInitFlowProto为流表所用于的各种流协议进行配置，主要是设置timeout时间。

31. 初始化Decect engine。若配置文件中未指定mpm(多模式匹配器)，则默认使用AC，即使用mpm_table中AC那一项。SRepInit函数（与前面的SCReputationInitCtx不同！）会初始化检测引擎中域reputaion相关信息，即从配置文件中指定的文件中读取声望数据。其余配置比较复杂，暂不关注。

32. 读取和解析classification.config和reference.config，这两个文件用于支持规则格式中的classification（规则分类）和refercence（规则参考资料）字段。

33. 设置规则的动作优先级顺序，默认为Pass->Drop->Reject->Alert。举例来说，若有一条Pass规则和Drop规则都匹配到了某个数据库，则会优先应用Pass规则。

34. 初始化Magic模块。Magic模块只是对libmagic库进行了一层封装，通过文件中的magic字段来检测文件的类型（如”PDF-1.3“对应PDF文件）。

35. 设置是否延迟检测。若delayed-detect为yes，则系统将在载入规则集之前就开始处理数据包，这样能够在IPS模式下将少系统的down time（宕机时间）。

36. 如果没有设置延迟检测，就调用LoadSignatures载入规则集。

37. 如果设置了live_reload，则重新注册用于规则重载的SIGUSR2信号处理函数（这次是设置为真正的重载处理函数）。放在这里是为了防止在初次载入规则集时就被触发重载。

38. 初始化ASN.1解码模块。Wikipedia：ASN.1（Abstract Syntax Notation One) 是一套标准，是描述数据的表示、编码、传输、解码的灵活的记法。应用层协议如X.400（email）、X.500和LDAP（目录服务）、H.323（VoIP）和SNMP使用 ASN.1 描述它们交互的协议数据单元。

39. 处理CoreDump相关配置。Linux下可用prctl函数获取和设置进程dumpable状态，设置corefile大小则是通过通用的setrlimit函数。

40. 调用gettimeofday保存当前时间，存储在suri->start_time中，作为系统的启动时间。

41. 去除主线程的权限。这个是通过libcap-ng实现的，首先调用capng_clear清空所有权限，然后根据运行模式添加一些必要权限（主要是为了抓包），最后调用capng_change_id设置新的uid和gid。主线程的权限应该会被新建的子线程继承，因此只需要在主线程设置即可。

42. 初始化所有Output模块。这些模块之前在线程模块注册函数里已经都注册了，这里会根据配置文件再进行配置和初始化，最后把当前配置下启用了的output模块放到RunModeOutputs链表中。

43. 若当前抓包模式下未指定设备接口（通过-i <dev>或--pcap=<dev>等方式），则解析配置文件中指定的Interface，并调用LiveRegisterDevice对其进行注册。

44. 若当前的模式为CONF_TEST，即测试配置文件是否有效，则现在就可以退出了。这也说明，程序运行到这里，配置工作已经基本完成了。

45. 初始化运行模式。首先，根据配置文件和程序中的默认值来配置运行模式（single、auto这些），而运行模式类型（PCAP_DEV、PCAPFILE这些）也在之前已经确定了，因此运行模式已经固定下来，可以从runmodes表中获取到特定的RunMode了，接着就调用RunMode中的RunModeFunc，进入当前运行模式的初始化函数。以PCAP_DEV类型下的autofp模式为例，该模式的初始化函数为：RunModeIdsPcapAutoFp。这个函数的执行流程为：

调用RunModeInitialize进行通用的运行模式初始化，目前主要是设置CPU affinity和threading_detect_ratio。
调用RunModeSetLiveCaptureAutoFp设置该模式下的模块组合：
确实参数：接口个数nlive、线程个数thread_max（由用户指定，或CPU个数决定）。
RunmodeAutoFpCreatePickupQueuesString：创建一个包含thread_max个接收队列名字的字符串，如"pickup1,pickup2,pickup3"。
ParsePcapConfig：解析pcap接口相关配置，如buffer-size、bpf-filter、promisc等。
PcapConfigGeThreadsCount：获取pcap接口配置中指定的threads（抓包线程个数，默认为1），保存到threads_count变量。
创造threads_count个抓包线程：
TmThreadCreatePacketHandler函数专门用于创建包处理线程，函数内部会调用通用的TmThreadCreate创建线程，并将线程类型设置为TVT_PPT。
线程名字为"RxPcap"+接口名+i，如“RxPcapeth01”。
inq、inqh都设置为"packetpool"，表示将从数据包池（而不是某个数据包队列）中获取包。
outqh设置为"flow"，表示使用之前注册的flow类型的queue handler作为线程的输出队列处理器，这个类型可以保证同一条flow的包都会输出给同一个queue，具体的包调度策略取决于autop-scheduler指定的算法。
outq设置为前面所设置的接收队列名字符串，而之前的flow类型handler的TmqhOutputFlowSetupCtx函数将会解析队列名字符串，并创建出相应个数（threads_max）的队列。
slots函数设置为"pktacqloop"，表示这个线程的插槽类型为pktacqloop，这样在TmThreadSetSlots函数中就会将线程执行函数（tm_func）设置为针对该插槽类型的TmThreadsSlotPktAcqLoop函数。最终线程在被pthread_create执行时传入的回调函数就是这个线程执行函数。
TmSlotSetFuncAppend：将“ReceivePcap"和"DecodePcap"这两个线程模块嵌入到前面创建的每个抓包线程的插槽中去。
TmThreadSetCPU：设置线程的CPU相关参数。
TmThreadSpawn：按照之前所填充好的ThreadVars生成实际的线程，并将该线程添加到全局线程数组tv_root中去。
创造thread_max个检测线程：
线程名字为"Detect"+i，每个线程都有与一个输入队列绑定，即inq设置为"pickup"+i 队列。
inqh设置为"flow"，即使用flow类型（与前面的抓包线程相匹配）的queue handler作为线程的输入队列处理器。
outq、outqh都设置为"packetpool"，表示这个线程的包处理完后会直接回收到packet pool中去。
slots函数设置为"varslot"，表示这个线程的插槽类型为varslot，对应的执行函数为TmThreadsSlotVar。
接着，跟上面类似，把"StreamTcp"（用于TCP会话跟踪、重组等）、"Detect"（调用检测引擎进行实际的入侵检测）和"RespondReject"（用于通过主动应答来拒绝连接）这三个线程模块嵌入进去。不过，这里在插入“Detect”模块时，调用的是TmSlotSetFuncAppendDelayed，用于支持delayed-detect功能。
SetupOutputs：由于这组检测线程是处理数据包的完结之处，因此这里需要把输出模块也嵌入到这些线程中去，方式也是通过TmSlotSetFuncAppend函数，对象是RunModeOutputs中存储的输出模块。
46. 若unix-command为enable状态，则创建Unix-socket命令线程，可与suricata客户端使用JSON格式信息进行通信。命令线程的创建是通过TmThreadCreateCmdThread函数，创建的线程类型为TVT_CMD。线程执行函数为UnixManagerThread。

47. 创建Flow管理线程，用于对流表进行超时删除处理。管理线程创建是通过TmThreadCreateMgmtThread函数，类型为TVT_MGMT，执行函数为FlowManagerThread。

48. 初始化Stream TCP模块。其中调用了StreamTcpReassembleInit函数进行重组模块初始化。

49. 创建性能计数相关线程，包括一个定期对各计数器进行同步的唤醒线程（SCPerfWakeupThread），和一个定期输出计数值的管理线程（SCPerfMgmtThread）。

50. 检查数据包队列的状态是否有效：每个数据包队列都应该至少有一个reader和一个writer。在前面线程绑定inq时会增加其reader_cnt，绑定outq时会增加其writer_cnt。

51. 等待子线程初始化完成。检查是否初始化完成的方式是遍历tv_root，调用TmThreadsCheckFlag检查子线程的状态标志。

52. 更新engine_stage为SURICATA_RUNTIME，即程序已经初始化完成，进入运转状态。这里的更新用的是原子CAS操作，防止并发更新导致状态不一致（但目前没在代码中只到到主线程有更新engine_stage操作，不存在并发更新）。

53. 让目前处于paused状态的线程继续执行。在TmThreadCreate中，线程的初始状态设置为了PAUSE，因此初始化完成后就会等待主线程调用TmThreadContinue让其继续。从这以后，各线程就开始正式执行其主流程了。

54. 若设置了delayed_detect，则现在开始调用LoadSignatures加载规则集，激活检测线程，并注册rule_reload信号处理函数。这里，激活检测线程是通过调用TmThreadActivateDummySlot函数，这个函数会将之前注册的slot中的slotFunc替换为实际操作函数，而不是原先在delayed_detect情况下设置的什么都不做的TmDummyFunc。

55. 进入死循环。若受到引擎退出信号（SURICATA_KILL或SURICATA_STOP），则退出循环，执行后续退出操作，否则就调用TmThreadCheckThreadState检查各线程的状态，决定是否进行结束线程、重启线程、终止程序等操作，然后usleep一会儿（1s），继续循环。

56. 接着，程序就进入到了退出阶段，首先会更新engine_stage为SURICATA_DEINIT，然后依次关闭Unix-socket线程、Flow管理线程。

57. 停止包含抓包或解码线程模块的线程。这个是通过TmThreadDisableThreadsWithTMS实现，里面会检查每个线程的slots里嵌入的线程模块的flags中是否包含指定的flag（这里是TM_FLAG_RECEIVE_TM或TM_FLAG_DECODE_TM），一个线程模块的flags在注册时就已经指定了。关闭是通过向线程发送KILL信号（设置线程变量的THV_KILL标志）实现，收到该信号的线程会进入RUNNING_DONE状态，然后等待主线程下一步发出DEINIT信号。

58. 强制对仍有未处理的分段的流进行重组。

59. 打印进程运行的总时间（elapsed time）。

60. 在rule_reload开启下，首先同样调用TmThreadDisableThreadsWithTMS停止检测线程。特别地，该函数对于inq不为"packetpool"的线程（即该线程从一个PakcetQueue中获取数据包），会等到inq中的数据包都处理完毕再关闭这个线程。然后，检测是否reload正在进行，如果是则等待其完成，即不去打断它。

61. 杀死所有子线程。杀死线程的函数为TmThreadKillThread，这个函数会同时向子线程发出KILL和DEINIT信号，然后等待子线程进入CLOSED状态，之后，再调用线程的清理函数（InShutdownHandler）以及其对应的ouqh的清理函数（OutHandlerCtxFree），最后调用pthread_join等待子线程退出。

62. 执行一大堆清理函数：清理性能计数模块、关闭Flow engine、清理StreamTCP、关闭Host engine、清理HTP模块并打印状态、移除PID文件、关闭检测引擎、清理应用层识别模块、清理Tag环境、关闭所有输出模块，etc…

63. 调用exit以engine_retval为退出状态终止程序。
*/
int main(int argc, char **argv)
{
    SCInstance suri;

    SCInstanceInit(&suri);
    suri.progname = argv[0];

    sc_set_caps = FALSE;

    SC_ATOMIC_INIT(engine_stage);

    /* initialize the logging subsys.Suricata中的main函数接下来所做的事情是：*/
    SCLogInitLogModule(NULL);//初始化日志系统;

	//给主线程设置线程名称;
    if (SCSetThreadName("Suricata-Main") < 0) {
        SCLogWarning(SC_ERR_THREAD_INIT, "Unable to set thread name");
    }

    ParseSizeInit();

	//设置运行模式;
    RunModeRegisterRunModes();

    /* By default use IDS mode, but if nfq or ipfw
     * are specified, IPS mode will overwrite this */
    /*suricata默认情况下是运行IDS模式。而在RunModeRegisterRunModes()函数中，
    主要是在引擎中注册所有的运行模式。函数所在位置是在runmodes.c中。
	*/
    EngineModeSetIDS();

#ifdef OS_WIN32
    /* service initialization */
    if (WindowsInit(argc, argv) != 0) {
        exit(EXIT_FAILURE);
    }
#endif /* OS_WIN32 */

    /* Initialize the configuration module. */
    ConfInit();

    if (ParseCommandLine(argc, argv, &suri) != TM_ECODE_OK) {
        exit(EXIT_FAILURE);
    }

    if (FinalizeRunMode(&suri, argv) != TM_ECODE_OK) {
        exit(EXIT_FAILURE);
    }

    switch (StartInternalRunMode(&suri, argc, argv)) {
        case TM_ECODE_DONE:
            exit(EXIT_SUCCESS);
        case TM_ECODE_FAILED:
            exit(EXIT_FAILURE);
    }

#ifdef __SC_CUDA_SUPPORT__
    /* Init the CUDA environment */
    SCCudaInitCudaEnvironment();
    CudaBufferInit();
#endif

    /* Initializations for global vars, queues, etc (memsets, mutex init..) */
    GlobalInits();
    TimeInit();
    SupportFastPatternForSigMatchTypes();
    if (suri.run_mode != RUNMODE_UNIX_SOCKET) {
        StatsInit();
    }

    /* Load yaml configuration file if provided. */
    if (LoadYamlConfig(&suri) != TM_ECODE_OK) {
        exit(EXIT_FAILURE);
    }

    if (suri.run_mode == RUNMODE_DUMP_CONFIG) {
        ConfDump();
        exit(EXIT_SUCCESS);
    }

    /* Since our config is now loaded we can finish configurating the
     * logging module. */
    SCLogLoadConfig(suri.daemon, suri.verbose);

    SCPrintVersion();

    UtilCpuPrintSummary();

    if (ParseInterfacesList(suri.run_mode, suri.pcap_dev) != TM_ECODE_OK) {
        exit(EXIT_FAILURE);
    }

    if (PostConfLoadedSetup(&suri) != TM_ECODE_OK) {
        exit(EXIT_FAILURE);
    }

    if (suri.run_mode != RUNMODE_UNIX_SOCKET) {
        FlowInitConfig(FLOW_VERBOSE);
        StreamTcpInitConfig(STREAM_VERBOSE);
        IPPairInitConfig(IPPAIR_VERBOSE);
        AppLayerRegisterGlobalCounters();
    }

    DetectEngineCtx *de_ctx = NULL;
    if (!suri.disabled_detect) {
        SCClassConfInit();
        SCReferenceConfInit();
        SetupDelayedDetect(&suri);
        int mt_enabled = 0;
        (void)ConfGetBool("multi-detect.enabled", &mt_enabled);
        int default_tenant = 0;
        if (mt_enabled)
            (void)ConfGetBool("multi-detect.default", &default_tenant);
        if (DetectEngineMultiTenantSetup() == -1) {
            SCLogError(SC_ERR_INITIALIZATION, "initializing multi-detect "
                    "detection engine contexts failed.");
            exit(EXIT_FAILURE);
        }
        if ((suri.delayed_detect || (mt_enabled && !default_tenant)) &&
            (suri.run_mode != RUNMODE_CONF_TEST)) {
            de_ctx = DetectEngineCtxInitMinimal();
        } else {
            de_ctx = DetectEngineCtxInit();
        }
        if (de_ctx == NULL) {
            SCLogError(SC_ERR_INITIALIZATION, "initializing detection engine "
                    "context failed.");
            exit(EXIT_FAILURE);
        }

#ifdef __SC_CUDA_SUPPORT__
        if (PatternMatchDefaultMatcher() == MPM_AC_CUDA)
            CudaVarsSetDeCtx(de_ctx);
#endif /* __SC_CUDA_SUPPORT__ */

        if (!de_ctx->minimal) {
            if (LoadSignatures(de_ctx, &suri) != TM_ECODE_OK)
                exit(EXIT_FAILURE);
            if (suri.run_mode == RUNMODE_ENGINE_ANALYSIS) {
                exit(EXIT_SUCCESS);
            }
        }

        DetectEngineAddToMaster(de_ctx);
    } else {
        /* tell the app layer to consider only the log id */
        RegisterAppLayerGetActiveTxIdFunc(AppLayerTransactionGetActiveLogOnly);
    }

    SCSetStartTime(&suri);

    SCDropMainThreadCaps(suri.userid, suri.groupid);

    if (suri.run_mode != RUNMODE_UNIX_SOCKET) {
        RunModeInitializeOutputs();
        StatsSetupPostConfig();
    }

    if (suri.run_mode == RUNMODE_CONF_TEST){
        SCLogNotice("Configuration provided was successfully loaded. Exiting.");
        MagicDeinit();
        exit(EXIT_SUCCESS);
    }

    RunModeDispatch(suri.run_mode, suri.runmode_custom_mode);

    /* In Unix socket runmode, Flow manager is started on demand */
    if (suri.run_mode != RUNMODE_UNIX_SOCKET) {
        /* Spawn the unix socket manager thread */
        int unix_socket = ConfUnixSocketIsEnable();
        if (unix_socket == 1) {
            UnixManagerThreadSpawn(0);
#ifdef BUILD_UNIX_SOCKET
            UnixManagerRegisterCommand("iface-stat", LiveDeviceIfaceStat, NULL,
                                       UNIX_CMD_TAKE_ARGS);
            UnixManagerRegisterCommand("iface-list", LiveDeviceIfaceList, NULL, 0);
#endif
        }
        /* Spawn the flow manager thread */
        FlowManagerThreadSpawn();
        FlowRecyclerThreadSpawn();
        StatsSpawnThreads();
    }

    /* Wait till all the threads have been initialized.
	等待子线程初始化完成。检查是否初始化完成的方式是遍历tv_root，
	调用TmThreadsCheckFlag检查子线程的状态标志。
    */
    if (TmThreadWaitOnThreadInit() == TM_ECODE_FAILED) {
        SCLogError(SC_ERR_INITIALIZATION, "Engine initialization failed, "
                   "aborting...");
        exit(EXIT_FAILURE);
    }

    (void) SC_ATOMIC_CAS(&engine_stage, SURICATA_INIT, SURICATA_RUNTIME);
    PacketPoolPostRunmodes();

    /* Un-pause all the paused threads .
	继续运行暂停的线程;*/
    TmThreadContinueThreads();
    /* registering singal handlers we use.  We register usr2 here, so that one
     * can't call it during the first sig load phase or while threads are still
     * starting up. 
	设置Sigusr2信号的处理函数;
     */
    if (DetectEngineEnabled() && suri.sig_file == NULL &&
            suri.delayed_detect == 0)
        UtilSignalHandlerSetup(SIGUSR2, SignalHandlerSigusr2);

    if (suri.delayed_detect) {
        /* force 'reload', this will load the rules and swap engines .
	重新加载detect engine;*/
        DetectEngineReload(&suri);
        SCLogNotice("Signature(s) loaded, Detect thread(s) activated.");
    }


#ifdef DBG_MEM_ALLOC
    SCLogInfo("Memory used at startup: %"PRIdMAX, (intmax_t)global_mem);
#ifdef DBG_MEM_ALLOC_SKIP_STARTUP
    print_mem_flag = 1;
#endif
#endif

    int engine_retval = EXIT_SUCCESS;
    while(1) {
		/*
		若收到引擎退出信号（SURICATA_KILL或SURICATA_STOP），则退出循环，执行后续退出操作;
		*/
        if (sigterm_count || sigint_count) {
            suricata_ctl_flags |= SURICATA_STOP;
        }

        if (suricata_ctl_flags & SURICATA_STOP) {
            SCLogNotice("Signal Received.  Stopping engine.");
            break;
        }

        TmThreadCheckThreadState();

		/*检查各线程的状态，决定是否进行结束线程、重启线程、终止程序等操作;*/
        if (sighup_count > 0) {
			/*循环设置注册文件的flags;*/
            OutputNotifyFileRotation();
            sighup_count--;
        }

        if (sigusr2_count > 0) {
            if (suri.sig_file != NULL) {
                SCLogWarning(SC_ERR_LIVE_RULE_SWAP, "Live rule reload not "
                        "possible if -s or -S option used at runtime.");
                sigusr2_count--;
            } else {
                if (!(DetectEngineReloadIsStart())) {
                    DetectEngineReloadStart();
                    DetectEngineReload(&suri);
                    DetectEngineReloadSetDone();
                    sigusr2_count--;
                }
            }

        } else if (DetectEngineReloadIsStart()) {
            if (suri.sig_file != NULL) {
                SCLogWarning(SC_ERR_LIVE_RULE_SWAP, "Live rule reload not "
                        "possible if -s or -S option used at runtime.");
                DetectEngineReloadSetDone();
            } else {
                DetectEngineReload(&suri);
                DetectEngineReloadSetDone();
            }
        }

        usleep(10* 1000);
    }

    /* Update the engine stage/status flag */
    (void) SC_ATOMIC_CAS(&engine_stage, SURICATA_RUNTIME, SURICATA_DEINIT);

    UnixSocketKillSocketThread();

    if (suri.run_mode != RUNMODE_UNIX_SOCKET) {
        /* First we need to disable the flow manager thread */
        FlowDisableFlowManagerThread();
    }


    /* Disable packet acquisition first */
    TmThreadDisableReceiveThreads();

    if (suri.run_mode != RUNMODE_UNIX_SOCKET) {
        /* we need a packet pool for FlowForceReassembly */
        PacketPoolInit();

        FlowForceReassembly();
        /* kill receive threads when they have processed all
         * flow timeout packets */
        TmThreadDisablePacketThreads();
    }

    SCPrintElapsedTime(&suri);

    /* before TmThreadKillThreads, as otherwise that kills it
     * but more slowly */
    if (suri.run_mode != RUNMODE_UNIX_SOCKET) {
        FlowDisableFlowRecyclerThread();
    }

    /* kill remaining threads */
    TmThreadKillThreads();


    if (suri.run_mode != RUNMODE_UNIX_SOCKET) {
        /* destroy the packet pool for flow reassembly after all
         * the other threads are gone. */
        PacketPoolDestroy();

        StatsReleaseResources();
        IPPairShutdown();
        FlowShutdown();
        StreamTcpFreeConfig(STREAM_VERBOSE);
    }
    HostShutdown();

    HTPFreeConfig();
    HTPAtExitPrintStats();

#ifdef DBG_MEM_ALLOC
    SCLogInfo("Total memory used (without SCFree()): %"PRIdMAX, (intmax_t)global_mem);
#ifdef DBG_MEM_ALLOC_SKIP_STARTUP
    print_mem_flag = 0;
#endif
#endif

    SCPidfileRemove(suri.pid_filename);

    AppLayerHtpPrintStats();

    /** TODO this can do into it's own func */
    de_ctx = DetectEngineGetCurrent();
    if (de_ctx) {
        DetectEngineMoveToFreeList(de_ctx);
        DetectEngineDeReference(&de_ctx);
    }
    DetectEnginePruneFreeList();

    AppLayerDeSetup();

    TagDestroyCtx();

    LiveDeviceListClean();
    RunModeShutDown();
    OutputDeregisterAll();
    TimeDeinit();
    SCProtoNameDeInit();
    if (suri.run_mode != RUNMODE_UNIX_SOCKET) {
        DefragDestroy();
    }
    if (!suri.disabled_detect) {
        SCReferenceConfDeinit();
        SCClassConfDeinit();
    }
    MagicDeinit();
    TmqhCleanup();
    TmModuleRunDeInit();
    ParseSizeDeinit();
#ifdef HAVE_NSS
    NSS_Shutdown();
    PR_Cleanup();
#endif

#ifdef HAVE_AF_PACKET
    AFPPeersListClean();
#endif

#ifdef PROFILING
    if (suri.run_mode != RUNMODE_UNIX_SOCKET) {
        if (profiling_rules_enabled)
            SCProfilingDump();
        SCProfilingDestroy();
    }
#endif

#ifdef OS_WIN32
	if (daemon) {
		return 0;
	}
#endif /* OS_WIN32 */

    SC_ATOMIC_DESTROY(engine_stage);

#ifdef BUILD_HYPERSCAN
    MpmHSGlobalCleanup();
#endif

#ifdef __SC_CUDA_SUPPORT__
    if (PatternMatchDefaultMatcher() == MPM_AC_CUDA)
        MpmCudaBufferDeSetup();
    CudaHandlerFreeProfiles();
#endif
    ConfDeInit();
#ifdef HAVE_LUAJIT
    LuajitFreeStatesPool();
#endif
    SCLogDeInitLogModule();
    DetectParseFreeRegexes();
    exit(engine_retval);
}
