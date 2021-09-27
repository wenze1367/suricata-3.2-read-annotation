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
 *  \author Victor Julien <victor@inliniac.net>
 *  \author Breno Silva <breno.silva@gmail.com>
 *
 * Implements the flowbits keyword
 */

#include "suricata-common.h"
#include "decode.h"
#include "detect.h"
#include "threads.h"
#include "flow.h"
#include "flow-bit.h"
#include "flow-util.h"
#include "detect-flowbits.h"
#include "util-spm.h"

#include "app-layer-parser.h"

#include "detect-parse.h"
#include "detect-engine.h"
#include "detect-engine-mpm.h"
#include "detect-engine-state.h"

#include "util-var-name.h"
#include "util-unittest.h"
#include "util-debug.h"

#define PARSE_REGEX         "([a-z]+)(?:,\\s*(.*))?"
static pcre *parse_regex;
static pcre_extra *parse_regex_study;

int DetectFlowbitMatch (ThreadVars *, DetectEngineThreadCtx *, Packet *, Signature *, const SigMatchCtx *);
static int DetectFlowbitSetup (DetectEngineCtx *, Signature *, char *);
void DetectFlowbitFree (void *);
void FlowBitsRegisterTests(void);

void DetectFlowbitsRegister (void)
{
    sigmatch_table[DETECT_FLOWBITS].name = "flowbits";
    sigmatch_table[DETECT_FLOWBITS].desc = "operate on flow flag";
    sigmatch_table[DETECT_FLOWBITS].url = DOC_URL DOC_VERSION "/rules/flow-keywords.html#flowbits";
    sigmatch_table[DETECT_FLOWBITS].Match = DetectFlowbitMatch;
    sigmatch_table[DETECT_FLOWBITS].Setup = DetectFlowbitSetup;
    sigmatch_table[DETECT_FLOWBITS].Free  = DetectFlowbitFree;
    sigmatch_table[DETECT_FLOWBITS].RegisterTests = FlowBitsRegisterTests;
    /* this is compatible to ip-only signatures */
    sigmatch_table[DETECT_FLOWBITS].flags |= SIGMATCH_IPONLY_COMPAT;

    DetectSetupParseRegexes(PARSE_REGEX, &parse_regex, &parse_regex_study);
}


static int DetectFlowbitMatchToggle (Packet *p, const DetectFlowbitsData *fd)
{
    if (p->flow == NULL)
        return 0;

    FlowBitToggle(p->flow,fd->idx);

    return 1;
}

static int DetectFlowbitMatchUnset (Packet *p, const DetectFlowbitsData *fd)
{
    if (p->flow == NULL)
        return 0;

    FlowBitUnset(p->flow,fd->idx);

    return 1;
}

static int DetectFlowbitMatchSet (Packet *p, const DetectFlowbitsData *fd)
{
    if (p->flow == NULL)
        return 0;

    FlowBitSet(p->flow,fd->idx);

    return 1;
}

static int DetectFlowbitMatchIsset (Packet *p, const DetectFlowbitsData *fd)
{
    if (p->flow == NULL)
        return 0;

    return FlowBitIsset(p->flow,fd->idx);
}

static int DetectFlowbitMatchIsnotset (Packet *p, const DetectFlowbitsData *fd)
{
    if (p->flow == NULL)
        return 0;

    return FlowBitIsnotset(p->flow,fd->idx);
}

/*
 * returns 0: no match
 *         1: match
 *        -1: error
 */

int DetectFlowbitMatch (ThreadVars *t, DetectEngineThreadCtx *det_ctx, Packet *p, Signature *s, const SigMatchCtx *ctx)
{
    const DetectFlowbitsData *fd = (const DetectFlowbitsData *)ctx;
    if (fd == NULL)
        return 0;

    switch (fd->cmd) {
        case DETECT_FLOWBITS_CMD_ISSET:
            return DetectFlowbitMatchIsset(p,fd);
        case DETECT_FLOWBITS_CMD_ISNOTSET:
            return DetectFlowbitMatchIsnotset(p,fd);
        case DETECT_FLOWBITS_CMD_SET:
            return DetectFlowbitMatchSet(p,fd);
        case DETECT_FLOWBITS_CMD_UNSET:
            return DetectFlowbitMatchUnset(p,fd);
        case DETECT_FLOWBITS_CMD_TOGGLE:
            return DetectFlowbitMatchToggle(p,fd);
        default:
            SCLogError(SC_ERR_UNKNOWN_VALUE, "unknown cmd %" PRIu32 "", fd->cmd);
            return 0;
    }

    return 0;
}

static int DetectFlowbitParse(char *str, char *cmd, int cmd_len, char *name,
    int name_len)
{
    const int max_substrings = 30;
    int count, rc;
    int ov[max_substrings];

    count = pcre_exec(parse_regex, parse_regex_study, str, strlen(str), 0, 0,
        ov, max_substrings);
    if (count != 2 && count != 3) {
        SCLogError(SC_ERR_PCRE_MATCH,
            "\"%s\" is not a valid setting for flowbits.", str);
        return 0;
    }

    rc = pcre_copy_substring((char *)str, ov, max_substrings, 1, cmd, cmd_len);
    if (rc < 0) {
        SCLogError(SC_ERR_PCRE_GET_SUBSTRING, "pcre_copy_substring failed");
        return 0;
    }

    if (count == 3) {
        rc = pcre_copy_substring((char *)str, ov, max_substrings, 2, name,
            name_len);
        if (rc < 0) {
            SCLogError(SC_ERR_PCRE_GET_SUBSTRING, "pcre_copy_substring failed");
            return 0;
        }

        /* Trim trailing whitespace. */
        while (strlen(name) > 0 && isblank(name[strlen(name) - 1])) {
            name[strlen(name) - 1] = '\0';
        }

        /* Validate name, spaces are not allowed. */
        for (size_t i = 0; i < strlen(name); i++) {
            if (isblank(name[i])) {
                SCLogError(SC_ERR_INVALID_SIGNATURE,
                    "spaces not allowed in flowbit names");
                return 0;
            }
        }
    }

    return 1;
}

int DetectFlowbitSetup (DetectEngineCtx *de_ctx, Signature *s, char *rawstr)
{
    DetectFlowbitsData *cd = NULL;
    SigMatch *sm = NULL;
    uint8_t fb_cmd = 0;
    char fb_cmd_str[16] = "", fb_name[256] = "";

    if (!DetectFlowbitParse(rawstr, fb_cmd_str, sizeof(fb_cmd_str), fb_name,
            sizeof(fb_name))) {
        return -1;
    }

    if (strcmp(fb_cmd_str,"noalert") == 0) {
        fb_cmd = DETECT_FLOWBITS_CMD_NOALERT;
    } else if (strcmp(fb_cmd_str,"isset") == 0) {
        fb_cmd = DETECT_FLOWBITS_CMD_ISSET;
    } else if (strcmp(fb_cmd_str,"isnotset") == 0) {
        fb_cmd = DETECT_FLOWBITS_CMD_ISNOTSET;
    } else if (strcmp(fb_cmd_str,"set") == 0) {
        fb_cmd = DETECT_FLOWBITS_CMD_SET;
    } else if (strcmp(fb_cmd_str,"unset") == 0) {
        fb_cmd = DETECT_FLOWBITS_CMD_UNSET;
    } else if (strcmp(fb_cmd_str,"toggle") == 0) {
        fb_cmd = DETECT_FLOWBITS_CMD_TOGGLE;
    } else {
        SCLogError(SC_ERR_UNKNOWN_VALUE, "ERROR: flowbits action \"%s\" is not supported.", fb_cmd_str);
        goto error;
    }

    switch (fb_cmd) {
        case DETECT_FLOWBITS_CMD_NOALERT:
            if (strlen(fb_name) != 0)
                goto error;
            s->flags |= SIG_FLAG_NOALERT;
            return 0;
        case DETECT_FLOWBITS_CMD_ISNOTSET:
        case DETECT_FLOWBITS_CMD_ISSET:
        case DETECT_FLOWBITS_CMD_SET:
        case DETECT_FLOWBITS_CMD_UNSET:
        case DETECT_FLOWBITS_CMD_TOGGLE:
        default:
            if (strlen(fb_name) == 0)
                goto error;
            break;
    }

    cd = SCMalloc(sizeof(DetectFlowbitsData));
    if (unlikely(cd == NULL))
        goto error;

    cd->idx = VariableNameGetIdx(de_ctx, fb_name, VAR_TYPE_FLOW_BIT);
    cd->cmd = fb_cmd;

    SCLogDebug("idx %" PRIu32 ", cmd %s, name %s",
        cd->idx, fb_cmd_str, strlen(fb_name) ? fb_name : "(none)");

    /* Okay so far so good, lets get this into a SigMatch
     * and put it in the Signature. */
    sm = SigMatchAlloc();
    if (sm == NULL)
        goto error;

    sm->type = DETECT_FLOWBITS;
    sm->ctx = (SigMatchCtx *)cd;

    switch (fb_cmd) {
        /* case DETECT_FLOWBITS_CMD_NOALERT can't happen here */

        case DETECT_FLOWBITS_CMD_ISNOTSET:
        case DETECT_FLOWBITS_CMD_ISSET:
            /* checks, so packet list */
            SigMatchAppendSMToList(s, sm, DETECT_SM_LIST_MATCH);
            break;

        case DETECT_FLOWBITS_CMD_SET:
        case DETECT_FLOWBITS_CMD_UNSET:
        case DETECT_FLOWBITS_CMD_TOGGLE:
            /* modifiers, only run when entire sig has matched */
            SigMatchAppendSMToList(s, sm, DETECT_SM_LIST_POSTMATCH);
            break;
    }

    return 0;

error:
    if (cd != NULL)
        SCFree(cd);
    if (sm != NULL)
        SCFree(sm);
    return -1;
}

void DetectFlowbitFree (void *ptr)
{
    DetectFlowbitsData *fd = (DetectFlowbitsData *)ptr;

    if (fd == NULL)
        return;

    SCFree(fd);
}

#ifdef UNITTESTS

static int FlowBitsTestParse01(void)
{
    char command[16] = "", name[16] = "";

    /* Single argument version. */
    FAIL_IF(!DetectFlowbitParse("noalert", command, sizeof(command), name,
            sizeof(name)));
    FAIL_IF(strcmp(command, "noalert") != 0);

    /* No leading or trailing spaces. */
    FAIL_IF(!DetectFlowbitParse("set,flowbit", command, sizeof(command), name,
            sizeof(name)));
    FAIL_IF(strcmp(command, "set") != 0);
    FAIL_IF(strcmp(name, "flowbit") != 0);

    /* Leading space. */
    FAIL_IF(!DetectFlowbitParse("set, flowbit", command, sizeof(command), name,
            sizeof(name)));
    FAIL_IF(strcmp(command, "set") != 0);
    FAIL_IF(strcmp(name, "flowbit") != 0);

    /* Trailing space. */
    FAIL_IF(!DetectFlowbitParse("set,flowbit ", command, sizeof(command), name,
            sizeof(name)));
    FAIL_IF(strcmp(command, "set") != 0);
    FAIL_IF(strcmp(name, "flowbit") != 0);

    /* Leading and trailing space. */
    FAIL_IF(!DetectFlowbitParse("set, flowbit ", command, sizeof(command), name,
            sizeof(name)));
    FAIL_IF(strcmp(command, "set") != 0);
    FAIL_IF(strcmp(name, "flowbit") != 0);

    /* Spaces are not allowed in the name. */
    FAIL_IF(DetectFlowbitParse("set,namewith space", command, sizeof(command),
            name, sizeof(name)));

    PASS;
}

/**
 * \test FlowBitsTestSig01 is a test for a valid noalert flowbits option
 *
 *  \retval 1 on succces
 *  \retval 0 on failure
 */

static int FlowBitsTestSig01(void)
{
    Signature *s = NULL;
    DetectEngineCtx *de_ctx = NULL;

    de_ctx = DetectEngineCtxInit();
    FAIL_IF_NULL(de_ctx);

    de_ctx->flags |= DE_QUIET;

    s = de_ctx->sig_list = SigInit(de_ctx,"alert ip any any -> any any (msg:\"Noalert\"; flowbits:noalert,wrongusage; content:\"GET \"; sid:1;)");
    FAIL_IF_NOT_NULL(s);

    DetectEngineCtxFree(de_ctx);
    PASS;
}

/**
 * \test FlowBitsTestSig02 is a test for a valid isset,set,isnotset,unset,toggle flowbits options
 *
 *  \retval 1 on succces
 *  \retval 0 on failure
 */

static int FlowBitsTestSig02(void)
{
    Signature *s = NULL;
    ThreadVars th_v;
    DetectEngineCtx *de_ctx = NULL;

    memset(&th_v, 0, sizeof(th_v));

    de_ctx = DetectEngineCtxInit();
    FAIL_IF_NULL(de_ctx);

    de_ctx->flags |= DE_QUIET;

    s = de_ctx->sig_list = SigInit(de_ctx,"alert ip any any -> any any (msg:\"isset rule need an option\"; flowbits:isset; content:\"GET \"; sid:1;)");
    FAIL_IF_NOT_NULL(s);

    s = de_ctx->sig_list = SigInit(de_ctx,"alert ip any any -> any any (msg:\"isnotset rule need an option\"; flowbits:isnotset; content:\"GET \"; sid:2;)");
    FAIL_IF_NOT_NULL(s);

    s = de_ctx->sig_list = SigInit(de_ctx,"alert ip any any -> any any (msg:\"set rule need an option\"; flowbits:set; content:\"GET \"; sid:3;)");
    FAIL_IF_NOT_NULL(s);

    s = de_ctx->sig_list = SigInit(de_ctx,"alert ip any any -> any any (msg:\"unset rule need an option\"; flowbits:unset; content:\"GET \"; sid:4;)");
    FAIL_IF_NOT_NULL(s);

    s = de_ctx->sig_list = SigInit(de_ctx,"alert ip any any -> any any (msg:\"toggle rule need an option\"; flowbits:toggle; content:\"GET \"; sid:5;)");
    FAIL_IF_NOT_NULL(s);

    DetectEngineCtxFree(de_ctx);

    PASS;
}

/**
 * \test FlowBitsTestSig03 is a test for a invalid flowbits option
 *
 *  \retval 1 on succces
 *  \retval 0 on failure
 */

static int FlowBitsTestSig03(void)
{
    Signature *s = NULL;
    DetectEngineCtx *de_ctx = NULL;

    de_ctx = DetectEngineCtxInit();
    FAIL_IF_NULL(de_ctx);

    de_ctx->flags |= DE_QUIET;

    s = de_ctx->sig_list = SigInit(de_ctx,"alert ip any any -> any any (msg:\"Unknown cmd\"; flowbits:wrongcmd; content:\"GET \"; sid:1;)");
    FAIL_IF_NOT_NULL(s);

    DetectEngineCtxFree(de_ctx);
    PASS;
}

/**
 * \test FlowBitsTestSig04 is a test check idx value
 *
 *  \retval 1 on succces
 *  \retval 0 on failure
 */

static int FlowBitsTestSig04(void)
{
    Signature *s = NULL;
    DetectEngineCtx *de_ctx = NULL;
    int idx = 0;

    de_ctx = DetectEngineCtxInit();
    FAIL_IF_NULL(de_ctx);

    de_ctx->flags |= DE_QUIET;

    s = de_ctx->sig_list = SigInit(de_ctx,"alert ip any any -> any any (msg:\"isset option\"; flowbits:isset,fbt; content:\"GET \"; sid:1;)");
    FAIL_IF_NULL(s);

    idx = VariableNameGetIdx(de_ctx, "fbt", VAR_TYPE_FLOW_BIT);
    FAIL_IF(idx != 1);

    DetectEngineCtxFree(de_ctx);
    PASS;
}

/**
 * \test FlowBitsTestSig05 is a test check noalert flag
 *
 *  \retval 1 on succces
 *  \retval 0 on failure
 */

static int FlowBitsTestSig05(void)
{
    Signature *s = NULL;
    DetectEngineCtx *de_ctx = NULL;

    de_ctx = DetectEngineCtxInit();
    FAIL_IF_NULL(de_ctx);

    de_ctx->flags |= DE_QUIET;

    s = de_ctx->sig_list = SigInit(de_ctx,"alert ip any any -> any any (msg:\"Noalert\"; flowbits:noalert; content:\"GET \"; sid:1;)");
    FAIL_IF_NULL(s);
    FAIL_IF((s->flags & SIG_FLAG_NOALERT) != SIG_FLAG_NOALERT);

    DetectEngineCtxFree(de_ctx);
    PASS;
}

/**
 * \test FlowBitsTestSig06 is a test set flowbits option
 *
 *  \retval 1 on succces
 *  \retval 0 on failure
 */

static int FlowBitsTestSig06(void)
{
    uint8_t *buf = (uint8_t *)
                    "GET /one/ HTTP/1.1\r\n"
                    "Host: one.example.org\r\n"
                    "\r\n";
    uint16_t buflen = strlen((char *)buf);
    Packet *p = SCMalloc(SIZE_OF_PACKET);
    FAIL_IF_NULL(p);
    Signature *s = NULL;
    ThreadVars th_v;
    DetectEngineThreadCtx *det_ctx = NULL;
    DetectEngineCtx *de_ctx = NULL;
    Flow f;
    GenericVar flowvar, *gv = NULL;
    int result = 0;
    int idx = 0;

    memset(p, 0, SIZE_OF_PACKET);
    memset(&th_v, 0, sizeof(th_v));
    memset(&f, 0, sizeof(Flow));
    memset(&flowvar, 0, sizeof(GenericVar));

    FLOW_INITIALIZE(&f);
    p->flow = &f;
    p->flow->flowvar = &flowvar;

    p->src.family = AF_INET;
    p->dst.family = AF_INET;
    p->payload = buf;
    p->payload_len = buflen;
    p->proto = IPPROTO_TCP;
    p->flags |= PKT_HAS_FLOW;
    p->flowflags |= FLOW_PKT_TOSERVER;

    de_ctx = DetectEngineCtxInit();
    FAIL_IF_NULL(de_ctx);

    de_ctx->flags |= DE_QUIET;

    s = de_ctx->sig_list = SigInit(de_ctx,"alert ip any any -> any any (msg:\"Flowbit set\"; flowbits:set,myflow; sid:10;)");
    FAIL_IF_NULL(s);

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&th_v, (void *)de_ctx, (void *)&det_ctx);

    SigMatchSignatures(&th_v, de_ctx, det_ctx, p);

    idx = VariableNameGetIdx(de_ctx, "myflow", VAR_TYPE_FLOW_BIT);

    gv = p->flow->flowvar;

    for ( ; gv != NULL; gv = gv->next) {
        if (gv->type == DETECT_FLOWBITS && gv->idx == idx) {
                result = 1;
        }
    }
    FAIL_IF_NOT(result);

    SigGroupCleanup(de_ctx);
    SigCleanSignatures(de_ctx);

    DetectEngineThreadCtxDeinit(&th_v, (void *)det_ctx);
    DetectEngineCtxFree(de_ctx);

    if(gv) GenericVarFree(gv);
    FLOW_DESTROY(&f);

    SCFree(p);
    PASS;
}

/**
 * \test FlowBitsTestSig07 is a test unset flowbits option
 *
 *  \retval 1 on succces
 *  \retval 0 on failure
 */

static int FlowBitsTestSig07(void)
{
    uint8_t *buf = (uint8_t *)
                    "GET /one/ HTTP/1.1\r\n"
                    "Host: one.example.org\r\n"
                    "\r\n";
    uint16_t buflen = strlen((char *)buf);
    Packet *p = SCMalloc(SIZE_OF_PACKET);
    FAIL_IF_NULL(p);
    Signature *s = NULL;
    ThreadVars th_v;
    DetectEngineThreadCtx *det_ctx = NULL;
    DetectEngineCtx *de_ctx = NULL;
    Flow f;
    GenericVar flowvar, *gv = NULL;
    int result = 0;
    int idx = 0;

    memset(p, 0, SIZE_OF_PACKET);
    memset(&th_v, 0, sizeof(th_v));
    memset(&f, 0, sizeof(Flow));
    memset(&flowvar, 0, sizeof(GenericVar));

    FLOW_INITIALIZE(&f);
    p->flow = &f;
    p->flow->flowvar = &flowvar;

    p->src.family = AF_INET;
    p->dst.family = AF_INET;
    p->payload = buf;
    p->payload_len = buflen;
    p->proto = IPPROTO_TCP;

    de_ctx = DetectEngineCtxInit();
    FAIL_IF_NULL(de_ctx);

    de_ctx->flags |= DE_QUIET;

    s = de_ctx->sig_list = SigInit(de_ctx,"alert ip any any -> any any (msg:\"Flowbit set\"; flowbits:set,myflow2; sid:10;)");
    FAIL_IF_NULL(s);

    s = s->next = SigInit(de_ctx,"alert ip any any -> any any (msg:\"Flowbit unset\"; flowbits:unset,myflow2; sid:11;)");
    FAIL_IF_NULL(s);

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&th_v, (void *)de_ctx, (void *)&det_ctx);

    SigMatchSignatures(&th_v, de_ctx, det_ctx, p);

    idx = VariableNameGetIdx(de_ctx, "myflow", VAR_TYPE_FLOW_BIT);

    gv = p->flow->flowvar;

    for ( ; gv != NULL; gv = gv->next) {
        if (gv->type == DETECT_FLOWBITS && gv->idx == idx) {
                result = 1;
        }
    }
    FAIL_IF(result);

    SigGroupCleanup(de_ctx);
    SigCleanSignatures(de_ctx);

    DetectEngineThreadCtxDeinit(&th_v, (void *)det_ctx);
    DetectEngineCtxFree(de_ctx);

    if(gv) GenericVarFree(gv);
    FLOW_DESTROY(&f);

    SCFree(p);
    PASS;
}

/**
 * \test FlowBitsTestSig08 is a test toogle flowbits option
 *
 *  \retval 1 on succces
 *  \retval 0 on failure
 */

static int FlowBitsTestSig08(void)
{
    uint8_t *buf = (uint8_t *)
                    "GET /one/ HTTP/1.1\r\n"
                    "Host: one.example.org\r\n"
                    "\r\n";
    uint16_t buflen = strlen((char *)buf);
    Packet *p = SCMalloc(SIZE_OF_PACKET);
    if (unlikely(p == NULL))
        return 0;
    Signature *s = NULL;
    ThreadVars th_v;
    DetectEngineThreadCtx *det_ctx = NULL;
    DetectEngineCtx *de_ctx = NULL;
    Flow f;
    GenericVar flowvar, *gv = NULL;
    int result = 0;
    int idx = 0;

    memset(p, 0, SIZE_OF_PACKET);
    memset(&th_v, 0, sizeof(th_v));
    memset(&f, 0, sizeof(Flow));
    memset(&flowvar, 0, sizeof(GenericVar));

    FLOW_INITIALIZE(&f);
    p->flow = &f;
    p->flow->flowvar = &flowvar;

    p->src.family = AF_INET;
    p->dst.family = AF_INET;
    p->payload = buf;
    p->payload_len = buflen;
    p->proto = IPPROTO_TCP;

    de_ctx = DetectEngineCtxInit();
    FAIL_IF_NULL(de_ctx);

    de_ctx->flags |= DE_QUIET;

    s = de_ctx->sig_list = SigInit(de_ctx,"alert ip any any -> any any (msg:\"Flowbit set\"; flowbits:set,myflow2; sid:10;)");
    FAIL_IF_NULL(s);

    s = s->next  = SigInit(de_ctx,"alert ip any any -> any any (msg:\"Flowbit unset\"; flowbits:toggle,myflow2; sid:11;)");
    FAIL_IF_NULL(s);

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&th_v, (void *)de_ctx, (void *)&det_ctx);

    SigMatchSignatures(&th_v, de_ctx, det_ctx, p);

    idx = VariableNameGetIdx(de_ctx, "myflow", VAR_TYPE_FLOW_BIT);

    gv = p->flow->flowvar;

    for ( ; gv != NULL; gv = gv->next) {
        if (gv->type == DETECT_FLOWBITS && gv->idx == idx) {
                result = 1;
        }
    }
    FAIL_IF(result);

    SigGroupCleanup(de_ctx);
    SigCleanSignatures(de_ctx);

    DetectEngineThreadCtxDeinit(&th_v, (void *)det_ctx);
    DetectEngineCtxFree(de_ctx);

    if(gv) GenericVarFree(gv);
    FLOW_DESTROY(&f);

    SCFree(p);
    PASS;
}
#endif /* UNITTESTS */

/**
 * \brief this function registers unit tests for FlowBits
 */
void FlowBitsRegisterTests(void)
{
#ifdef UNITTESTS
    UtRegisterTest("FlowBitsTestParse01", FlowBitsTestParse01);
    UtRegisterTest("FlowBitsTestSig01", FlowBitsTestSig01);
    UtRegisterTest("FlowBitsTestSig02", FlowBitsTestSig02);
    UtRegisterTest("FlowBitsTestSig03", FlowBitsTestSig03);
    UtRegisterTest("FlowBitsTestSig04", FlowBitsTestSig04);
    UtRegisterTest("FlowBitsTestSig05", FlowBitsTestSig05);
    UtRegisterTest("FlowBitsTestSig06", FlowBitsTestSig06);
    UtRegisterTest("FlowBitsTestSig07", FlowBitsTestSig07);
    UtRegisterTest("FlowBitsTestSig08", FlowBitsTestSig08);
#endif /* UNITTESTS */
}
