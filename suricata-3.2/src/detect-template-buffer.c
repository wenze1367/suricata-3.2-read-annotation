/* Copyright (C) 2015 Open Information Security Foundation
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

/*
 * TODO: Update the \author in this file and detect-template-buffer.h.
 * TODO: Update description in the \file section below.
 * TODO: Remove SCLogNotice statements or convert to debug.
 */

/**
 * \file
 *
 * \author FirstName LastName <yourname@domain>
 *
 * Set up of the "template_buffer" keyword to allow content
 * inspections on the decoded template application layer buffers.
 */

#include "suricata-common.h"
#include "conf.h"
#include "detect.h"
#include "detect-engine.h"
#include "app-layer-template.h"
#include "detect-engine-template.h"

static int DetectTemplateBufferSetup(DetectEngineCtx *, Signature *, char *);
static void DetectTemplateBufferRegisterTests(void);

void DetectTemplateBufferRegister(void)
{
    /* TEMPLATE_START_REMOVE */
    if (ConfGetNode("app-layer.protocols.template") == NULL) {
        return;
    }
    /* TEMPLATE_END_REMOVE */
    sigmatch_table[DETECT_AL_TEMPLATE_BUFFER].name = "template_buffer";
    sigmatch_table[DETECT_AL_TEMPLATE_BUFFER].desc =
        "Template content modififier to match on the template buffers";
    sigmatch_table[DETECT_AL_TEMPLATE_BUFFER].Setup = DetectTemplateBufferSetup;
    sigmatch_table[DETECT_AL_TEMPLATE_BUFFER].RegisterTests =
        DetectTemplateBufferRegisterTests;

    sigmatch_table[DETECT_AL_TEMPLATE_BUFFER].flags |= SIGMATCH_NOOPT;
    sigmatch_table[DETECT_AL_TEMPLATE_BUFFER].flags |= SIGMATCH_PAYLOAD;

    /* register inspect engines */
    DetectAppLayerInspectEngineRegister(ALPROTO_TEMPLATE, SIG_FLAG_TOSERVER,
            DETECT_SM_LIST_TEMPLATE_BUFFER_MATCH,
            DetectEngineInspectTemplateBuffer);
    DetectAppLayerInspectEngineRegister(ALPROTO_TEMPLATE, SIG_FLAG_TOCLIENT,
            DETECT_SM_LIST_TEMPLATE_BUFFER_MATCH,
            DetectEngineInspectTemplateBuffer);

    SCLogNotice("Template application layer detect registered.");
}

static int DetectTemplateBufferSetup(DetectEngineCtx *de_ctx, Signature *s,
    char *str)
{
    s->list = DETECT_SM_LIST_TEMPLATE_BUFFER_MATCH;
    s->alproto = ALPROTO_TEMPLATE;
    return 0;
}

#ifdef UNITTESTS

#include "util-unittest.h"
#include "util-unittest-helper.h"
#include "app-layer-parser.h"
#include "detect-engine.h"
#include "detect-parse.h"
#include "flow-util.h"
#include "stream-tcp.h"

static int DetectTemplateBufferTest(void)
{
    AppLayerParserThreadCtx *alp_tctx = AppLayerParserThreadCtxAlloc();
    DetectEngineThreadCtx *det_ctx = NULL;
    DetectEngineCtx *de_ctx = NULL;
    Flow f;
    Packet *p;
    TcpSession tcp;
    ThreadVars tv;
    Signature *s;

    uint8_t request[] = "Hello World!";

    /* Setup flow. */
    memset(&f, 0, sizeof(Flow));
    memset(&tcp, 0, sizeof(TcpSession));
    memset(&tv, 0, sizeof(ThreadVars));
    p = UTHBuildPacket(request, sizeof(request), IPPROTO_TCP);
    FLOW_INITIALIZE(&f);
    f.alproto = ALPROTO_TEMPLATE;
    f.protoctx = (void *)&tcp;
    f.proto = IPPROTO_TCP;
    f.flags |= FLOW_IPV4;
    p->flow = &f;
    p->flags |= PKT_HAS_FLOW | PKT_STREAM_EST;
    p->flowflags |= FLOW_PKT_TOSERVER | FLOW_PKT_ESTABLISHED;
    StreamTcpInitConfig(TRUE);

    de_ctx = DetectEngineCtxInit();
    FAIL_IF_NULL(de_ctx);

    /* This rule should match. */
    s = DetectEngineAppendSig(de_ctx,
        "alert tcp any any -> any any ("
        "msg:\"TEMPLATE Test Rule\"; "
        "template_buffer; content:\"World!\"; "
        "sid:1; rev:1;)");
    FAIL_IF_NULL(s);

    /* This rule should not match. */
    s = DetectEngineAppendSig(de_ctx,
        "alert tcp any any -> any any ("
        "msg:\"TEMPLATE Test Rule\"; "
        "template_buffer; content:\"W0rld!\"; "
        "sid:2; rev:1;)");
    FAIL_IF_NULL(s);

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&tv, (void *)de_ctx, (void *)&det_ctx);

    FLOWLOCK_WRLOCK(&f);
    AppLayerParserParse(NULL, alp_tctx, &f, ALPROTO_TEMPLATE,
                        STREAM_TOSERVER, request, sizeof(request));
    FLOWLOCK_UNLOCK(&f);

    /* Check that we have app-layer state. */
    FAIL_IF_NULL(f.alstate);

    SigMatchSignatures(&tv, de_ctx, det_ctx, p);
    FAIL_IF(!PacketAlertCheck(p, 1));
    FAIL_IF(PacketAlertCheck(p, 2));

    /* Cleanup. */
    if (alp_tctx != NULL)
        AppLayerParserThreadCtxFree(alp_tctx);
    if (det_ctx != NULL)
        DetectEngineThreadCtxDeinit(&tv, det_ctx);
    if (de_ctx != NULL)
        SigGroupCleanup(de_ctx);
    if (de_ctx != NULL)
        DetectEngineCtxFree(de_ctx);
    StreamTcpFreeConfig(TRUE);
    FLOW_DESTROY(&f);
    UTHFreePacket(p);

    PASS;
}

#endif

static void DetectTemplateBufferRegisterTests(void)
{
#ifdef UNITTESTS
    UtRegisterTest("DetectTemplateBufferTest", DetectTemplateBufferTest);
#endif /* UNITTESTS */
}
