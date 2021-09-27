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
 *
 * Wrappers and tests for libmagic usage.
 *
 * Libmagic's API is not thread safe. The data the pointer returned by
 * magic_buffer is overwritten by the next magic_buffer call. This is
 * why we need to lock calls and copy the returned string.
 */

#include "suricata-common.h"
#include "conf.h"

#include "util-unittest.h"
#include <magic.h>

static magic_t g_magic_ctx = NULL;
static SCMutex g_magic_lock;

/**
 *  \brief Initialize the "magic" context.
 */
int MagicInit(void)
{
    BUG_ON(g_magic_ctx != NULL);

    SCEnter();

    char *filename = NULL;
    FILE *fd = NULL;

    SCMutexInit(&g_magic_lock, NULL);
    SCMutexLock(&g_magic_lock);

    g_magic_ctx = magic_open(0);
    if (g_magic_ctx == NULL) {
        SCLogError(SC_ERR_MAGIC_OPEN, "magic_open failed: %s",
                magic_error(g_magic_ctx));
        goto error;
    }

    (void)ConfGet("magic-file", &filename);


    if (filename != NULL) {
        if (strlen(filename) == 0) {
            /* set filename to NULL on *nix systems so magic_load uses system
             * default path (see man libmagic) */
            SCLogConfig("using system default magic-file");
            filename = NULL;
        }
        else {
            SCLogConfig("using magic-file %s", filename);

            if ( (fd = fopen(filename, "r")) == NULL) {
                SCLogWarning(SC_ERR_FOPEN, "Error opening file: \"%s\": %s",
                        filename, strerror(errno));
                goto error;
            }
            fclose(fd);
        }
    }

    if (magic_load(g_magic_ctx, filename) != 0) {
        SCLogError(SC_ERR_MAGIC_LOAD, "magic_load failed: %s",
                magic_error(g_magic_ctx));
        goto error;
    }

    SCMutexUnlock(&g_magic_lock);
    SCReturnInt(0);

error:
    if (g_magic_ctx != NULL) {
        magic_close(g_magic_ctx);
        g_magic_ctx = NULL;
    }

    SCMutexUnlock(&g_magic_lock);
    SCReturnInt(-1);
}

/**
 *  \brief Find the magic value for a buffer.
 *
 *  \param buf the buffer
 *  \param buflen length of the buffer
 *
 *  \retval result pointer to null terminated string
 */
char *MagicGlobalLookup(const uint8_t *buf, uint32_t buflen)
{
    const char *result = NULL;
    char *magic = NULL;

    SCMutexLock(&g_magic_lock);

    if (buf != NULL && buflen > 0) {
        result = magic_buffer(g_magic_ctx, (void *)buf, (size_t)buflen);
        if (result != NULL) {
            magic = SCStrdup(result);
            if (unlikely(magic == NULL)) {
                SCLogError(SC_ERR_MEM_ALLOC, "Unable to dup magic");
            }
        }
    }

    SCMutexUnlock(&g_magic_lock);
    SCReturnPtr(magic, "const char");
}

/**
 *  \brief Find the magic value for a buffer.
 *
 *  \param buf the buffer
 *  \param buflen length of the buffer
 *
 *  \retval result pointer to null terminated string
 */
char *MagicThreadLookup(magic_t *ctx, const uint8_t *buf, uint32_t buflen)
{
    const char *result = NULL;
    char *magic = NULL;

    if (buf != NULL && buflen > 0) {
        result = magic_buffer(*ctx, (void *)buf, (size_t)buflen);
        if (result != NULL) {
            magic = SCStrdup(result);
            if (unlikely(magic == NULL)) {
                SCLogError(SC_ERR_MEM_ALLOC, "Unable to dup magic");
            }
        }
    }

    SCReturnPtr(magic, "const char");
}

void MagicDeinit(void)
{
    SCMutexLock(&g_magic_lock);
    if (g_magic_ctx != NULL) {
        magic_close(g_magic_ctx);
        g_magic_ctx = NULL;
    }
    SCMutexUnlock(&g_magic_lock);
    SCMutexDestroy(&g_magic_lock);
}

#ifdef UNITTESTS

#if defined OS_FREEBSD || defined OS_DARWIN
#define MICROSOFT_OFFICE_DOC "OLE 2 Compound Document"
#else
#define MICROSOFT_OFFICE_DOC "Microsoft Office Document"
#endif

/** \test magic lib calls -- init */
int MagicInitTest01(void)
{
    int result = 0;
    magic_t magic_ctx;

    magic_ctx = magic_open(0);
    if (magic_ctx == NULL) {
        printf("failure retrieving magic_ctx\n");
        return 0;
    }

    if (magic_load(magic_ctx, NULL) == -1) {
        printf("failure magic_load\n");
        goto end;
    }

    result = 1;
 end:
    magic_close(magic_ctx);
    return result;
}

/** \test magic init through api */
int MagicInitTest02(void)
{
    if (g_magic_ctx != NULL) {
        printf("g_magic_ctx != NULL at start of the test: ");
        return 0;
    }

    if (MagicInit() < 0) {
        printf("MagicInit() failure\n");
        return 0;
    }

    if (g_magic_ctx == NULL) {
        printf("g_magic_ctx == NULL: ");
        return 0;
    }

    MagicDeinit();

    if (g_magic_ctx != NULL) {
        printf("g_magic_ctx != NULL at end of the test: ");
        return 0;
    }

    return 1;
}

/** \test magic lib calls -- lookup */
int MagicDetectTest01(void)
{
    magic_t magic_ctx;
    char *result = NULL;
    char buffer[] = { 0x25, 'P', 'D', 'F', '-', '1', '.', '3', 0x0d, 0x0a};
    size_t buffer_len = sizeof(buffer);
    int retval = 0;

    magic_ctx = magic_open(0);
    if (magic_ctx == NULL) {
        printf("failure retrieving magic_ctx\n");
        return 0;
    }

    if (magic_load(magic_ctx, NULL) == -1) {
        printf("magic_load failure\n");
        goto end;
    }

    result = (char *)magic_buffer(magic_ctx, (void *)buffer, buffer_len);
    if (result == NULL || strncmp(result, "PDF document", 12) != 0) {
        printf("result %p:%s, not \"PDF document\": ", result,result?result:"(null)");
        goto end;
    }

    retval = 1;
end:
    magic_close(magic_ctx);
    return retval;
}
#if 0
/** \test magic lib calls -- lookup */
int MagicDetectTest02(void)
{
    magic_t magic_ctx;
    char *result = NULL;

    char buffer[] = {
        0xd0, 0xcf, 0x11, 0xe0, 0xa1, 0xb1, 0x1a, 0xe1,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x3e, 0x00, 0x03, 0x00, 0xfe, 0xff, 0x09, 0x00,

        0x06, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00,
        0x96, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x10, 0x00, 0x00, 0x98, 0x00, 0x00, 0x00,

        0x01, 0x00, 0x00, 0x00, 0xfe, 0xff, 0xff, 0xff,
        0x00, 0x00, 0x00, 0x00, 0x90, 0x00, 0x00, 0x00,
        0x97, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    };
    size_t buffer_len = sizeof(buffer);
    int retval = 0;

    magic_ctx = magic_open(0);
    if (magic_ctx == NULL) {
        printf("failure retrieving magic_ctx\n");
        return 0;
    }

    if (magic_load(magic_ctx, NULL) == -1) {
        printf("magic_load failure\n");
        goto end;
    }

    result = (char *)magic_buffer(magic_ctx, (void *)buffer, buffer_len);
    if (result == NULL || strcmp(result, MICROSOFT_OFFICE_DOC) != 0) {
        printf("result %p:%s, not \"Microsoft Office Document\": ", result,result?result:"(null)");
        goto end;
    }

    retval = 1;
end:
    magic_close(magic_ctx);
    return retval;
}
#endif
/** \test magic lib calls -- lookup */
int MagicDetectTest03(void)
{
    char buffer[] = {
        0x50, 0x4b, 0x03, 0x04, 0x14, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x0b, 0x55, 0x2a, 0x36, 0x5e, 0xc6,
        0x32, 0x0c, 0x27, 0x00, 0x00, 0x00, 0x27, 0x00,
        0x00, 0x00, 0x08, 0x00, 0x00, 0x00, 0x6d, 0x69,

        0x6d, 0x65, 0x74, 0x79, 0x70, 0x65, 0x61, 0x70,
        0x70, 0x6c, 0x69, 0x63, 0x61, 0x74, 0x69, 0x6f,
        0x6e, 0x2f, 0x76, 0x6e, 0x64, 0x2e, 0x6f, 0x61,
        0x73, 0x69, 0x73, 0x2e, 0x6f, 0x70, 0x65, 0x6e,

        0x64, 0x6f, 0x63, 0x75, 0x6d, 0x65, 0x6e, 0x74,
        0x2e, 0x74, 0x65, 0x78, 0x74, 0x50, 0x4b, 0x03,
        0x04, 0x14, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0b,
        0x55, 0x2a, 0x36, 0x00, 0x00, 0x00, 0x00, 0x00,

        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x1a,
        0x00, 0x00, 0x00, 0x43, 0x6f, 0x6e, 0x66, 0x69,
        0x67, 0x75, 0x72, 0x61, 0x74, 0x69, 0x6f, 0x6e,
        0x73, 0x32, 0x2f, 0x73, 0x74, 0x61, 0x74, 0x75,

        0x73, 0x62, 0x61, 0x72, 0x2f, 0x50, 0x4b, 0x03,
        0x04, 0x14, 0x00, 0x08, 0x00, 0x08, 0x00, 0x0b,
    };
    size_t buffer_len = sizeof(buffer);

    magic_t magic_ctx = magic_open(0);
    FAIL_IF_NULL(magic_ctx);

    FAIL_IF(magic_load(magic_ctx, NULL) == -1);

    char *result = (char *)magic_buffer(magic_ctx, (void *)buffer, buffer_len);
    FAIL_IF_NULL(result);

    char *str = strstr(result, "OpenDocument Text");
    if (str == NULL) {
        printf("result %s, not \"OpenDocument Text\": ", str);
        FAIL;
    }

    magic_close(magic_ctx);
    PASS;
}

/** \test magic lib calls -- lookup */
int MagicDetectTest04(void)
{
    magic_t magic_ctx;
    char *result = NULL;

    char buffer[] = {
        0x50, 0x4b, 0x03, 0x04, 0x14, 0x00, 0x00, 0x08,
        0x00, 0x00, 0x52, 0x7b, 0x86, 0x3c, 0x8b, 0x70,
        0x96, 0x08, 0x1c, 0x00, 0x00, 0x00, 0x1c, 0x00,
        0x00, 0x00, 0x08, 0x00, 0x00, 0x00, 0x6d, 0x69,

        0x6d, 0x65, 0x74, 0x79, 0x70, 0x65, 0x61, 0x70,
        0x70, 0x6c, 0x69, 0x63, 0x61, 0x74, 0x69, 0x6f,
        0x6e, 0x2f, 0x76, 0x6e, 0x64, 0x2e, 0x73, 0x75,
        0x6e, 0x2e, 0x78, 0x6d, 0x6c, 0x2e, 0x62, 0x61,

        0x73, 0x65, 0x50, 0x4b, 0x03, 0x04, 0x14, 0x00,
        0x00, 0x08, 0x00, 0x00, 0x52, 0x7b, 0x86, 0x3c,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x09, 0x00, 0x00, 0x00,

        0x4d, 0x45, 0x54, 0x41, 0x2d, 0x49, 0x4e, 0x46,
        0x2f, 0x50, 0x4b, 0x03, 0x04, 0x14, 0x00, 0x00,
        0x08, 0x08, 0x00, 0xa8, 0x42, 0x1d, 0x37, 0x5d,
        0xa7, 0xb2, 0xc1, 0xde, 0x01, 0x00, 0x00, 0x7e,

        0x04, 0x00, 0x00, 0x0b, 0x00, 0x00, 0x00, 0x63,
        0x6f, 0x6e, 0x74, 0x65, 0x6e, 0x74, 0x2e, 0x78,
        0x6d, 0x6c, 0x95, 0x54, 0x4d, 0x6f, 0xdb, 0x30,
        0x0c, 0xbd, 0xe7, 0x57, 0x18, 0x02, 0x06, 0x6c,

        0x07, 0xc5, 0xe9, 0xb6, 0xc3, 0x22, 0xc4, 0x29,
        0x86, 0x7d, 0x00, 0x05, 0x8a, 0x9d, 0xb2, 0x43,
        0x8f, 0xb2, 0x24, 0xa7, 0xc2, 0x64, 0xc9, 0x15,
    };
    size_t buffer_len = sizeof(buffer);
    int retval = 0;

    magic_ctx = magic_open(0);
    if (magic_ctx == NULL) {
        printf("failure retrieving magic_ctx\n");
        return 0;
    }

    if (magic_load(magic_ctx, NULL) == -1) {
        printf("magic_load failure\n");
        goto end;
    }

    result = (char *)magic_buffer(magic_ctx, (void *)buffer, buffer_len);
    if (result == NULL || strncmp(result, "OpenOffice.org 1.x", 18) != 0) {
        printf("result %p:%s, not \"OpenOffice.org 1.x\": ", result,result?result:"(null)");
        goto end;
    }

    retval = 1;
end:
    magic_close(magic_ctx);
    return retval;
}

/** \test magic api calls -- lookup */
int MagicDetectTest05(void)
{
    const char *result = NULL;
    uint8_t buffer[] = { 0x25, 'P', 'D', 'F', '-', '1', '.', '3', 0x0d, 0x0a};
    size_t buffer_len = sizeof(buffer);
    int retval = 0;

    if (MagicInit() < 0) {
        printf("MagicInit() failure\n");
        return 0;
    }

    result = MagicGlobalLookup(buffer, buffer_len);
    if (result == NULL || strncmp(result, "PDF document", 12) != 0) {
        printf("result %p:%s, not \"PDF document\": ", result,result?result:"(null)");
        goto end;
    }

    retval = 1;
end:
    MagicDeinit();
    return retval;
}
#if 0
/** \test magic api calls -- lookup */
int MagicDetectTest06(void)
{
    const char *result = NULL;
    uint8_t buffer[] = {
        0xd0, 0xcf, 0x11, 0xe0, 0xa1, 0xb1, 0x1a, 0xe1,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x3e, 0x00, 0x03, 0x00, 0xfe, 0xff, 0x09, 0x00,

        0x06, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00,
        0x96, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x10, 0x00, 0x00, 0x98, 0x00, 0x00, 0x00,

        0x01, 0x00, 0x00, 0x00, 0xfe, 0xff, 0xff, 0xff,
        0x00, 0x00, 0x00, 0x00, 0x90, 0x00, 0x00, 0x00,
        0x97, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    };
    size_t buffer_len = sizeof(buffer);
    int retval = 0;

    if (MagicInit() < 0) {
        printf("MagicInit() failure\n");
        return 0;
    }

    result = MagicGlobalLookup(buffer, buffer_len);
    if (result == NULL || strcmp(result, MICROSOFT_OFFICE_DOC) != 0) {
        printf("result %p:%s, not \"Microsoft Office Document\": ", result,result?result:"(null)");
        goto end;
    }

    retval = 1;

end:
    MagicDeinit();
    return retval;
}
#endif
/** \test magic api calls -- lookup */
int MagicDetectTest07(void)
{
    const char *result = NULL;
    uint8_t buffer[] = {
        0x50, 0x4b, 0x03, 0x04, 0x14, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x0b, 0x55, 0x2a, 0x36, 0x5e, 0xc6,
        0x32, 0x0c, 0x27, 0x00, 0x00, 0x00, 0x27, 0x00,
        0x00, 0x00, 0x08, 0x00, 0x00, 0x00, 0x6d, 0x69,

        0x6d, 0x65, 0x74, 0x79, 0x70, 0x65, 0x61, 0x70,
        0x70, 0x6c, 0x69, 0x63, 0x61, 0x74, 0x69, 0x6f,
        0x6e, 0x2f, 0x76, 0x6e, 0x64, 0x2e, 0x6f, 0x61,
        0x73, 0x69, 0x73, 0x2e, 0x6f, 0x70, 0x65, 0x6e,

        0x64, 0x6f, 0x63, 0x75, 0x6d, 0x65, 0x6e, 0x74,
        0x2e, 0x74, 0x65, 0x78, 0x74, 0x50, 0x4b, 0x03,
        0x04, 0x14, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0b,
        0x55, 0x2a, 0x36, 0x00, 0x00, 0x00, 0x00, 0x00,

        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x1a,
        0x00, 0x00, 0x00, 0x43, 0x6f, 0x6e, 0x66, 0x69,
        0x67, 0x75, 0x72, 0x61, 0x74, 0x69, 0x6f, 0x6e,
        0x73, 0x32, 0x2f, 0x73, 0x74, 0x61, 0x74, 0x75,

        0x73, 0x62, 0x61, 0x72, 0x2f, 0x50, 0x4b, 0x03,
        0x04, 0x14, 0x00, 0x08, 0x00, 0x08, 0x00, 0x0b,
    };
    size_t buffer_len = sizeof(buffer);

    FAIL_IF(MagicInit() < 0);

    result = MagicGlobalLookup(buffer, buffer_len);
    FAIL_IF_NULL(result);

    char *str = strstr(result, "OpenDocument Text");
    if (str == NULL) {
        printf("result %s, not \"OpenDocument Text\": ", str);
        FAIL;
    }

    MagicDeinit();
    PASS;
}

/** \test magic api calls -- lookup */
int MagicDetectTest08(void)
{
    const char *result = NULL;
    uint8_t buffer[] = {
        0x50, 0x4b, 0x03, 0x04, 0x14, 0x00, 0x00, 0x08,
        0x00, 0x00, 0x52, 0x7b, 0x86, 0x3c, 0x8b, 0x70,
        0x96, 0x08, 0x1c, 0x00, 0x00, 0x00, 0x1c, 0x00,
        0x00, 0x00, 0x08, 0x00, 0x00, 0x00, 0x6d, 0x69,

        0x6d, 0x65, 0x74, 0x79, 0x70, 0x65, 0x61, 0x70,
        0x70, 0x6c, 0x69, 0x63, 0x61, 0x74, 0x69, 0x6f,
        0x6e, 0x2f, 0x76, 0x6e, 0x64, 0x2e, 0x73, 0x75,
        0x6e, 0x2e, 0x78, 0x6d, 0x6c, 0x2e, 0x62, 0x61,

        0x73, 0x65, 0x50, 0x4b, 0x03, 0x04, 0x14, 0x00,
        0x00, 0x08, 0x00, 0x00, 0x52, 0x7b, 0x86, 0x3c,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x09, 0x00, 0x00, 0x00,

        0x4d, 0x45, 0x54, 0x41, 0x2d, 0x49, 0x4e, 0x46,
        0x2f, 0x50, 0x4b, 0x03, 0x04, 0x14, 0x00, 0x00,
        0x08, 0x08, 0x00, 0xa8, 0x42, 0x1d, 0x37, 0x5d,
        0xa7, 0xb2, 0xc1, 0xde, 0x01, 0x00, 0x00, 0x7e,

        0x04, 0x00, 0x00, 0x0b, 0x00, 0x00, 0x00, 0x63,
        0x6f, 0x6e, 0x74, 0x65, 0x6e, 0x74, 0x2e, 0x78,
        0x6d, 0x6c, 0x95, 0x54, 0x4d, 0x6f, 0xdb, 0x30,

        0x0c, 0xbd, 0xe7, 0x57, 0x18, 0x02, 0x06, 0x6c,
        0x07, 0xc5, 0xe9, 0xb6, 0xc3, 0x22, 0xc4, 0x29,
        0x86, 0x7d, 0x00, 0x05, 0x8a, 0x9d, 0xb2, 0x43,
        0x8f, 0xb2, 0x24, 0xa7, 0xc2, 0x64, 0xc9, 0x15,
    };
    size_t buffer_len = sizeof(buffer);
    int retval = 0;

    if (MagicInit() < 0) {
        printf("MagicInit() failure\n");
        return 0;
    }

    result = MagicGlobalLookup(buffer, buffer_len);
    if (result == NULL || strncmp(result, "OpenOffice.org 1.x", 18) != 0) {
        printf("result %p:%s, not \"OpenOffice.org 1.x\": ", result,result?result:"(null)");
        goto end;
    }

    retval = 1;
end:
    MagicDeinit();
    return retval;
}

/** \test magic api calls -- make sure memory is shared */
int MagicDetectTest09(void)
{
    const char *result1 = NULL;
    const char *result2 = NULL;
    uint8_t buffer[] = { 0x25, 'P', 'D', 'F', '-', '1', '.', '3', 0x0d, 0x0a};
    size_t buffer_len = sizeof(buffer);
    int retval = 0;

    if (MagicInit() < 0) {
        printf("MagicInit() failure\n");
        return 0;
    }

    result1 = MagicGlobalLookup(buffer, buffer_len);
    if (result1 == NULL || strncmp(result1, "PDF document", 12) != 0) {
        printf("result %p:%s, not \"PDF document\": ", result1,result1?result1:"(null)");
        goto end;
    }

    result2 = MagicGlobalLookup(buffer, buffer_len);
    if (result2 == NULL || strncmp(result2, "PDF document", 12) != 0) {
        printf("result %p:%s, not \"PDF document\": ", result2,result2?result2:"(null)");
        goto end;
    }

    if (result1 != result2) {
        printf("pointers not equal, weird... %p != %p: ", result1, result2);
        goto end;
    }

    retval = 1;
end:
    MagicDeinit();
    return retval;
}

/** \test results in valgrind warning about invalid read, tested with
 *        file 5.09 and 5.11 */
static int MagicDetectTest10ValgrindError(void)
{
    const char *result = NULL;
    uint8_t buffer[] = {
        0xFF,0xD8,0xFF,0xE0,0x00,0x10,0x4A,0x46,0x49,0x46,0x00,0x01,0x01,0x01,0x01,0x2C,
        0x01,0x2C,0x00,0x00,0xFF,0xFE,0x00,0x4C,0x53,0x69,0x67,0x6E,0x61,0x74,0x75,0x72,
        0x65,0x3A,0x34,0x31,0x31,0x65,0x33,0x38,0x61,0x61,0x61,0x31,0x37,0x65,0x33,0x30,
        0x66,0x30,0x32,0x38,0x62,0x61,0x30,0x31,0x36,0x32,0x36,0x37,0x66,0x66,0x30,0x31,
        0x36,0x36,0x61,0x65,0x35,0x39,0x65,0x38,0x31,0x39,0x62,0x61,0x32,0x34,0x63,0x39,
        0x62,0x31,0x33,0x37,0x33,0x62,0x31,0x61,0x35,0x61,0x38,0x65,0x64,0x63,0x36,0x30,
        0x65,0x37,0xFF,0xE2,0x02,0x2C,0x49,0x43,0x43,0x5F,0x50,0x52,0x4F,0x46,0x49,0x4C,
        0x45,0x00,0x01,0x01,0x00,0x00,0x02,0x1C,0x41,0x44,0x42,0x45,0x02,0x10,0x00,0x00,
        0x6D,0x6E,0x74,0x72,0x52,0x47,0x42,0x20,0x58,0x59,0x5A,0x20,0x07,0xCF,0x00,0x05,
        0x00,0x09,0x00,0x15,0x00,0x0B,0x00,0x21,0x61,0x63,0x73,0x70,0x41,0x50,0x50,0x4C,
        0x00,0x00,0x00,0x00,0x6E,0x6F,0x6E,0x65,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    };
    size_t buffer_len = sizeof(buffer);
    int retval = 0;

    if (MagicInit() < 0) {
        printf("MagicInit() failure\n");
        return 0;
    }

    result = MagicGlobalLookup(buffer, buffer_len);
    if (result == NULL || strncmp(result, "JPEG", 4) != 0) {
        printf("result %p:%s, not \"JPEG\": ", result,result?result:"(null)");
        goto end;
    }

    retval = 1;
end:
    MagicDeinit();
    return retval;
}

#endif /* UNITTESTS */


void MagicRegisterTests(void)
{
#ifdef UNITTESTS
    UtRegisterTest("MagicInitTest01", MagicInitTest01);
    UtRegisterTest("MagicInitTest02", MagicInitTest02);
    UtRegisterTest("MagicDetectTest01", MagicDetectTest01);
    //UtRegisterTest("MagicDetectTest02", MagicDetectTest02, 1);
    UtRegisterTest("MagicDetectTest03", MagicDetectTest03);
    UtRegisterTest("MagicDetectTest04", MagicDetectTest04);
    UtRegisterTest("MagicDetectTest05", MagicDetectTest05);
    //UtRegisterTest("MagicDetectTest06", MagicDetectTest06, 1);
    UtRegisterTest("MagicDetectTest07", MagicDetectTest07);
    UtRegisterTest("MagicDetectTest08", MagicDetectTest08);
    /* fails in valgrind, somehow it returns different pointers then.
    UtRegisterTest("MagicDetectTest09", MagicDetectTest09, 1); */

    UtRegisterTest("MagicDetectTest10ValgrindError",
                   MagicDetectTest10ValgrindError);
#endif /* UNITTESTS */
}
