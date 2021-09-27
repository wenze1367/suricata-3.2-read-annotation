/* Copyright (C) 2007-2012 Open Information Security Foundation
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
 * Information about ippairs.
 */

#include "suricata-common.h"
#include "conf.h"

#include "util-debug.h"
#include "ippair.h"
#include "ippair-storage.h"

#include "util-random.h"
#include "util-misc.h"
#include "util-byte.h"

#include "ippair-queue.h"

#include "detect-tag.h"
#include "detect-engine-tag.h"
#include "detect-engine-threshold.h"

#include "util-hash-lookup3.h"

static IPPair *IPPairGetUsedIPPair(void);

/** queue with spare ippairs */
static IPPairQueue ippair_spare_q;

/** size of the ippair object. Maybe updated in IPPairInitConfig to include
 *  the storage APIs additions. */
static uint16_t g_ippair_size = sizeof(IPPair);

uint32_t IPPairSpareQueueGetSize(void)
{
    return IPPairQueueLen(&ippair_spare_q);
}

void IPPairMoveToSpare(IPPair *h)
{
    IPPairEnqueue(&ippair_spare_q, h);
    (void) SC_ATOMIC_SUB(ippair_counter, 1);
}

IPPair *IPPairAlloc(void)
{
    if (!(IPPAIR_CHECK_MEMCAP(g_ippair_size))) {
        return NULL;
    }

    (void) SC_ATOMIC_ADD(ippair_memuse, g_ippair_size);

    IPPair *h = SCMalloc(g_ippair_size);
    if (unlikely(h == NULL))
        goto error;

    memset(h, 0x00, g_ippair_size);

    SCMutexInit(&h->m, NULL);
    SC_ATOMIC_INIT(h->use_cnt);
    return h;

error:
    return NULL;
}

void IPPairFree(IPPair *h)
{
    if (h != NULL) {
        IPPairClearMemory(h);

        SC_ATOMIC_DESTROY(h->use_cnt);
        SCMutexDestroy(&h->m);
        SCFree(h);
        (void) SC_ATOMIC_SUB(ippair_memuse, g_ippair_size);
    }
}

IPPair *IPPairNew(Address *a, Address *b)
{
    IPPair *p = IPPairAlloc();
    if (p == NULL)
        goto error;

    /* copy addresses */
    COPY_ADDRESS(a, &p->a[0]);
    COPY_ADDRESS(b, &p->a[1]);

    return p;

error:
    return NULL;
}

void IPPairClearMemory(IPPair *h)
{
    if (IPPairStorageSize() > 0)
        IPPairFreeStorage(h);
}

#define IPPAIR_DEFAULT_HASHSIZE 4096
#define IPPAIR_DEFAULT_MEMCAP 16777216
#define IPPAIR_DEFAULT_PREALLOC 1000

/** \brief initialize the configuration
 *  \warning Not thread safe */
void IPPairInitConfig(char quiet)
{
    SCLogDebug("initializing ippair engine...");
    if (IPPairStorageSize() > 0)
        g_ippair_size = sizeof(IPPair) + IPPairStorageSize();

    memset(&ippair_config,  0, sizeof(ippair_config));
    //SC_ATOMIC_INIT(flow_flags);
    SC_ATOMIC_INIT(ippair_counter);
    SC_ATOMIC_INIT(ippair_memuse);
    SC_ATOMIC_INIT(ippair_prune_idx);
    IPPairQueueInit(&ippair_spare_q);

#ifndef AFLFUZZ_NO_RANDOM
    unsigned int seed = RandomTimePreseed();
    /* set defaults */
    ippair_config.hash_rand   = (int)( IPPAIR_DEFAULT_HASHSIZE * (rand_r(&seed) / RAND_MAX + 1.0));
#endif
    ippair_config.hash_size   = IPPAIR_DEFAULT_HASHSIZE;
    ippair_config.memcap      = IPPAIR_DEFAULT_MEMCAP;
    ippair_config.prealloc    = IPPAIR_DEFAULT_PREALLOC;

    /* Check if we have memcap and hash_size defined at config */
    char *conf_val;
    uint32_t configval = 0;

    /** set config values for memcap, prealloc and hash_size */
    if ((ConfGet("ippair.memcap", &conf_val)) == 1)
    {
        if (ParseSizeStringU64(conf_val, &ippair_config.memcap) < 0) {
            SCLogError(SC_ERR_SIZE_PARSE, "Error parsing ippair.memcap "
                       "from conf file - %s.  Killing engine",
                       conf_val);
            exit(EXIT_FAILURE);
        }
    }
    if ((ConfGet("ippair.hash-size", &conf_val)) == 1)
    {
        if (ByteExtractStringUint32(&configval, 10, strlen(conf_val),
                                    conf_val) > 0) {
            ippair_config.hash_size = configval;
        }
    }

    if ((ConfGet("ippair.prealloc", &conf_val)) == 1)
    {
        if (ByteExtractStringUint32(&configval, 10, strlen(conf_val),
                                    conf_val) > 0) {
            ippair_config.prealloc = configval;
        } else {
            WarnInvalidConfEntry("ippair.prealloc", "%"PRIu32, ippair_config.prealloc);
        }
    }
    SCLogDebug("IPPair config from suricata.yaml: memcap: %"PRIu64", hash-size: "
               "%"PRIu32", prealloc: %"PRIu32, ippair_config.memcap,
               ippair_config.hash_size, ippair_config.prealloc);

    /* alloc hash memory */
    uint64_t hash_size = ippair_config.hash_size * sizeof(IPPairHashRow);
    if (!(IPPAIR_CHECK_MEMCAP(hash_size))) {
        SCLogError(SC_ERR_IPPAIR_INIT, "allocating ippair hash failed: "
                "max ippair memcap is smaller than projected hash size. "
                "Memcap: %"PRIu64", Hash table size %"PRIu64". Calculate "
                "total hash size by multiplying \"ippair.hash-size\" with %"PRIuMAX", "
                "which is the hash bucket size.", ippair_config.memcap, hash_size,
                (uintmax_t)sizeof(IPPairHashRow));
        exit(EXIT_FAILURE);
    }
    ippair_hash = SCMallocAligned(ippair_config.hash_size * sizeof(IPPairHashRow), CLS);
    if (unlikely(ippair_hash == NULL)) {
        SCLogError(SC_ERR_FATAL, "Fatal error encountered in IPPairInitConfig. Exiting...");
        exit(EXIT_FAILURE);
    }
    memset(ippair_hash, 0, ippair_config.hash_size * sizeof(IPPairHashRow));

    uint32_t i = 0;
    for (i = 0; i < ippair_config.hash_size; i++) {
        HRLOCK_INIT(&ippair_hash[i]);
    }
    (void) SC_ATOMIC_ADD(ippair_memuse, (ippair_config.hash_size * sizeof(IPPairHashRow)));

    if (quiet == FALSE) {
        SCLogConfig("allocated %llu bytes of memory for the ippair hash... "
                  "%" PRIu32 " buckets of size %" PRIuMAX "",
                  SC_ATOMIC_GET(ippair_memuse), ippair_config.hash_size,
                  (uintmax_t)sizeof(IPPairHashRow));
    }

    /* pre allocate ippairs */
    for (i = 0; i < ippair_config.prealloc; i++) {
        if (!(IPPAIR_CHECK_MEMCAP(g_ippair_size))) {
            SCLogError(SC_ERR_IPPAIR_INIT, "preallocating ippairs failed: "
                    "max ippair memcap reached. Memcap %"PRIu64", "
                    "Memuse %"PRIu64".", ippair_config.memcap,
                    ((uint64_t)SC_ATOMIC_GET(ippair_memuse) + g_ippair_size));
            exit(EXIT_FAILURE);
        }

        IPPair *h = IPPairAlloc();
        if (h == NULL) {
            SCLogError(SC_ERR_IPPAIR_INIT, "preallocating ippair failed: %s", strerror(errno));
            exit(EXIT_FAILURE);
        }
        IPPairEnqueue(&ippair_spare_q,h);
    }

    if (quiet == FALSE) {
        SCLogConfig("preallocated %" PRIu32 " ippairs of size %" PRIu16 "",
                ippair_spare_q.len, g_ippair_size);
        SCLogConfig("ippair memory usage: %llu bytes, maximum: %"PRIu64,
                SC_ATOMIC_GET(ippair_memuse), ippair_config.memcap);
    }

    return;
}

/** \brief print some ippair stats
 *  \warning Not thread safe */
void IPPairPrintStats (void)
{
#ifdef IPPAIRBITS_STATS
    SCLogPerf("ippairbits added: %" PRIu32 ", removed: %" PRIu32 ", max memory usage: %" PRIu32 "",
        ippairbits_added, ippairbits_removed, ippairbits_memuse_max);
#endif /* IPPAIRBITS_STATS */
    SCLogPerf("ippair memory usage: %llu bytes, maximum: %"PRIu64,
            SC_ATOMIC_GET(ippair_memuse), ippair_config.memcap);
    return;
}

/** \brief shutdown the flow engine
 *  \warning Not thread safe */
void IPPairShutdown(void)
{
    IPPair *h;
    uint32_t u;

    IPPairPrintStats();

    /* free spare queue */
    while((h = IPPairDequeue(&ippair_spare_q))) {
        BUG_ON(SC_ATOMIC_GET(h->use_cnt) > 0);
        IPPairFree(h);
    }

    /* clear and free the hash */
    if (ippair_hash != NULL) {
        for (u = 0; u < ippair_config.hash_size; u++) {
            h = ippair_hash[u].head;
            while (h) {
                IPPair *n = h->hnext;
                IPPairFree(h);
                h = n;
            }

            HRLOCK_DESTROY(&ippair_hash[u]);
        }
        SCFreeAligned(ippair_hash);
        ippair_hash = NULL;
    }
    (void) SC_ATOMIC_SUB(ippair_memuse, ippair_config.hash_size * sizeof(IPPairHashRow));
    IPPairQueueDestroy(&ippair_spare_q);

    SC_ATOMIC_DESTROY(ippair_prune_idx);
    SC_ATOMIC_DESTROY(ippair_memuse);
    SC_ATOMIC_DESTROY(ippair_counter);
    //SC_ATOMIC_DESTROY(flow_flags);
    return;
}

/** \brief Cleanup the ippair engine
 *
 * Cleanup the ippair engine from tag and threshold.
 *
 */
void IPPairCleanup(void)
{
    IPPair *h;
    uint32_t u;

    if (ippair_hash != NULL) {
        for (u = 0; u < ippair_config.hash_size; u++) {
            h = ippair_hash[u].head;
            IPPairHashRow *hb = &ippair_hash[u];
            HRLOCK_LOCK(hb);
            while (h) {
                if ((SC_ATOMIC_GET(h->use_cnt) > 0)) {
                    /* iprep is attached to ippair only clear local storage */
                    IPPairFreeStorage(h);
                    h = h->hnext;
                } else {
                    IPPair *n = h->hnext;
                    /* remove from the hash */
                    if (h->hprev != NULL)
                        h->hprev->hnext = h->hnext;
                    if (h->hnext != NULL)
                        h->hnext->hprev = h->hprev;
                    if (hb->head == h)
                        hb->head = h->hnext;
                    if (hb->tail == h)
                        hb->tail = h->hprev;
                    h->hnext = NULL;
                    h->hprev = NULL;
                    IPPairClearMemory(h);
                    IPPairMoveToSpare(h);
                    h = n;
                }
            }
            HRLOCK_UNLOCK(hb);
        }
    }

    return;
}

/* calculate the hash key for this packet
 *
 * we're using:
 *  hash_rand -- set at init time
 *  source address
 */
static uint32_t IPPairGetKey(Address *a, Address *b)
{
    uint32_t key;

    if (a->family == AF_INET) {
        uint32_t hash = hashword(&a->addr_data32[0], 1, ippair_config.hash_rand);
        key = hash % ippair_config.hash_size;
    } else if (a->family == AF_INET6) {
        uint32_t hash = hashword(a->addr_data32, 4, ippair_config.hash_rand);
        key = hash % ippair_config.hash_size;
    } else
        key = 0;

    return key;
}

/* Since two or more ippairs can have the same hash key, we need to compare
 * the ippair with the current addresses. */
static inline int IPPairCompare(IPPair *p, Address *a, Address *b)
{
    /* compare in both directions */
    if ((CMP_ADDR(&p->a[0], a) && CMP_ADDR(&p->a[1], b)) ||
        (CMP_ADDR(&p->a[0], b) && CMP_ADDR(&p->a[1], a)))
        return 1;
    return 0;
}

/**
 *  \brief Get a new ippair
 *
 *  Get a new ippair. We're checking memcap first and will try to make room
 *  if the memcap is reached.
 *
 *  \retval h *LOCKED* ippair on succes, NULL on error.
 */
static IPPair *IPPairGetNew(Address *a, Address *b)
{
    IPPair *h = NULL;

    /* get a ippair from the spare queue */
    h = IPPairDequeue(&ippair_spare_q);
    if (h == NULL) {
        /* If we reached the max memcap, we get a used ippair */
        if (!(IPPAIR_CHECK_MEMCAP(g_ippair_size))) {
            /* declare state of emergency */
            //if (!(SC_ATOMIC_GET(ippair_flags) & IPPAIR_EMERGENCY)) {
            //    SC_ATOMIC_OR(ippair_flags, IPPAIR_EMERGENCY);

                /* under high load, waking up the flow mgr each time leads
                 * to high cpu usage. Flows are not timed out much faster if
                 * we check a 1000 times a second. */
            //    FlowWakeupFlowManagerThread();
            //}

            h = IPPairGetUsedIPPair();
            if (h == NULL) {
                return NULL;
            }

            /* freed a ippair, but it's unlocked */
        } else {
            /* now see if we can alloc a new ippair */
            h = IPPairNew(a,b);
            if (h == NULL) {
                return NULL;
            }

            /* ippair is initialized but *unlocked* */
        }
    } else {
        /* ippair has been recycled before it went into the spare queue */

        /* ippair is initialized (recylced) but *unlocked* */
    }

    (void) SC_ATOMIC_ADD(ippair_counter, 1);
    SCMutexLock(&h->m);
    return h;
}

void IPPairInit(IPPair *h, Address *a, Address *b)
{
    COPY_ADDRESS(a, &h->a[0]);
    COPY_ADDRESS(b, &h->a[1]);
    (void) IPPairIncrUsecnt(h);
}

void IPPairRelease(IPPair *h)
{
    (void) IPPairDecrUsecnt(h);
    SCMutexUnlock(&h->m);
}

void IPPairLock(IPPair *h)
{
    SCMutexLock(&h->m);
}

void IPPairUnlock(IPPair *h)
{
    SCMutexUnlock(&h->m);
}

/* IPPairGetIPPairFromHash
 *
 * Hash retrieval function for ippairs. Looks up the hash bucket containing the
 * ippair pointer. Then compares the packet with the found ippair to see if it is
 * the ippair we need. If it isn't, walk the list until the right ippair is found.
 *
 * returns a *LOCKED* ippair or NULL
 */
IPPair *IPPairGetIPPairFromHash (Address *a, Address *b)
{
    IPPair *h = NULL;

    /* get the key to our bucket */
    uint32_t key = IPPairGetKey(a, b);
    /* get our hash bucket and lock it */
    IPPairHashRow *hb = &ippair_hash[key];
    HRLOCK_LOCK(hb);

    /* see if the bucket already has a ippair */
    if (hb->head == NULL) {
        h = IPPairGetNew(a,b);
        if (h == NULL) {
            HRLOCK_UNLOCK(hb);
            return NULL;
        }

        /* ippair is locked */
        hb->head = h;
        hb->tail = h;

        /* got one, now lock, initialize and return */
        IPPairInit(h,a,b);

        HRLOCK_UNLOCK(hb);
        return h;
    }

    /* ok, we have a ippair in the bucket. Let's find out if it is our ippair */
    h = hb->head;

    /* see if this is the ippair we are looking for */
    if (IPPairCompare(h, a, b) == 0) {
        IPPair *ph = NULL; /* previous ippair */

        while (h) {
            ph = h;
            h = h->hnext;

            if (h == NULL) {
                h = ph->hnext = IPPairGetNew(a,b);
                if (h == NULL) {
                    HRLOCK_UNLOCK(hb);
                    return NULL;
                }
                hb->tail = h;

                /* ippair is locked */

                h->hprev = ph;

                /* initialize and return */
                IPPairInit(h,a,b);

                HRLOCK_UNLOCK(hb);
                return h;
            }

            if (IPPairCompare(h, a, b) != 0) {
                /* we found our ippair, lets put it on top of the
                 * hash list -- this rewards active ippairs */
                if (h->hnext) {
                    h->hnext->hprev = h->hprev;
                }
                if (h->hprev) {
                    h->hprev->hnext = h->hnext;
                }
                if (h == hb->tail) {
                    hb->tail = h->hprev;
                }

                h->hnext = hb->head;
                h->hprev = NULL;
                hb->head->hprev = h;
                hb->head = h;

                /* found our ippair, lock & return */
                SCMutexLock(&h->m);
                (void) IPPairIncrUsecnt(h);
                HRLOCK_UNLOCK(hb);
                return h;
            }
        }
    }

    /* lock & return */
    SCMutexLock(&h->m);
    (void) IPPairIncrUsecnt(h);
    HRLOCK_UNLOCK(hb);
    return h;
}

/** \brief look up a ippair in the hash
 *
 *  \param a address to look up
 *
 *  \retval h *LOCKED* ippair or NULL
 */
IPPair *IPPairLookupIPPairFromHash (Address *a, Address *b)
{
    IPPair *h = NULL;

    /* get the key to our bucket */
    uint32_t key = IPPairGetKey(a, b);
    /* get our hash bucket and lock it */
    IPPairHashRow *hb = &ippair_hash[key];
    HRLOCK_LOCK(hb);

    /* see if the bucket already has a ippair */
    if (hb->head == NULL) {
        HRLOCK_UNLOCK(hb);
        return h;
    }

    /* ok, we have a ippair in the bucket. Let's find out if it is our ippair */
    h = hb->head;

    /* see if this is the ippair we are looking for */
    if (IPPairCompare(h, a, b) == 0) {
        while (h) {
            h = h->hnext;

            if (h == NULL) {
                HRLOCK_UNLOCK(hb);
                return h;
            }

            if (IPPairCompare(h, a, b) != 0) {
                /* we found our ippair, lets put it on top of the
                 * hash list -- this rewards active ippairs */
                if (h->hnext) {
                    h->hnext->hprev = h->hprev;
                }
                if (h->hprev) {
                    h->hprev->hnext = h->hnext;
                }
                if (h == hb->tail) {
                    hb->tail = h->hprev;
                }

                h->hnext = hb->head;
                h->hprev = NULL;
                hb->head->hprev = h;
                hb->head = h;

                /* found our ippair, lock & return */
                SCMutexLock(&h->m);
                (void) IPPairIncrUsecnt(h);
                HRLOCK_UNLOCK(hb);
                return h;
            }
        }
    }

    /* lock & return */
    SCMutexLock(&h->m);
    (void) IPPairIncrUsecnt(h);
    HRLOCK_UNLOCK(hb);
    return h;
}

/** \internal
 *  \brief Get a ippair from the hash directly.
 *
 *  Called in conditions where the spare queue is empty and memcap is reached.
 *
 *  Walks the hash until a ippair can be freed. "ippair_prune_idx" atomic int makes
 *  sure we don't start at the top each time since that would clear the top of
 *  the hash leading to longer and longer search times under high pressure (observed).
 *
 *  \retval h ippair or NULL
 */
static IPPair *IPPairGetUsedIPPair(void)
{
    uint32_t idx = SC_ATOMIC_GET(ippair_prune_idx) % ippair_config.hash_size;
    uint32_t cnt = ippair_config.hash_size;

    while (cnt--) {
        if (++idx >= ippair_config.hash_size)
            idx = 0;

        IPPairHashRow *hb = &ippair_hash[idx];

        if (HRLOCK_TRYLOCK(hb) != 0)
            continue;

        IPPair *h = hb->tail;
        if (h == NULL) {
            HRLOCK_UNLOCK(hb);
            continue;
        }

        if (SCMutexTrylock(&h->m) != 0) {
            HRLOCK_UNLOCK(hb);
            continue;
        }

        /** never prune a ippair that is used by a packets
         *  we are currently processing in one of the threads */
        if (SC_ATOMIC_GET(h->use_cnt) > 0) {
            HRLOCK_UNLOCK(hb);
            SCMutexUnlock(&h->m);
            continue;
        }

        /* remove from the hash */
        if (h->hprev != NULL)
            h->hprev->hnext = h->hnext;
        if (h->hnext != NULL)
            h->hnext->hprev = h->hprev;
        if (hb->head == h)
            hb->head = h->hnext;
        if (hb->tail == h)
            hb->tail = h->hprev;

        h->hnext = NULL;
        h->hprev = NULL;
        HRLOCK_UNLOCK(hb);

        IPPairClearMemory (h);

        SCMutexUnlock(&h->m);

        (void) SC_ATOMIC_ADD(ippair_prune_idx, (ippair_config.hash_size - cnt));
        return h;
    }

    return NULL;
}

void IPPairRegisterUnittests(void)
{
    RegisterIPPairStorageTests();
}
