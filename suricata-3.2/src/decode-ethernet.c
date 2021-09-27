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
 * \ingroup decode
 *
 * @{
 */


/**
 * \file
 *
 * \author Victor Julien <victor@inliniac.net>
 *
 * Decode Ethernet
 */

#include "suricata-common.h"
#include "decode.h"
#include "decode-ethernet.h"
#include "decode-events.h"

#include "util-unittest.h"
#include "util-debug.h"

/*
*Ethernet解码
DecodeEthernet函数流程：

若包长小于ETHERNET_HEADER_LEN（14），则调用ENGINE_SET_EVENT向本数据包添加一个ETHERNET_PKT_TOO_SMALL事件，并返回。
设置ethh指针（EthernetHdr *类型），并根据eth_type调用下一层的解码函数：
以太网承载类型	解码函数	说明
ETHERNET_TYPE_IP	DecodeIPV4	IPv4数据包
ETHERNET_TYPE_IPV6	DecodeIPV6	IPv6数据包
ETHERNET_TYPE_PPPOE_SESS	DecodePPPOESession	PPPoE会话阶段数据包，见：PPPoE - 维基百科
ETHERNET_TYPE_PPPOE_DISC	DecodePPPOEDiscovery	PPPoE发现阶段数据包
ETHERNET_TYPE_VLAN	DecodeVLAN	VLAN数据包，见：虚拟局域网 - 维基百科
PPPoE和VLAN都是夹在Ethernet协议和IP协议之间的，而相比PPPoE来说，VLAN在公司环境中更加普遍，
因此下面只记录VLAN解码。
*/
int DecodeEthernet(ThreadVars *tv, DecodeThreadVars *dtv, Packet *p,
                   uint8_t *pkt, uint16_t len, PacketQueue *pq)
{
    StatsIncr(tv, dtv->counter_eth);

    if (unlikely(len < ETHERNET_HEADER_LEN)) {
        ENGINE_SET_INVALID_EVENT(p, ETHERNET_PKT_TOO_SMALL);
        return TM_ECODE_FAILED;
    }

    p->ethh = (EthernetHdr *)pkt;
    if (unlikely(p->ethh == NULL))
        return TM_ECODE_FAILED;

    SCLogDebug("p %p pkt %p ether type %04x", p, pkt, ntohs(p->ethh->eth_type));

    switch (ntohs(p->ethh->eth_type)) {
        case ETHERNET_TYPE_IP:
            //printf("DecodeEthernet ip4\n");
            DecodeIPV4(tv, dtv, p, pkt + ETHERNET_HEADER_LEN,
                       len - ETHERNET_HEADER_LEN, pq);
            break;
        case ETHERNET_TYPE_IPV6:
            //printf("DecodeEthernet ip6\n");
            DecodeIPV6(tv, dtv, p, pkt + ETHERNET_HEADER_LEN,
                       len - ETHERNET_HEADER_LEN, pq);
            break;
        case ETHERNET_TYPE_PPPOE_SESS:
            //printf("DecodeEthernet PPPOE Session\n");
            DecodePPPOESession(tv, dtv, p, pkt + ETHERNET_HEADER_LEN,
                               len - ETHERNET_HEADER_LEN, pq);
            break;
        case ETHERNET_TYPE_PPPOE_DISC:
            //printf("DecodeEthernet PPPOE Discovery\n");
            DecodePPPOEDiscovery(tv, dtv, p, pkt + ETHERNET_HEADER_LEN,
                                 len - ETHERNET_HEADER_LEN, pq);
            break;
        case ETHERNET_TYPE_VLAN:
        case ETHERNET_TYPE_8021QINQ:
            DecodeVLAN(tv, dtv, p, pkt + ETHERNET_HEADER_LEN,
                                 len - ETHERNET_HEADER_LEN, pq);
            break;
        case ETHERNET_TYPE_MPLS_UNICAST:
        case ETHERNET_TYPE_MPLS_MULTICAST:
            DecodeMPLS(tv, dtv, p, pkt + ETHERNET_HEADER_LEN,
                       len - ETHERNET_HEADER_LEN, pq);
            break;
        case ETHERNET_TYPE_DCE:
            if (unlikely(len < ETHERNET_DCE_HEADER_LEN)) {
                ENGINE_SET_INVALID_EVENT(p, DCE_PKT_TOO_SMALL);
            } else {
                DecodeEthernet(tv, dtv, p, pkt + ETHERNET_DCE_HEADER_LEN,
                    len - ETHERNET_DCE_HEADER_LEN, pq);
            }
            break;
        default:
            SCLogDebug("p %p pkt %p ether type %04x not supported", p,
                       pkt, ntohs(p->ethh->eth_type));
    }

    return TM_ECODE_OK;
}

#ifdef UNITTESTS
/** DecodeEthernettest01
 *  \brief Valid Ethernet packet
 *  \retval 0 Expected test value
 */
static int DecodeEthernetTest01 (void)
{
    /* ICMP packet wrapped in PPPOE */
    uint8_t raw_eth[] = {
        0x00, 0x10, 0x94, 0x55, 0x00, 0x01, 0x00, 0x10,
        0x94, 0x56, 0x00, 0x01, 0x88, 0x64, 0x11, 0x00,
        0x00, 0x01, 0x00, 0x68, 0x00, 0x21, 0x45, 0xc0,
        0x00, 0x64, 0x00, 0x1e, 0x00, 0x00, 0xff, 0x01,
        0xa7, 0x78, 0x0a, 0x00, 0x00, 0x02, 0x0a, 0x00,
        0x00, 0x01, 0x08, 0x00, 0x4a, 0x61, 0x00, 0x06,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0f,
        0x3b, 0xd4, 0xab, 0xcd, 0xab, 0xcd, 0xab, 0xcd,
        0xab, 0xcd, 0xab, 0xcd, 0xab, 0xcd, 0xab, 0xcd,
        0xab, 0xcd, 0xab, 0xcd, 0xab, 0xcd, 0xab, 0xcd,
        0xab, 0xcd, 0xab, 0xcd, 0xab, 0xcd, 0xab, 0xcd,
        0xab, 0xcd, 0xab, 0xcd, 0xab, 0xcd, 0xab, 0xcd,
        0xab, 0xcd, 0xab, 0xcd, 0xab, 0xcd, 0xab, 0xcd,
        0xab, 0xcd, 0xab, 0xcd, 0xab, 0xcd, 0xab, 0xcd,
        0xab, 0xcd, 0xab, 0xcd, 0xab, 0xcd, 0xab, 0xcd,
        0xab, 0xcd };

    Packet *p = SCMalloc(SIZE_OF_PACKET);
    if (unlikely(p == NULL))
        return 0;
    ThreadVars tv;
    DecodeThreadVars dtv;

    memset(&dtv, 0, sizeof(DecodeThreadVars));
    memset(&tv,  0, sizeof(ThreadVars));
    memset(p, 0, SIZE_OF_PACKET);

    DecodeEthernet(&tv, &dtv, p, raw_eth, sizeof(raw_eth), NULL);

    SCFree(p);
    return 1;
}
#endif /* UNITTESTS */


/**
 * \brief Registers Ethernet unit tests
 * \todo More Ethernet tests
 */
void DecodeEthernetRegisterTests(void)
{
#ifdef UNITTESTS
    UtRegisterTest("DecodeEthernetTest01", DecodeEthernetTest01);
#endif /* UNITTESTS */
}
/**
 * @}
 */
