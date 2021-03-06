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
 * \todo RAW* macro's should be returning the raw value, not the host order
 */

#ifndef __DECODE_TCP_H__
#define __DECODE_TCP_H__

#define TCP_HEADER_LEN                       20
#define TCP_OPTLENMAX                        40
#define TCP_OPTMAX                           20 /* every opt is at least 2 bytes
                                                 * (type + len), except EOL and NOP */

/* TCP flags */

#define TH_FIN                               0x01
#define TH_SYN                               0x02
#define TH_RST                               0x04
#define TH_PUSH                              0x08
#define TH_ACK                               0x10
#define TH_URG                               0x20
/** Establish a new connection reducing window */
#define TH_ECN                               0x40
/** Echo Congestion flag */
#define TH_CWR                               0x80

/*
类型	               含义
TCP_OPT_EOL	   选项表结束。
TCP_OPT_NOP	   空操作，一般用于将TCP选项的总长度填充为4字节的整数倍。
TCP_OPT_MSS	   最大报文段长度选项，一般设置为MTU-40，关于MTU可参考：以太网最大帧和最小帧、MTU。
TCP_OPT_WS	    窗口扩大选项，用于增加TCP窗口值（16位，最大64KB），提高吞吐量。
TCP_OPT_SACKOK	选择性确认（Selective Acknowledgements ）选项，用在连接初始化时，表示是否支持SACK技术。
TCP_OPT_SACK	 SACK实际工作的选项，可让发送端只重新发送丢失的TCP报文段。
TCP_OPT_TS	     时间戳选项，用于计算RTT，从而为TCP流量控制提供重要信息。
*/
/* tcp option codes */
#define TCP_OPT_EOL                          0x00 /*选项表结束。*/
#define TCP_OPT_NOP                          0x01 /*空操作，一般用于将TCP选项的总长度填充为4字节的整数倍。*/
#define TCP_OPT_MSS                          0x02 /*最大报文段长度选项，一般设置为MTU-40，关于MTU可参考：以太网最大帧和最小帧、MTU。*/
#define TCP_OPT_WS                           0x03 /*窗口扩大选项，用于增加TCP窗口值（16位，最大64KB），提高吞吐量。*/
#define TCP_OPT_SACKOK                       0x04 /*选择性确认（Selective Acknowledgements ）选项，用在连接初始化时，表示是否支持SACK技术。*/
#define TCP_OPT_SACK                         0x05 /*实际工作的选项，可让发送端只重新发送丢失的TCP报文段。*/
#define TCP_OPT_TS                           0x08 /*时间戳选项，用于计算RTT，从而为TCP流量控制提供重要信息。*/

#define TCP_OPT_SACKOK_LEN                   2
#define TCP_OPT_WS_LEN                       3
#define TCP_OPT_TS_LEN                       10
#define TCP_OPT_MSS_LEN                      4
#define TCP_OPT_SACK_MIN_LEN                 10 /* hdr 2, 1 pair 8 = 10 */
#define TCP_OPT_SACK_MAX_LEN                 34 /* hdr 2, 4 pair 32= 34 */

/** Max valid wscale value. */
#define TCP_WSCALE_MAX                       14

#define TCP_GET_RAW_OFFSET(tcph)             (((tcph)->th_offx2 & 0xf0) >> 4)
#define TCP_GET_RAW_X2(tcph)                 (unsigned char)((tcph)->th_offx2 & 0x0f)
#define TCP_GET_RAW_SRC_PORT(tcph)           ntohs((tcph)->th_sport)
#define TCP_GET_RAW_DST_PORT(tcph)           ntohs((tcph)->th_dport)

#define TCP_SET_RAW_TCP_OFFSET(tcph, value)  ((tcph)->th_offx2 = (unsigned char)(((tcph)->th_offx2 & 0x0f) | (value << 4)))
#define TCP_SET_RAW_TCP_X2(tcph, value)      ((tcph)->th_offx2 = (unsigned char)(((tcph)->th_offx2 & 0xf0) | (value & 0x0f)))

#define TCP_GET_RAW_SEQ(tcph)                ntohl((tcph)->th_seq)
#define TCP_GET_RAW_ACK(tcph)                ntohl((tcph)->th_ack)

#define TCP_GET_RAW_WINDOW(tcph)             ntohs((tcph)->th_win)
#define TCP_GET_RAW_URG_POINTER(tcph)        ntohs((tcph)->th_urp)
#define TCP_GET_RAW_SUM(tcph)                ntohs((tcph)->th_sum)

/** macro for getting the first timestamp from the packet in host order */
#define TCP_GET_TSVAL(p)                    ((p)->tcpvars.ts_val)

/** macro for getting the second timestamp from the packet in host order. */
#define TCP_GET_TSECR(p)                    ((p)->tcpvars.ts_ecr)

#define TCP_HAS_WSCALE(p)                   ((p)->tcpvars.ws.type == TCP_OPT_WS)
#define TCP_HAS_SACK(p)                     ((p)->tcpvars.sack.type == TCP_OPT_SACK)
#define TCP_HAS_SACKOK(p)                   ((p)->tcpvars.sackok.type == TCP_OPT_SACKOK)
#define TCP_HAS_TS(p)                       ((p)->tcpvars.ts_set == TRUE)
#define TCP_HAS_MSS(p)                      ((p)->tcpvars.mss.type == TCP_OPT_MSS)

/** macro for getting the wscale from the packet. */
#define TCP_GET_WSCALE(p)                    (TCP_HAS_WSCALE((p)) ? \
                                                (((*(uint8_t *)(p)->tcpvars.ws.data) <= TCP_WSCALE_MAX) ? \
                                                  (*(uint8_t *)((p)->tcpvars.ws.data)) : 0) : 0)

#define TCP_GET_SACKOK(p)                    (TCP_HAS_SACKOK((p)) ? 1 : 0)
#define TCP_GET_SACK_PTR(p)                  TCP_HAS_SACK((p)) ? (p)->tcpvars.sack.data : NULL
#define TCP_GET_SACK_CNT(p)                  (TCP_HAS_SACK((p)) ? (((p)->tcpvars.sack.len - 2) / 8) : 0)

#define TCP_GET_OFFSET(p)                    TCP_GET_RAW_OFFSET((p)->tcph)
#define TCP_GET_X2(p)                        TCP_GET_RAW_X2((p)->tcph)
#define TCP_GET_HLEN(p)                      (TCP_GET_OFFSET((p)) << 2)
#define TCP_GET_SRC_PORT(p)                  TCP_GET_RAW_SRC_PORT((p)->tcph)
#define TCP_GET_DST_PORT(p)                  TCP_GET_RAW_DST_PORT((p)->tcph)
#define TCP_GET_SEQ(p)                       TCP_GET_RAW_SEQ((p)->tcph)
#define TCP_GET_ACK(p)                       TCP_GET_RAW_ACK((p)->tcph)
#define TCP_GET_WINDOW(p)                    TCP_GET_RAW_WINDOW((p)->tcph)
#define TCP_GET_URG_POINTER(p)               TCP_GET_RAW_URG_POINTER((p)->tcph)
#define TCP_GET_SUM(p)                       TCP_GET_RAW_SUM((p)->tcph)
#define TCP_GET_FLAGS(p)                     (p)->tcph->th_flags

#define TCP_ISSET_FLAG_FIN(p)                ((p)->tcph->th_flags & TH_FIN)
#define TCP_ISSET_FLAG_SYN(p)                ((p)->tcph->th_flags & TH_SYN)
#define TCP_ISSET_FLAG_RST(p)                ((p)->tcph->th_flags & TH_RST)
#define TCP_ISSET_FLAG_PUSH(p)               ((p)->tcph->th_flags & TH_PUSH)
#define TCP_ISSET_FLAG_ACK(p)                ((p)->tcph->th_flags & TH_ACK)
#define TCP_ISSET_FLAG_URG(p)                ((p)->tcph->th_flags & TH_URG)
#define TCP_ISSET_FLAG_RES2(p)               ((p)->tcph->th_flags & TH_RES2)
#define TCP_ISSET_FLAG_RES1(p)               ((p)->tcph->th_flags & TH_RES1)

typedef struct TCPOpt_ {
    uint8_t type;/* 选项类型 */
    uint8_t len;/* 选项长度 */
    uint8_t *data;/* 内容指针 */
} TCPOpt;

typedef struct TCPOptSackRecord_ {
    uint32_t le;        /**< left edge, network order */
    uint32_t re;        /**< right edge, network order */
} TCPOptSackRecord;

typedef struct TCPHdr_
{
    uint16_t th_sport;  /**< source port */
    uint16_t th_dport;  /**< destination port */
    uint32_t th_seq;    /**< sequence number */
    uint32_t th_ack;    /**< acknowledgement number */
    uint8_t th_offx2;   /**< offset and reserved */
    uint8_t th_flags;   /**< pkt flags */
    uint16_t th_win;    /**< pkt window */
    uint16_t th_sum;    /**< checksum */
    uint16_t th_urp;    /**< urgent pointer */
} __attribute__((__packed__)) TCPHdr;

typedef struct TCPVars_
{
    /* commonly used and needed opts */
    _Bool ts_set;
    uint32_t ts_val;    /* host-order */
    uint32_t ts_ecr;    /* host-order */
    TCPOpt sack;
    TCPOpt sackok;
    TCPOpt ws;
    TCPOpt mss;
} TCPVars;

#define CLEAR_TCP_PACKET(p) {   \
    (p)->level4_comp_csum = -1; \
    PACKET_CLEAR_L4VARS((p));   \
    (p)->tcph = NULL;           \
}

void DecodeTCPRegisterTests(void);

/** -------- Inline functions ------- */
static inline uint16_t TCPCalculateChecksum(uint16_t *, uint16_t *, uint16_t);
static inline uint16_t TCPV6CalculateChecksum(uint16_t *, uint16_t *, uint16_t);

/**
 * \brief Calculates the checksum for the TCP packet
 *
 * \param shdr Pointer to source address field from the IP packet.  Used as a
 *             part of the pseudoheader for computing the checksum
 * \param pkt  Pointer to the start of the TCP packet
 * \param tlen Total length of the TCP packet(header + payload)
 *
 * \retval csum Checksum for the TCP packet
 */
static inline uint16_t TCPCalculateChecksum(uint16_t *shdr, uint16_t *pkt,
                                            uint16_t tlen)
{
    uint16_t pad = 0;
    uint32_t csum = shdr[0];

    csum += shdr[1] + shdr[2] + shdr[3] + htons(6) + htons(tlen);

    csum += pkt[0] + pkt[1] + pkt[2] + pkt[3] + pkt[4] + pkt[5] + pkt[6] +
        pkt[7] + pkt[9];

    tlen -= 20;
    pkt += 10;

    while (tlen >= 32) {
        csum += pkt[0] + pkt[1] + pkt[2] + pkt[3] + pkt[4] + pkt[5] + pkt[6] +
            pkt[7] + pkt[8] + pkt[9] + pkt[10] + pkt[11] + pkt[12] + pkt[13] +
            pkt[14] + pkt[15];
        tlen -= 32;
        pkt += 16;
    }

    while(tlen >= 8) {
        csum += pkt[0] + pkt[1] + pkt[2] + pkt[3];
        tlen -= 8;
        pkt += 4;
    }

    while(tlen >= 4) {
        csum += pkt[0] + pkt[1];
        tlen -= 4;
        pkt += 2;
    }

    while (tlen > 1) {
        csum += pkt[0];
        pkt += 1;
        tlen -= 2;
    }

    if (tlen == 1) {
        *(uint8_t *)(&pad) = (*(uint8_t *)pkt);
        csum += pad;
    }

    csum = (csum >> 16) + (csum & 0x0000FFFF);
    csum += (csum >> 16);

    return (uint16_t)~csum;
}

/**
 * \brief Calculates the checksum for the TCP packet
 *
 * \param shdr Pointer to source address field from the IPV6 packet.  Used as a
 *             part of the psuedoheader for computing the checksum
 * \param pkt  Pointer to the start of the TCP packet
 * \param tlen Total length of the TCP packet(header + payload)
 *
 * \retval csum Checksum for the TCP packet
 */
static inline uint16_t TCPV6CalculateChecksum(uint16_t *shdr, uint16_t *pkt,
                                       uint16_t tlen)
{
    uint16_t pad = 0;
    uint32_t csum = shdr[0];

    csum += shdr[1] + shdr[2] + shdr[3] + shdr[4] + shdr[5] + shdr[6] +
        shdr[7] + shdr[8] + shdr[9] + shdr[10] + shdr[11] + shdr[12] +
        shdr[13] + shdr[14] + shdr[15] + htons(6) + htons(tlen);

    csum += pkt[0] + pkt[1] + pkt[2] + pkt[3] + pkt[4] + pkt[5] + pkt[6] +
        pkt[7] + pkt[9];

    tlen -= 20;
    pkt += 10;

    while (tlen >= 32) {
        csum += pkt[0] + pkt[1] + pkt[2] + pkt[3] + pkt[4] + pkt[5] + pkt[6] +
            pkt[7] + pkt[8] + pkt[9] + pkt[10] + pkt[11] + pkt[12] + pkt[13] +
            pkt[14] + pkt[15];
        tlen -= 32;
        pkt += 16;
    }

    while(tlen >= 8) {
        csum += pkt[0] + pkt[1] + pkt[2] + pkt[3];
        tlen -= 8;
        pkt += 4;
    }

    while(tlen >= 4) {
        csum += pkt[0] + pkt[1];
        tlen -= 4;
        pkt += 2;
    }

    while (tlen > 1) {
        csum += pkt[0];
        pkt += 1;
        tlen -= 2;
    }

    if (tlen == 1) {
        *(uint8_t *)(&pad) = (*(uint8_t *)pkt);
        csum += pad;
    }

    csum = (csum >> 16) + (csum & 0x0000FFFF);
    csum += (csum >> 16);

    return (uint16_t)~csum;
}


#endif /* __DECODE_TCP_H__ */

