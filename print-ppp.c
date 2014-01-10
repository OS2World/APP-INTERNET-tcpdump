/*
 * Copyright (c) 1990, 1991, 1993, 1994, 1995, 1996, 1997
 *      The Regents of the University of California.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that: (1) source code distributions
 * retain the above copyright notice and this paragraph in its entirety, (2)
 * distributions including binary code include the above copyright notice and
 * this paragraph in its entirety in the documentation or other materials
 * provided with the distribution, and (3) all advertising materials mentioning
 * features or use of this software display the following acknowledgement:
 * ``This product includes software developed by the University of California,
 * Lawrence Berkeley Laboratory and its contributors.'' Neither the name of
 * the University nor the names of its contributors may be used to endorse
 * or promote products derived from this software without specific prior
 * written permission.
 * THIS SOFTWARE IS PROVIDED ``AS IS'' AND WITHOUT ANY EXPRESS OR IMPLIED
 * WARRANTIES, INCLUDING, WITHOUT LIMITATION, THE IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE.
 */

#ifndef lint
static const char rcsid[] =
    "@(#) $Header: print-ppp.c,v 1.26 97/06/12 14:21:29 leres Exp $ (LBL)";
#endif

#include <sys/types.h>
#include <sys/param.h>
#include <sys/time.h>
#include <sys/socket.h>
#include <sys/file.h>
#include <sys/ioctl.h>

#if __STDC__
struct mbuf;
struct rtentry;
#endif
#include <net/if.h>

#include <netinet/in.h>
#include <netinet/in_systm.h>
#include <netinet/ip.h>

#include <ctype.h>
#include <netdb.h>
#include <pcap.h>
#include <stdio.h>

#include "interface.h"
#include "addrtoname.h"
#include "ppp.h"
#include "lcp.h"

/* XXX This goes somewhere else. */
#define PPP_HDRLEN 4

/* Standard PPP printer */
void
ppp_if_print(u_char *user, const struct pcap_pkthdr *h,
             register const u_char *p)
{
        register u_int length = h->len;
        register u_int caplen = h->caplen;
        const struct ip *ip;

        ts_print(&h->ts);

        if (caplen < PPP_HDRLEN) {
                printf("[|ppp]");
                goto out;
        }

        /*
         * Some printers want to get back at the link level addresses,
         * and/or check that they're not walking off the end of the packet.
         * Rather than pass them all the way down, we set these globals.
         */
        packetp = p;
        snapend = p + caplen;

        if (eflag)
                printf("%c %4d %02x %04x: ", p[0] ? 'O' : 'I', length,
                       p[1], ntohs(*(u_short *)&p[2]));

        length -= PPP_HDRLEN;
        ip = (struct ip *)(p + PPP_HDRLEN);
        ip_print((const u_char *)ip, length);

        if (xflag)
                default_print((const u_char *)ip, caplen - PPP_HDRLEN);
out:
        putchar('\n');
}

/* proto type to string mapping */
static struct tok ptype2str[] = {
        { PPP_IP,       "IP" },
        { PPP_NS,       "NS" },
        { PPP_DECNET,   "DECnet" },
        { PPP_APPLE,    "Appletalk" },
        { PPP_IPX,      "IPX" },
        { PPP_BRPDU,    "Bridging PDU" },
        { PPP_STII,     "ST-II" },
        { PPP_VINES,    "Vines" },
        { PPP_HELLO,    "802.1d hello" },
        { PPP_LUXCOM,   "Luxcom" },
        { PPP_SNS,      "Sigma" },
        { PPP_IPCP,     "IP CP" },
        { PPP_OSICP,    "OSI CP" },
        { PPP_NSCP,     "NS CP" },
        { PPP_DECNETCP, "DECnet CP" },
        { PPP_APPLECP,  "Appletalk CP" },
        { PPP_IPXCP,    "IPX CP" },
        { PPP_VJC,      "VJC" },
        { PPP_VJNC,     "VJNC" },
        { PPP_OSI,      "OSI" },
        { PPP_LCP,      "LCP" },
        { PPP_STIICP,   "ST-II CP" },
        { PPP_VINESCP,  "Vines CP" },
        { PPP_LQM,      "LQM" },
        { PPP_PAP,      "PAP" },
        { PPP_CHAP,     "CHAP" },
        { PPP_CD,       "cdgram" },
        { PPP_ICD,      "icdgram" },
        { PPP_CCP,      "CCP" },
        { 0,            NULL }
};

/* LCP type to string mapping */
static struct tok ltype2str[] = {
        { LCP_CONFREQ,       "conf-req" },
        { LCP_CONFACK,       "conf-ack" },
        { LCP_CONFNAK,       "conf-nak" },
        { LCP_CONFREJ,       "conf-rej" },
        { LCP_TERMREQ,       "term-req" },
        { LCP_TERMACK,       "term-ack" },
        { LCP_CODEREJ,       "code-rej" },
        { LCP_PROTREQ,       "prot-req" },
        { LCP_ECHOREQ,       "echo-req" },
        { LCP_ECHOREP,       "echo-rep" },
        { LCP_DISCREQ,       "disc-req" },
        { LCP_RESTREQ,       "rest-req" },
        { LCP_RESTACK,       "rest-ack" },
        { 0,            NULL }
};

#define PPP_BSDI_HDRLEN 4

/* BSD/OS specific PPP printer */
void
ppp_bsdos_if_print(u_char *user, const struct pcap_pkthdr *h,
             register const u_char *p)
{
        register u_int length = h->len;
        register u_int caplen = h->caplen;
        register u_int totallen;
        register int hdrlength, tlrlength;
        register const u_char *fcs_start;
        u_short ptype;
        int i;

        ts_print(&h->ts);

        if (caplen < PPP_BSDI_HDRLEN) {
                printf("[|ppp]");
                goto out;
        }

        /*
         * Some printers want to get back at the link level addresses,
         * and/or check that they're not walking off the end of the packet.
         * Rather than pass them all the way down, we set these globals.
         */
        packetp = p;
        snapend = p + caplen;
        hdrlength = 0;
        tlrlength = 0;

#define HDLC_FLAG 0x7e
#define HDLC_ESCAPE 0x7d
#define HDLC_XOR 0x20

        totallen = 0;
        fcs_start = p;
        for (i = 0; i < caplen; i++, totallen++)
          p[totallen] = (p[i] == HDLC_ESCAPE) ? (p[++i] ^ HDLC_XOR) : p[i];

        /* strip optional HDLC flag */
        if (p[0] == HDLC_FLAG) {
          if (eflag)
                printf("%02x ", p[0]);
          p++;
          hdrlength++;
        }

        /* strip optional address and control fields */
        if (p[0] == PPP_ADDRESS && p[1] == PPP_CONTROL) {
                if (eflag)
                        printf("%02x %02x ", p[0], p[1]);
                p += 2;
                hdrlength += 2;
        }

        /* retrieve the protocol type */
        if (*p & 01) {
                /* compressed protocol field, one byte */
                ptype = *p;
                if (eflag)
                        printf("%02x ", ptype);
                p++;
                hdrlength += 1;
        } else {
                /* un-compressed protocol field, two bytes */
                ptype = ntohs(*(u_short *)p);
                if (eflag)
                        printf("%04x ", ptype);
                p += 2;
                hdrlength += 2;
        }


        if (p[totallen - hdrlength - 1] == HDLC_FLAG) {
          int fcs_len = totallen - 1;

          if (*fcs_start == HDLC_FLAG) {
            fcs_start++;
            fcs_len--;
          }

          if (ppp_fcs16_cksum(PPP_INITFCS16, fcs_start, fcs_len) == PPP_GOODFCS16)
            tlrlength += 2;
          else if (ppp_fcs32_cksum(PPP_INITFCS32, fcs_start, fcs_len) == PPP_GOODFCS32)
            tlrlength += 4;
          else
            if (eflag) printf("bad cksum ");

          tlrlength++;
        }
        else
          if (eflag) printf("|");

        if (eflag)
          printf("ppp-%s %d: ", tok2str(ptype2str, "#%d", ptype), caplen);
        else
          printf("ppp-%s: ", tok2str(ptype2str, "#%d", ptype));

        length = totallen - hdrlength - tlrlength;

        if (ptype == PPP_IP)
                ip_print(p, length);
        else if (ptype == PPP_APPLE)
                atalk_print(p, length);
        else if (ptype == PPP_IPX)
                ipx_print(p, length);
        else if (ptype == PPP_DECNET)
                decnet_print(p, length, length);
        else if (ptype == PPP_LCP)
                printf("%s", tok2str(ltype2str, "#%d", *p));

        if (xflag)
                default_print((const u_char *)p, length);
out:
        putchar('\n');
}
