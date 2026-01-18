#include "netcat.h"
#include "quic.h"

/*
 * QUIC Probing
 *
 * We send a QUIC Long Header packet with a reserved version to trigger
 * a Version Negotiation packet from the server.
 *
 * Packet Format (Initial/Long Header):
 * Byte 0: 1 (Header Form) | 1 (Fixed Bit) | Type (2 bits) | Type Specific (4 bits)
 *         We use 0xC0 (11000000) - Long Header, Fixed Bit set, Initial?
 *         Actually type for Initial is 0x0.
 *         So 0x80 | 0x40 | 0x00 ... = 0xC0?
 *         RFC 9000: Initial Packet Type is 0x0.
 *         Header Form (1) | Fixed Bit (1) | Long Packet Type (2) | Type Specific (4)
 *         1 1 00 0000 -> 0xC0.
 * Bytes 1-4: Version. We use a grease version or reserved version.
 *         0x0a0a0a0a (Grease)
 * Byte 5: DCID Len.
 * Bytes 6..: DCID.
 * Byte ..: SCID Len.
 * Bytes ..: SCID.
 *
 * We keep it simple.
 */

int quic_test(int s, char* host, char* port) {
    unsigned char buf[1200]; /* Min UDP payload for QUIC is often 1200, though initial can be smaller?
                                Clients MUST expand UDP payloads to at least 1200 bytes. */
    unsigned char recv_buf[2048];
    struct sockaddr_storage peer;
    socklen_t peerlen = sizeof(peer);
    ssize_t len;
    struct pollfd pfd;

    /*
     * Construct a QUIC Initial Packet with a reserved version.
     * Use version 0xbadc0de1 (Reserved/Grease-like)
     */
    memset(buf, 0, sizeof(buf));

    /* Header Byte: Long Header (0x80) | Fixed Bit (0x40) | Initial (0x00) */
    buf[0] = 0xC0;

    /* Version: 0xbadc0de1 (Not supported, triggers Version Negotiation) */
    buf[1] = 0xba;
    buf[2] = 0xdc;
    buf[3] = 0x0d;
    buf[4] = 0xe1;

    /* DCID Length: 8 bytes */
    buf[5] = 0x08;

    /* DCID: Random 8 bytes */
    arc4random_buf(&buf[6], 8);

    /* SCID Length: 0 bytes */
    buf[14] = 0x00;

    /* Token Length: 0 (Varint) */
    buf[15] = 0x00;

    /* Length: 0 (Varint) - Payload is empty/padding */
    buf[16] = 0x00;

    /*
     * Fill the rest with padding to reach 1200 bytes, as servers might drop smaller packets.
     * RFC 9000 8.1: "A client MUST expand the payload of all UDP datagrams carrying an Initial packet to at least 1200
     * bytes"
     */

    /* Send the probe */
    if (write(s, buf, 1200) != 1200) {
        warn("quic write failed");
        return -1;
    }

    /* Wait for response */
    pfd.fd = s;
    pfd.events = POLLIN;

    /* Wait up to timeout (default 2s if not set?) - Use 'timeout' global or 2000ms */
    int t = (timeout == -1) ? 2000 : timeout;

    if (poll(&pfd, 1, t) == -1) {
        warn("quic poll failed");
        return -1;
    }

    if (pfd.revents & POLLIN) {
        len = recvfrom(s, recv_buf, sizeof(recv_buf), 0, (struct sockaddr*)&peer, &peerlen);
        if (len < 0) {
            warn("quic recv failed");
            return -1;
        }

        /* Check for Version Negotiation Packet */
        /* Header: 1xxxxxxx */
        if ((recv_buf[0] & 0x80) == 0) {
            /* Short header? Unlikely response to Initial with bad version. */
            if (vflag)
                warnx("Received short header packet from %s", host);
            return 0;
        }

        /* Version must be 0 for Version Negotiation */
        if (len >= 5 && recv_buf[1] == 0 && recv_buf[2] == 0 && recv_buf[3] == 0 && recv_buf[4] == 0) {
            if (vflag)
                fprintf(stderr, "QUIC Version Negotiation packet received from %s\n", host);
            if (jflag) {
                /* Structured log is handled by connection_info generally, but we can augment? */
            }
            return 1;
        }

        /* Or maybe the server accepted our bogus version? Unlikely. */
        if (vflag)
            warnx("Received QUIC packet with version %02x%02x%02x%02x from %s", recv_buf[1], recv_buf[2], recv_buf[3],
                  recv_buf[4], host);

        /* If we got ANY valid-looking QUIC packet back, we can probably say it speaks QUIC. */
        return 1;
    }

    return 0; /* Timeout or no response */
}
