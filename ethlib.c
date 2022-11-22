/*
 * Copyright (C) 2011 by Project SESA, Boston University
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */
#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <pthread.h>
#include <stdint.h>
#include "ethlib.h"

/* TBD: Confirm that this is using PACKET_MMAP on Linux */

enum {PCAP_DEFAULT_SNAPLEN = 1500};

pcap_t *hdl;

static 
void packet_callback(u_char *user, const struct pcap_pkthdr *h,
		     const u_char *bytes)
{
  fprintf(stderr, "+"); fflush(stderr);
}


// fixme with real args
intptr_t
ethlib_nic_readpkt(pcap_handler cb, u_char * cbarg) {
  if (cb == NULL) cb = packet_callback;
  pcap_dispatch(hdl, 1, cb, cbarg);
  return 1;
}

intptr_t
ethlib_nic_poll(pcap_handler cb, u_char * cbarg, int count) {
  if (cb == NULL) cb = packet_callback;
  pcap_loop(hdl,
	    count, // -1 Poll until error
	    cb,
	    cbarg);
}

intptr_t ethlib_nic_close(void) {
  pcap_close(hdl);
}

intptr_t
ethlib_nic_list(void)
{
  int i;
  char errbuf[PCAP_ERRBUF_SIZE];
  pcap_if_t *devs, *d;
  
  errbuf[0]=0;
  
  if (pcap_findalldevs(&devs, errbuf) || devs == NULL) {
    fprintf(stderr, "ERROR: %s: %s\n", __func__, errbuf);
    return -1;
  }
  
  for (i=0,d=devs; d!=NULL; i++,d=d->next) {
    i++;
    fprintf(stderr, "d:%d: %s\n", i, d->name);
  }
  
  pcap_freealldevs(devs);
  return 0;
}

static int
activate(pcap_t *hdl)
{
  int rc =  pcap_activate(hdl);
  if (rc > 0) {
    switch (rc) {
    case PCAP_WARNING_PROMISC_NOTSUP:
      fprintf(stderr,
	      "WARNING: pcap_activate: PCAP_WARNING_PROMISC_NOTSUP: %s\n",
	      pcap_geterr(hdl)
	      );
      break;
    case PCAP_WARNING_TSTAMP_TYPE_NOTSUP:
      fprintf(stderr,
	      "WARNING: pcap_activate: PCAP_WARNING_TSTAMP_TYPE_NOTSUP\n");
      break;
    default:
      fprintf(stderr,
	      "WARNING: pcap_activate: %s\n", pcap_geterr(hdl));
      
    }
  }
  if (rc < 0) {
      switch (rc) {
      case PCAP_ERROR_ACTIVATED:
	fprintf(stderr, "ERROR: pcap_activated: PCAP_ERROR_ACTIVATED\n");
	break;
      case PCAP_ERROR_NO_SUCH_DEVICE:
	fprintf(stderr, "ERROR: pcap_activated: PCAP_ERROR_NO_SUCH_DEVICE: %s\n",
		pcap_geterr(hdl));
	break;
      case PCAP_ERROR_PERM_DENIED:
	fprintf(stderr, "ERROR: pcap_activated: PCAP_ERROR_PERM_DENIED: %s\n",
		pcap_geterr(hdl));
	break;
      case PCAP_ERROR_PROMISC_PERM_DENIED:
	fprintf(stderr, "ERROR: pcap_activated: PCAP_ERROR_PROMISC_PERM_DENIED\n");
	break;
      case PCAP_ERROR_RFMON_NOTSUP:
	fprintf(stderr, "ERROR: pcap_activated: PCAP_ERROR_RFMON_NOTSUP\n");
	break;
      case PCAP_ERROR_IFACE_NOT_UP:
	fprintf(stderr, "ERROR: pcap_activated: PCAP_ERROR_IFACE_NOT_UP\n");
	break;
      default:
	fprintf(stderr, "ERROR: pcap_activated: PCAP_ERROR: %s\n",
		pcap_geterr(hdl));
      }
  }
  return rc;
}

intptr_t
ethlib_nic_init(char *dev,  int *fd)
{
  char errbuf[PCAP_ERRBUF_SIZE];
  errbuf[0]=0;
  
  if (dev == NULL) dev="any";

#ifdef OLD_PCAP_API
  
  hdl = pcap_open_live(dev,
		       PCAP_DEFAULT_SNAPLEN,  // snap length
		       0,                     // promiscous = false
		       0,                     // timout ms (to_ms) = 0
		       errbuf);
  
  if (hdl == NULL) {
    fprintf(stderr, "ERROR: pcap_open_live on \"%s\" failed: %s\n", 
	    dev, errbuf);
    return -1;
  }
#else
  if (pcap_init(PCAP_CHAR_ENC_UTF_8,errbuf) != 0) {
    fprintf(stderr, "ERROR: pcap_init failed: %s\n", errbuf);
    return -1;
  }
  
  hdl = pcap_create(dev, errbuf);
  
  if (hdl == NULL) {
    fprintf(stderr, "ERROR: pcap_create on \"%s\" failed: %s\n", 
	    dev, errbuf);
    return -1;
  }

  if (pcap_set_snaplen(hdl, PCAP_DEFAULT_SNAPLEN) != 0) {
    fprintf(stderr, "ERROR: pcap_set_sanplen\n");
    return -1;
  }
  
  if (pcap_set_promisc(hdl, 0) != 0) {
    fprintf(stderr, "ERROR: pcap_set_promisc\n");
    return -1;
  }

  /* packet buffer timeout If, when capturing, packets are delivered
     as soon as they arrive, the application capturing the packets
     will be woken up for each packet as it arrives, and might have to
     make one or more calls to the operating system to fetch each
     packet.  If, instead, packets are not delivered as soon as they
     arrive, but are delivered after a short delay (called a "packet
     buffer timeout"), more than one packet can be accumulated before
     the packets are delivered, so that a single wakeup would be done
     for multiple packets, and each set of calls made to the operating
     system would supply multiple packets, rather than a single
     packet. This reduces the per-packet CPU overhead if packets are
     arriving at a high rate, increasing the number of packets per
     second that can be captured.  The packet buffer timeout is
     required so that an application won't wait for the operating
     system's capture buffer to fill up before packets are delivered;
     if packets are arriving slowly, that wait could take an
     arbitrarily long period of time.  Not all platforms support a
     packet buffer timeout; on platforms that don't, the packet buffer
     timeout is ignored. A zero value for the timeout, on platforms
     that support a packet buffer timeout, will cause a read to wait
     forever to allow enough packets to arrive, with no timeout. A
     negative value is invalid; the result of setting the timeout to a
     negative value is unpredictable.  NOTE: the packet buffer timeout
     cannot be used to cause calls that read packets to return within
     a limited period of time, because, on some platforms, the packet
     buffer timeout isn't supported, and, on other platforms, the
     timer doesn't start until at least one packet arrives. This means
     that the packet buffer timeout should NOT be used, for example,
     in an interactive application to allow the packet capture loop to
     ``poll'' for user input periodically, as there's no guarantee
     that a call reading packets will return after the timeout expires
     even if no packets have arrived.
  */
  if (pcap_set_timeout(hdl, 0) != 0) {
    fprintf(stderr, "ERROR: pcap_set_timeout\n");
    return -1;
  }

  // Turn on immediate mode
  /* In immediate mode, packets are always delivered as soon as they
     arrive, with no buffering. Immediate mode is set with */
  if (pcap_set_immediate_mode(hdl, 1) != 0) {
    fprintf(stderr, "ERROR: pcap_set_immediate_mode\n");
    return -1;
  }


  /* buffer size Packets that arrive for a capture are stored in a
     buffer, so that they do not have to be read by the application as
     soon as they arrive. On some platforms, the buffer's size can be
     set; a size that's too small could mean that, if too many packets
     are being captured and the snapshot length doesn't limit the
     amount of data that's buffered, packets could be dropped if the
     buffer fills up before the application can read packets from it,
     while a size that's too large could use more non-pageable
     operating system memory than is necessary to prevent packets from
     being dropped.  The buffer size is set with
     pcap_set_buffer_size().  timestamp type On some platforms, the
     time stamp given to packets on live captures can come from
     different sources that can have different resolutions or that can
     have different relationships to the time values for the current
     time supplied by routines on the native operating system. See
     pcap-tstamp(7) for a list of time stamp types.  The time stamp
     type is set with pcap_set_tstamp_type().
  */

  /* On network interface devices on Linux, pcap_set_protocol_linux()
     sets the protocol to be used in the socket(2) call to create a
     capture socket when the handle is activated. The argument is a
     link-layer protocol value, such as the values in the
     <linux/if_ether.h> header file, specified in host byte order. If
     protocol is non-zero, packets of that protocol will be captured
     when the handle is activated, otherwise, all packets will be
     captured. This function is only provided on Linux, and, if it is
     used on any device other than a network interface, it will have
     no effect.
   */
  if (pcap_set_protocol_linux(hdl, 0) != 0) {
    fprintf(stderr, "ERROR: pcap_set_protocol_linux\n");
    return -1;
  }

  if (activate(hdl) < 0) return -1;
#endif
  {
    int blocking = pcap_getnonblock(hdl, errbuf);
    fprintf(stderr, "pcap_getnonblock: %d %s\n", blocking, errbuf);
  }

  
#if 0
  if(pcap_setnonblock(hdl, 1, errbuf) == 1) {
    pcap
  }
#endif
  
  *fd = pcap_get_selectable_fd(hdl);
  assert(*fd != -1);
  
  return 0;
}
