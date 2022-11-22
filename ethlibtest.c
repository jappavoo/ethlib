#include <stdio.h>
#include <stdint.h>
#include <ctype.h>
#include <stdlib.h>
#include <unistd.h>
#include "ethlib.h"


uint64_t pkt_count = 0;
uint64_t pkt_count_threshold=0;

void usage(int argc, char **argv)
{
  fprintf(stderr, "%s [-l] [-s] [-c val] [dev]\n"
	          "  -l : list devices\n"
	          "  -s : use select on fd\n"
	          "  -c <val>: use count callback with val\n"
	          " dev : device to use default is any\n"
	  , argv[0]);
}

static
void pkt_ctr(u_char *user, const struct pcap_pkthdr *h,
		     const u_char *bytes)
{
  pkt_count ++;
  if (pkt_count_threshold!=0 && (pkt_count % pkt_count_threshold)==0) fprintf(stderr, "+");
}

int main(int argc, char **argv)
{
  int nicfd;
  char *dev = NULL;
  int useSelect = 0;
  char c;
  int count = -1;
  pcap_handler cb = NULL;
  
  opterr = 0;

  while ((c = getopt (argc, argv, "hlsc:C:")) != -1) {
    switch (c)
      {
      case 's':
        useSelect = 1;
        break;
      case 'l':
	ethlib_nic_list();
	return 0;
	break;
      case 'c':
	cb = pkt_ctr;
	pkt_count_threshold = atoll(optarg);
	break;
      case 'C':
	count = atoi(optarg);
	break;
      case 'h':
	usage(argc, argv);
	return 0;
      default:
	fprintf(stderr, "ERROR: unknown argument\n");
	usage(argc, argv);
        return -1;
      }
  }

  if ((argc - optind) > 0) {
    dev = argv[optind];
  }
  
  printf("**ETHLIBTEST: BEGIN:\n");
  
  if (ethlib_nic_init(dev, &nicfd)<0) {
    fprintf(stderr, "ERROR: ethlib_nic_init failed\n");
    goto done;
  }

  if (useSelect) {
    fprintf(stderr, "NYI: ebblib picloop\n");
  } else {
    if (ethlib_nic_poll(cb, // use defaut call-back
			NULL, // use default call-back arg
			count)   // poll until error
	< 0) {
      fprintf(stderr, "ERROR: ethlib_nic_poll failed\n");
    }
  }
    
  ethlib_nic_close();  

 done:
  if (cb != NULL) printf("pkt_count = %ull\n", pkt_count);
  printf("**ETHLIBTEST: END\n");
  return 0;
}
