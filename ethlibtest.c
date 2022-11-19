#include <stdio.h>
#include <stdint.h>
#include <ctype.h>
#include <stdlib.h>
#include <unistd.h>
#include "ethlib.h"

void usage(int argc, char **argv)
{
  fprintf(stderr, "%s [-l] [-s] [dev]\n"
	          "  -l : list devices\n"
	          "  -s : use select on fd\n"
	          " dev : device to use default is any\n"
	  , argv[0]);
}

int main(int argc, char **argv)
{
  int nicfd;
  char *dev = NULL;
  int useSelect = 0;
  char c;
  
  opterr = 0;

  while ((c = getopt (argc, argv, "hls")) != -1) {
    switch (c)
      {
      case 's':
        useSelect = 1;
        break;
      case 'l':
	ethlib_nic_list();
	return 0;
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
    if (ethlib_nic_poll(NULL, // use defaut call-back
			NULL, // use default call-back arg
			-1)   // poll until error
	< 0) {
      fprintf(stderr, "ERROR: ethlib_nic_poll failed\n");
    }
  }
    
  ethlib_nic_close();  

 done:
  printf("**ETHLIBTEST: END\n");
  return 0;
}
