//On importe les librairies
#ifndef INCLUDES_H
#define INCLUDES_H

//On importe les librairies standards
#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <wchar.h>
#include <unistd.h>

//On importe les librairies réseaux
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/ip_icmp.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <pcap.h>
#include <netinet/ether.h>

//On importe les fichiers
#include "args.h"
#include "compute.h"
#include "logs/log.h"
#include "logs/logger.h"
#include "logs/v1.h"
#include "logs/v2.h"
#include "logs/v3.h"
#include "pck.h"
#include "proto/app.h"
#include "proto/app/bootp.h"
#include "proto/app/dns.h"
#include "proto/app/ftp.h"
#include "proto/app/telnet.h"
#include "proto/link.h"
#include "proto/link/ethernet.h"
#include "proto/net.h"
#include "proto/net/arp.h"
#include "proto/net/ip.h"
#include "proto/net/ip6.h"
#include "proto/trans.h"
#include "proto/trans/icmp.h"
#include "proto/trans/tcp.h"
#include "proto/trans/udp.h"
#include "utils.h"

#endif // INCLUDES_H