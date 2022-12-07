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
#include <unistd.h>

//On importe les librairies réseaux
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <pcap.h>
#include <netinet/ether.h>


//On importe les fichiers
#include "args.h"
#include "arp.h"
#include "bootp.h"
#include "dhcp.h"
#include "dns.h"
#include "ethernet.h"
#include "ftp.h"
#include "icmp.h"
#include "ipv4.h"
#include "printer.h"
#include "sniffer.h"
#include "tcp.h"
#include "telnet.h"
#include "udp.h"
#include "utils.h"

#endif // INCLUDES_H