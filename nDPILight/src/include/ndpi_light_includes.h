#ifndef NDPILIGHT_NDPI_LIGHT_INCLUDES_H
#define NDPILIGHT_NDPI_LIGHT_INCLUDES_H

#include <iostream>
#include <csignal>
#include <cstdio>
#include <cstring>
#include <cerrno>
#include <cstdlib>
#include <fstream>
#include <algorithm>
#include <memory>
#include <thread>
#include <pcap/pcap.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <pcap/pcap.h>
#include <pthread.h>
#include <unistd.h>
#include <atomic>
#include <sys/stat.h>
#include <syslog.h>
#include <sys/time.h>
#include <inttypes.h>

#include <nt.h>

#include "ndpi_main.h"
#include "ndpi_typedefs.h"
#include "ndpi_classify.h"
#include "Trace.h"
#include "FlowInfo.h"
#include "Reader.h"
#include "ReaderThread.h"
#include "SupportStructs.h"
#include "PacketDissector.h"
#include "PcapReader.h"
#include "PcapDissector.h"
#include "NapatechReader.h"
#include "NtDissector.h"

/* ********************************** */

#define MAX_FLOW_ROOTS_PER_THREAD 1048576
#define MAX_IDLE_FLOWS_PER_THREAD 65536
#define TICK_RESOLUTION 1000
#define IDLE_SCAN_PERIOD 15000 /* msec */
#define PACKET_SCAN_PERIOD 524288 /* n_pkts */
#define MAX_IDLE_TIME 300000 /* msec */

#ifndef ETH_P_IP
#define ETH_P_IP 0x0800
#endif

#ifndef ETH_P_IPV6
#define ETH_P_IPV6 0x86DD
#endif

#ifndef ETH_P_ARP
#define ETH_P_ARP  0x0806
#endif

#define STREAM_ID_ANY  1
#define STREAM_ID_UNHA  2

#define KEY_ID_IPV4     1
#define KEY_ID_IPV6     2

#define COLOR_IPV4      0x1
#define COLOR_IPV6      0x2

#define STR_INNER(A)  #A
#define STR(A)        STR_INNER(A)


#endif //NDPILIGHT_NDPI_LIGHT_INCLUDES_H
