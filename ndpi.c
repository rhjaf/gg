
#ifndef WIN32
#include <arpa/inet.h>
#include <netinet/in.h>
#endif
#include <errno.h>
#include <ndpi_api.h>
#include <ndpi_main.h>
#include <ndpi_typedefs.h>
#include <pcap/pcap.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>


//DPDK
/* List of queues to be polled for a given lcore. 8< */
struct lcore_queue_conf {
	unsigned n_rx_port;
	unsigned rx_port_list[MAX_RX_QUEUE_PER_LCORE];
} __rte_cache_aligned;
struct lcore_queue_conf lcore_queue_conf[RTE_MAX_LCORE];


//nDPI
// #define VERBOSE 1
/*
#define MAX_FLOW_ROOTS_PER_THREAD 2048
#define MAX_IDLE_FLOWS_PER_THREAD 64
#define TICK_RESOLUTION 1000
#define MAX_READER_THREADS 1
#define IDLE_SCAN_PERIOD 10000 // msec
#define MAX_IDLE_TIME 300000 // msec
#define INITIAL_THREAD_HASH 0x03dd018b
*/

// static int number_of_interfaces = 2;

#ifndef ETH_P_IP
#define ETH_P_IP 0x0800
#endif

#ifndef ETH_P_IPV6
#define ETH_P_IPV6 0x86DD
#endif

#ifndef ETH_P_ARP
#define ETH_P_ARP  0x0806
#endif

enum nDPI_l3_type {
  L3_IP, L3_IP6
};

struct nDPI_flow_info {
  uint32_t flow_id;
  unsigned long long int packets_processed;
  uint64_t first_seen;
  uint64_t last_seen;
  uint64_t hashval;

  enum nDPI_l3_type l3_type;
  union {
    struct {
      uint32_t src;
      uint32_t pad_00[3];
      uint32_t dst;
      uint32_t pad_01[3];
    } v4;
    struct {
      uint64_t src[2];
      uint64_t dst[2];
    } v6;

    struct {
      uint32_t src[4];
      uint32_t dst[4];
    } u32;
  } ip_tuple;

  unsigned long long int total_l4_data_len;
  uint16_t src_port;
  uint16_t dst_port;

  uint8_t is_midstream_flow:1;
  uint8_t flow_fin_ack_seen:1;
  uint8_t flow_ack_seen:1;
  uint8_t detection_completed:1;
  uint8_t tls_client_hello_seen:1;
  uint8_t tls_server_hello_seen:1;
  uint8_t flow_info_printed:1;
  uint8_t reserved_00:1;
  uint8_t l4_protocol;

  struct ndpi_proto detected_l7_protocol;
  struct ndpi_proto guessed_protocol;

  struct ndpi_flow_struct * ndpi_flow;
};

struct nDPI_workflow {

  volatile long int error_or_eof;

  unsigned long long int packets_captured;
  unsigned long long int packets_processed;
  unsigned long long int total_l4_data_len;
  unsigned long long int detected_flow_protocols;

  uint64_t last_idle_scan_time;
  uint64_t last_time;

  void ** ndpi_flows_active;
  unsigned long long int max_active_flows;
  unsigned long long int cur_active_flows;
  unsigned long long int total_active_flows;

  void ** ndpi_flows_idle;
  unsigned long long int max_idle_flows;
  unsigned long long int cur_idle_flows;
  unsigned long long int total_idle_flows;

  struct ndpi_detection_module_struct * ndpi_struct;
};

struct nDPI_reader_thread {
  struct nDPI_workflow * workflow;
  // pthread_t thread_id;
  // uint32_t array_index;
};

static struct nDPI_reader_thread reader_threads[RTE_MAX_LCORE] = {};
static int reader_thread_count = RTE_MAX_LCORE;
static volatile long int main_thread_shutdown = 0;
static volatile long int flow_id = 0;



static void ndpi_flow_info_freer(void * const node)
{
  struct nDPI_flow_info * const flow = (struct nDPI_flow_info *)node;

  ndpi_flow_free(flow->ndpi_flow);
  ndpi_free(flow);
}

static void free_workflow(struct nDPI_workflow ** const workflow)
{
  struct nDPI_workflow * const w = *workflow;

  if (w == NULL) {
    return;
  }

  if (w->pcap_handle != NULL) {
    pcap_close(w->pcap_handle);
    w->pcap_handle = NULL;
  }

  if (w->ndpi_struct != NULL) {
    ndpi_exit_detection_module(w->ndpi_struct);
  }
  for(size_t i = 0; i < w->max_active_flows; i++) {
    ndpi_tdestroy(w->ndpi_flows_active[i], ndpi_flow_info_freer);
  }
  ndpi_free(w->ndpi_flows_active);
  ndpi_free(w->ndpi_flows_idle);
  ndpi_free(w);
  *workflow = NULL;
}

static char * get_default_pcapdev(char *errbuf)
{
  char * ifname;
  pcap_if_t * all_devices = NULL;

  if (pcap_findalldevs(&all_devices, errbuf) != 0)
    {
      return NULL;
    }

  ifname = strdup(all_devices[0].name);
  pcap_freealldevs(all_devices);

  return ifname;
}

// static int reader_thread_index = 0;

// static int setup_reader_threads(char const * const interface_name)
static int setup_reader_threads(uint16_t port,unsigned reader_thread_index)
{
  reader_threads[reader_thread_index].workflow = init_workflow(port);
  return 0;
  /*
  char * file_or_default_device;
  char pcap_error_buffer[PCAP_ERRBUF_SIZE];

  if (reader_thread_count > MAX_READER_THREADS) {
    return 1;
  }

  if (port == NULL) {
      return 1;
  } else {
    file_or_default_device = strdup(file_or_device);
    if (file_or_default_device == NULL) {
      return 1;
    }
  }

  for (reader_thread_index; reader_thread_index < reader_thread_count/number_of_interfaces; ++reader_thread_index) {
    
    if (reader_threads[reader_thread_index].workflow == NULL)
      {
	free(file_or_default_device);
	return 1;
      }
  }

  free(file_or_default_device);
  */
}

static int ip_tuple_to_string(struct nDPI_flow_info const * const flow,
                              char * const src_addr_str, size_t src_addr_len,
                              char * const dst_addr_str, size_t dst_addr_len)
{
  switch (flow->l3_type) {
  case L3_IP:
    return inet_ntop(AF_INET, (struct sockaddr_in *)&flow->ip_tuple.v4.src,
		     src_addr_str, src_addr_len) != NULL &&
      inet_ntop(AF_INET, (struct sockaddr_in *)&flow->ip_tuple.v4.dst,
		dst_addr_str, dst_addr_len) != NULL;
  case L3_IP6:
    return inet_ntop(AF_INET6, (struct sockaddr_in6 *)&flow->ip_tuple.v6.src[0],
		     src_addr_str, src_addr_len) != NULL &&
      inet_ntop(AF_INET6, (struct sockaddr_in6 *)&flow->ip_tuple.v6.dst[0],
		dst_addr_str, dst_addr_len) != NULL;
  }

  return 0;
}

#ifdef VERBOSE
static void print_packet_info(struct nDPI_reader_thread const * const reader_thread,
                              struct pcap_pkthdr const * const header,
                              uint32_t l4_data_len,
                              struct nDPI_flow_info const * const flow)
{
  struct nDPI_workflow const * const workflow = reader_thread->workflow;
  char src_addr_str[INET6_ADDRSTRLEN+1] = {0};
  char dst_addr_str[INET6_ADDRSTRLEN+1] = {0};
  char buf[256];
  int used = 0, ret;

  ret = ndpi_snprintf(buf, sizeof(buf), "[%8llu, %d, %4u] %4u bytes: ",
		 workflow->packets_captured, reader_thread->array_index,
		 flow->flow_id, header->caplen);
  if (ret > 0) {
    used += ret;
  }

  if (ip_tuple_to_string(flow, src_addr_str, sizeof(src_addr_str), dst_addr_str, sizeof(dst_addr_str)) != 0) {
    ret = ndpi_snprintf(buf + used, sizeof(buf) - used, "IP[%s -> %s]", src_addr_str, dst_addr_str);
  } else {
    ret = ndpi_snprintf(buf + used, sizeof(buf) - used, "IP[ERROR]");
  }
  if (ret > 0) {
    used += ret;
  }

  switch (flow->l4_protocol) {
  case IPPROTO_UDP:
    ret = ndpi_snprintf(buf + used, sizeof(buf) - used, " -> UDP[%u -> %u, %u bytes]",
		   flow->src_port, flow->dst_port, l4_data_len);
    break;
  case IPPROTO_TCP:
    ret = ndpi_snprintf(buf + used, sizeof(buf) - used, " -> TCP[%u -> %u, %u bytes]",
		   flow->src_port, flow->dst_port, l4_data_len);
    break;
  case IPPROTO_ICMP:
    ret = ndpi_snprintf(buf + used, sizeof(buf) - used, " -> ICMP");
    break;
  case IPPROTO_ICMPV6:
    ret = ndpi_snprintf(buf + used, sizeof(buf) - used, " -> ICMP6");
    break;
  case IPPROTO_HOPOPTS:
    ret = ndpi_snprintf(buf + used, sizeof(buf) - used, " -> ICMP6 Hop-By-Hop");
    break;
  default:
    ret = ndpi_snprintf(buf + used, sizeof(buf) - used, " -> Unknown[0x%X]", flow->l4_protocol);
    break;
  }
  if (ret > 0) {
    used += ret;
  }

  printf("%.*s\n", used, buf);
}
#endif

static int ip_tuples_compare(struct nDPI_flow_info const * const A, struct nDPI_flow_info const * const B)
{
  // generate a warning if the enum changes
  switch (A->l3_type)
  {
    case L3_IP:
    case L3_IP6:
      break;
  }

  if (A->l3_type == L3_IP && B->l3_type == L3_IP)
  {
    if (A->ip_tuple.v4.src < B->ip_tuple.v4.src)
    {
      return -1;
    }
    if (A->ip_tuple.v4.src > B->ip_tuple.v4.src)
    {
      return 1;
    }
    if (A->ip_tuple.v4.dst < B->ip_tuple.v4.dst)
    {
      return -1;
    }
    if (A->ip_tuple.v4.dst > B->ip_tuple.v4.dst)
    {
      return 1;
    }
  }
  else if (A->l3_type == L3_IP6 && B->l3_type == L3_IP6)
  {
    if (A->ip_tuple.v6.src[0] < B->ip_tuple.v6.src[0] && A->ip_tuple.v6.src[1] < B->ip_tuple.v6.src[1])
    {
      return -1;
    }
    if (A->ip_tuple.v6.src[0] > B->ip_tuple.v6.src[0] && A->ip_tuple.v6.src[1] > B->ip_tuple.v6.src[1])
    {
      return 1;
    }
    if (A->ip_tuple.v6.dst[0] < B->ip_tuple.v6.dst[0] && A->ip_tuple.v6.dst[1] < B->ip_tuple.v6.dst[1])
    {
      return -1;
    }
    if (A->ip_tuple.v6.dst[0] > B->ip_tuple.v6.dst[0] && A->ip_tuple.v6.dst[1] > B->ip_tuple.v6.dst[1])
    {
      return 1;
    }
  }

  if (A->src_port < B->src_port)
  {
    return -1;
  }
  if (A->src_port > B->src_port)
  {
    return 1;
  }
  if (A->dst_port < B->dst_port)
  {
    return -1;
  }
  if (A->dst_port > B->dst_port)
  {
    return 1;
  }

  return 0;
}

static void ndpi_idle_scan_walker(void const * const A, ndpi_VISIT which, int depth, void * const user_data)
{
  struct nDPI_workflow * const workflow = (struct nDPI_workflow *)user_data;
  struct nDPI_flow_info * const flow = *(struct nDPI_flow_info **)A;

  (void)depth;

  if (workflow == NULL || flow == NULL) {
    return;
  }

  if (workflow->cur_idle_flows == MAX_IDLE_FLOWS_PER_THREAD) {
    return;
  }

  if (which == ndpi_preorder || which == ndpi_leaf) {
    if ((flow->flow_fin_ack_seen == 1 && flow->flow_ack_seen == 1) ||
	flow->last_seen + MAX_IDLE_TIME < workflow->last_time)
      {
	char src_addr_str[INET6_ADDRSTRLEN+1];
	char dst_addr_str[INET6_ADDRSTRLEN+1];
	ip_tuple_to_string(flow, src_addr_str, sizeof(src_addr_str), dst_addr_str, sizeof(dst_addr_str));
	workflow->ndpi_flows_idle[workflow->cur_idle_flows++] = flow;
	workflow->total_idle_flows++;
      }
  }
}

static int ndpi_workflow_node_cmp(void const * const A, void const * const B) {
  struct nDPI_flow_info const * const flow_info_a = (struct nDPI_flow_info *)A;
  struct nDPI_flow_info const * const flow_info_b = (struct nDPI_flow_info *)B;

  if (flow_info_a->hashval < flow_info_b->hashval) {
    return(-1);
  } else if (flow_info_a->hashval > flow_info_b->hashval) {
    return(1);
  }

  /* Flows have the same hash */
  if (flow_info_a->l4_protocol < flow_info_b->l4_protocol) {
    return(-1);
  } else if (flow_info_a->l4_protocol > flow_info_b->l4_protocol) {
    return(1);
  }

  return ip_tuples_compare(flow_info_a, flow_info_b);
}

static void check_for_idle_flows(struct nDPI_workflow * const workflow)
{
  if (workflow->last_idle_scan_time + IDLE_SCAN_PERIOD < workflow->last_time) {
    for (size_t idle_scan_index = 0; idle_scan_index < workflow->max_active_flows; ++idle_scan_index) {
      ndpi_twalk(workflow->ndpi_flows_active[idle_scan_index], ndpi_idle_scan_walker, workflow);

      while (workflow->cur_idle_flows > 0) {
	struct nDPI_flow_info * const f =
	  (struct nDPI_flow_info *)workflow->ndpi_flows_idle[--workflow->cur_idle_flows];
	if (f->flow_fin_ack_seen == 1) {
	  printf("Free fin flow with id %u\n", f->flow_id);
	} else {
	  printf("Free idle flow with id %u\n", f->flow_id);
	}
	ndpi_tdelete(f, &workflow->ndpi_flows_active[idle_scan_index],
		     ndpi_workflow_node_cmp);
	ndpi_flow_info_freer(f);
	workflow->cur_active_flows--;
      }
    }

    workflow->last_idle_scan_time = workflow->last_time;
  }
}



static void run_pcap_loop(struct nDPI_reader_thread const * const reader_thread)
{
  if (reader_thread->workflow != NULL &&
      reader_thread->workflow->pcap_handle != NULL) {

    if (pcap_loop(reader_thread->workflow->pcap_handle, -1,
		  &ndpi_process_packet, (uint8_t *)reader_thread) == PCAP_ERROR) {

      fprintf(stderr, "Error while reading pcap file: '%s'\n",
	      pcap_geterr(reader_thread->workflow->pcap_handle));
      __sync_fetch_and_add(&reader_thread->workflow->error_or_eof, 1);
    }
  }
}

static void break_pcap_loop(struct nDPI_reader_thread * const reader_thread)
{
  if (reader_thread->workflow != NULL &&
      reader_thread->workflow->pcap_handle != NULL)
    {
      pcap_breakloop(reader_thread->workflow->pcap_handle);
    }
}

static void * processing_thread(void * const ndpi_thread_arg)
{
  struct nDPI_reader_thread const * const reader_thread =
    (struct nDPI_reader_thread *)ndpi_thread_arg;

  printf("Starting Thread %d\n", reader_thread->array_index);
  run_pcap_loop(reader_thread);
  __sync_fetch_and_add(&reader_thread->workflow->error_or_eof, 1);
  return NULL;
}

static int processing_threads_error_or_eof(void)
{
  for (int i = 0; i < reader_thread_count; ++i) {
    if (__sync_fetch_and_add(&reader_threads[i].workflow->error_or_eof, 0) == 0) {
      return 0;
    }
  }
  return 1;
}

static int start_reader_threads(void)
{
  /*
#ifndef WIN32
  sigset_t thread_signal_set, old_signal_set;

  sigfillset(&thread_signal_set);
  sigdelset(&thread_signal_set, SIGINT);
  sigdelset(&thread_signal_set, SIGTERM);
  if (pthread_sigmask(SIG_BLOCK, &thread_signal_set, &old_signal_set) != 0) {
    fprintf(stderr, "pthread_sigmask: %s\n", strerror(errno));
    return 1;
  }
#endif
*/
  for (int i = 0; i < reader_thread_count; ++i) {
    reader_threads[i].array_index = i;

    if (reader_threads[i].workflow == NULL) {
      /* no more threads should be started */
      break;
    }

    if (pthread_create(&reader_threads[i].thread_id, NULL,
		       processing_thread, &reader_threads[i]) != 0)
      {
	fprintf(stderr, "pthread_create: %s\n", strerror(errno));
	return 1;
      }
  }

  if (pthread_sigmask(SIG_BLOCK, &old_signal_set, NULL) != 0) {
    fprintf(stderr, "pthread_sigmask: %s\n", strerror(errno));
    return 1;
  }

  return 0;
}

static int stop_reader_threads(void)
{
  unsigned long long int total_packets_captured = 0;
  unsigned long long int total_packets_processed = 0;
  unsigned long long int total_l4_data_len = 0;
  unsigned long long int total_flows_captured = 0;
  unsigned long long int total_flows_idle = 0;
  unsigned long long int total_flows_detected = 0;

  for (int i = 0; i < reader_thread_count; ++i) {
    break_pcap_loop(&reader_threads[i]);
  }

  printf("------------------------------------ Stopping reader threads\n");

  for (int i = 0; i < reader_thread_count; ++i) {
    if (reader_threads[i].workflow == NULL) {
      continue;
    }

    if (pthread_join(reader_threads[i].thread_id, NULL) != 0) {
      fprintf(stderr, "pthread_join: %s\n", strerror(errno));
    }

    total_packets_processed += reader_threads[i].workflow->packets_processed;
    total_l4_data_len += reader_threads[i].workflow->total_l4_data_len;
    total_flows_captured += reader_threads[i].workflow->total_active_flows;
    total_flows_idle += reader_threads[i].workflow->total_idle_flows;
    total_flows_detected += reader_threads[i].workflow->detected_flow_protocols;

    printf("Stopping Thread %d, processed %10llu packets, %12llu bytes, total flows: %8llu, "
	   "idle flows: %8llu, detected flows: %8llu\n",
	   reader_threads[i].array_index, reader_threads[i].workflow->packets_processed,
	   reader_threads[i].workflow->total_l4_data_len, reader_threads[i].workflow->total_active_flows,
	   reader_threads[i].workflow->total_idle_flows, reader_threads[i].workflow->detected_flow_protocols);
  }

  /* total packets captured: same value for all threads as packet2thread distribution happens later */
  total_packets_captured = reader_threads[0].workflow->packets_captured;

  for (int i = 0; i < reader_thread_count; ++i) {
    if (reader_threads[i].workflow == NULL) {
      continue;
    }

    free_workflow(&reader_threads[i].workflow);
  }

  printf("Total packets captured.: %llu\n", total_packets_captured);
  printf("Total packets processed: %llu\n", total_packets_processed);
  printf("Total layer4 data size.: %llu\n", total_l4_data_len);
  printf("Total flows captured...: %llu\n", total_flows_captured);
  printf("Total flows timed out..: %llu\n", total_flows_idle);
  printf("Total flows detected...: %llu\n", total_flows_detected);

  return 0;
}

static void sighandler(int signum)
{
  fprintf(stderr, "Received SIGNAL %d\n", signum);

  if (__sync_fetch_and_add(&main_thread_shutdown, 0) == 0) {
    __sync_fetch_and_add(&main_thread_shutdown, 1);
  } else {
    fprintf(stderr, "Reader threads are already shutting down, please be patient.\n");
  }
}

int main(int argc, char ** argv)
{
 
    if(setup_reader_threads(portid,rx_lcore_id)!=0){
      fprintf(stderr, "%s: setup_reader_threads failed\n", "ens160");
      return 1;
    }; // nDPI reader
	}

  /* Creates a new mbuf mempool in memory to hold the mbufs objects (that store packets).
  containts NUM_MBUFS * nb_ports of mbuf pkts in it with each of them's size is RTE_MBUF_DEFAULT_BUF_SIZE
  a cache of 
  Each lcore cache will be MBUF_CACHE_SIZE
  number of mbuf pkts */
  mbuf_pool = rte_pktmbuf_pool_create("MBUF_POOL",RTE_MAX((nb_rxd + 0 + MAX_PKT_BURST + nb_lcores * MBUF_CACHE_SIZE) * nb_ports,8192u),MBUF_CACHE_SIZE, 0, RTE_MBUF_DEFAULT_BUF_SIZE, rte_socket_id());
  if (mbuf_pool == NULL)
    rte_exit(EXIT_FAILURE, "Cannot create mbuf pool\n");
  
  /* Initialize all ports. */
  RTE_ETH_FOREACH_DEV(portid){
    if (port_init(portid, mbuf_pool) != 0)
      rte_exit(EXIT_FAILURE, "Cannot init port %"PRIu16 "\n",portid);
  }
        
  ret = 0;


  /* launch per-lcore init on every lcore also on main lcore */
  rte_eal_mp_remote_launch(lcore_main, NULL, CALL_MAIN);
  
	RTE_LCORE_FOREACH_WORKER(lcore_id) {
    if (rte_eal_wait_lcore(lcore_id) < 0) {
			ret = -1;
			break;
		}
	}



  










  signal(SIGINT, sighandler);
  signal(SIGTERM, sighandler);
  while (__sync_fetch_and_add(&main_thread_shutdown, 0) == 0 && processing_threads_error_or_eof() == 0) {
    sleep(1);
  }

  if (stop_reader_threads() != 0) {
    fprintf(stderr, "%s: stop_reader_threads\n", argv[0]);
    return 1;
  }

  return 0;
}