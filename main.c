
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <inttypes.h>
#include <sys/types.h>
#include <sys/queue.h>
#include <setjmp.h>
#include <stdarg.h>
#include <ctype.h>
#include <pthread.h>
#include <unistd.h>
#include <errno.h>
#include <getopt.h>
#include <signal.h>
#include <stdbool.h>
#include <math.h>
#include <time.h>
#include<stdio.h>
#include<stdlib.h>
#include <limits.h>
#include <pcap/pcap.h>
#ifdef __linux__
#include <sched.h>
#endif

// DBScan
#include "DB_SCAN.h"
// DBScan parameters
#define DBSCAN_EPS 50.0  // Epsilon value for DBScan (distance threshold) - adjusted for new metric
#define DBSCAN_MIN_PTS 3

// DPDK
#include <rte_common.h>
#include <rte_flow.h>
#include <rte_log.h>
#include <rte_malloc.h>
#include <rte_memory.h>
#include <rte_memcpy.h>
#include <rte_eal.h>
#include <rte_launch.h>
#include <rte_cycles.h>
#include <rte_prefetch.h>
#include <rte_lcore.h>
#include <rte_per_lcore.h>
#include <rte_interrupts.h>
#include <rte_random.h>
#include <rte_debug.h>
#include <rte_ether.h>
#include <rte_ip.h>
#include <rte_ethdev.h>
#include <rte_mempool.h>
#include <rte_mbuf.h>
#include <rte_flow.h>

// nDPI
#include <ndpi_main.h>
#include <ndpi_typedefs.h>
#include <ndpi_api.h>


// DPDK parameters
#define RTE_LOGTYPE_DDD RTE_LOGTYPE_USER1
#define MAX_RX_QUEUE_PER_LCORE 1 // RX queues per lcore
#define MAX_RX_QUEUE_PER_PORT 2
#define MAX_TX_QUEUE_PER_PORT 2
#define RX_DESC_DEFAULT 1024
#define TX_DESC_DEFAULT 1024
#define MBUF_CACHE_SIZE 256
#define MAX_PKT_BURST 32 
#define max_number_of_flows_in_a_interval 2000
#define RX_RING_SIZE 1024
#define TX_RING_SIZE 1024
#define max_number_of_flows 2000
#define max_src 3000
#define V_PRED 3
#define R_PRED 3

// ndpi definitions
#define MAX_FLOW_ROOTS 200000 // max active flows for each workflow
#define MAX_IDLE_FLOWS 64
#define TICK_RESOLUTION 1000
#define IDLE_SCAN_PERIOD 5000 // msec
#define MAX_IDLE_TIME 3000 // msec
// #define MAX_IDLE_TIME 5000 // msec


#ifndef ETH_P_IP
#define ETH_P_IP 0x0800
#endif

#ifndef ETH_P_IPV6
#define ETH_P_IPV6 0x86DD
#endif

#ifndef ETH_P_ARP
#define ETH_P_ARP  0x0806
#endif


static uint16_t nb_rxd = RX_DESC_DEFAULT;
static uint16_t nb_txd = TX_DESC_DEFAULT;

static volatile bool force_quit;
static int promiscuous_on = 1;
static const struct rte_eth_conf port_conf_default = {
        .rxmode = {
                .max_lro_pkt_size = RTE_ETHER_MAX_LEN,
        },
};
struct rte_mempool *mbuf_pool = NULL;

/* List of queues to be polled for a given lcore. 8< */
struct lcore_queue_conf {
	unsigned n_rx_port;
	unsigned rx_port_list[MAX_RX_QUEUE_PER_LCORE];
} __rte_cache_aligned;
struct lcore_queue_conf lcore_queue_conf[RTE_MAX_LCORE];


/* Per-port statistics struct */
struct l2fwd_port_statistics {
	uint64_t tx;
	uint64_t rx;
	uint64_t dropped;
} __rte_cache_aligned;
struct l2fwd_port_statistics port_statistics[RTE_MAX_ETHPORTS];



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
struct ndpi_thread {
  struct nDPI_workflow * workflow;
  // pthread_t thread_id;
  // uint32_t array_index;
};
static struct ndpi_thread ndpi_threads[RTE_MAX_LCORE] = {};
static volatile long int flow_id = 0;

static inline int port_init(uint16_t port, struct rte_mempool *mbuf_pool)
{
        struct rte_eth_conf port_conf = port_conf_default;
        const uint16_t rx_rings = MAX_RX_QUEUE_PER_PORT;

        const uint16_t tx_rings = MAX_TX_QUEUE_PER_PORT;
        
        int retval;
        uint16_t q;

        struct rte_eth_dev_info dev_info;
        struct rte_eth_txconf txconf;

        if (!rte_eth_dev_is_valid_port(port))
                return -1;
        
        rte_eth_dev_info_get(port, &dev_info);
        if (dev_info.tx_offload_capa & RTE_ETH_TX_OFFLOAD_MBUF_FAST_FREE)
               port_conf.txmode.offloads |= RTE_ETH_TX_OFFLOAD_MBUF_FAST_FREE;

        /* Configure the Ethernet device. */
        
        retval = rte_eth_dev_configure(port, rx_rings, tx_rings, &port_conf);
        if (retval != 0){
          printf("can not configure device\n");
          return retval;
        
        }
        retval = rte_eth_dev_adjust_nb_rx_tx_desc(port, &nb_rxd, &nb_txd);
        if (retval != 0){
          printf("can not buffer descriptor device\n");
          return retval;
        
        }

        /* Allocate and set up RX queue per Ethernet port. */ 
        for (q = 0; q < rx_rings; q++) {
                retval = rte_eth_rx_queue_setup(port, q, nb_rxd, rte_eth_dev_socket_id(port), NULL, mbuf_pool);
                if (retval < 0){
                    printf("rx queue %d allocation failed\n",q);
                    return retval;
                }
        }
        /* Allocate and set up TX queue per Ethernet port. */ 
        txconf = dev_info.default_txconf;
        txconf.offloads = port_conf.txmode.offloads;
        // Allocate and set up 1 TX queue per Ethernet port.
        for (q = 0; q < tx_rings; q++) {
                retval = rte_eth_tx_queue_setup(port, q, nb_txd,
                                rte_eth_dev_socket_id(port), &txconf);
                if (retval < 0)
                        return retval;
        }


        /* Start the Ethernet port. */
        retval = rte_eth_dev_start(port);
        if (retval < 0)
                return retval;

        /* Display the port MAC address. */
        struct rte_ether_addr addr;
        rte_eth_macaddr_get(port, &addr);
        printf("Port %u MAC: %02" PRIx8 " %02" PRIx8 " %02" PRIx8
                           " %02" PRIx8 " %02" PRIx8 " %02" PRIx8 "\n",
                        port,
                        addr.addr_bytes[0], addr.addr_bytes[1],
                        addr.addr_bytes[2], addr.addr_bytes[3],
                        addr.addr_bytes[4], addr.addr_bytes[5]);

        /* Enable RX in promiscuous mode for the Ethernet device. */
        rte_eth_promiscuous_enable(port);


        printf("Port %u: \n\n", port);

	      /* initialize port stats */
	      memset(&port_statistics, 0, sizeof(port_statistics));

        return 0;
}

static void free_workflow(struct nDPI_workflow ** const workflow);

// static struct nDPI_workflow * init_workflow(char const * const file_or_device)
static struct nDPI_workflow * init_workflow()
{
  
  struct nDPI_workflow * workflow = (struct nDPI_workflow *)ndpi_calloc(1, sizeof(*workflow));

  ndpi_init_prefs init_prefs = ndpi_no_prefs;
  workflow->ndpi_struct = ndpi_init_detection_module(init_prefs);
  if (workflow->ndpi_struct == NULL) {
    free_workflow(&workflow);
    return NULL;
  }

  workflow->total_active_flows = 0;
  workflow->max_active_flows = MAX_FLOW_ROOTS;
  workflow->ndpi_flows_active = (void **)ndpi_calloc(workflow->max_active_flows, sizeof(void *));
  if (workflow->ndpi_flows_active == NULL) {
    free_workflow(&workflow);
    return NULL;
  }

  workflow->total_idle_flows = 0;
  workflow->max_idle_flows = MAX_IDLE_FLOWS;
  workflow->ndpi_flows_idle = (void **)ndpi_calloc(workflow->max_idle_flows, sizeof(void *));
  if (workflow->ndpi_flows_idle == NULL) {
    free_workflow(&workflow);
    return NULL;
  }

  NDPI_PROTOCOL_BITMASK protos;
  NDPI_BITMASK_SET_ALL(protos);
  ndpi_set_protocol_detection_bitmask2(workflow->ndpi_struct, &protos);
  ndpi_finalize_initialization(workflow->ndpi_struct);

  return workflow;
}

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

static int ip_tuple_to_string(struct nDPI_flow_info const * const flow, char * const src_addr_str, size_t src_addr_len, char * const dst_addr_str, size_t dst_addr_len)
{
  switch (flow->l3_type) {
  case L3_IP:
    return inet_ntop(AF_INET, (struct sockaddr_in *)&flow->ip_tuple.v4.src, src_addr_str, src_addr_len) != NULL &&
      inet_ntop(AF_INET, (struct sockaddr_in *)&flow->ip_tuple.v4.dst, dst_addr_str, dst_addr_len) != NULL;
  case L3_IP6:
    return inet_ntop(AF_INET6, (struct sockaddr_in6 *)&flow->ip_tuple.v6.src[0], src_addr_str, src_addr_len) != NULL &&
      inet_ntop(AF_INET6, (struct sockaddr_in6 *)&flow->ip_tuple.v6.dst[0],	dst_addr_str, dst_addr_len) != NULL;
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

  if (workflow->cur_idle_flows == MAX_IDLE_FLOWS) {
    return;
  }

  if (which == ndpi_preorder || which == ndpi_leaf) {
    if ((flow->flow_fin_ack_seen == 1 && flow->flow_ack_seen == 1) || flow->last_seen + MAX_IDLE_TIME < workflow->last_time)
    {
	char src_addr_str[INET6_ADDRSTRLEN+1];
	char dst_addr_str[INET6_ADDRSTRLEN+1];
	ip_tuple_to_string(flow, src_addr_str, sizeof(src_addr_str), dst_addr_str, sizeof(dst_addr_str));

	workflow->ndpi_flows_idle[workflow->cur_idle_flows++] = flow;
	workflow->total_idle_flows++;
  struct ndpi_flow_struct fs ;
  memcpy(&fs, flow->ndpi_flow, sizeof(*flow->ndpi_flow));
      }
  }
}




#define window_size 10
#define app_types 368

/*
struct src_stat{
  char * ip_string;
  uint16_t packet_count;
  uint16_t packet_volume;
  uint16_t total_session;
  uint16_t idle_session;
};
*/
struct src_stat src_stats[max_src];

typedef struct app_info{
  char * app_name;
  uint64_t max_counter; // initialize =0
  uint64_t min_counter; // initialize =INT_MAX
  uint64_t counter_window[window_size];
  uint64_t interval_counter;
  uint64_t ratio_window[window_size];
  double ratio_pred;
  uint16_t new_session; // new session for this application
  uint16_t source_count[max_src]; // Active Source IP entropy of each application
  
  // D3 Algorithm inspired statistical data (based on IEEE paper 9424610)
  uint32_t training_samples;      // Number of samples collected during training
  double entropy_src_ip;          // Source IP entropy for this protocol
  double entropy_dst_port;        // Destination port entropy for this protocol
  double entropy_packet_size;     // Packet size entropy for this protocol
  double traffic_rate;            // Current traffic rate (packets/second)
  double baseline_entropy_src;    // Baseline source IP entropy during normal traffic
  double baseline_entropy_dst;    // Baseline destination port entropy during normal traffic
  double baseline_entropy_size;   // Baseline packet size entropy during normal traffic
  double baseline_traffic_rate;   // Baseline traffic rate during normal traffic
  double entropy_threshold;       // Dynamic threshold for entropy-based detection
  double rate_threshold;          // Dynamic threshold for rate-based detection
  double anomaly_score;           // Combined anomaly score
  bool has_baseline;              // Whether this protocol has established a baseline
  uint32_t packet_sizes[256];     // Histogram of packet sizes for entropy calculation
  uint32_t dst_ports[65536];      // Histogram of destination ports for entropy calculation
  uint32_t unique_src_ips;        // Count of unique source IPs in current interval
  uint32_t total_packets;         // Total packets in current interval
} app_info;

app_info apps[app_types] = {
  [0 ... app_types-1] = {
    .min_counter = INT_MAX,
    .training_samples = 0,
    .entropy_src_ip = 0,
    .entropy_dst_port = 0,
    .entropy_packet_size = 0,
    .traffic_rate = 0,
    .baseline_entropy_src = 0,
    .baseline_entropy_dst = 0,
    .baseline_entropy_size = 0,
    .baseline_traffic_rate = 0,
    .entropy_threshold = 0,
    .rate_threshold = 0,
    .anomaly_score = 0,
    .has_baseline = false,
    .unique_src_ips = 0,
    .total_packets = 0
  }
};

void clearScreen() {
    printf("\033[2J\033[1;1H");
}

// Comparison function for qsort
int compare(const void *a, const void *b) {
    int *x = (int *)a;
    int *y = (int *)b;
    return *y - *x;
}

int find_max(const int arr[],int arr_size){
        int max = arr[0];
        for(int i=0;i<arr_size;i++){
                if (arr[i]>max)
                        max = arr[i];
        }
        return max;
}

double sum(int arr[],int arr_size){
  int res = 0;
  for(int i=0;i<arr_size;i++)
    res+=arr[i];
  return res;
}

// Helper function to get the minimum of two integers
int min(int a, int b) {
    return (a < b) ? a : b;
}

double mean(int arr[],int arr_size){
  int res = 0;
  for(int i=0;i<arr_size;i++)
    res+=arr[i];
  res/=(double)arr_size;
  return res;
}

double var(int arr[], int arr_size, double avg) {
  double res = 0;
  for(int i = 0; i < arr_size; i++)
    res += pow((arr[i] - avg), 2);
  res /= (double)arr_size;
  return res;
}


// Calculate Shannon entropy for a histogram
double calculate_entropy(uint32_t *histogram, int size, uint32_t total) {
  if (total == 0) return 0.0;
  
  double entropy = 0.0;
  for (int i = 0; i < size; i++) {
    if (histogram[i] > 0) {
      double probability = (double)histogram[i] / total;
      entropy -= probability * log2(probability);
    }
  }
  return entropy;
}

// Calculate source IP entropy for an application
double calculate_src_ip_entropy(app_info *app) {
  uint32_t total_unique_ips = 0;
  uint32_t ip_counts[max_src];
  
  // Count unique source IPs and their frequencies
  for (int i = 0; i < max_src; i++) {
    ip_counts[i] = app->source_count[i];
    if (ip_counts[i] > 0) {
      total_unique_ips++;
    }
  }
  
  if (total_unique_ips == 0) return 0.0;
  
  // Calculate entropy based on IP distribution
  return calculate_entropy(ip_counts, max_src, app->total_packets);
}

// Calculate packet size entropy for an application
double calculate_packet_size_entropy(app_info *app) {
  return calculate_entropy(app->packet_sizes, 256, app->total_packets);
}

// Calculate destination port entropy for an application
double calculate_dst_port_entropy(app_info *app) {
  return calculate_entropy(app->dst_ports, 65536, app->total_packets);
}

// Update packet size histogram
void update_packet_size_histogram(app_info *app, uint16_t packet_size) {
  // Normalize packet size to 0-255 range for histogram
  uint8_t size_bucket = (packet_size > 1500) ? 255 : (packet_size * 255 / 1500);
  app->packet_sizes[size_bucket]++;
}

// Update destination port histogram
void update_dst_port_histogram(app_info *app, uint16_t dst_port) {
  app->dst_ports[dst_port]++;
}

// D3 Algorithm: Establish baseline during training phase
void establish_baseline(app_info *app) {
  if (app->training_samples < 10) return; // Need minimum samples
  
  // Calculate current entropy values
  app->entropy_src_ip = calculate_src_ip_entropy(app);
  app->entropy_dst_port = calculate_dst_port_entropy(app);
  app->entropy_packet_size = calculate_packet_size_entropy(app);
  app->traffic_rate = (double)app->total_packets; // packets per interval
  
  // Update baseline values (running average)
  double alpha = 0.1; // Learning rate
  if (app->baseline_entropy_src == 0) {
    // First time initialization
    app->baseline_entropy_src = app->entropy_src_ip;
    app->baseline_entropy_dst = app->entropy_dst_port;
    app->baseline_entropy_size = app->entropy_packet_size;
    app->baseline_traffic_rate = app->traffic_rate;
  } else {
    // Update with exponential moving average
    // NOTICE: Should we remove it?
    app->baseline_entropy_src = (1 - alpha) * app->baseline_entropy_src + alpha * app->entropy_src_ip;
    app->baseline_entropy_dst = (1 - alpha) * app->baseline_entropy_dst + alpha * app->entropy_dst_port;
    app->baseline_entropy_size = (1 - alpha) * app->baseline_entropy_size + alpha * app->entropy_packet_size;
    app->baseline_traffic_rate = (1 - alpha) * app->baseline_traffic_rate + alpha * app->traffic_rate;
  }
  
  // NOTICE 
  // Calculate dynamic thresholds based on baseline
  // Lower entropy indicates potential DDoS (concentrated sources/ports)
  app->entropy_threshold = app->baseline_entropy_src * 0.7; // 30% reduction threshold
  app->rate_threshold = app->baseline_traffic_rate * 2.0;   // 100% increase threshold
  
  // Mark as having baseline after sufficient training
  if (app->training_samples >= 20) {
    app->has_baseline = true;
  }
}

// D3 Algorithm: Calculate anomaly score based on entropy and traffic rate
double calculate_anomaly_score(app_info *app) {
  if (!app->has_baseline) return 0.0;
  
  // Calculate current entropy values
  app->entropy_src_ip = calculate_src_ip_entropy(app);
  app->entropy_dst_port = calculate_dst_port_entropy(app);
  app->entropy_packet_size = calculate_packet_size_entropy(app);
  app->traffic_rate = (double)app->total_packets;
  
  // Calculate entropy deviation (lower entropy = higher anomaly)
  double entropy_deviation = 0.0;
  if (app->baseline_entropy_src > 0) {
    entropy_deviation += fmax(0, (app->baseline_entropy_src - app->entropy_src_ip) / app->baseline_entropy_src);
  }
  if (app->baseline_entropy_dst > 0) {
    entropy_deviation += fmax(0, (app->baseline_entropy_dst - app->entropy_dst_port) / app->baseline_entropy_dst);
  }
  
  // Calculate traffic rate deviation (higher rate = higher anomaly)
  double rate_deviation = 0.0;
  if (app->baseline_traffic_rate > 0) {
    rate_deviation = fmax(0, (app->traffic_rate - app->baseline_traffic_rate) / app->baseline_traffic_rate);
  }
  
  // Combined anomaly score (weighted combination)
  double entropy_weight = 0.6;
  double rate_weight = 0.4;
  // Notice
  // Good Score
  app->anomaly_score = entropy_weight * entropy_deviation + rate_weight * rate_deviation;
  
  return app->anomaly_score;
}

// D3 Algorithm: DDoS detection based on statistical anomaly
bool detect_ddos_attack(app_info *app) {
  if (!app->has_baseline) return false;
  
  double anomaly_score = calculate_anomaly_score(app);
  
  // Detection criteria based on D3 algorithm
  bool entropy_anomaly = (app->entropy_src_ip < app->entropy_threshold);
  bool rate_anomaly = (app->traffic_rate > app->rate_threshold);
  bool combined_anomaly = (anomaly_score > 0.5); // Threshold for combined score
  
  // DDoS detected if multiple conditions are met
  return (entropy_anomaly && rate_anomaly) || combined_anomaly;
}

// Reset interval statistics for next measurement
void reset_interval_stats(app_info *app) {
  // Clear histograms
  memset(app->packet_sizes, 0, sizeof(app->packet_sizes));
  memset(app->dst_ports, 0, sizeof(app->dst_ports));
  
  // Reset counters
  app->unique_src_ips = 0;
  app->total_packets = 0;
  app->interval_counter = 0;
  app->new_session = 0;
  
  // Clear source count for next interval
  memset(app->source_count, 0, sizeof(app->source_count));
}

void append(uint64_t arr[], int arr_size, uint64_t item) {
  // Notice. What is actually adding
  uint64_t *res = malloc(sizeof(uint64_t) * arr_size);
  for(int i = 0; i < arr_size - 1; i++) {
    res[i] = arr[i + 1];
  }
  res[arr_size - 1] = item;
  memcpy(arr, res, sizeof(uint64_t) * arr_size);
  free(res);
}


// Function to perform DBScan clustering on source IPs for a specific application
void perform_dbscan_clustering(int app_index) {
    printf("\n===== Performing DBScan clustering for application: %s =====\n", apps[app_index].app_name);
    printf("Using new distance metric based on average packet size and total sessions\n");
    printf("Epsilon: %.2f, MinPoints: %d\n", DBSCAN_EPS, DBSCAN_MIN_PTS);

    // Initialize points container
    dbscan_points_t* points = dbscan_init_points(100);
    if (!points) {
        printf("Failed to initialize DBScan points container\n");
        return;
    }

    // Collect all source IPs associated with this application
    int count = 0;
    for (int i = 0; i < max_src; i++) {
        if (apps[app_index].source_count[i] > 0 && src_stats[i].ip_string != NULL) {
            dbscan_add_point(points, i, src_stats[i].ip_string,
                            src_stats[i].packet_count,
                            src_stats[i].packet_volume);
                            // NOTICE
                            // src_stats[i].total_session
                          
            count++;
        }
    }

    printf("Collected %d source IPs for clustering\n", count);

    if (count > 0) {
        // Print some sample distances to understand the new metric
        if (count >= 2) {
            printf("\nSample distances between points using new metric:\n");
            for (int i = 0; i < min(5, count); i++) {
                for (int j = i+1; j < min(5, count); j++) {
                    uint32_t ip1 = points->points[i].ip;
                    uint32_t ip2 = points->points[j].ip;
                    double distance = ip_distance(ip1, ip2);
                    
                    // Calculate the components for explanation
                    int idx1 = ip1 % max_src;
                    int idx2 = ip2 % max_src;
                    double avg_pkt_size1 = (src_stats[idx1].packet_count > 0) ? 
                                         (double)src_stats[idx1].packet_volume / src_stats[idx1].packet_count : 0;
                    double avg_pkt_size2 = (src_stats[idx2].packet_count > 0) ? 
                                         (double)src_stats[idx2].packet_volume / src_stats[idx2].packet_count : 0;
                    
                    printf("Distance between %s and %s: %.2f\n", 
                           points->points[i].ip_str, points->points[j].ip_str, distance);
                    printf("  IP1: Avg Pkt Size=%.2f, Sessions=%u\n", 
                           avg_pkt_size1, src_stats[idx1].total_session);
                    printf("  IP2: Avg Pkt Size=%.2f, Sessions=%u\n", 
                           avg_pkt_size2, src_stats[idx2].total_session);
                }
            }
            printf("\n");
        }

        // Perform DBScan clustering
        int num_clusters = dbscan_cluster(points, DBSCAN_EPS, DBSCAN_MIN_PTS);

        // Print clustering results
        dbscan_print_clusters(points, num_clusters);
        
        // Print additional statistics about clusters
        if (num_clusters > 0) {
            printf("\nCluster Statistics:\n");
            for (int c = 0; c < num_clusters; c++) {
                double total_avg_pkt_size = 0;
                double total_sessions = 0;
                int cluster_size = 0;
                
                for (int i = 0; i < points->num_points; i++) {
                    if (points->points[i].cluster_id == c) {
                        int idx = points->points[i].ip % max_src;
                        double avg_pkt_size = (src_stats[idx].packet_count > 0) ? 
                                            (double)src_stats[idx].packet_volume / src_stats[idx].packet_count : 0;
                        total_avg_pkt_size += avg_pkt_size;
                        total_sessions += src_stats[idx].total_session;
                        cluster_size++;
                    }
                }
                
                if (cluster_size > 0) {
                    printf("Cluster %d:\n", c);
                    printf("  Average packet size: %.2f\n", total_avg_pkt_size / cluster_size);
                    printf("  Average sessions: %.2f\n", total_sessions / cluster_size);
                }
            }
        }
    } else {
        printf("No source IPs to cluster\n");
    }

    // Free resources
    dbscan_free_points(points);
    printf("=================================================================\n");
}



static void check_for_idle_flows(struct nDPI_workflow * const workflow)
{
  if (workflow->last_idle_scan_time + IDLE_SCAN_PERIOD < workflow->last_time) {
    for (size_t idle_scan_index = 0; idle_scan_index < workflow->max_active_flows; ++idle_scan_index) {
      ndpi_twalk(workflow->ndpi_flows_active[idle_scan_index], ndpi_idle_scan_walker, workflow);

      while (workflow->cur_idle_flows > 0) {
	      struct nDPI_flow_info * const f = (struct nDPI_flow_info *)workflow->ndpi_flows_idle[--workflow->cur_idle_flows];
	      src_stats[f->ip_tuple.v4.src%max_src].idle_session +=1;
        apps[f->detected_l7_protocol.app_protocol].source_count[f->ip_tuple.v4.src%max_src]--;
        
        // if (f->flow_fin_ack_seen == 1) {
          // remove_comment
        /*
	        printf("Free fin flow with id %u\n", f->flow_id);
          */
	      // } else {
          // remove_comment
        /*
	        printf("Free idle flow with id %u\n", f->flow_id);
          */
	      // }
  
	      ndpi_tdelete(f, &workflow->ndpi_flows_active[idle_scan_index], ndpi_workflow_node_cmp);
        
	      ndpi_flow_info_freer(f);
	      workflow->cur_active_flows--;
      }
    }
    workflow->last_idle_scan_time = workflow->last_time;
  }
}




static void ndpi_process_packet(struct ndpi_thread *nDPI_thread, struct pcap_pkthdr const * const header, uint8_t const * const packet, uint32_t pkt_len)
{
  struct ndpi_thread * const reader_thread = (struct ndpi_thread *)nDPI_thread;
  struct nDPI_workflow * workflow;
  struct nDPI_flow_info flow = {};

  size_t hashed_index;
  void * tree_result;
  struct nDPI_flow_info * flow_to_process;

  const struct ndpi_ethhdr * ethernet;
  const struct ndpi_iphdr * ip;
  struct ndpi_ipv6hdr * ip6;

  uint64_t time_ms;
  const uint16_t eth_offset = 0;
  uint16_t ip_offset;
  uint16_t ip_size;

  const uint8_t * l4_ptr = NULL;
  uint16_t l4_len = 0;

  uint16_t type;

  
  workflow = reader_thread->workflow;

  if (workflow == NULL) {
    return;
  }

  workflow->packets_captured++;
  time_ms = ((uint64_t) header->ts.tv_sec) * TICK_RESOLUTION + header->ts.tv_usec / (1000000 / TICK_RESOLUTION);
  workflow->last_time = time_ms;

  check_for_idle_flows(workflow);

  if (header->len < sizeof(struct ndpi_ethhdr)) {
      // fprintf(stderr, "[%8llu] Ethernet packet too short - skipping\n", workflow->packets_captured);
      return;
  }
  ethernet = (struct ndpi_ethhdr *) &packet[eth_offset];
  ip_offset = sizeof(struct ndpi_ethhdr) + eth_offset;
  type = ntohs(ethernet->h_proto);
  switch (type) {
    case ETH_P_IP: // IPv4
      if (header->len < sizeof(struct ndpi_ethhdr) + sizeof(struct ndpi_iphdr)) {
	      // fprintf(stderr, "[%8llu] IP packet too short - skipping\n", workflow->packets_captured);
	      return;
      }
      break;
    case ETH_P_IPV6: // IPV6
      if (header->len < sizeof(struct ndpi_ethhdr) + sizeof(struct ndpi_ipv6hdr)) {
	      // fprintf(stderr, "[%8llu] IP6 packet too short - skipping\n", workflow->packets_captured);
	      return;
      }
      break;
    case ETH_P_ARP: // ARP
      return;
    default:
      // fprintf(stderr, "[%8llu] Unknown Ethernet packet with type 0x%X - skipping\n", workflow->packets_captured, type);
      return;
  }

  if (type == ETH_P_IP) {
    ip = (struct ndpi_iphdr *)&packet[ip_offset];
    ip6 = NULL;
  } else if (type == ETH_P_IPV6) {
    ip = NULL;
    ip6 = (struct ndpi_ipv6hdr *)&packet[ip_offset];
  } else {
    // fprintf(stderr, "[%8llu] Captured non IPv4/IPv6 packet with type 0x%X - skipping\n", workflow->packets_captured, type);
    return;
  }
  ip_size = header->len - ip_offset;

  if (type == ETH_P_IP && header->len >= ip_offset) {
    if (header->caplen < header->len) {
      // fprintf(stderr, "[%8llu] Captured packet size is smaller than packet size: %u < %u\n", workflow->packets_captured, header->caplen, header->len);
    }
  }
  /* process layer3 e.g. IPv4 / IPv6 */
  if (ip != NULL && ip->version == 4) {
    if (ip_size < sizeof(*ip)) {
      // fprintf(stderr, "[%8llu] Packet smaller than IP4 header length: %u < %zu\n", workflow->packets_captured, ip_size, sizeof(*ip));
      return;
    }

    flow.l3_type = L3_IP;
    if (ndpi_detection_get_l4((uint8_t*)ip, ip_size, &l4_ptr, &l4_len, &flow.l4_protocol, NDPI_DETECTION_ONLY_IPV4) != 0)
      {
	      // fprintf(stderr, "[%8llu] nDPI IPv4/L4 payload detection failed, L4 length: %zu\n", workflow->packets_captured, ip_size - sizeof(*ip));
	      return;
      }

    flow.ip_tuple.v4.src = ip->saddr;
    flow.ip_tuple.v4.dst = ip->daddr;
  } else if (ip6 != NULL) {
    if (ip_size < sizeof(ip6->ip6_hdr)) {
        // fprintf(stderr, "[%8llu] Packet smaller than IP6 header length: %u < %zu\n", workflow->packets_captured, ip_size, sizeof(ip6->ip6_hdr));
        return;
    }

    flow.l3_type = L3_IP6;
    if (ndpi_detection_get_l4((uint8_t*)ip6, ip_size, &l4_ptr, &l4_len, &flow.l4_protocol, NDPI_DETECTION_ONLY_IPV6) != 0)
    {
	    // fprintf(stderr, "[%8llu] nDPI IPv6/L4 payload detection failed, L4 length: %zu\n", workflow->packets_captured, ip_size - sizeof(*ip6));
	    return;
    }

    flow.ip_tuple.v6.src[0] = ip6->ip6_src.u6_addr.u6_addr64[0];
    flow.ip_tuple.v6.src[1] = ip6->ip6_src.u6_addr.u6_addr64[1];
    flow.ip_tuple.v6.dst[0] = ip6->ip6_dst.u6_addr.u6_addr64[0];
    flow.ip_tuple.v6.dst[1] = ip6->ip6_dst.u6_addr.u6_addr64[1];
    uint64_t min_addr[2];
    if (flow.ip_tuple.v6.src[0] > flow.ip_tuple.v6.dst[0] &&
	flow.ip_tuple.v6.src[1] > flow.ip_tuple.v6.dst[1])
      {
	min_addr[0] = flow.ip_tuple.v6.dst[0];
	min_addr[1] = flow.ip_tuple.v6.dst[0];
      } else {
      min_addr[0] = flow.ip_tuple.v6.src[0];
      min_addr[1] = flow.ip_tuple.v6.src[0];
    }
  } else {
    // fprintf(stderr, "[%8llu] Non IP/IPv6 protocol detected: 0x%X\n", workflow->packets_captured, type);
    return;
  }

  /* process layer4 e.g. TCP / UDP */
  if (flow.l4_protocol == IPPROTO_TCP) {
    const struct ndpi_tcphdr * tcp;

    if (header->len < (l4_ptr - packet) + sizeof(struct ndpi_tcphdr)) {
      // fprintf(stderr, "[%8llu] Malformed TCP packet, packet size smaller than expected: %u < %zu\n", workflow->packets_captured, header->len, (l4_ptr - packet) + sizeof(struct ndpi_tcphdr));
      return;
    }
    tcp = (struct ndpi_tcphdr *)l4_ptr;
    flow.is_midstream_flow = (tcp->syn == 0 ? 1 : 0);
    flow.flow_fin_ack_seen = (tcp->fin == 1 && tcp->ack == 1 ? 1 : 0);
    flow.flow_ack_seen = tcp->ack;
    flow.src_port = ntohs(tcp->source);
    flow.dst_port = ntohs(tcp->dest);
  } else if (flow.l4_protocol == IPPROTO_UDP) {
    const struct ndpi_udphdr * udp;

    if (header->len < (l4_ptr - packet) + sizeof(struct ndpi_udphdr)) {
      // fprintf(stderr, "[%8llu] Malformed UDP packet, packet size smaller than expected: %u < %zu\n", workflow->packets_captured, header->len, (l4_ptr - packet) + sizeof(struct ndpi_udphdr));
      return;
    }
    udp = (struct ndpi_udphdr *)l4_ptr;
    flow.src_port = ntohs(udp->source);
    flow.dst_port = ntohs(udp->dest);
  }

  
  workflow->packets_processed++;
  workflow->total_l4_data_len += l4_len;

#ifdef VERBOSE
  print_packet_info(header, l4_len, &flow);
#endif
  bool new_flow=false;
  /* calculate flow hash for btree find, search(insert) */
  if (flow.l3_type == L3_IP) {
    if (ndpi_flowv4_flow_hash(flow.l4_protocol, flow.ip_tuple.v4.src, flow.ip_tuple.v4.dst, flow.src_port, flow.dst_port, 0, 0, (uint8_t *)&flow.hashval, sizeof(flow.hashval)) != 0)
      {
	      flow.hashval = flow.ip_tuple.v4.src + flow.ip_tuple.v4.dst; // fallback // IMPORTANT
      }
    } else if (flow.l3_type == L3_IP6) {
    if (ndpi_flowv6_flow_hash(flow.l4_protocol, &ip6->ip6_src, &ip6->ip6_dst, flow.src_port, flow.dst_port, 0, 0, (uint8_t *)&flow.hashval, sizeof(flow.hashval)) != 0)
      {
	      flow.hashval = flow.ip_tuple.v6.src[0] + flow.ip_tuple.v6.src[1]; // IMPORTANT
	      flow.hashval += flow.ip_tuple.v6.dst[0] + flow.ip_tuple.v6.dst[1]; // IMPORTANT
      }
    }
    flow.hashval += flow.l4_protocol + flow.src_port + flow.dst_port; // IMPORTANT

  hashed_index = flow.hashval % workflow->max_active_flows;
  tree_result = ndpi_tfind(&flow, &workflow->ndpi_flows_active[hashed_index], ndpi_workflow_node_cmp);
  if (tree_result == NULL) {
    /* flow not found in btree: switch src <-> dst and try to find it again */
    uint32_t orig_src_ip[4] = { flow.ip_tuple.u32.src[0], flow.ip_tuple.u32.src[1], 
                                flow.ip_tuple.u32.src[2], flow.ip_tuple.u32.src[3] };
    uint32_t orig_dst_ip[4] = { flow.ip_tuple.u32.dst[0], flow.ip_tuple.u32.dst[1],
                                flow.ip_tuple.u32.dst[2], flow.ip_tuple.u32.dst[3] };
    uint16_t orig_src_port = flow.src_port;
    uint16_t orig_dst_port = flow.dst_port;

    flow.ip_tuple.u32.src[0] = orig_dst_ip[0];
    flow.ip_tuple.u32.src[1] = orig_dst_ip[1];
    flow.ip_tuple.u32.src[2] = orig_dst_ip[2];
    flow.ip_tuple.u32.src[3] = orig_dst_ip[3];

    flow.ip_tuple.u32.dst[0] = orig_src_ip[0];
    flow.ip_tuple.u32.dst[1] = orig_src_ip[1];
    flow.ip_tuple.u32.dst[2] = orig_src_ip[2];
    flow.ip_tuple.u32.dst[3] = orig_src_ip[3];

    flow.src_port = orig_dst_port;
    flow.dst_port = orig_src_port;

    tree_result = ndpi_tfind(&flow, &workflow->ndpi_flows_active[hashed_index], ndpi_workflow_node_cmp);

    flow.ip_tuple.u32.src[0] = orig_src_ip[0];
    flow.ip_tuple.u32.src[1] = orig_src_ip[1];
    flow.ip_tuple.u32.src[2] = orig_src_ip[2];
    flow.ip_tuple.u32.src[3] = orig_src_ip[3];

    flow.ip_tuple.u32.dst[0] = orig_dst_ip[0];
    flow.ip_tuple.u32.dst[1] = orig_dst_ip[1];
    flow.ip_tuple.u32.dst[2] = orig_dst_ip[2];
    flow.ip_tuple.u32.dst[3] = orig_dst_ip[3];

    flow.src_port = orig_src_port;
    flow.dst_port = orig_dst_port;
  }

  if (tree_result == NULL) {
    /* flow still not found, must be new */
    if (workflow->cur_active_flows == workflow->max_active_flows) {
      // fprintf(stderr, "[%8llu] max flows to track reached: %llu, idle: %llu\n", workflow->packets_captured, workflow->max_active_flows, workflow->cur_idle_flows);
      return;
    }

    flow_to_process = (struct nDPI_flow_info *)ndpi_malloc(sizeof(*flow_to_process));
    if (flow_to_process == NULL) {
      // fprintf(stderr, "[%8llu] Not enough memory for flow info\n", workflow->packets_captured);
      return;
    }

    memcpy(flow_to_process, &flow, sizeof(*flow_to_process));
    flow_to_process->flow_id = __sync_fetch_and_add(&flow_id, 1); // IMPORTANT

    flow_to_process->ndpi_flow = (struct ndpi_flow_struct *)ndpi_flow_malloc(SIZEOF_FLOW_STRUCT);
    if (flow_to_process->ndpi_flow == NULL) {
      // fprintf(stderr, "[%8llu, %4u] Not enough memory for flow struct\n", workflow->packets_captured, flow_to_process->flow_id);
      return;
    }
    memset(flow_to_process->ndpi_flow, 0, SIZEOF_FLOW_STRUCT);
    // remove_comment
    // printf("[%8llu, %4u] new %sflow\n", workflow->packets_captured, flow_to_process->flow_id, (flow_to_process->is_midstream_flow != 0 ? "midstream-" : ""));
    
    if (ndpi_tsearch(flow_to_process, &workflow->ndpi_flows_active[hashed_index], ndpi_workflow_node_cmp) == NULL) {
      /* Possible Leak, but should not happen as we'd abort earlier. */
      return;
    }

    workflow->cur_active_flows++;
    workflow->total_active_flows++;
    // increase flow counter of the srcip
    src_stats[flow_to_process->ip_tuple.v4.src%max_src].total_session += 1;
    new_flow = true;

  } else {
    flow_to_process = *(struct nDPI_flow_info **)tree_result;
  }

  flow_to_process->packets_processed++;
  flow_to_process->total_l4_data_len += l4_len;
  /* update timestamps, important for timeout handling */
  if (flow_to_process->first_seen == 0) {
    flow_to_process->first_seen = time_ms;
  }
  flow_to_process->last_seen = time_ms;
  /* current packet is an TCP-ACK? */
  flow_to_process->flow_ack_seen = flow.flow_ack_seen;

  /* TCP-FIN: indicates that at least one side wants to end the connection */
  if (flow.flow_fin_ack_seen != 0 && flow_to_process->flow_fin_ack_seen == 0) {
    flow_to_process->flow_fin_ack_seen = 1;
    // remove_comment
        /*
    printf("[%8llu, %4u] end of flow\n",  workflow->packets_captured, flow_to_process->flow_id); */
    return;
  }

  /*
   * This example tries to use maximum supported packets for detection:
   * for uint8: 0xFF
   */
  if (flow_to_process->ndpi_flow->num_processed_pkts == 0xFF) {
    return;
  } else if (flow_to_process->ndpi_flow->num_processed_pkts == 0xFE) {
    /* last chance to guess something, better then nothing */
    uint8_t protocol_was_guessed = 0;
    flow_to_process->guessed_protocol = ndpi_detection_giveup(workflow->ndpi_struct, flow_to_process->ndpi_flow, 1, &protocol_was_guessed);
    if (protocol_was_guessed != 0) {
      // remove_comment

      printf("[%8llu, %4d][GUESSED] protocol: %s | app protocol: %s | category: %s\n", 
      workflow->packets_captured,flow_to_process->flow_id,
      ndpi_get_proto_name(workflow->ndpi_struct, flow_to_process->guessed_protocol.master_protocol),
      ndpi_get_proto_name(workflow->ndpi_struct, flow_to_process->guessed_protocol.app_protocol),
      ndpi_category_get_name(workflow->ndpi_struct, flow_to_process->guessed_protocol.category));
    } else {
      // remove_comment
      
      printf("[%8llu, %4d][FLOW NOT CLASSIFIED]\n",
	     workflow->packets_captured, flow_to_process->flow_id);
    }
  }

  flow_to_process->detected_l7_protocol = ndpi_detection_process_packet(workflow->ndpi_struct, flow_to_process->ndpi_flow, ip != NULL ? (uint8_t *)ip : (uint8_t *)ip6, ip_size, time_ms, NULL);

  if (ndpi_is_protocol_detected(workflow->ndpi_struct, flow_to_process->detected_l7_protocol) != 0 && flow_to_process->detection_completed == 0)
    {
      if (flow_to_process->detected_l7_protocol.master_protocol != NDPI_PROTOCOL_UNKNOWN ||
          flow_to_process->detected_l7_protocol.app_protocol != NDPI_PROTOCOL_UNKNOWN)
      {
        flow_to_process->detection_completed = 1;
        workflow->detected_flow_protocols++;
        // remove_comment
        
        printf("[%8llu, %4d][DETECTED] protocol: %s | app protocol: %s | category: %s | app_protocol_num: %d\n" ,
	       workflow->packets_captured, flow_to_process->flow_id,
	       ndpi_get_proto_name(workflow->ndpi_struct, flow_to_process->detected_l7_protocol.master_protocol),
	       ndpi_get_proto_name(workflow->ndpi_struct, flow_to_process->detected_l7_protocol.app_protocol),
	       ndpi_category_get_name(workflow->ndpi_struct, flow_to_process->detected_l7_protocol.category),
         flow_to_process->detected_l7_protocol.app_protocol
         );
        
         // Update D3 algorithm statistics
         int app_idx = flow_to_process->detected_l7_protocol.app_protocol;
         apps[app_idx].interval_counter += pkt_len;
         apps[app_idx].source_count[flow_to_process->ip_tuple.v4.src % max_src]++;
         apps[app_idx].app_name = strdup(ndpi_get_proto_name(workflow->ndpi_struct, flow_to_process->detected_l7_protocol.app_protocol));
         
         // Update D3 algorithm specific statistics
         apps[app_idx].total_packets++;
         update_packet_size_histogram(&apps[app_idx], pkt_len);
         update_dst_port_histogram(&apps[app_idx], flow_to_process->dst_port);
         
         if(new_flow) {
           apps[app_idx].new_session += 1;
           // Count unique source IPs
           bool is_new_src = true;
           for(int i = 0; i < max_src; i++) {
             if(apps[app_idx].source_count[i] > 0 && i == (flow_to_process->ip_tuple.v4.src % max_src)) {
               if(apps[app_idx].source_count[i] == 1) {
                 apps[app_idx].unique_src_ips++;
               }
               break;
             }
           }
         }
        
         // NOTICE
         printf("app_types : %d",flow_to_process->detected_l7_protocol.master_protocol);
         printf("\tv_max = %" PRIu64 " v_min = %" PRIu64" ",apps[flow_to_process->detected_l7_protocol.master_protocol].max_counter,apps[flow_to_process->detected_l7_protocol.master_protocol].min_counter);
         printf(" interval_counter = %" PRIu64 " ratio_pred = %" PRIu64"\n",apps[flow_to_process->detected_l7_protocol.master_protocol].interval_counter,apps[flow_to_process->detected_l7_protocol.master_protocol].ratio_pred);
        
      }
    }

  // TODO
  char src_addr_str[INET6_ADDRSTRLEN+1];
	char dst_addr_str[INET6_ADDRSTRLEN+1];
	ip_tuple_to_string(flow_to_process, src_addr_str, sizeof(src_addr_str), dst_addr_str, sizeof(dst_addr_str));
  if(!src_stats[flow_to_process->ip_tuple.v4.src%max_src].ip_string)
    src_stats[flow_to_process->ip_tuple.v4.src%max_src].ip_string = strdup(src_addr_str);
  src_stats[flow_to_process->ip_tuple.v4.src%max_src].packet_count +=1;
  src_stats[flow_to_process->ip_tuple.v4.src%max_src].packet_volume += pkt_len;
}


// Threshold Export/ Import
#define DEFAULT_THRESHOLD_FILE "/tmp/d3_thresholds.dat"

// Threshold record structure for file storage
typedef struct threshold_record {
    char app_name[64];                // Protocol name
    uint32_t training_samples;        // Number of samples used for training
    double baseline_entropy_src;      // Baseline source IP entropy
    double baseline_entropy_dst;      // Baseline destination port entropy
    double baseline_entropy_size;     // Baseline packet size entropy
    double baseline_traffic_rate;     // Baseline traffic rate
    double entropy_threshold;         // Entropy threshold for detection
    double rate_threshold;            // Rate threshold for detection
} threshold_record_t;

bool save_thresholds(const char *filename, app_info *apps, int app_count) {
    FILE *fp = fopen(filename, "w");
    if (!fp) {
        printf("Error: Could not open threshold file %s for writing\n", filename);
        return false;
    }
    
    int saved_count = 0;
    time_t now = time(NULL);
    
    // Write file header with metadata
    fprintf(fp, "# D3 Algorithm Threshold File\n");
    fprintf(fp, "# Generated on: %s", ctime(&now));
    fprintf(fp, "# Format: protocol_name training_samples baseline_entropy_src baseline_entropy_dst baseline_entropy_size baseline_traffic_rate entropy_threshold rate_threshold\n");
    fprintf(fp, "# Version: 1.0\n");
    fprintf(fp, "\n");
    
    // Count valid protocols first
    int valid_count = 0;
    for (int i = 0; i < app_count; i++) {
        if (apps[i].app_name != NULL && apps[i].has_baseline) {
            valid_count++;
        }
    }
    
    fprintf(fp, "PROTOCOL_COUNT=%d\n\n", valid_count);
    
    // Write each protocol's thresholds in readable format
    for (int i = 0; i < app_count; i++) {
        if (apps[i].app_name == NULL || !apps[i].has_baseline) {
            continue;
        }
        
        // fprintf(fp, "# Protocol: %s\n", apps[i].app_name);
        fprintf(fp, "PROTOCOL=%s\n", apps[i].app_name);
        fprintf(fp, "TRAINING_SAMPLES=%u\n", apps[i].training_samples);
        fprintf(fp, "BASELINE_ENTROPY_SRC=%.6f\n", apps[i].baseline_entropy_src);
        fprintf(fp, "BASELINE_ENTROPY_DST=%.6f\n", apps[i].baseline_entropy_dst);
        fprintf(fp, "BASELINE_ENTROPY_SIZE=%.6f\n", apps[i].baseline_entropy_size);
        fprintf(fp, "BASELINE_TRAFFIC_RATE=%.6f\n", apps[i].baseline_traffic_rate);
        fprintf(fp, "ENTROPY_THRESHOLD=%.6f\n", apps[i].entropy_threshold);
        fprintf(fp, "RATE_THRESHOLD=%.6f\n", apps[i].rate_threshold);
        fprintf(fp, "\n");
        
        saved_count++;
    }
    
    fclose(fp);
    printf("Successfully saved thresholds for %d protocols to %s\n", saved_count, filename);
    printf("Threshold file is now human-readable and can be edited manually\n");
    return true;
}

/*
 * Load protocol thresholds from a human-readable text file
 * 
 * @param filename: Path to the threshold file
 * @param apps: Array of app_info structures to populate
 * @param app_count: Number of applications
 * @return: true if successful, false otherwise
 */
bool load_thresholds(const char *filename, app_info *apps, int app_count) {
    FILE *fp = fopen(filename, "r");
    if (!fp) {
        printf("Error: Could not open threshold file %s for reading\n", filename);
        return false;
    }
    
    char line[256];
    int protocol_count = 0;
    int loaded_count = 0;
    char current_protocol[64] = "";
    
    // Temporary variables for current protocol being loaded
    uint32_t training_samples = 0;
    double baseline_entropy_src = 0.0;
    double baseline_entropy_dst = 0.0;
    double baseline_entropy_size = 0.0;
    double baseline_traffic_rate = 0.0;
    double entropy_threshold = 0.0;
    double rate_threshold = 0.0;
    bool protocol_data_complete = false;
    
    printf("Loading thresholds from %s\n", filename);
    
    // Read file line by line
    while (fgets(line, sizeof(line), fp)) {
        // Skip comments and empty lines
        if (line[0] == '#' || line[0] == '\n' || line[0] == '\r') {
            continue;
        }
        
        // Remove trailing newline
        // line[strcspn(line, "\n\r")] = 0;
        
        // Parse protocol count
        if (sscanf(line, "PROTOCOL_COUNT=%d", &protocol_count) == 1) {
            printf("Expected to load %d protocols\n", protocol_count);
            continue;
        }
        
        // Parse protocol name
        if (sscanf(line, "PROTOCOL=%63s", current_protocol) == 1) {
            protocol_data_complete = false;
            continue;
        }
        
        // Parse training samples
        if (sscanf(line, "TRAINING_SAMPLES=%u", &training_samples) == 1) {
            continue;
        }
        
        // Parse baseline entropy values
        if (sscanf(line, "BASELINE_ENTROPY_SRC=%lf", &baseline_entropy_src) == 1) {
            continue;
        }
        if (sscanf(line, "BASELINE_ENTROPY_DST=%lf", &baseline_entropy_dst) == 1) {
            continue;
        }
        if (sscanf(line, "BASELINE_ENTROPY_SIZE=%lf", &baseline_entropy_size) == 1) {
            continue;
        }
        
        // Parse baseline traffic rate
        if (sscanf(line, "BASELINE_TRAFFIC_RATE=%lf", &baseline_traffic_rate) == 1) {
            continue;
        }
        
        // Parse thresholds
        if (sscanf(line, "ENTROPY_THRESHOLD=%lf", &entropy_threshold) == 1) {
            continue;
        }
        if (sscanf(line, "RATE_THRESHOLD=%lf", &rate_threshold) == 1) {
            protocol_data_complete = true;
            
            // All data for current protocol is loaded, find matching app and update
            bool found = false;
            for (int j = 0; j < app_count; j++) {
                if (apps[j].app_name != NULL && strcmp(apps[j].app_name, current_protocol) == 0) {
                    // Found matching protocol, load thresholds
                    apps[j].training_samples = training_samples;
                    apps[j].baseline_entropy_src = baseline_entropy_src;
                    apps[j].baseline_entropy_dst = baseline_entropy_dst;
                    apps[j].baseline_entropy_size = baseline_entropy_size;
                    apps[j].baseline_traffic_rate = baseline_traffic_rate;
                    apps[j].entropy_threshold = entropy_threshold;
                    apps[j].rate_threshold = rate_threshold;
                    apps[j].has_baseline = true;
                    
                    printf("  Loaded thresholds for protocol: %s\n", current_protocol);
                    printf("    Training samples: %u\n", training_samples);
                    printf("    Baseline entropy - src: %.3f, dst: %.3f, size: %.3f\n",
                           baseline_entropy_src, baseline_entropy_dst, baseline_entropy_size);
                    printf("    Baseline traffic rate: %.2f\n", baseline_traffic_rate);
                    printf("    Thresholds - entropy: %.3f, rate: %.2f\n",
                           entropy_threshold, rate_threshold);
                    
                    loaded_count++;
                    found = true;
                    break;
                }
            }
            
            if (!found) {
                printf("  Warning: Protocol %s from threshold file not found in current configuration\n", 
                       current_protocol);
            }
            
            // Reset for next protocol
            memset(current_protocol, 0, sizeof(current_protocol));
            continue;
        }
    }
    
    fclose(fp);
    printf("Successfully loaded thresholds for %d protocols\n", loaded_count);
    return loaded_count > 0;
}

/*
 * Print the current thresholds for all protocols with baselines
 * 
 * @param apps: Array of app_info structures
 * @param app_count: Number of applications
 */
void print_thresholds(app_info *apps, int app_count) {
    printf("\n=== Current Protocol Thresholds ===\n");
    int count = 0;
    
    for (int i = 0; i < app_count; i++) {
        if (apps[i].app_name != NULL && apps[i].has_baseline) {
            printf("Protocol: %s\n", apps[i].app_name);
            printf("  Baseline entropy - src: %.3f, dst: %.3f, size: %.3f\n",
                   apps[i].baseline_entropy_src, apps[i].baseline_entropy_dst, 
                   apps[i].baseline_entropy_size);
            printf("  Baseline traffic rate: %.2f packets/interval\n", 
                   apps[i].baseline_traffic_rate);
            printf("  Detection thresholds - entropy: %.3f, rate: %.2f\n",
                   apps[i].entropy_threshold, apps[i].rate_threshold);
            printf("  Training samples: %d\n", apps[i].training_samples);
            count++;
        }
    }
    
    if (count == 0) {
        printf("No protocols with established baselines found\n");
    }
    
    printf("=== Total: %d protocols ===\n\n", count);
}



bool skip_training = false;           // Skip training phase and load thresholds
bool save_thresholds_after_training = false;  // Save thresholds after training
char threshold_file[256] = DEFAULT_THRESHOLD_FILE;





/*
 * The lcore main. This is the main thread that does the work, reading from
 * an input port, and do processing on the metrics.
 */
static int lcore_main(__rte_unused void *dummy){  
  struct rte_mbuf *pkts_burst[MAX_PKT_BURST];
  struct rte_mbuf *m;
  unsigned int i, j, port, lcore_id, nb_rx, nb_tx;
  struct lcore_queue_conf *qconf;
  lcore_id = rte_lcore_id();
  qconf = &lcore_queue_conf[lcore_id];

  if (qconf->n_rx_port == 0) {
    RTE_LOG(INFO, DDD, "lcore %u has nothing to do\n", lcore_id);
    return 0;
  }

  RTE_LOG(INFO, DDD, "entering main loop on lcore %u\n", lcore_id);

  for (i = 0; i < qconf->n_rx_port; i++) {
    port = qconf->rx_port_list[i];
    RTE_LOG(INFO, DDD, " -- lcoreid=%u portid=%u\n", lcore_id, port);
  }
  
  ndpi_threads[lcore_id].workflow = init_workflow();
  
  // D3 Algorithm variables
  clock_t start_time, end_time;
  int c = 0; // interval counter
  struct rte_mbuf *pkt;
  i = 0;
  long long int number_of_packets_in_a_interval;
  clock_t interval_len = CLOCKS_PER_SEC;
  
  // Training configuration for D3 algorithm
  int min_training_intervals = 30;  // Minimum intervals for baseline establishment
  int max_training_intervals = 60;  // Maximum training intervals
  bool training = !skip_training;   // Skip training if thresholds are loaded
  
  printf("=== D3 Algorithm Inspired DDoS Detection System ===\n");
  printf("Based on IEEE paper 9424610: Statistical Anomaly Detection\n");
  
  // Load thresholds if in detection-only mode
  if (skip_training) {
    printf("Detection-only mode: Loading thresholds from %s\n", threshold_file);
    print_thresholds(apps, app_types);
    if (load_thresholds(threshold_file, apps, app_types)) {
      printf("Successfully loaded thresholds, skipping training phase\n");
      print_thresholds(apps, app_types);
    } else {
      printf("Failed to load thresholds, reverting to training mode\n");
      training = true;
    }
  }
  
  if (training) {
    printf("Training phase: %d-%d intervals per protocol\n", min_training_intervals, max_training_intervals);
  }
  
  printf("Detection features: Source IP entropy, Destination port entropy, Packet size entropy, Traffic rate\n\n");

  while(!force_quit) {        
    start_time = clock();
    end_time = clock();
    number_of_packets_in_a_interval = 0;
    
    // Training phase - establish statistical baselines
    if (training) {
      printf("\rD3 Training phase: interval %d/%d", c+1, max_training_intervals);
      fflush(stdout);
      
      start_time = clock();
      end_time = clock();
      // Collect packets for an Interval (one second)
      while((((end_time - start_time) / interval_len) < 1) && (!force_quit)) {
        // Receiving packets
        for (i = 0; i < qconf->n_rx_port; i++) {
          port = qconf->rx_port_list[i];
          // printf("%d\n",port);
          nb_rx = rte_eth_rx_burst(port, 0, pkts_burst, MAX_PKT_BURST);
          // printf("%d\n",nb_rx);
          if (unlikely(nb_rx == 0))
            continue;
          port_statistics[port].rx += nb_rx;
          
          // Processing packets
          for (j = 0; j < nb_rx; j++) {
            pkt = pkts_burst[j];
            uint16_t packetLength = rte_pktmbuf_pkt_len(pkt);
            uint16_t payloadLength = packetLength - pkt->l2_len - pkt->l3_len - pkt->l4_len;
            uint32_t pkt_len = pkt->pkt_len;
            char *data = rte_pktmbuf_mtod(pkt, char *);
            int len = rte_pktmbuf_pkt_len(pkt);
            struct pcap_pkthdr h;
            h.len = h.caplen = len;
            gettimeofday(&h.ts, NULL);
            ndpi_process_packet(&ndpi_threads[lcore_id], &h, (const u_char *)data, pkt_len+payloadLength);
          }
          
          // Sending packets back
          nb_tx = rte_eth_tx_burst(port ^ 1, 0, pkts_burst, nb_rx);
          if (unlikely(nb_tx < nb_rx)) {
            uint16_t buf;
            for (buf = nb_tx; buf < nb_rx; buf++)
              rte_pktmbuf_free(pkts_burst[buf]);
          }
          number_of_packets_in_a_interval += nb_rx;
        }
        end_time = clock();
      }
  
      // Process training data for each protocol
      clearScreen();
      
      for(int i = 0; i < app_types; i++) {
        if (apps[i].app_name == NULL || apps[i].total_packets == 0) continue;
        
        // Update training sample count
        apps[i].training_samples++;
        
        // Establish baseline for this protocol
        establish_baseline(&apps[i]);
        
        // Display training progress
        // if (apps[i].training_samples % 10 == 0) {
        //   printf("\nProtocol %s: Training sample %d\n", apps[i].app_name, apps[i].training_samples);
        //   printf("  Baseline entropy (src): %.3f, threshold: %.3f\n", 
        //          apps[i].baseline_entropy_src, apps[i].entropy_threshold);
        //   printf("  Baseline traffic rate: %.2f, threshold: %.2f\n", 
        //          apps[i].baseline_traffic_rate, apps[i].rate_threshold);
        //   printf("  Current entropy (src): %.3f, (dst): %.3f, (size): %.3f\n",
        //          apps[i].entropy_src_ip, apps[i].entropy_dst_port, apps[i].entropy_packet_size);
        // }
        
        // Reset interval statistics
        reset_interval_stats(&apps[i]);
      }
      
      // Check if training should end

      // Notice
      
      bool all_protocols_trained = true;
      int protocols_with_baseline = 0;
      
      for(int i = 0; i < app_types; i++) {
        if (apps[i].app_name != NULL && apps[i].training_samples > 0) {
          if (apps[i].has_baseline) {
            protocols_with_baseline++;
          } else if (apps[i].training_samples < min_training_intervals) {
            all_protocols_trained = false;
          }
        }
      }
      
      
      // End training if conditions are met
      if ((protocols_with_baseline > 0 && all_protocols_trained) || c >= max_training_intervals - 1) {
        training = false;
        printf("\n\n=== D3 Training Phase Completed ===\n");
        printf("Protocols with established baselines: %d\n", protocols_with_baseline);
        
        // Display final baseline statistics
        for(int i = 0; i < app_types; i++) {
          if (apps[i].app_name != NULL && apps[i].has_baseline) {
            printf("\nProtocol: %s (samples: %d)\n", apps[i].app_name, apps[i].training_samples);
            printf("  Baseline entropy - src: %.3f, dst: %.3f, size: %.3f\n",
                   apps[i].baseline_entropy_src, apps[i].baseline_entropy_dst, apps[i].baseline_entropy_size);
            printf("  Baseline traffic rate: %.2f packets/interval\n", apps[i].baseline_traffic_rate);
            printf("  Detection thresholds - entropy: %.3f, rate: %.2f\n",
                   apps[i].entropy_threshold, apps[i].rate_threshold);
          }
        }
        printf("=== Starting D3 Detection Phase ===\n\n");
        
        // Save thresholds if requested
        if (save_thresholds_after_training) {
            printf("Saving thresholds to %s\n", threshold_file);
            if (save_thresholds(threshold_file, apps, app_types)) {
                printf("Thresholds saved successfully\n");
            } else {
                printf("Failed to save thresholds\n");
            }
        }
        
        c = 0;
        start_time = clock();
        end_time = clock();
      } else {
        ++c;
      }
      
      number_of_packets_in_a_interval = 0;
    }
    
    // Detection phase - D3 algorithm anomaly detection
    if (!training) {
      // Collect packets for one second
      while(((end_time - start_time) / CLOCKS_PER_SEC) < 1 && (!force_quit)) {
        // Receiving packets
        for (i = 0; i < qconf->n_rx_port; i++) {
          port = qconf->rx_port_list[i];
          nb_rx = rte_eth_rx_burst(port, 0, pkts_burst, MAX_PKT_BURST);
          if (unlikely(nb_rx == 0))
            continue;
          port_statistics[port].rx += nb_rx;
          
          // Processing packets
          for (j = 0; j < nb_rx; j++) {
            pkt = pkts_burst[j];
            uint16_t packetLength = rte_pktmbuf_pkt_len(pkt);
            uint16_t payloadLength = packetLength - pkt->l2_len - pkt->l3_len - pkt->l4_len;
            uint32_t pkt_len = pkt->pkt_len;
            char *data = rte_pktmbuf_mtod(pkt, char *);
            int len = rte_pktmbuf_pkt_len(pkt);
            struct pcap_pkthdr h;
            h.len = h.caplen = len;
            gettimeofday(&h.ts, NULL);
            ndpi_process_packet(&ndpi_threads[lcore_id], &h, (const u_char *)data, pkt_len+payloadLength);
          }
          
          // Sending packets back
          nb_tx = rte_eth_tx_burst(port ^ 1, 0, pkts_burst, nb_rx);
          if (unlikely(nb_tx < nb_rx)) {
            uint16_t buf;
            for (buf = nb_tx; buf < nb_rx; buf++)
              rte_pktmbuf_free(pkts_burst[buf]);
          }
          number_of_packets_in_a_interval += nb_rx;
        }
        end_time = clock();
      }
      
      // D3 Algorithm: Analyze traffic and detect DDoS attacks
      clearScreen();
      printf("D3 Detection phase: interval %d\n", c+1);
      printf("=== Real-time Traffic Analysis ===\n");
      
      for(int i = 0; i < app_types; i++) {
        if (apps[i].app_name == NULL || !apps[i].has_baseline) continue;
        
        // Skip if no traffic in this interval
        if (apps[i].total_packets == 0) {
          reset_interval_stats(&apps[i]);
          continue;
        }
        
        // D3 Algorithm: Perform DDoS detection
        bool attack_detected = detect_ddos_attack(&apps[i]);
        
        if (attack_detected) {
          printf("\n!!! D3 ALGORITHM: DDoS ATTACK DETECTED !!!\n");
          printf("Protocol: %s\n", apps[i].app_name);
          printf("=== Attack Characteristics ===\n");
          printf("  Current entropy (src IP): %.3f (baseline: %.3f, threshold: %.3f)\n",
                 apps[i].entropy_src_ip, apps[i].baseline_entropy_src, apps[i].entropy_threshold);
          printf("  Current entropy (dst port): %.3f (baseline: %.3f)\n",
                 apps[i].entropy_dst_port, apps[i].baseline_entropy_dst);
          printf("  Current entropy (pkt size): %.3f (baseline: %.3f)\n",
                 apps[i].entropy_packet_size, apps[i].baseline_entropy_size);
          printf("  Current traffic rate: %.2f (baseline: %.2f, threshold: %.2f)\n",
                 apps[i].traffic_rate, apps[i].baseline_traffic_rate, apps[i].rate_threshold);
          printf("  Anomaly score: %.3f\n", apps[i].anomaly_score);
          printf("  Unique source IPs: %d\n", apps[i].unique_src_ips);
          printf("  Total packets: %d\n", apps[i].total_packets);
          
          // Determine attack type based on entropy patterns
          if (apps[i].entropy_src_ip < apps[i].entropy_threshold && apps[i].traffic_rate > apps[i].rate_threshold) {
            printf("  Attack type: High-volume attack from concentrated sources\n");
          } else if (apps[i].anomaly_score > 0.7) {
            printf("  Attack type: Statistical anomaly detected\n");
          }
          
          printf("=== Initiating Mitigation ===\n");
          
          // Perform DBScan clustering for attack source analysis
          perform_dbscan_clustering(i);
          
        } else {
          // Normal traffic - display statistics periodically
          if (c % 10 == 0) {
            printf("\nProtocol: %s (Normal)\n", apps[i].app_name);
            printf("  Entropy: src=%.3f, dst=%.3f, size=%.3f\n",
                   apps[i].entropy_src_ip, apps[i].entropy_dst_port, apps[i].entropy_packet_size);
            printf("  Traffic rate: %.2f, Anomaly score: %.3f\n",
                   apps[i].traffic_rate, apps[i].anomaly_score);
          }
          
          // Adaptive baseline update for normal traffic
          if (apps[i].anomaly_score < 0.2) { // Very normal traffic
            double alpha = 0.05; // Slow adaptation
            apps[i].baseline_entropy_src = (1 - alpha) * apps[i].baseline_entropy_src + alpha * apps[i].entropy_src_ip;
            apps[i].baseline_entropy_dst = (1 - alpha) * apps[i].baseline_entropy_dst + alpha * apps[i].entropy_dst_port;
            apps[i].baseline_traffic_rate = (1 - alpha) * apps[i].baseline_traffic_rate + alpha * apps[i].traffic_rate;
            
            // Update thresholds
            apps[i].entropy_threshold = apps[i].baseline_entropy_src * 0.7;
            apps[i].rate_threshold = apps[i].baseline_traffic_rate * 2.0;
          }
        }
        
        // Reset interval statistics for next measurement
        reset_interval_stats(&apps[i]);
      }
      
      number_of_packets_in_a_interval = 0;
      c++;
      
      // Reset counter periodically
      if (c % 100 == 0) {
        printf("\n=== D3 Algorithm Status ===\n");
        printf("Detection intervals completed: %d\n", c);
        printf("System running normally...\n\n");
        c = 0;
      }
    }
  }
  
  return 0;
}

static void print_usage(const char *prgname) {
  printf("%s [EAL options] -- [application options]\n"
         "Application options:\n"
         "  -d, --detection-only: Skip training phase and load thresholds from file\n"
         "  -s, --save-thresholds: Save thresholds after training phase\n"
         "  -f, --threshold-file=FILE: Specify threshold file path (default: %s)\n"
         "  -h, --help: Display this help message\n",
         prgname, DEFAULT_THRESHOLD_FILE);
}

// Parse application-specific arguments
static int parse_app_args(int argc, char **argv) {
  int opt, option_index;
  static struct option lgopts[] = {
    {"detection-only", no_argument, NULL, 'd'},
    {"save-thresholds", no_argument, NULL, 's'},
    {"threshold-file", required_argument, NULL, 'f'},
    {"help", no_argument, NULL, 'h'},
    {NULL, 0, 0, 0}
  };

  while ((opt = getopt_long(argc, argv, "dsf:h", lgopts, &option_index)) != EOF) {
    switch (opt) {
      case 'd':
        skip_training = true;
        printf("Detection-only mode enabled\n");
        break;
      case 's':
        save_thresholds_after_training = true;
        printf("Saving thresholds after training\n");
        break;
      case 'f':
        strncpy(threshold_file, optarg, sizeof(threshold_file) - 1);
        threshold_file[sizeof(threshold_file) - 1] = '\0';
        printf("Using threshold file: %s\n", threshold_file);
        break;
      case 'h':
        print_usage(argv[0]);
        return -1;
      default:
        printf("Invalid option: %c\n", opt);
        print_usage(argv[0]);
        return -1;
    }
  }
  
  return 0;
}


static void signal_handler(int signum)
{
	if (signum == SIGINT || signum == SIGTERM) {
		printf("\n\nSignal %d received, preparing to exit...\n",
				signum);
		force_quit = true;
	}
}

int main(int argc, char *argv[]){
  
  struct lcore_queue_conf *qconf=NULL;
  unsigned nb_ports;
  uint16_t portid;
  unsigned lcore_id, rx_lcore_id=0;
  unsigned int nb_lcores = 0;

  /* Initialize the Environment Abstraction Layer (EAL). */
  int ret = rte_eal_init(argc, argv);
  
  if (ret < 0)
    rte_exit(EXIT_FAILURE, "Error with EAL initialization\n");
  
  argc -= ret;
  argv += ret;
  
  // Parse application arguments
  ret = parse_app_args(argc, argv);
  if (ret < 0)
    rte_exit(EXIT_FAILURE, "Invalid application arguments\n");
  


  force_quit = false;
  signal(SIGINT, signal_handler);
  signal(SIGINT, signal_handler);
  
  nb_ports = rte_eth_dev_count_avail();
  if (nb_ports==0)
    rte_exit(EXIT_FAILURE, "No Ethernet ports\n");

  int port_cores_assigned = 0;

	/* Initialize the port/queue configuration of each logical core */
  /*
  RTE_ETH_FOREACH_DEV(portid){
    while (rte_lcore_is_enabled(rx_lcore_id) == 0 ){
      if(port_cores_assigned/MAX_RX_QUEUE_PER_LCORE==portid){
        port_cores_assigned=0;
        break;
      }
      if(lcore_queue_conf[rx_lcore_id].n_rx_port != MAX_RX_QUEUE_PER_LCORE){
        qconf = &lcore_queue_conf[rx_lcore_id];
        qconf->rx_port_list[qconf->n_rx_port] = portid;
		    qconf->n_rx_port++;
        printf("Lcore %u: RX port %u\n", rx_lcore_id, portid);
        port_cores_assigned++;
      }
      else if(rx_lcore_id>=RTE_MAX_LCORE && port_cores_assigned==0)
        rte_exit(EXIT_FAILURE, "Not enough cores\n");
      rx_lcore_id++;
    }

  }
  */

  
	RTE_ETH_FOREACH_DEV(portid) {
		//  get the lcore_id for this port 
		while (rte_lcore_is_enabled(rx_lcore_id) == 0 || lcore_queue_conf[rx_lcore_id].n_rx_port == MAX_RX_QUEUE_PER_LCORE) {
			rx_lcore_id++;
			if (rx_lcore_id >= RTE_MAX_LCORE)
				rte_exit(EXIT_FAILURE, "Not enough cores\n");
		}

		if (qconf != &lcore_queue_conf[rx_lcore_id]) {
			// Assigned a new logical core in the loop above.
			qconf = &lcore_queue_conf[rx_lcore_id];
			nb_lcores++;
		}

		qconf->rx_port_list[qconf->n_rx_port] = portid;
		qconf->n_rx_port++;
		printf("Lcore %u: RX port %u\n", rx_lcore_id, portid);
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
       
  // closing ports
  RTE_ETH_FOREACH_DEV(portid){
    printf("Closing port %d...", portid);
		ret = rte_eth_dev_stop(portid);
		if (ret != 0)
			printf("rte_eth_dev_stop: err=%d, port=%d\n", ret, portid);
		rte_eth_dev_close(portid);
		printf(" Done\n");
  }

  // for(unsigned int li=0;li<RTE_MAX_LCORE;li++){
  //   qconf = &lcore_queue_conf[li];
  //   if (qconf->n_rx_port != 0) {
  //     printf("current active flows for %u : %llu  , total flows: %llu\n",li,ndpi_threads[li].workflow->cur_active_flows, ndpi_threads[li].workflow->total_active_flows);
  //   }
  // }

  // Clean-up EAL
  rte_eal_cleanup();
  
  printf("Bye...\n");
        
  return ret;
}
