/*
 * D3 Algorithm Inspired Detection Implementation
 * Based on IEEE paper 9424610: "An Efficient IDS Framework for DDoS Attacks in SDN Environment"
 * 
 * This implementation replaces the original 3-sigma rule detection with an entropy-based
 * statistical anomaly detection algorithm inspired by the D3 framework.
 * 
 * Key features:
 * 1. Entropy-based detection using source IP, destination port, and packet size distributions
 * 2. Statistical baseline establishment during training phase
 * 3. Dynamic threshold calculation based on observed behavior
 * 4. Combined anomaly scoring for robust detection
 */

// Replace the existing lcore_main function with this improved version
static int d3_lcore_main(__rte_unused void *dummy) {  
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
  bool training = true;
  
  printf("=== D3 Algorithm Inspired DDoS Detection System ===\n");
  printf("Based on IEEE paper 9424610: Statistical Anomaly Detection\n");
  printf("Training phase: %d-%d intervals per protocol\n", min_training_intervals, max_training_intervals);
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
      
      // Collect packets for one second
      while((((end_time - start_time) / interval_len) < 1) && (!force_quit)) {
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
  
      // Process training data for each protocol
      clearScreen();
      
      for(int i = 0; i < app_types; i++) {
        if (apps[i].app_name == NULL || apps[i].total_packets == 0) continue;
        
        // Update training sample count
        apps[i].training_samples++;
        
        // Establish baseline for this protocol
        establish_baseline(&apps[i]);
        
        // Display training progress
        if (apps[i].training_samples % 10 == 0) {
          printf("\nProtocol %s: Training sample %d\n", apps[i].app_name, apps[i].training_samples);
          printf("  Baseline entropy (src): %.3f, threshold: %.3f\n", 
                 apps[i].baseline_entropy_src, apps[i].entropy_threshold);
          printf("  Baseline traffic rate: %.2f, threshold: %.2f\n", 
                 apps[i].baseline_traffic_rate, apps[i].rate_threshold);
          printf("  Current entropy (src): %.3f, (dst): %.3f, (size): %.3f\n",
                 apps[i].entropy_src_ip, apps[i].entropy_dst_port, apps[i].entropy_packet_size);
        }
        
        // Reset interval statistics
        reset_interval_stats(&apps[i]);
      }
      
      // Check if training should end
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

/*
 * Instructions for integration:
 * 
 * 1. Replace the existing lcore_main function in main.c with d3_lcore_main
 * 2. Update the main() function to call d3_lcore_main instead of lcore_main
 * 3. Ensure all D3 algorithm functions are included in main.c
 * 4. The app_info structure should be updated as shown in the main modifications
 * 
 * The D3 algorithm provides:
 * - Entropy-based detection using multiple traffic features
 * - Statistical baseline establishment during training
 * - Dynamic threshold adaptation
 * - Combined anomaly scoring for robust detection
 * - Real-time traffic analysis and attack characterization
 */