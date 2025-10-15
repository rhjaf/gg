/*
 * Improved detection algorithm for DPDK packet processing application
 * This file contains an improved implementation of the training phase and detection
 * algorithm that properly establishes baselines for each protocol based on observed behavior.
 * 
 * To use this implementation:
 * 1. Include this file in main.c
 * 2. Replace the existing lcore_main function with the improved_lcore_main function
 * 3. Update the app_info structure as described in the comments
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <math.h>
#include <time.h>
#include <string.h>
#include <inttypes.h>

/*
 * The app_info structure should be updated to include the following fields:
 *
 * typedef struct app_info{
 *   char * app_name;
 *   uint64_t max_counter; // initialize =0
 *   uint64_t min_counter; // initialize =INT_MAX
 *   uint64_t counter_window[window_size];
 *   uint64_t interval_counter;
 *   uint64_t ratio_window[window_size];
 *   double ratio_pred;
 *   uint16_t new_session; // new session for this application
 *   uint16_t source_count[max_src]; // Active Source IP entropy of each application
 *   
 *   // Training and statistical data
 *   uint32_t training_samples;      // Number of samples collected during training
 *   double volume_mean;             // Mean of volume (interval_counter)
 *   double volume_stddev;           // Standard deviation of volume
 *   double ratio_mean;              // Mean of ratio
 *   double ratio_stddev;            // Standard deviation of ratio
 *   double volume_threshold_high;   // Upper threshold for volume
 *   double volume_threshold_low;    // Lower threshold for volume
 *   double ratio_threshold_high;    // Upper threshold for ratio
 *   double ratio_threshold_low;     // Lower threshold for ratio
 *   double confidence;              // Confidence level in the thresholds (0-1)
 *   bool has_baseline;              // Whether this protocol has established a baseline
 * } app_info;
 */

// Helper functions for statistical calculations

// Calculate variance for uint64_t array
double var_uint64(uint64_t arr[], int arr_size, double avg) {
  double res = 0;
  for(int i = 0; i < arr_size; i++)
    res += pow((arr[i] - avg), 2);
  res /= (double)arr_size;
  return res;
}

// Calculate mean for uint64_t array
double mean_uint64(uint64_t arr[], int arr_size) {
  double res = 0;
  for(int i = 0; i < arr_size; i++)
    res += arr[i];
  return res / (double)arr_size;
}

// Update running statistics with a new sample using Welford's algorithm
void update_statistics(double *mean, double *var, int *n, double new_value) {
  (*n)++;
  double delta = new_value - *mean;
  *mean += delta / *n;
  double delta2 = new_value - *mean;
  *var += delta * delta2;
}

// Calculate standard deviation from variance and sample count
double calculate_stddev(double variance, int n) {
  if (n <= 1) return 0;
  return sqrt(variance / (n - 1));
}

// Calculate thresholds based on statistics and confidence
void calculate_thresholds(app_info *app, double sigma_multiplier) {
  // Only calculate if we have enough samples
  if (app->training_samples < 2) return;
  
  // Calculate standard deviations
  app->volume_stddev = calculate_stddev(app->volume_stddev, app->training_samples);
  app->ratio_stddev = calculate_stddev(app->ratio_stddev, app->training_samples);
  
  // Calculate thresholds with adaptive sigma multiplier
  // For protocols with high variability, use a higher multiplier
  double volume_multiplier = sigma_multiplier;
  double ratio_multiplier = sigma_multiplier;
  
  // Adjust multiplier based on coefficient of variation
  if (app->volume_mean > 0) {
    double cv = app->volume_stddev / app->volume_mean;
    if (cv > 0.5) volume_multiplier += 1.0; // Add extra margin for highly variable protocols
  }
  
  if (app->ratio_mean > 0) {
    double cv = app->ratio_stddev / app->ratio_mean;
    if (cv > 0.5) ratio_multiplier += 1.0;
  }
  
  // Set thresholds
  app->volume_threshold_high = app->volume_mean + volume_multiplier * app->volume_stddev;
  app->volume_threshold_low = fmax(0, app->volume_mean - volume_multiplier * app->volume_stddev);
  app->ratio_threshold_high = app->ratio_mean + ratio_multiplier * app->ratio_stddev;
  app->ratio_threshold_low = fmax(0, app->ratio_mean - ratio_multiplier * app->ratio_stddev);
  
  // Set confidence based on number of samples
  app->confidence = fmin(1.0, app->training_samples / 30.0);
  
  // Mark as having a baseline if we have enough samples
  if (app->training_samples >= 10) {
    app->has_baseline = true;
  }
}

/*
 * Improved lcore_main function with proper training phase
 * This function replaces the existing lcore_main function in main.c
 */
static int improved_lcore_main(__rte_unused void *dummy) {
  struct rte_mbuf *pkts_burst[MAX_PKT_BURST];
  struct rte_mbuf *m;
  unsigned int i, j, port, lcore_id, nb_rx, nb_tx;
  struct lcore_queue_conf *qconf;
  double r_u = INT_MAX;
  double r_l = INT_MAX;
  double r_pred;
  uint64_t v_pred;
  double avg, sd;
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
  
  // Basic variables for packet processing
  clock_t start_time, end_time;
  double time_elapsed;
  int c = 0; // interval counter
  struct rte_ipv4_hdr *ipv4_hdr;
  struct rte_mbuf *pkt;
  i = 0;
  long long int number_of_packets_in_a_interval;
  clock_t interval_len = CLOCKS_PER_SEC;
  
  // Training configuration
  int min_training_samples = 30;  // Minimum number of samples needed for reliable statistics
  int max_training_intervals = 60; // Maximum number of intervals for training (prevent endless training)
  bool training = true;
  
  // Initialize training data arrays for collecting statistics
  uint64_t *training_volumes = malloc(sizeof(uint64_t) * app_types * max_training_intervals);
  double *training_ratios = malloc(sizeof(double) * app_types * max_training_intervals);
  int *training_counts = calloc(app_types, sizeof(int));
  
  if (!training_volumes || !training_ratios || !training_counts) {
    printf("Error: Failed to allocate memory for training data\n");
    if (training_volumes) free(training_volumes);
    if (training_ratios) free(training_ratios);
    if (training_counts) free(training_counts);
    return 1;
  }

  printf("Starting packet processing with improved training phase...\n");
  printf("Training will collect at least %d samples per protocol or run for %d intervals\n", 
         min_training_samples, max_training_intervals);

  while(!force_quit) {        
    start_time = clock();
    end_time = clock();
    number_of_packets_in_a_interval = 0;
    
    // Training phase - collect data and establish baselines
    if (training) {
      printf("\rTraining phase: interval %d/%d", c+1, max_training_intervals);
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
          /* Free any unsent packets. */
          if (unlikely(nb_tx < nb_rx)) {
            uint16_t buf;
            for (buf = nb_tx; buf < nb_rx; buf++)
              rte_pktmbuf_free(pkts_burst[buf]);
          }
          number_of_packets_in_a_interval += nb_rx;
        }
        end_time = clock();
      }
  
      // Process data collected in this interval
      clearScreen();
      
      // For each application protocol
      for(int i = 0; i < app_types; i++) {
        // Skip protocols with no traffic
        if (apps[i].app_name == NULL) continue;
        
        // Update min/max counters
        if (apps[i].interval_counter > apps[i].max_counter)
          apps[i].max_counter = apps[i].interval_counter;
        else if((apps[i].interval_counter != 0) && (apps[i].interval_counter < apps[i].min_counter))
          apps[i].min_counter = apps[i].interval_counter;
        else if((apps[i].interval_counter == 0) && (apps[i].max_counter != 0))
          apps[i].min_counter = 0;
        
        // Calculate v_pred and r_pred for this interval
        uint64_t v_pred = 0;
        for(int t = 0; t < window_size; t++) {
          if (apps[i].counter_window[t] > 0)
            v_pred += apps[i].counter_window[t] * (double)(t+1); 
          else
            break;
        }
        v_pred /= (double)55;
        if(v_pred <= 0)
          v_pred = V_PRED;
        
        double r_pred = apps[i].interval_counter / (double)v_pred;
        if(r_pred <= 0)
          r_pred = R_PRED;
        
        // If we have traffic for this protocol, collect training data
        if (apps[i].interval_counter > 0) {
          int idx = training_counts[i];
          if (idx < max_training_intervals) {
            training_volumes[i * max_training_intervals + idx] = apps[i].interval_counter;
            training_ratios[i * max_training_intervals + idx] = r_pred;
            training_counts[i]++;
            
            // Update running statistics for this protocol
            int n = apps[i].training_samples;
            update_statistics(&apps[i].volume_mean, &apps[i].volume_stddev, &n, apps[i].interval_counter);
            update_statistics(&apps[i].ratio_mean, &apps[i].ratio_stddev, &n, r_pred);
            apps[i].training_samples = n;
            
            // Store in window arrays for visualization
            append(apps[i].counter_window, window_size, apps[i].interval_counter);
            append(apps[i].ratio_window, window_size, r_pred);
            
            // Calculate thresholds after each new sample
            calculate_thresholds(&apps[i], 3.0); // Start with 3-sigma
            
            if (apps[i].training_samples % 5 == 0) {
              printf("\nProtocol %s: Collected %d samples\n", 
                     apps[i].app_name, apps[i].training_samples);
              printf("  Volume: mean=%.2f, stddev=%.2f, thresholds=[%.2f, %.2f]\n",
                     apps[i].volume_mean, apps[i].volume_stddev, 
                     apps[i].volume_threshold_low, apps[i].volume_threshold_high);
              printf("  Ratio: mean=%.2f, stddev=%.2f, thresholds=[%.2f, %.2f]\n",
                     apps[i].ratio_mean, apps[i].ratio_stddev,
                     apps[i].ratio_threshold_low, apps[i].ratio_threshold_high);
            }
          }
        }
        
        // Reset counters for next interval
        apps[i].interval_counter = 0;
        apps[i].new_session = 0;
      }
      
      // Check if we should end training
      bool all_protocols_trained = true;
      int protocols_with_traffic = 0;
      
      for(int i = 0; i < app_types; i++) {
        if (apps[i].app_name != NULL) {
          protocols_with_traffic++;
          if (apps[i].training_samples < min_training_samples) {
            all_protocols_trained = false;
          }
        }
      }
      
      // End training if we've collected enough samples or reached max intervals
      if ((protocols_with_traffic > 0 && all_protocols_trained) || c >= max_training_intervals - 1) {
        training = false;
        printf("\n\n===== Training phase completed =====\n");
        printf("Protocols with traffic: %d\n", protocols_with_traffic);
        
        // Final threshold calculation for all protocols
        for(int i = 0; i < app_types; i++) {
          if (apps[i].app_name != NULL && apps[i].training_samples > 0) {
            // Use adaptive sigma multiplier based on sample count
            double sigma_multiplier = 3.0;
            if (apps[i].training_samples < 10) {
              sigma_multiplier = 4.0; // Be more conservative with fewer samples
            }
            
            calculate_thresholds(&apps[i], sigma_multiplier);
            
            printf("\nProtocol: %s (%d samples, confidence: %.2f)\n", 
                   apps[i].app_name, apps[i].training_samples, apps[i].confidence);
            printf("  Volume: mean=%.2f, stddev=%.2f, thresholds=[%.2f, %.2f]\n",
                   apps[i].volume_mean, apps[i].volume_stddev, 
                   apps[i].volume_threshold_low, apps[i].volume_threshold_high);
            printf("  Ratio: mean=%.2f, stddev=%.2f, thresholds=[%.2f, %.2f]\n",
                   apps[i].ratio_mean, apps[i].ratio_stddev,
                   apps[i].ratio_threshold_low, apps[i].ratio_threshold_high);
          }
        }
        printf("=====================================\n\n");
        
        c = 0;
        start_time = clock();
        end_time = clock();
      } else {
        ++c;
      }
      
      number_of_packets_in_a_interval = 0;
    }
    
    // Free training data arrays when training is complete
    if (!training && training_volumes) {
      free(training_volumes);
      training_volumes = NULL;
    }
    if (!training && training_ratios) {
      free(training_ratios);
      training_ratios = NULL;
    }
    if (!training && training_counts) {
      free(training_counts);
      training_counts = NULL;
    }
    
    // Detection phase - monitor traffic and detect anomalies
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
          // Free any unsent packets
          if (unlikely(nb_tx < nb_rx)) {
            uint16_t buf;
            for (buf = nb_tx; buf < nb_rx; buf++)
              rte_pktmbuf_free(pkts_burst[buf]);
          }
          number_of_packets_in_a_interval += nb_rx;
        }
        end_time = clock();
      }
      
      // Process data collected in this interval
      clearScreen();
      printf("Detection phase: interval %d\n", c+1);
      
      // For each application protocol
      for(int i = 0; i < app_types; i++) {
        // Skip protocols with no baseline
        if (apps[i].app_name == NULL || !apps[i].has_baseline) continue;
        
        // Calculate v_pred and r_pred for this interval
        uint64_t v_pred = 0;
        for(int t = 0; t < window_size; t++) {
          if (apps[i].counter_window[t] > 0)
            v_pred += apps[i].counter_window[t] * (double)(t+1); 
          else
            break;
        }
        v_pred /= (double)55;
        if(v_pred <= 0)
          v_pred = V_PRED;
        
        double r_pred = apps[i].interval_counter / (double)v_pred;
        if(r_pred <= 0)
          r_pred = R_PRED;
        
        // Store current values for display
        apps[i].ratio_pred = r_pred;
        
        // Check for anomalies using protocol-specific thresholds
        bool volume_anomaly = false;
        bool ratio_anomaly = false;
        
        // Volume-based anomaly detection
        if (apps[i].interval_counter > apps[i].volume_threshold_high) {
          volume_anomaly = true;
        }
        
        // Ratio-based anomaly detection
        if (r_pred > apps[i].ratio_threshold_high || 
            (r_pred < apps[i].ratio_threshold_low && apps[i].interval_counter > 0)) {
          ratio_anomaly = true;
        }
        
        // If anomaly detected, trigger alert and clustering
        if ((volume_anomaly || ratio_anomaly) && apps[i].confidence >= 0.3) {
          printf("\n!!! ANOMALY DETECTED in protocol: %s !!!\n", apps[i].app_name);
          
          if (volume_anomaly) {
            printf("  Volume anomaly: current=%lu, threshold=%.2f\n", 
                   apps[i].interval_counter, apps[i].volume_threshold_high);
          }
          
          if (ratio_anomaly) {
            printf("  Ratio anomaly: current=%.2f, thresholds=[%.2f, %.2f]\n", 
                   r_pred, apps[i].ratio_threshold_low, apps[i].ratio_threshold_high);
          }
          
          printf("  Confidence: %.2f\n", apps[i].confidence);
          
          // Count unique source IPs
          int src_counter = 0;
          for(int ic = 0; ic < max_src; ic++) {
            if(apps[i].source_count[ic] > 0)
              src_counter++;
          }
          printf("  Unique source IPs: %d\n", src_counter);
          
          // Perform DBScan clustering for mitigation
          perform_dbscan_clustering(i);
        } else {
          // No anomaly, update statistics and windows
          uint64_t *tmp = malloc(sizeof(uint64_t) * window_size);
          if (tmp) {
            memcpy(tmp, apps[i].counter_window, window_size * sizeof(uint64_t));
            append(apps[i].ratio_window, window_size, r_pred);
            append(tmp, window_size, apps[i].interval_counter);
            memcpy(apps[i].counter_window, tmp, window_size * sizeof(uint64_t));
            free(tmp);
          }
          
          // Continuously update statistics (adaptive learning)
          if (apps[i].interval_counter > 0) {
            int n = apps[i].training_samples;
            // Give less weight to new samples (0.1 weight)
            double volume_update = apps[i].interval_counter * 0.1 + apps[i].volume_mean * 0.9;
            double ratio_update = r_pred * 0.1 + apps[i].ratio_mean * 0.9;
            
            update_statistics(&apps[i].volume_mean, &apps[i].volume_stddev, &n, volume_update);
            update_statistics(&apps[i].ratio_mean, &apps[i].ratio_stddev, &n, ratio_update);
            
            // Recalculate thresholds periodically
            if (c % 10 == 0) {
              calculate_thresholds(&apps[i], 3.0);
            }
          }
        }
        
        // Display current statistics
        if (apps[i].interval_counter > 0 && c % 5 == 0) {
          printf("\nProtocol: %s\n", apps[i].app_name);
          printf("  Volume: current=%lu, mean=%.2f, thresholds=[%.2f, %.2f]\n",
                 apps[i].interval_counter, apps[i].volume_mean,
                 apps[i].volume_threshold_low, apps[i].volume_threshold_high);
          printf("  Ratio: current=%.2f, mean=%.2f, thresholds=[%.2f, %.2f]\n",
                 r_pred, apps[i].ratio_mean,
                 apps[i].ratio_threshold_low, apps[i].ratio_threshold_high);
        }
        
        // Reset counters for next interval
        apps[i].interval_counter = 0;
        apps[i].new_session = 0;
      }
      
      number_of_packets_in_a_interval = 0;
      c++;
      
      // Reset counter after window_size intervals
      if (c % window_size == 0) {
        c = 0;
      }
    }
  }
  
  return 0;
}