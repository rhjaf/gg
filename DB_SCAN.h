#ifndef DBSCAN_H
#define DBSCAN_H

#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <math.h>
#include <arpa/inet.h>

// Forward declaration of external structures and variables
#define max_src 3000
extern struct src_stat {
    char* ip_string;
    uint16_t packet_count;
    uint16_t packet_volume;
    uint16_t total_session;
    uint16_t idle_session;
} src_stats[max_src];

// DBScan cluster labels
#define NOISE -1
#define UNCLASSIFIED -2

// Structure to represent a point (IP address) for clustering
typedef struct {
    uint32_t ip;           // IP address in network byte order
    char ip_str[INET_ADDRSTRLEN]; // String representation
    int cluster_id;        // Cluster ID assigned by DBScan
    uint16_t packet_count; // Packet count for this IP
    uint16_t packet_volume; // Packet volume for this IP
} dbscan_point_t;

// Structure to hold all points for clustering
typedef struct {
    dbscan_point_t* points;
    int num_points;
    int capacity;
} dbscan_points_t;

// Initialize points container
dbscan_points_t* dbscan_init_points(int initial_capacity) {
    dbscan_points_t* points = (dbscan_points_t*)malloc(sizeof(dbscan_points_t));
    if (!points) return NULL;

    points->points = (dbscan_point_t*)malloc(initial_capacity * sizeof(dbscan_point_t));
    if (!points->points) {
        free(points);
        return NULL;
    }

    points->num_points = 0;
    points->capacity = initial_capacity;
    return points;
}

// Add a point to the container
void dbscan_add_point(dbscan_points_t* points, uint32_t ip, const char* ip_str, uint16_t packet_count, uint16_t packet_volume) {
    if (points->num_points >= points->capacity) {
        int new_capacity = points->capacity * 2;
        dbscan_point_t* new_points = (dbscan_point_t*)realloc(points->points, new_capacity * sizeof(dbscan_point_t));
        if (!new_points) return;

        points->points = new_points;
        points->capacity = new_capacity;
    }

    points->points[points->num_points].ip = ip;
    strncpy(points->points[points->num_points].ip_str, ip_str, INET_ADDRSTRLEN);
    points->points[points->num_points].cluster_id = UNCLASSIFIED;
    // NOTICE
    points->points[points->num_points].packet_count = packet_count;
    // NOTICE
    points->points[points->num_points].packet_volume = packet_volume;
    points->num_points++;
}

// Free points container
void dbscan_free_points(dbscan_points_t* points) {
    if (points) {
        if (points->points) free(points->points);
        free(points);
    }
}

// Calculate distance between two points based on average packet size and total sessions
// This is a more sophisticated metric that considers traffic behavior
double ip_distance(uint32_t ip1, uint32_t ip2) {
    // Get indices for src_stats array
    int idx1 = ip1 % max_src;
    int idx2 = ip2 % max_src;
    
    // Calculate average packet size for each IP
    double avg_pkt_size1 = (src_stats[idx1].packet_count > 0) ? 
                          (double)src_stats[idx1].packet_volume / src_stats[idx1].packet_count : 0;
    double avg_pkt_size2 = (src_stats[idx2].packet_count > 0) ? 
                          (double)src_stats[idx2].packet_volume / src_stats[idx2].packet_count : 0;
    
    // Calculate normalized differences
    double pkt_size_diff = fabs(avg_pkt_size1 - avg_pkt_size2);
    double session_diff = fabs((double)src_stats[idx1].total_session - src_stats[idx2].total_session);
    
    // Weight factors (can be adjusted based on importance)
    double w1 = 0.5; // weight for average packet size difference
    double w2 = 0.5; // weight for total session difference
    
    // Combined distance metric
    return w1 * pkt_size_diff + w2 * session_diff;
}

// Find all neighbors within eps distance
int* dbscan_region_query(dbscan_points_t* points, int point_idx, double eps, int* neighbor_count) {
    int max_neighbors = points->num_points;
    int* neighbors = (int*)malloc(max_neighbors * sizeof(int));
    if (!neighbors) return NULL;

    *neighbor_count = 0;

    for (int i = 0; i < points->num_points; i++) {
        if (i == point_idx) continue;

        double dist = ip_distance(points->points[point_idx].ip, points->points[i].ip);
        if (dist <= eps) {
            neighbors[*neighbor_count] = i;
            (*neighbor_count)++;
        }
    }

    return neighbors;
}

// Expand cluster from a core point
bool dbscan_expand_cluster(dbscan_points_t* points, int point_idx, int cluster_id, double eps, int min_pts) {
    int neighbor_count = 0;
    int* neighbors = dbscan_region_query(points, point_idx, eps, &neighbor_count);

    if (!neighbors) return false;

    if (neighbor_count < min_pts) {
        points->points[point_idx].cluster_id = NOISE;
        free(neighbors);
        return false;
    }

    // Mark as part of the cluster
    // Notice
    points->points[point_idx].cluster_id = cluster_id;

    // Process all neighbors
    for (int i = 0; i < neighbor_count; i++) {
        int neighbor_idx = neighbors[i];

        // If previously marked as noise, add to cluster
        if (points->points[neighbor_idx].cluster_id == NOISE) {
            points->points[neighbor_idx].cluster_id = cluster_id;
        }
        // If not yet classified, add to cluster and process its neighbors
        else if (points->points[neighbor_idx].cluster_id == UNCLASSIFIED) {
            points->points[neighbor_idx].cluster_id = cluster_id;

            int sub_neighbor_count = 0;
            int* sub_neighbors = dbscan_region_query(points, neighbor_idx, eps, &sub_neighbor_count);

            if (sub_neighbors && sub_neighbor_count >= min_pts) {
                // Add new neighbors to the original list
                for (int j = 0; j < sub_neighbor_count; j++) {
                    bool found = false;
                    for (int k = 0; k < neighbor_count; k++) {
                        if (neighbors[k] == sub_neighbors[j]) {
                            found = true;
                            break;
                        }
                    }

                    if (!found) {
                        neighbors = (int*)realloc(neighbors, (neighbor_count + 1) * sizeof(int));
                        if (!neighbors) {
                            free(sub_neighbors);
                            return false;
                        }
                        neighbors[neighbor_count] = sub_neighbors[j];
                        neighbor_count++;
                    }
                }
            }

            if (sub_neighbors) free(sub_neighbors);
        }
    }

    free(neighbors);
    return true;
}

// Main DBScan algorithm
int dbscan_cluster(dbscan_points_t* points, double eps, int min_pts) {
    int cluster_id = 0;

    for (int i = 0; i < points->num_points; i++) {
        if (points->points[i].cluster_id != UNCLASSIFIED) continue;

        if (dbscan_expand_cluster(points, i, cluster_id, eps, min_pts)) {
            cluster_id++;
        }
    }

    return cluster_id; // Number of clusters found
}

// Print clustering results
void dbscan_print_clusters(dbscan_points_t* points, int num_clusters) {
    printf("\n===== DBScan Clustering Results =====\n");
    printf("Found %d clusters\n", num_clusters);

    // Print each cluster
    for (int c = 0; c < num_clusters; c++) {
        printf("\nCluster %d:\n", c);
        int count = 0;
        double total_avg_pkt_size = 0;
        uint32_t total_sessions = 0;

        for (int i = 0; i < points->num_points; i++) {
            if (points->points[i].cluster_id == c) {
                int idx = points->points[i].ip % max_src;
                double avg_pkt_size = (points->points[i].packet_count > 0) ? 
                                    (double)points->points[i].packet_volume / points->points[i].packet_count : 0;
                
                printf("  IP: %s, Packets: %u, Volume: %u, Avg Size: %.2f, Sessions: %u\n",
                       points->points[i].ip_str,
                       points->points[i].packet_count,
                       points->points[i].packet_volume,
                       avg_pkt_size,
                       src_stats[idx].total_session);
                
                total_avg_pkt_size += avg_pkt_size;
                total_sessions += src_stats[idx].total_session;
                count++;
            }
        }
        
        if (count > 0) {
            printf("Total IPs in cluster: %d\n", count);
            printf("Cluster average packet size: %.2f\n", total_avg_pkt_size / count);
            printf("Cluster average sessions: %.2f\n", (double)total_sessions / count);
        }
    }

    // Print noise points
    printf("\nNoise points (not in any cluster):\n");
    int noise_count = 0;
    double noise_total_avg_pkt_size = 0;
    uint32_t noise_total_sessions = 0;

    for (int i = 0; i < points->num_points; i++) {
        if (points->points[i].cluster_id == NOISE) {
            int idx = points->points[i].ip % max_src;
            double avg_pkt_size = (points->points[i].packet_count > 0) ? 
                                (double)points->points[i].packet_volume / points->points[i].packet_count : 0;
            
            printf("  IP: %s, Packets: %u, Volume: %u, Avg Size: %.2f, Sessions: %u\n",
                   points->points[i].ip_str,
                   points->points[i].packet_count,
                   points->points[i].packet_volume,
                   avg_pkt_size,
                   src_stats[idx].total_session);
            
            noise_total_avg_pkt_size += avg_pkt_size;
            noise_total_sessions += src_stats[idx].total_session;
            noise_count++;
        }
    }
    
    if (noise_count > 0) {
        printf("Total noise points: %d\n", noise_count);
        printf("Noise average packet size: %.2f\n", noise_total_avg_pkt_size / noise_count);
        printf("Noise average sessions: %.2f\n", (double)noise_total_sessions / noise_count);
    } else {
        printf("No noise points found\n");
    }
    
    printf("=====================================\n\n");
}

#endif /* DBSCAN_H */