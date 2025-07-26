#ifndef DBSCAN_H
#define DBSCAN_H

#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <math.h>
#include <arpa/inet.h>

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
    points->points[points->num_points].packet_count = packet_count;
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

// Calculate distance between two IP addresses
// This is a simple metric - you might want to use a more sophisticated one
double ip_distance(uint32_t ip1, uint32_t ip2) {
    // Convert to host byte order for arithmetic
    uint32_t host_ip1 = ntohl(ip1);
    uint32_t host_ip2 = ntohl(ip2);

    // Simple distance metric: absolute difference between IPs
    return (double)abs((int)(host_ip1 - host_ip2));
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

        for (int i = 0; i < points->num_points; i++) {
            if (points->points[i].cluster_id == c) {
                printf("  IP: %s, Packets: %u, Volume: %u\n",
                       points->points[i].ip_str,
                       points->points[i].packet_count,
                       points->points[i].packet_volume);
                count++;
            }
        }
        printf("Total IPs in cluster: %d\n", count);
    }

    // Print noise points
    printf("\nNoise points (not in any cluster):\n");
    int noise_count = 0;

    for (int i = 0; i < points->num_points; i++) {
        if (points->points[i].cluster_id == NOISE) {
            printf("  IP: %s, Packets: %u, Volume: %u\n",
                   points->points[i].ip_str,
                   points->points[i].packet_count,
                   points->points[i].packet_volume);
            noise_count++;
        }
    }
    printf("Total noise points: %d\n", noise_count);
    printf("=====================================\n\n");
}

#endif /* DBSCAN_H */