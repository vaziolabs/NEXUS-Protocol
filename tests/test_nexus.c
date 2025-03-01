#include "../include/nexus.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <assert.h>
#include <unistd.h>
#include <sys/time.h>

#define TEST_ITERATIONS 1000
#define BENCHMARK_ITERATIONS 10000
#define MAX_PAYLOAD_SIZE 1024

/* Test utilities */
typedef struct {
    const char* name;
    int (*func)(void);
    double duration;
    int passed;
} test_case_t;

double get_time_ms(void) {
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return (tv.tv_sec * 1000.0) + (tv.tv_usec / 1000.0);
}

/* Test cases */
int test_network_creation(void) {
    nexus_context_t ctx = {0};
    nexus_network_id_t network_id = {0};
    
    // Test normal creation
    int result = nexus_create_isolated_network(&ctx, &network_id, NEXUS_NET_PRIVATE, NULL, 0);
    assert(result == 0);
    assert(ctx.network_count == 1);
    
    // Test maximum networks
    for (int i = 1; i < NEXUS_MAX_NETWORKS + 1; i++) {
        result = nexus_create_isolated_network(&ctx, &network_id, NEXUS_NET_PRIVATE, NULL, 0);
    }
    assert(result == -1); // Should fail on exceeding max
    
    return 1;
}

int test_resource_sharing(void) {
    nexus_context_t ctx = {0};
    nexus_network_id_t network1 = {0};
    nexus_network_id_t network2 = {0};
    network2.id[0] = 1; // Make different from network1
    
    // Create networks
    nexus_create_isolated_network(&ctx, &network1, NEXUS_NET_PRIVATE, NULL, 0);
    nexus_create_isolated_network(&ctx, &network2, NEXUS_NET_PRIVATE, NULL, 0);
    
    // Test resource sharing
    nexus_resource_permission_t perm = {
        .resource_type = NEXUS_RESOURCE_COMPUTE,
        .permissions = 0xFF,
        .quota = 1000,
        .expiry = 3600
    };
    
    int result = nexus_share_resource(&ctx, &network1, &network2, &perm);
    assert(result == 0);
    
    return 1;
}

int test_network_bridging(void) {
    nexus_context_t ctx = {0};
    nexus_network_id_t network1 = {0};
    nexus_network_id_t network2 = {0};
    network2.id[0] = 1;
    
    // Create networks
    nexus_create_isolated_network(&ctx, &network1, NEXUS_NET_PRIVATE, NULL, 0);
    nexus_create_isolated_network(&ctx, &network2, NEXUS_NET_PRIVATE, NULL, 0);
    
    // Test bridge creation
    int result = nexus_bridge_networks(&ctx, &network1, &network2, 0);
    assert(result == 0);
    assert(ctx.bridge_count == 1);
    
    return 1;
}

/* Benchmarks */
void benchmark_network_operations(void) {
    nexus_context_t ctx = {0};
    nexus_network_id_t network_id = {0};
    double start, end;
    
    // Network creation benchmark
    start = get_time_ms();
    for (int i = 0; i < BENCHMARK_ITERATIONS && i < NEXUS_MAX_NETWORKS; i++) {
        network_id.id[0] = i;
        nexus_create_isolated_network(&ctx, &network_id, NEXUS_NET_PRIVATE, NULL, 0);
    }
    end = get_time_ms();
    printf("Network Creation: %.2f ops/sec\n", 
           BENCHMARK_ITERATIONS / ((end - start) / 1000.0));
    
    // Network discovery benchmark
    nexus_network_info_t networks[NEXUS_MAX_NETWORKS];
    size_t count = NEXUS_MAX_NETWORKS;
    
    start = get_time_ms();
    for (int i = 0; i < BENCHMARK_ITERATIONS; i++) {
        nexus_discover_networks(&ctx, networks, &count);
    }
    end = get_time_ms();
    printf("Network Discovery: %.2f ops/sec\n",
           BENCHMARK_ITERATIONS / ((end - start) / 1000.0));
}

void benchmark_packet_operations(void) {
    nexus_context_t ctx = {0};
    nexus_network_id_t network1 = {0};
    nexus_network_id_t network2 = {0};
    network2.id[0] = 1;
    
    // Setup networks and bridge
    nexus_create_isolated_network(&ctx, &network1, NEXUS_NET_PRIVATE, NULL, 0);
    nexus_create_isolated_network(&ctx, &network2, NEXUS_NET_PRIVATE, NULL, 0);
    nexus_bridge_networks(&ctx, &network1, &network2, 0);
    
    // Prepare test payload
    uint8_t payload[MAX_PAYLOAD_SIZE];
    memset(payload, 0xAA, MAX_PAYLOAD_SIZE);
    
    double start = get_time_ms();
    for (int i = 0; i < BENCHMARK_ITERATIONS; i++) {
        nexus_route_between_networks(&ctx, &network1, &network2, payload, MAX_PAYLOAD_SIZE);
    }
    double end = get_time_ms();
    
    printf("Packet Routing: %.2f packets/sec\n",
           BENCHMARK_ITERATIONS / ((end - start) / 1000.0));
}

/* Main test runner */
int main(void) {
    test_case_t tests[] = {
        {"Network Creation", test_network_creation, 0.0, 0},
        {"Resource Sharing", test_resource_sharing, 0.0, 0},
        {"Network Bridging", test_network_bridging, 0.0, 0},
        {NULL, NULL, 0.0, 0}
    };
    
    int passed = 0;
    int total = 0;
    
    printf("Running NEXUS Protocol Tests\n");
    printf("============================\n\n");
    
    // Run tests
    for (int i = 0; tests[i].name != NULL; i++) {
        double start = get_time_ms();
        tests[i].passed = tests[i].func();
        double end = get_time_ms();
        tests[i].duration = end - start;
        
        printf("%s: %s (%.2fms)\n", 
               tests[i].name,
               tests[i].passed ? "PASSED" : "FAILED",
               tests[i].duration);
        
        passed += tests[i].passed;
        total++;
    }
    
    printf("\nTest Summary: %d/%d passed\n\n", passed, total);
    
    // Run benchmarks
    printf("Running Benchmarks\n");
    printf("==================\n\n");
    
    benchmark_network_operations();
    benchmark_packet_operations();
    
    return (passed == total) ? EXIT_SUCCESS : EXIT_FAILURE;
}
