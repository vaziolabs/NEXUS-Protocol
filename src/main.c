#define _POSIX_C_SOURCE 200809L  // Add this at the very top

#include "nexus.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>
#include <getopt.h>
#include <stdbool.h>
#include <sys/socket.h>
#include <sys/epoll.h>
#include <sys/types.h>  // For pid_t
#include <sys/file.h>   // For flock
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <fcntl.h>
#include <errno.h>
#include <pthread.h>

#define DEFAULT_PORT "8080"
#define DEFAULT_IPV6_HOST "::"  
#define DEFAULT_IPV4_HOST "0.0.0.0"  // Start with IPv4
#define BACKLOG 10
#define MAX_EVENTS 64
#define MAX_CONNECTIONS 1024
#define BUFFER_SIZE 8192
#define PID_FILE "/tmp/nexus.pid"

static volatile bool running = true;
static int server_sockets[2] = {-1, -1}; // Store socket FDs globally for cleanup

typedef enum {
    CONN_TYPE_REST,
    CONN_TYPE_STREAM,
    CONN_TYPE_TUNNEL
} connection_type_t;

typedef struct {
    int fd;
    connection_type_t type;
    bool upgraded_to_v6;
    void* context;
    uint8_t buffer[BUFFER_SIZE];
    size_t buffer_used;
} connection_t;

typedef struct {
    bool is_server;
    bool is_client;
    char host[INET6_ADDRSTRLEN];
    char port[6];
    int port_offset;      // Add port offset for IPv6
    nexus_context_t* ctx;
    int ipv4_fd;
    int ipv6_fd;
    int epoll_fd;
    connection_t* connections[MAX_CONNECTIONS];
    pthread_mutex_t conn_mutex;
} nexus_app_config_t;

typedef struct {
    char name[256];
    uint16_t type;
    uint32_t ttl;
    size_t data_len;
    uint8_t data[1024];
    nexus_hash_t signature;
} dns_record_t;

typedef struct {
    char zone_name[256];
    nexus_network_id_t network_id;
    dns_record_t* records;
    size_t record_count;
    size_t record_capacity;
    bool is_authoritative;
} dns_zone_t;

typedef struct {
    dns_zone_t* zones;
    size_t zone_count;
    pthread_mutex_t dns_mutex;
} dns_registry_t;

// Function prototypes
void close_connection(nexus_app_config_t* config, int fd);
bool should_upgrade_to_v6(connection_t* conn);
void upgrade_to_v6(connection_t* conn);
void handle_rest_request(connection_t* conn);
void handle_stream_data(connection_t* conn);
void handle_tunnel_data(connection_t* conn);
int add_to_epoll(nexus_app_config_t* config, int fd, uint32_t events);
void handle_new_connection(nexus_app_config_t* config, int server_fd);
void handle_connection_data(nexus_app_config_t* config, int fd, uint32_t events);

void force_cleanup_ports(void) {
    // Clean up IPv4 port
    struct sockaddr_in addr4;
    int cleanup_fd4 = socket(AF_INET, SOCK_STREAM, 0);
    if (cleanup_fd4 != -1) {
        int reuse = 1;
        setsockopt(cleanup_fd4, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse));
        memset(&addr4, 0, sizeof(addr4));
        addr4.sin_family = AF_INET;
        addr4.sin_port = htons(atoi(DEFAULT_PORT));
        addr4.sin_addr.s_addr = INADDR_ANY;
        bind(cleanup_fd4, (struct sockaddr*)&addr4, sizeof(addr4));
        close(cleanup_fd4);
    }

    // Clean up IPv6 port
    struct sockaddr_in6 addr6;
    int cleanup_fd6 = socket(AF_INET6, SOCK_STREAM, 0);
    if (cleanup_fd6 != -1) {
        int reuse = 1;
        setsockopt(cleanup_fd6, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse));
        setsockopt(cleanup_fd6, IPPROTO_IPV6, IPV6_V6ONLY, &reuse, sizeof(reuse));
        memset(&addr6, 0, sizeof(addr6));
        addr6.sin6_family = AF_INET6;
        addr6.sin6_port = htons(atoi(DEFAULT_PORT) + 1);
        addr6.sin6_addr = in6addr_any;
        bind(cleanup_fd6, (struct sockaddr*)&addr6, sizeof(addr6));
        close(cleanup_fd6);
    }
}

void cleanup_server(void) {
    // Close sockets
    if (server_sockets[0] != -1) {
        close(server_sockets[0]);
        server_sockets[0] = -1;
    }
    if (server_sockets[1] != -1) {
        close(server_sockets[1]);
        server_sockets[1] = -1;
    }
    
    // Remove PID file
    unlink(PID_FILE);
    
    // Force cleanup ports
    force_cleanup_ports();
}

void signal_handler(int signum) {
    (void)signum;
    running = false;
    cleanup_server();
    exit(0);
}

int check_server_running(void) {
    int pid_fd = open(PID_FILE, O_RDONLY);
    if (pid_fd != -1) {
        pid_t pid;
        if (read(pid_fd, &pid, sizeof(pid)) == sizeof(pid)) {
            if (kill(pid, 0) == 0) {
                close(pid_fd);
                return 1; // Server is running
            }
        }
        close(pid_fd);
        unlink(PID_FILE); // Clean up stale PID file
    }
    return 0;
}

int create_pid_file(void) {
    int pid_fd = open(PID_FILE, O_CREAT | O_RDWR, 0644);
    if (pid_fd == -1) return -1;
    
    if (flock(pid_fd, LOCK_EX | LOCK_NB) == -1) {
        close(pid_fd);
        return -1;
    }
    
    pid_t pid = getpid();
    if (write(pid_fd, &pid, sizeof(pid)) != sizeof(pid)) {
        close(pid_fd);
        return -1;
    }
    
    return pid_fd;
}

void print_usage(const char* program_name) {
    printf("Usage: %s [-s|-c|-d] [-h host] [-p port] [-o offset]\n", program_name);
    printf("Options:\n");
    printf("  -s         Run as server\n");
    printf("  -c         Run as client\n");
    printf("  -d         Run in dual mode (both server and client)\n");
    printf("  -h host    Host address (default: %s)\n", DEFAULT_IPV4_HOST);
    printf("  -p port    Base port number (default: %s)\n", DEFAULT_PORT);
    printf("  -o offset  Port offset for IPv6 (default: 1)\n");
}

int parse_arguments(int argc, char* argv[], nexus_app_config_t* config) {
    static struct option long_options[] = {
        {"server", no_argument, 0, 's'},
        {"client", no_argument, 0, 'c'},
        {"dual-mode", no_argument, 0, 'd'},
        {"host", required_argument, 0, 'h'},
        {"port", required_argument, 0, 'p'},
        {"port-offset", required_argument, 0, 'o'},
        {0, 0, 0, 0}
    };

    // Set defaults - dual mode by default
    config->is_server = true;
    config->is_client = true;  // Add this field to nexus_app_config_t
    strncpy(config->host, DEFAULT_IPV4_HOST, sizeof(config->host));
    strncpy(config->port, DEFAULT_PORT, sizeof(config->port));
    config->port_offset = 1;

    int opt;
    int option_index = 0;
    while ((opt = getopt_long(argc, argv, "scdh:p:o:", long_options, &option_index)) != -1) {
        switch (opt) {
            case 's':
                config->is_server = true;
                config->is_client = false;  // Server only mode
                break;
            case 'c':
                config->is_server = false;
                config->is_client = true;   // Client only mode
                break;
            case 'd':
                config->is_server = true;
                config->is_client = true;   // Explicitly set dual mode
                break;
            case 'h':
                strncpy(config->host, optarg, sizeof(config->host) - 1);
                break;
            case 'p':
                strncpy(config->port, optarg, sizeof(config->port) - 1);
                break;
            case 'o':
                config->port_offset = atoi(optarg);
                break;
            default:
                return -1;
        }
    }
    
    return 0;
}

int initialize_socket_v4(nexus_app_config_t* config) {
    struct sockaddr_in addr;
    int fd;

    fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd == -1) {
        perror("socket v4");
        return -1;
    }

    int yes = 1;
    if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes)) == -1) {
        perror("setsockopt");
        close(fd);
        return -1;
    }

    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(atoi(config->port));
    addr.sin_addr.s_addr = INADDR_ANY;

    if (bind(fd, (struct sockaddr*)&addr, sizeof(addr)) == -1) {
        perror("bind v4");
        close(fd);
        return -1;
    }

    // Set non-blocking
    fcntl(fd, F_SETFL, O_NONBLOCK);

    config->ipv4_fd = fd;
    return 0;
}

int initialize_socket_v6(nexus_app_config_t* config) {
    struct sockaddr_in6 addr;
    int fd;

    fd = socket(AF_INET6, SOCK_STREAM, 0);
    if (fd == -1) {
        perror("socket v6");
        return -1;
    }

    int yes = 1;
    if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes)) == -1 ||
        setsockopt(fd, IPPROTO_IPV6, IPV6_V6ONLY, &yes, sizeof(yes)) == -1) {
        perror("setsockopt");
        close(fd);
        return -1;
    }

    memset(&addr, 0, sizeof(addr));
    addr.sin6_family = AF_INET6;
    addr.sin6_port = htons(atoi(config->port) + config->port_offset);  // Use offset port
    addr.sin6_addr = in6addr_any;

    if (bind(fd, (struct sockaddr*)&addr, sizeof(addr)) == -1) {
        perror("bind v6");
        close(fd);
        return -1;
    }

    if (listen(fd, BACKLOG) == -1) {
        perror("listen v6");
        close(fd);
        return -1;
    }

    config->ipv6_fd = fd;
    return 0;
}

int add_to_epoll(nexus_app_config_t* config, int fd, uint32_t events) {
    struct epoll_event ev;
    ev.events = events;
    ev.data.fd = fd;
    return epoll_ctl(config->epoll_fd, EPOLL_CTL_ADD, fd, &ev);
}

connection_t* create_connection(int fd, connection_type_t type) {
    connection_t* conn = calloc(1, sizeof(connection_t));
    if (!conn) return NULL;
    
    conn->fd = fd;
    conn->type = type;
    conn->upgraded_to_v6 = false;
    fcntl(fd, F_SETFL, O_NONBLOCK);
    
    return conn;
}

void handle_rest_request(connection_t* conn) {
    (void)conn;    // Silence unused parameter warning
    // TODO: Implement REST request handling
}

void handle_stream_data(connection_t* conn) {
    (void)conn;    // Silence unused parameter warning
    // TODO: Implement stream data handling
}

void handle_tunnel_data(connection_t* conn) {
    (void)conn;    // Silence unused parameter warning
    // TODO: Implement tunnel data handling
}

void upgrade_to_v6(connection_t* conn) {
    // Implement protocol upgrade to IPv6
    // TODO: Implement IPv6 upgrade protocol
    conn->upgraded_to_v6 = true;
}

void handle_new_connection(nexus_app_config_t* config, int server_fd) {
    struct sockaddr_storage client_addr;
    socklen_t addr_len = sizeof(client_addr);
    
    int client_fd = accept(server_fd, (struct sockaddr*)&client_addr, &addr_len);
    if (client_fd == -1) {
        if (errno != EAGAIN && errno != EWOULDBLOCK) {
            perror("accept");
        }
        return;
    }

    // Determine initial connection type (assume REST for initial connection)
    connection_t* conn = create_connection(client_fd, CONN_TYPE_REST);
    if (!conn) {
        close(client_fd);
        return;
    }

    // Add to epoll
    if (add_to_epoll(config, client_fd, EPOLLIN | EPOLLET) == -1) {
        free(conn);
        close(client_fd);
        return;
    }

    // Store connection
    pthread_mutex_lock(&config->conn_mutex);
    for (int i = 0; i < MAX_CONNECTIONS; i++) {
        if (config->connections[i] == NULL) {
            config->connections[i] = conn;
            break;
        }
    }
    pthread_mutex_unlock(&config->conn_mutex);
}

void handle_connection_data(nexus_app_config_t* config, int fd, uint32_t events) {
    (void)events;  // Silence unused parameter warning
    
    connection_t* conn = NULL;
    pthread_mutex_lock(&config->conn_mutex);
    for (int i = 0; i < MAX_CONNECTIONS; i++) {
        if (config->connections[i] && config->connections[i]->fd == fd) {
            conn = config->connections[i];
            break;
        }
    }
    pthread_mutex_unlock(&config->conn_mutex);
    
    if (!conn) {
        return;
    }
    
    // Read data from connection
    ssize_t bytes_read = read(fd, conn->buffer + conn->buffer_used, 
                             BUFFER_SIZE - conn->buffer_used);
    
    if (bytes_read <= 0) {
        if (bytes_read < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
            return;  // No data available, try again later
        }
        
        // Connection closed or error
        close_connection(config, fd);
        return;
    }
    
    conn->buffer_used += bytes_read;
    
    // Process data based on connection type
    switch (conn->type) {
        case CONN_TYPE_REST:
            handle_rest_request(conn);
            break;
        case CONN_TYPE_STREAM:
            handle_stream_data(conn);
            break;
        case CONN_TYPE_TUNNEL:
            handle_tunnel_data(conn);
            break;
    }
    
    // Check if connection should be upgraded to IPv6
    if (!conn->upgraded_to_v6 && should_upgrade_to_v6(conn)) {
        upgrade_to_v6(conn);
    }
}

void close_connection(nexus_app_config_t* config, int fd) {
    pthread_mutex_lock(&config->conn_mutex);
    for (int i = 0; i < MAX_CONNECTIONS; i++) {
        if (config->connections[i] && config->connections[i]->fd == fd) {
            close(fd);
            free(config->connections[i]);
            config->connections[i] = NULL;
            break;
        }
    }
    pthread_mutex_unlock(&config->conn_mutex);
}

bool should_upgrade_to_v6(connection_t* conn) {
    // Check if the connection data contains an upgrade request
    // This is a simplified check - in a real implementation, you would
    // parse the protocol headers properly
    if (conn->buffer_used >= 8) {
        return memcmp(conn->buffer, "UPGRADE6", 8) == 0;
    }
    return false;
}

bool add_dns_record(dns_registry_t* registry, const char* zone_name, dns_record_t* record) {
    pthread_mutex_lock(&registry->dns_mutex);
    
    // Find the zone
    dns_zone_t* zone = NULL;
    for (size_t i = 0; i < registry->zone_count; i++) {
        if (strcmp(registry->zones[i].zone_name, zone_name) == 0) {
            zone = &registry->zones[i];
            break;
        }
    }
    
    if (!zone) {
        pthread_mutex_unlock(&registry->dns_mutex);
        return false;
    }
    
    // Check if we need to resize
    if (zone->record_count >= zone->record_capacity) {
        dns_record_t* new_records = realloc(zone->records, 
                                     sizeof(dns_record_t) * zone->record_capacity * 2);
        if (!new_records) {
            pthread_mutex_unlock(&registry->dns_mutex);
            return false;
        }
        
        zone->records = new_records;
        zone->record_capacity *= 2;
    }
    
    // Add record to zone
    zone->records[zone->record_count++] = *record;
    
    pthread_mutex_unlock(&registry->dns_mutex);
    return true;
}

dns_record_t* query_dns_record(dns_registry_t* registry, const char* name, uint16_t type) {
    pthread_mutex_lock(&registry->dns_mutex);
    
    // Find the most specific zone for the query
    dns_zone_t* best_zone = NULL;
    size_t best_match_len = 0;
    
    for (size_t i = 0; i < registry->zone_count; i++) {
        dns_zone_t* zone = &registry->zones[i];
        const char* zone_name = zone->zone_name;
        size_t zone_name_len = strlen(zone_name);
        
        // Check if query name ends with this zone
        size_t name_len = strlen(name);
        if (name_len >= zone_name_len) {
            const char* suffix = name + name_len - zone_name_len;
            if (strcmp(suffix, zone_name) == 0) {
                if (zone_name_len > best_match_len) {
                    best_zone = zone;
                    best_match_len = zone_name_len;
                }
            }
        }
    }
    
    if (!best_zone) {
        pthread_mutex_unlock(&registry->dns_mutex);
        return NULL;
    }
    
    // Search for matching records in the zone
    dns_record_t* result = NULL;
    
    for (size_t i = 0; i < best_zone->record_count; i++) {
        dns_record_t* record = &best_zone->records[i];
        
        if (strcmp(record->name, name) == 0 && record->type == type) {
            result = record;
            break;
        }
    }
    
    pthread_mutex_unlock(&registry->dns_mutex);
    return result;
}

void handle_dns_query(int fd, dns_registry_t* registry) {
    struct sockaddr_in client_addr;
    socklen_t addr_len = sizeof(client_addr);
    uint8_t buffer[BUFFER_SIZE];
    
    ssize_t received = recvfrom(fd, buffer, BUFFER_SIZE, 0,
                               (struct sockaddr*)&client_addr, &addr_len);
    
    if (received <= 0) {
        return;
    }
    
    // In a real implementation, this would parse the DNS query format
    // For simplicity, we'll assume a basic format: name|type
    char query_name[256];
    uint16_t query_type;
    
    if (sscanf((char*)buffer, "%255[^|]|%hu", query_name, &query_type) == 2) {
        dns_record_t* record = query_dns_record(registry, query_name, query_type);
        
        if (record) {
            // Send back the record data
            sendto(fd, record->data, record->data_len, 0,
                   (struct sockaddr*)&client_addr, addr_len);
        } else {
            // No record found, send empty response
            sendto(fd, "", 0, 0, (struct sockaddr*)&client_addr, addr_len);
        }
    }
}

int run_server(nexus_app_config_t* config) {
    // Initialize nexus context
    config->ctx = malloc(sizeof(nexus_context_t));
    if (!config->ctx) {
        fprintf(stderr, "Failed to allocate nexus context\n");
        return -1;
    }
    memset(config->ctx, 0, sizeof(nexus_context_t));
    config->ctx->protocol_version = NEXUS_VERSION;
    
    // Create IPv4 socket
    if (initialize_socket_v4(config) != 0) {
        fprintf(stderr, "Failed to initialize IPv4 socket\n");
        free(config->ctx);
        return -1;
    }
    
    // Create IPv6 socket
    if (initialize_socket_v6(config) != 0) {
        fprintf(stderr, "Failed to initialize IPv6 socket\n");
        close(config->ipv4_fd);
        free(config->ctx);
        return -1;
    }
    
    // Store socket FDs globally for cleanup
    server_sockets[0] = config->ipv4_fd;
    server_sockets[1] = config->ipv6_fd;
    
    // Start listening on IPv4
    if (listen(config->ipv4_fd, BACKLOG) == -1) {
        perror("listen v4");
        cleanup_server();
        free(config->ctx);
        return -1;
    }
    
    // Create epoll instance
    config->epoll_fd = epoll_create1(0);
    if (config->epoll_fd == -1) {
        perror("epoll_create1");
        cleanup_server();
        free(config->ctx);
        return -1;
    }
    
    // Add server sockets to epoll
    if (add_to_epoll(config, config->ipv4_fd, EPOLLIN) == -1 ||
        add_to_epoll(config, config->ipv6_fd, EPOLLIN) == -1) {
        perror("epoll_ctl");
        close(config->epoll_fd);
        cleanup_server();
        free(config->ctx);
        return -1;
    }
    
    // Initialize connection mutex
    pthread_mutex_init(&config->conn_mutex, NULL);
    
    // Create default networks
    nexus_network_id_t public_net_id = {0};
    memcpy(public_net_id.id, "public_network", 14);
    public_net_id.type = NEXUS_NET_PUBLIC;
    
    nexus_network_id_t private_net_id = {0};
    memcpy(private_net_id.id, "private_network", 15);
    private_net_id.type = NEXUS_NET_PRIVATE;
    
    nexus_create_isolated_network(config->ctx, &public_net_id, NEXUS_NET_PUBLIC, NULL, 0);
    nexus_create_isolated_network(config->ctx, &private_net_id, NEXUS_NET_PRIVATE, NULL, 0);
    
    // Bridge the networks
    nexus_resource_permission_t perm = {0};
    perm.resource_type = NEXUS_RESOURCE_BANDWIDTH;
    perm.permissions = 0xFF;
    nexus_create_bridge(config->ctx, &public_net_id, &private_net_id, &perm);
    
    // Initialize DNS service
    dns_registry_t dns_registry;
    dns_registry.zones = malloc(sizeof(dns_zone_t) * 10);
    if (!dns_registry.zones) {
        fprintf(stderr, "Failed to allocate DNS zones\n");
        close(config->epoll_fd);
        cleanup_server();
        free(config->ctx);
        return -1;
    }
    dns_registry.zone_count = 0;
    pthread_mutex_init(&dns_registry.dns_mutex, NULL);

    // Create root zone
    dns_zone_t root_zone;
    memset(&root_zone, 0, sizeof(dns_zone_t));
    strncpy(root_zone.zone_name, ".", sizeof(root_zone.zone_name));
    root_zone.network_id = public_net_id;
    root_zone.is_authoritative = true;
    root_zone.records = malloc(sizeof(dns_record_t) * 100);
    if (!root_zone.records) {
        free(dns_registry.zones);
        close(config->epoll_fd);
        cleanup_server();
        free(config->ctx);
        return -1;
    }
    root_zone.record_count = 0;
    root_zone.record_capacity = 100;

    // Add root zone to registry
    dns_registry.zones[0] = root_zone;
    dns_registry.zone_count = 1;

    // Create UDP socket for DNS service
    int dns_sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (dns_sock == -1) {
        perror("DNS socket creation failed");
    } else {
        struct sockaddr_in dns_addr;
        memset(&dns_addr, 0, sizeof(dns_addr));
        dns_addr.sin_family = AF_INET;
        dns_addr.sin_addr.s_addr = htonl(INADDR_ANY);
        dns_addr.sin_port = htons(53);
        
        if (bind(dns_sock, (struct sockaddr*)&dns_addr, sizeof(dns_addr)) == 0) {
            // Add DNS socket to epoll
            if (add_to_epoll(config, dns_sock, EPOLLIN) == 0) {
                printf("DNS service running on port 53\n");
            } else {
                close(dns_sock);
            }
        } else {
            perror("DNS bind failed");
            close(dns_sock);
        }
    }
    
    printf("Server running on port %s (IPv4) and port %s (IPv6)\n", 
           config->port, config->port);
    
    // Event loop
    struct epoll_event events[MAX_EVENTS];
    while (running) {
        int nfds = epoll_wait(config->epoll_fd, events, MAX_EVENTS, -1);
        if (nfds == -1) {
            if (errno == EINTR) {
                continue;  // Interrupted by signal, continue
            }
            perror("epoll_wait");
            break;
        }
        
        for (int i = 0; i < nfds; i++) {
            if (events[i].data.fd == config->ipv4_fd || 
                events[i].data.fd == config->ipv6_fd) {
                // New connection
                handle_new_connection(config, events[i].data.fd);
            } else if (events[i].data.fd == dns_sock) {
                // Handle DNS query
                handle_dns_query(events[i].data.fd, &dns_registry);
            } else {
                // Data on existing connection
                handle_connection_data(config, events[i].data.fd, events[i].events);
            }
        }
    }
    
    // Cleanup
    pthread_mutex_destroy(&config->conn_mutex);
    close(config->epoll_fd);
    cleanup_server();
    
    // Clean up nexus context
    for (int i = 0; i < config->ctx->network_count; i++) {
        nexus_network_id_t* net_id = &config->ctx->networks[i].id;
        nexus_destroy_network(config->ctx, net_id);
    }
    free(config->ctx);
    
    // Clean up DNS resources
    for (size_t i = 0; i < dns_registry.zone_count; i++) {
        free(dns_registry.zones[i].records);
    }
    free(dns_registry.zones);
    pthread_mutex_destroy(&dns_registry.dns_mutex);
    
    return 0;
}

int run_client(nexus_app_config_t* config) {
    printf("Starting NEXUS client, connecting to [%s]:%s\n", config->host, config->port);

    // Create P2P network
    nexus_network_id_t network_id = {0};
    if (nexus_create_ephemeral_p2p(config->ctx, NULL, 3600, &network_id) != 0) {
        fprintf(stderr, "Failed to create P2P network\n");
        return -1;
    }

    while (running) {
        // TODO: Implement client communication logic
        sleep(1);
    }

    printf("Client shutting down...\n");
    return 0;
}

int initialize_nexus(nexus_app_config_t* config) {
    config->ctx = (nexus_context_t*)malloc(sizeof(nexus_context_t));
    if (!config->ctx) {
        fprintf(stderr, "Failed to allocate context\n");
        return -1;
    }

    memset(config->ctx, 0, sizeof(nexus_context_t));
    config->ctx->protocol_version = NEXUS_VERSION;
    config->ctx->network_count = 0;
    config->ctx->bridge_count = 0;

    return initialize_socket_v4(config) != 0 || initialize_socket_v6(config) != 0 ? -1 : 0;
}

// Add this function to run server in a separate thread
void* server_thread(void* arg) {
    nexus_app_config_t* config = (nexus_app_config_t*)arg;
    run_server(config);
    return NULL;
}

// Add this function to run in dual mode
int run_dual_mode(nexus_app_config_t* config) {
    // Create a copy of the config for the client
    nexus_app_config_t client_config = *config;
    client_config.is_server = false;
    client_config.is_client = true;
    
    // Start server in a separate thread
    pthread_t server_tid;
    if (pthread_create(&server_tid, NULL, server_thread, config) != 0) {
        perror("Failed to create server thread");
        return -1;
    }
    
    // Give the server a moment to start
    sleep(1);
    
    // Run client in main thread
    run_client(&client_config);
    
    // Wait for server thread to finish
    pthread_join(server_tid, NULL);
    
    return 0;
}

int main(int argc, char* argv[]) {
    // Set up signal handlers
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);
    
    // Parse command line arguments
    nexus_app_config_t config = {0};
    if (parse_arguments(argc, argv, &config) != 0) {
        print_usage(argv[0]);
        return 1;
    }
    
    // Initialize Nexus context
    if (initialize_nexus(&config) != 0) {
        fprintf(stderr, "Failed to initialize Nexus\n");
        return 1;
    }
    
    // Run server, client, or dual mode
    int result;
    if (config.is_server && config.is_client) {
        // Dual mode - run both server and client
        result = run_dual_mode(&config);
    } else if (config.is_server) {
        // Server only mode
        // Check if server is already running
        if (check_server_running()) {
            fprintf(stderr, "Server is already running\n");
            free(config.ctx);
            return 1;
        }
        
        // Create PID file
        int pid_fd = create_pid_file();
        if (pid_fd == -1) {
            fprintf(stderr, "Failed to create PID file\n");
            free(config.ctx);
            return 1;
        }
        
        // Run the server
        result = run_server(&config);
        
        // Clean up PID file after server stops
        close(pid_fd);
        unlink(PID_FILE);
    } else {
        // Client only mode
        result = run_client(&config);
    }
    
    return result;
}

