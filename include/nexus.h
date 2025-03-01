#ifndef NEXUS_PROTOCOL_H
#define NEXUS_PROTOCOL_H

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
/* Protocol constants */
#define NEXUS_VERSION          1
#define NEXUS_HEADER_SIZE     160        // Increased to accommodate network context
#define NEXUS_MAX_PACKET_SIZE 65535      // Maximum packet size 
#define NEXUS_TOKEN_SIZE      32         // Quantum secure token size to identify packet 
#define NEXUS_HASH_SIZE       32         // Quantum secure hash size to validate packet integrity
#define NEXUS_NET_ID_SIZE     16         // Network unique identifier size
#define NEXUS_MAX_NETWORKS    8          // Maximum simultaneous networks
#define NEXUS_MAX_RESOURCES   16         // Maximum resources that can be shared
#define NEXUS_CONNECTION_ID_SIZE 16      // Connection unique identifier size
#define NEXUS_MAX_BRIDGES     4

/* Network types */
typedef enum {
    NEXUS_NET_PUBLIC     = 0x01,  // Global public network
    NEXUS_NET_PRIVATE    = 0x02,  // Isolated private network
    NEXUS_NET_P2P        = 0x03,  // Ephemeral peer connection
    NEXUS_NET_COMPUTE    = 0x04,  // Compute resource network
    NEXUS_NET_STORAGE    = 0x05   // Storage resource network
} nexus_network_type_t;

/* Resource types that can be shared */
typedef enum {
    NEXUS_RESOURCE_COMPUTE   = 0x01,
    NEXUS_RESOURCE_STORAGE   = 0x02,
    NEXUS_RESOURCE_BANDWIDTH = 0x03,
    NEXUS_RESOURCE_SERVICE   = 0x04,
    NEXUS_RESOURCE_DATA      = 0x05
} nexus_resource_type_t;

/* nexus_hash_t uses quantum secure hash function */
typedef struct {
    uint8_t  hash[NEXUS_HASH_SIZE];
} nexus_hash_t;

/* nexus_token_t uses quantum secure token function */
typedef struct {
    uint8_t  token[NEXUS_TOKEN_SIZE];
} nexus_token_t;

/* Resource sharing permissions */
typedef struct {
    uint8_t  resource_type;
    uint8_t  permissions;    // Read/Write/Execute flags
    uint16_t quota;         // Resource usage limits
    uint32_t expiry;        // Time-based expiration
    nexus_hash_t auth_hash; // Resource access authorization
} __attribute__((packed)) nexus_resource_permission_t;

/* Network identifier */
typedef struct {
    uint8_t  id[NEXUS_NET_ID_SIZE];  // Network unique identifier
    uint8_t  type;                    // Network type
    uint8_t  flags;                   // Network-specific flags
    uint16_t reserved;
} __attribute__((packed)) nexus_network_id_t;

/* Network context flags */
typedef enum {
    NEXUS_NET_FLAG_BRIDGING    = 0x01,  // Allow bridging to other networks
    NEXUS_NET_FLAG_ISOLATED    = 0x02,  // Prevent external communication
    NEXUS_NET_FLAG_ENCRYPTED   = 0x04,  // Network requires encryption
    NEXUS_NET_FLAG_VALIDATED   = 0x08,  // Network membership validated
    NEXUS_NET_FLAG_METERED     = 0x10   // Network has usage constraints
} nexus_network_flags_t;

/* Per-network state */
typedef enum {
    NEXUS_NET_STATE_ACTIVE    = 0x01,       // Network is active
    NEXUS_NET_STATE_UNAVAILABLE = 0x02,     // Network has timed out
    NEXUS_NET_STATE_SUSPENDED = 0x04,       // Network connection has been terminated by the client
    NEXUS_NET_STATE_RETIRED   = 0x08,       // Network connection has been decommissioned due to inactivity
    NEXUS_NET_STATE_REVOKED = 0x10,         // Network connection has been revoked by the server
    NEXUS_NET_STATE_BLACKLISTED = 0x20      // Network connection has been blacklisted by the network
} nexus_network_state_t;

typedef struct {
    uint8_t  x;
    uint8_t  y;
    uint8_t  z;
} nexus_matrix_pos_t;

typedef struct {
    nexus_network_id_t id;
    uint8_t  type;
    uint8_t  state;          // Active, Suspended, etc.
    uint16_t flags;
    nexus_matrix_pos_t position;
    void*    security_ctx;   // Network-specific security
    void*    crypto_ctx;     // Network-specific crypto
    
    // Resource sharing
    nexus_resource_permission_t resources[NEXUS_MAX_RESOURCES];
    uint8_t resource_count;
    
    // Network-specific routing
    void*    routing_table;
    uint32_t metric;
    
    // Ephemeral properties
    uint32_t lifetime;       // For P2P/temporary networks
    uint32_t last_active;    // Last activity timestamp
} nexus_network_context_t;

/* nexus_connection_id_t */
typedef struct {
    uint8_t  id[NEXUS_CONNECTION_ID_SIZE];  // Connection unique identifier - IPv6 address
    uint8_t  type;                    // Connection type
    uint8_t  flags;                   // Connection-specific flags
    uint16_t reserved;
} __attribute__((packed)) nexus_connection_id_t;

/* nexus_header_t */
typedef struct {
    /* Basic header fields from before */
    uint8_t  version;
    uint8_t  type;
    uint16_t flags;
    uint32_t sequence;
    uint32_t ack;
    uint16_t length;
    uint16_t checksum;
    
    /* Network context */
    nexus_network_id_t source_network;   // Source network identifier
    nexus_network_id_t target_network;   // Target network identifier (if different)
    uint8_t  bridge_flags;               // Inter-network routing flags
    uint8_t  reserved;
    
    /* Identity and routing */
    nexus_connection_id_t connection_id;
    nexus_matrix_pos_t source_pos;
    nexus_matrix_pos_t target_pos;
    uint16_t matrix_flags;
    
    /* Security and verification */
    nexus_token_t token;
    nexus_hash_t hash;
    
    /* Timing and control */
    uint64_t timestamp;
    uint8_t  hop_limit;
    uint8_t  priority;
    uint16_t reserved2;
} __attribute__((packed)) nexus_header_t;

/* Network discovery */
typedef struct {
    nexus_network_id_t network;
    uint8_t  strength;          // Signal/connection strength
    uint16_t latency;          // Network latency
    uint32_t capabilities;      // Network capabilities
} nexus_network_info_t;

/* Network selection policy */
typedef struct {
    uint32_t flags;            // Policy control flags
    uint32_t priority;         // Network priority
    uint32_t max_latency;      // Maximum acceptable latency
    uint32_t min_strength;     // Minimum signal strength
    void*    custom_criteria;  // Implementation-specific criteria
} nexus_network_policy_t;

/* Bridge between networks */
typedef struct {
    nexus_network_id_t network1;
    nexus_network_id_t network2;
    nexus_resource_permission_t permissions;
    uint32_t flags;
    uint32_t expiry;
    nexus_token_t bridge_token;
} nexus_bridge_t;

/* nexus_context_t structure */
typedef struct {
    uint32_t protocol_version;
    uint32_t flags;
    nexus_network_context_t networks[NEXUS_MAX_NETWORKS];
    uint8_t network_count;
    nexus_bridge_t bridges[NEXUS_MAX_BRIDGES];
    uint8_t bridge_count;
    void* cert_context;
} nexus_context_t;

/* Network management functions */
int nexus_join_network(nexus_context_t* ctx, 
                      const nexus_network_id_t* network,
                      const void* credentials, 
                      size_t cred_len);
int nexus_leave_network(nexus_context_t* ctx, 
                       const nexus_network_id_t* network);
int nexus_bridge_networks(nexus_context_t* ctx, 
                         const nexus_network_id_t* network1,
                         const nexus_network_id_t* network2,
                         uint32_t bridge_flags);

/* Inter-network routing */
int nexus_route_between_networks(nexus_context_t* ctx,
                               const nexus_network_id_t* source_net,
                               const nexus_network_id_t* target_net,
                               const void* payload, 
                               size_t payload_len);

/* Network discovery */
int nexus_discover_networks(nexus_context_t* ctx, 
                          nexus_network_info_t* networks,
                          size_t* count);

/* Per-network position management */
int nexus_update_network_position(nexus_context_t* ctx,
                                const nexus_network_id_t* network,
                                const nexus_matrix_pos_t* pos);

int nexus_set_network_policy(nexus_context_t* ctx,
                           const nexus_network_id_t* network,
                           const nexus_network_policy_t* policy);

int nexus_create_isolated_network(nexus_context_t* ctx, 
                                const nexus_network_id_t* network,
                                uint8_t type,
                                const void* config,
                                size_t config_len);

int nexus_destroy_network(nexus_context_t* ctx,
                         const nexus_network_id_t* network);

int nexus_share_resource(nexus_context_t* ctx,
                        const nexus_network_id_t* source,
                        const nexus_network_id_t* target,
                        const nexus_resource_permission_t* permission);

int nexus_revoke_resource(nexus_context_t* ctx,
                         const nexus_network_id_t* source,
                         const nexus_network_id_t* target,
                         uint8_t resource_type);

int nexus_create_bridge(nexus_context_t* ctx,
                       const nexus_network_id_t* network1,
                       const nexus_network_id_t* network2,
                       const nexus_resource_permission_t* permissions);

int nexus_destroy_bridge(nexus_context_t* ctx,
                        const nexus_bridge_t* bridge);

int nexus_send_isolated(nexus_context_t* ctx,
                       const nexus_network_id_t* network,
                       const void* payload,
                       size_t payload_len);

int nexus_send_bridged(nexus_context_t* ctx,
                      const nexus_bridge_t* bridge,
                      const void* payload,
                      size_t payload_len);

int nexus_create_ephemeral_p2p(nexus_context_t* ctx,
                              const void* peer_info,
                              uint32_t lifetime,
                              nexus_network_id_t* network_id);

#endif /* NEXUS_PROTOCOL_H */