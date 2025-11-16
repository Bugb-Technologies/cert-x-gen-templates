/*
 * CERT-X-GEN Redis Unauthenticated Access Detection
 * 
 * Template Metadata:
 *   ID: redis-unauthenticated
 *   Name: Redis Unauthenticated Access Detection
 *   Author: CERT-X-GEN Team
 *   Severity: high
 *   Tags: redis,database,unauthenticated,network
 *   Language: c
 *   CWE: CWE-306
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>

// Template configuration
typedef struct {
    char id[256];
    char name[256];
    char author[256];
    char severity[32];
    int confidence;
    char tags[512];
    char cwe[32];
} TemplateConfig;

// Finding structure
typedef struct {
    char template_id[256];
    char severity[32];
    int confidence;
    char title[512];
    char description[1024];
    char evidence[2048];
    char cwe[32];
    float cvss_score;
    char remediation[1024];
    char references[1024];
} Finding;

// Global variables
static TemplateConfig config;
static char target_host[256] = {0};
static int target_port = 6379;
static int json_output = 0;

// Redis commands to test
static const char* redis_commands[] = {
    "INFO",
    "PING",
    "CONFIG GET *",
    "KEYS *",
    "DBSIZE",
    "CLIENT LIST",
    "MONITOR",
    "FLUSHALL",
    "FLUSHDB",
    "SAVE",
    "BGSAVE",
    "LASTSAVE",
    "SHUTDOWN",
    "SLAVEOF NO ONE",
    "REPLICAOF NO ONE",
    "SLAVEOF",
    "REPLICAOF",
    "SYNC",
    "PSYNC",
    "REPLCONF",
    "AUTH",
    "QUIT",
    "SELECT",
    "ECHO",
    "TIME",
    "ROLE",
    "MEMORY USAGE",
    "MEMORY STATS",
    "MEMORY DOCTOR",
    "MEMORY PURGE",
    "MEMORY MALLOC-STATS",
    "MEMORY USAGE",
    "MEMORY STATS",
    "MEMORY DOCTOR",
    "MEMORY PURGE",
    "MEMORY MALLOC-STATS",
    NULL
};

// Connect to Redis server
int connect_redis(const char* host, int port) {
    int sockfd;
    struct sockaddr_in server_addr;
    struct hostent* server;
    
    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) {
        return -1;
    }
    
    server = gethostbyname(host);
    if (server == NULL) {
        close(sockfd);
        return -1;
    }
    
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(port);
    memcpy(&server_addr.sin_addr.s_addr, server->h_addr, server->h_length);
    
    if (connect(sockfd, (struct sockaddr*)&server_addr, sizeof(server_addr)) < 0) {
        close(sockfd);
        return -1;
    }
    
    return sockfd;
}

// Send Redis command
int send_redis_command(int sockfd, const char* command) {
    char buffer[1024];
    snprintf(buffer, sizeof(buffer), "*1\r\n$%zu\r\n%s\r\n", strlen(command), command);
    
    if (send(sockfd, buffer, strlen(buffer), 0) < 0) {
        return -1;
    }
    
    return 0;
}

// Receive Redis response
int receive_redis_response(int sockfd, char* buffer, size_t buffer_size) {
    ssize_t bytes_received = recv(sockfd, buffer, buffer_size - 1, 0);
    if (bytes_received < 0) {
        return -1;
    }
    
    buffer[bytes_received] = '\0';
    return bytes_received;
}

// Test Redis command
int test_redis_command(const char* host, int port, const char* command) {
    int sockfd = connect_redis(host, port);
    if (sockfd < 0) {
        return 0;
    }
    
    char response[4096];
    int result = 0;
    
    if (send_redis_command(sockfd, command) == 0) {
        if (receive_redis_response(sockfd, response, sizeof(response)) > 0) {
            // Check for successful response (not error)
            if (response[0] != '-' && response[0] != 'E') {
                result = 1;
            }
        }
    }
    
    close(sockfd);
    return result;
}

// Test Redis authentication
int test_redis_auth(const char* host, int port) {
    int sockfd = connect_redis(host, port);
    if (sockfd < 0) {
        return 0;
    }
    
    char response[4096];
    int result = 0;
    
    // Try to run INFO command without auth
    if (send_redis_command(sockfd, "INFO") == 0) {
        if (receive_redis_response(sockfd, response, sizeof(response)) > 0) {
            // If we get a successful response, Redis is unauthenticated
            if (response[0] != '-' && response[0] != 'E') {
                result = 1;
            }
        }
    }
    
    close(sockfd);
    return result;
}

// Create a finding
void create_finding(Finding* finding, const char* title, const char* description, 
                   const char* evidence, const char* severity) {
    strncpy(finding->template_id, config.id, sizeof(finding->template_id) - 1);
    strncpy(finding->severity, severity ? severity : config.severity, sizeof(finding->severity) - 1);
    finding->confidence = config.confidence;
    strncpy(finding->title, title, sizeof(finding->title) - 1);
    strncpy(finding->description, description, sizeof(finding->description) - 1);
    strncpy(finding->evidence, evidence, sizeof(finding->evidence) - 1);
    strncpy(finding->cwe, config.cwe, sizeof(finding->cwe) - 1);
    
    // Calculate CVSS score
    if (strcmp(finding->severity, "critical") == 0) {
        finding->cvss_score = 9.0;
    } else if (strcmp(finding->severity, "high") == 0) {
        finding->cvss_score = 7.5;
    } else if (strcmp(finding->severity, "medium") == 0) {
        finding->cvss_score = 5.0;
    } else if (strcmp(finding->severity, "low") == 0) {
        finding->cvss_score = 3.0;
    } else {
        finding->cvss_score = 0.0;
    }
    
    strncpy(finding->remediation, "Enable Redis authentication using the 'requirepass' directive in redis.conf", 
            sizeof(finding->remediation) - 1);
    strncpy(finding->references, "https://redis.io/docs/management/security/,https://cwe.mitre.org/data/definitions/306.html", 
            sizeof(finding->references) - 1);
}

// Output finding as JSON
void output_finding_json(const Finding* finding) {
    printf("  {\n");
    printf("    \"template_id\": \"%s\",\n", finding->template_id);
    printf("    \"severity\": \"%s\",\n", finding->severity);
    printf("    \"confidence\": %d,\n", finding->confidence);
    printf("    \"title\": \"%s\",\n", finding->title);
    printf("    \"description\": \"%s\",\n", finding->description);
    printf("    \"evidence\": %s,\n", finding->evidence);
    printf("    \"cwe\": \"%s\",\n", finding->cwe);
    printf("    \"cvss_score\": %.1f,\n", finding->cvss_score);
    printf("    \"remediation\": \"%s\",\n", finding->remediation);
    printf("    \"references\": [\"%s\"]\n", finding->references);
    printf("  }");
}

// Main scanning logic
int execute_scan() {
    Finding findings[64];
    int finding_count = 0;
    
    // Test Redis authentication
    if (test_redis_auth(target_host, target_port)) {
        char evidence[2048];
        char title[512];
        char description[1024];
        
        snprintf(evidence, sizeof(evidence), 
                "{\"service\": \"redis\", \"host\": \"%s\", \"port\": %d, \"status\": \"unauthenticated\", \"test_command\": \"INFO\"}", 
                target_host, target_port);
        
        snprintf(title, sizeof(title), "Redis Unauthenticated Access on %s:%d", 
                target_host, target_port);
        
        snprintf(description, sizeof(description), 
                "Redis server on %s:%d is accessible without authentication", 
                target_host, target_port);
        
        create_finding(&findings[finding_count], title, description, evidence, "high");
        finding_count++;
        
        // Test additional commands
        for (int i = 0; redis_commands[i] && finding_count < 64; i++) {
            const char* command = redis_commands[i];
            
            if (test_redis_command(target_host, target_port, command)) {
                char cmd_evidence[2048];
                char cmd_title[512];
                char cmd_description[1024];
                
                snprintf(cmd_evidence, sizeof(cmd_evidence), 
                        "{\"service\": \"redis\", \"host\": \"%s\", \"port\": %d, \"command\": \"%s\", \"status\": \"executed\"}", 
                        target_host, target_port, command);
                
                snprintf(cmd_title, sizeof(cmd_title), "Redis Command '%s' Executed on %s:%d", 
                        command, target_host, target_port);
                
                snprintf(cmd_description, sizeof(cmd_description), 
                        "Redis command '%s' was successfully executed on %s:%d without authentication", 
                        command, target_host, target_port);
                
                create_finding(&findings[finding_count], cmd_title, cmd_description, cmd_evidence, "medium");
                finding_count++;
            }
        }
    }
    
    // Output findings
    if (json_output) {
        printf("[\n");
        for (int i = 0; i < finding_count; i++) {
            if (i > 0) printf(",\n");
            output_finding_json(&findings[i]);
        }
        printf("\n]\n");
    } else {
        if (finding_count > 0) {
            printf("\n[+] Found %d Redis vulnerability(ies):\n\n", finding_count);
            for (int i = 0; i < finding_count; i++) {
                printf("[%s] %s\n", findings[i].severity, findings[i].title);
                printf("    %s\n", findings[i].description);
                printf("\n");
            }
        } else {
            printf("\n[-] No Redis vulnerabilities found\n");
        }
    }
    
    return finding_count;
}

// Get environment variable
char* get_env_var(const char* name) {
    return getenv(name);
}

// Parse arguments
int parse_args(int argc, char* argv[]) {
    // Initialize default config
    strcpy(config.id, "redis-unauthenticated");
    strcpy(config.name, "Redis Unauthenticated Access Detection");
    strcpy(config.author, "CERT-X-GEN Team");
    strcpy(config.severity, "high");
    config.confidence = 90;
    strcpy(config.tags, "redis,database,unauthenticated,network");
    strcpy(config.cwe, "CWE-306");
    
    // Parse command line arguments
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--target") == 0) {
            if (i + 1 < argc) {
                strncpy(target_host, argv[++i], sizeof(target_host) - 1);
            } else {
                fprintf(stderr, "Error: --target requires an argument\n");
                return 0;
            }
        } else if (strcmp(argv[i], "--port") == 0) {
            if (i + 1 < argc) {
                target_port = atoi(argv[++i]);
            } else {
                fprintf(stderr, "Error: --port requires an argument\n");
                return 0;
            }
        } else if (strcmp(argv[i], "--json") == 0) {
            json_output = 1;
        } else if (strcmp(argv[i], "--help") == 0 || strcmp(argv[i], "-h") == 0) {
            printf("Usage: %s [OPTIONS] <target>\n\n", argv[0]);
            printf("%s\n", config.name);
            printf("\nOptions:\n");
            printf("  --target <HOST>  Target host or IP address\n");
            printf("  --port <PORT>    Target port (default: 6379)\n");
            printf("  --json           Output findings as JSON\n");
            printf("  --help           Show this help message\n");
            exit(0);
        } else if (!target_host[0] && argv[i][0] != '-') {
            strncpy(target_host, argv[i], sizeof(target_host) - 1);
        }
    }
    
    // Check environment variables (for CERT-X-GEN engine integration)
    if (!target_host[0]) {
        char* host = get_env_var("CERT_X_GEN_TARGET_HOST");
        if (host) {
            strncpy(target_host, host, sizeof(target_host) - 1);
        }
    }
    
    char* port_str = get_env_var("CERT_X_GEN_TARGET_PORT");
    if (port_str) {
        target_port = atoi(port_str);
    }
    
    if (get_env_var("CERT_X_GEN_MODE")) {
        json_output = 1;
    }
    
    if (!target_host[0]) {
        fprintf(stderr, "Error: No target specified\n");
        return 0;
    }
    
    return 1;
}

int main(int argc, char* argv[]) {
    // Parse arguments
    if (!parse_args(argc, argv)) {
        return 1;
    }
    
    // Print banner (if not JSON output)
    if (!json_output) {
        printf("\n╔════════════════════════════════════════════════════════════╗\n");
        printf("║  %-52s ║\n", config.name);
        printf("║  CERT-X-GEN Security Template                              ║\n");
        printf("╚════════════════════════════════════════════════════════════╝\n\n");
        printf("Target: %s:%d\n", target_host, target_port);
    }
    
    // Execute the scan
    int finding_count = execute_scan();
    
    return 0;
}
