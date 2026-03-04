/*
 * @id: vnc-no-auth
 * @name: VNC No Authentication Detection
 * @author: CERT-X-GEN Security Team
 * @severity: critical
 * @description: Detects VNC servers allowing connections without authentication using RFB protocol handshake
 * @tags: vnc, remote-access, no-auth, binary-protocol, rce
 * @cwe: CWE-306
 * @cvss: 9.8
 * @references: https://tools.ietf.org/html/rfc6143, https://www.realvnc.com/en/connect/docs/security.html
 * @confidence: 100
 * @version: 1.0.0
 *
 * WHY C?
 * VNC uses the RFB (Remote Framebuffer) binary protocol. C provides:
 * - Direct byte-level manipulation for protocol parsing
 * - Struct packing for wire format handling
 * - Maximum performance for handshake operations
 * - No runtime overhead
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/select.h>

#define VNC_DEFAULT_PORT 5900
#define TIMEOUT_SECONDS 10
#define BUFFER_SIZE 256

/* VNC Security Types */
#define SEC_INVALID     0
#define SEC_NONE        1   /* No authentication required! */
#define SEC_VNC_AUTH    2   /* VNC password authentication */
#define SEC_TIGHT       16
#define SEC_ULTRA       17
#define SEC_TLS         18
#define SEC_VENCRYPT    19

/* Security type names for reporting */
const char* security_type_name(unsigned char type) {
    switch(type) {
        case SEC_INVALID:   return "Invalid";
        case SEC_NONE:      return "None (NO AUTHENTICATION)";
        case SEC_VNC_AUTH:  return "VNC Authentication";
        case SEC_TIGHT:     return "Tight";
        case SEC_ULTRA:     return "Ultra";
        case SEC_TLS:       return "TLS";
        case SEC_VENCRYPT:  return "VeNCrypt";
        default:            return "Unknown";
    }
}

/* Set socket to non-blocking with timeout */
int connect_with_timeout(int sockfd, struct sockaddr *addr, socklen_t addrlen, int timeout_sec) {
    int flags, ret;
    fd_set writefds;
    struct timeval tv;
    
    /* Set non-blocking */
    flags = fcntl(sockfd, F_GETFL, 0);
    fcntl(sockfd, F_SETFL, flags | O_NONBLOCK);
    
    ret = connect(sockfd, addr, addrlen);
    
    if (ret < 0 && errno != EINPROGRESS) {
        return -1;
    }
    
    if (ret == 0) {
        /* Connected immediately */
        fcntl(sockfd, F_SETFL, flags);
        return 0;
    }
    
    /* Wait for connection */
    FD_ZERO(&writefds);
    FD_SET(sockfd, &writefds);
    tv.tv_sec = timeout_sec;
    tv.tv_usec = 0;
    
    ret = select(sockfd + 1, NULL, &writefds, NULL, &tv);
    
    /* Restore blocking mode */
    fcntl(sockfd, F_SETFL, flags);
    
    if (ret <= 0) {
        return -1;  /* Timeout or error */
    }
    
    /* Check for connection error */
    int error;
    socklen_t len = sizeof(error);
    getsockopt(sockfd, SOL_SOCKET, SO_ERROR, &error, &len);
    
    return error ? -1 : 0;
}

/* Perform VNC handshake and detect authentication requirements */
int check_vnc_auth(const char *host, int port, char *version_out, 
                   unsigned char *sec_types_out, int *num_sec_types,
                   int *no_auth_available) {
    int sockfd;
    struct sockaddr_in server_addr;
    struct hostent *server;
    char buffer[BUFFER_SIZE];
    ssize_t bytes_read;
    
    *no_auth_available = 0;
    *num_sec_types = 0;
    
    /* Create socket */
    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) {
        return -1;
    }
    
    /* Resolve hostname */
    server = gethostbyname(host);
    if (server == NULL) {
        close(sockfd);
        return -1;
    }
    
    /* Setup server address */
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    memcpy(&server_addr.sin_addr.s_addr, server->h_addr, server->h_length);
    server_addr.sin_port = htons(port);
    
    /* Connect with timeout */
    if (connect_with_timeout(sockfd, (struct sockaddr *)&server_addr, 
                             sizeof(server_addr), TIMEOUT_SECONDS) < 0) {
        close(sockfd);
        return -1;
    }
    
    /* Set receive timeout */
    struct timeval tv;
    tv.tv_sec = TIMEOUT_SECONDS;
    tv.tv_usec = 0;
    setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    
    /* Step 1: Receive ProtocolVersion from server */
    /* Format: "RFB xxx.yyy\n" (12 bytes) */
    bytes_read = recv(sockfd, buffer, 12, 0);
    if (bytes_read != 12 || strncmp(buffer, "RFB ", 4) != 0) {
        close(sockfd);
        return -2;  /* Not VNC */
    }
    
    /* Extract version */
    buffer[11] = '\0';  /* Null terminate before newline */
    strncpy(version_out, buffer + 4, 7);
    version_out[7] = '\0';
    
    /* Step 2: Send our protocol version (3.8) */
    const char *client_version = "RFB 003.008\n";
    if (send(sockfd, client_version, 12, 0) != 12) {
        close(sockfd);
        return -3;
    }
    
    /* Step 3: Receive security types */
    bytes_read = recv(sockfd, buffer, 1, 0);
    if (bytes_read != 1) {
        close(sockfd);
        return -4;
    }
    
    unsigned char num_types = (unsigned char)buffer[0];
    
    if (num_types == 0) {
        /* Connection failed - read reason */
        close(sockfd);
        return -5;
    }
    
    /* Read security types */
    bytes_read = recv(sockfd, buffer, num_types, 0);
    if (bytes_read != num_types) {
        close(sockfd);
        return -6;
    }
    
    *num_sec_types = num_types;
    
    for (int i = 0; i < num_types; i++) {
        sec_types_out[i] = (unsigned char)buffer[i];
        
        /* Check if no-auth is available */
        if (sec_types_out[i] == SEC_NONE) {
            *no_auth_available = 1;
        }
    }
    
    close(sockfd);
    return 0;
}

/* Output JSON result */
void output_json(const char *host, int port, const char *version,
                 unsigned char *sec_types, int num_sec_types,
                 int no_auth_available, int error_code) {
    
    printf("{\"findings\":[");
    
    if (error_code == 0 && num_sec_types > 0) {
        if (no_auth_available) {
            /* CRITICAL: No auth required */
            printf("{");
            printf("\"target\":\"%s:%d\",", host, port);
            printf("\"template_id\":\"vnc-no-auth\",");
            printf("\"id\":\"vnc-no-auth\",");
            printf("\"name\":\"VNC No Authentication Required\",");
            printf("\"severity\":\"critical\",");
            printf("\"confidence\":100,");
            printf("\"description\":\"VNC server on %s:%d accepts connections without authentication (Security Type 1: None). Anyone can connect and control the remote desktop.\",", host, port);
            printf("\"evidence\":{");
            printf("\"protocol_version\":\"%s\",", version);
            printf("\"security_types\":[");
            for (int i = 0; i < num_sec_types; i++) {
                printf("\"%s\"%s", security_type_name(sec_types[i]), 
                       i < num_sec_types - 1 ? "," : "");
            }
            printf("],");
            printf("\"no_auth_available\":true");
            printf("},");
            printf("\"remediation\":\"Configure VNC with strong password authentication. Use VPN or SSH tunneling for remote access. Never expose VNC directly to the internet.\",");
            printf("\"cwe\":[\"CWE-306\"],");
            printf("\"cvss_score\":9.8");
            printf("}");
        } else {
            /* VNC detected but requires auth */
            int has_weak_auth = 0;
            for (int i = 0; i < num_sec_types; i++) {
                if (sec_types[i] == SEC_VNC_AUTH) has_weak_auth = 1;
            }
            
            printf("{");
            printf("\"target\":\"%s:%d\",", host, port);
            printf("\"template_id\":\"vnc-no-auth\",");
            printf("\"id\":\"vnc-exposed\",");
            printf("\"name\":\"VNC Server Exposed\",");
            printf("\"severity\":\"%s\",", has_weak_auth ? "high" : "medium");
            printf("\"confidence\":90,");
            printf("\"description\":\"VNC server on %s:%d is network accessible. ", host, port);
            if (has_weak_auth) {
                printf("VNC Authentication (Type 2) is vulnerable to brute force attacks.");
            }
            printf("\",");
            printf("\"evidence\":{");
            printf("\"protocol_version\":\"%s\",", version);
            printf("\"security_types\":[");
            for (int i = 0; i < num_sec_types; i++) {
                printf("\"%s\"%s", security_type_name(sec_types[i]),
                       i < num_sec_types - 1 ? "," : "");
            }
            printf("],");
            printf("\"no_auth_available\":false");
            printf("},");
            printf("\"remediation\":\"Restrict VNC access via firewall. Use VPN for remote access. Consider more secure alternatives like SSH.\"");
            printf("}");
        }
    }
    
    printf("]}\n");
}

int main(int argc, char *argv[]) {
    const char *host;
    int port = VNC_DEFAULT_PORT;
    char version[16] = {0};
    unsigned char sec_types[32] = {0};
    int num_sec_types = 0;
    int no_auth_available = 0;
    int result;
    
    /* Get target from environment or args */
    host = getenv("CERT_X_GEN_TARGET_HOST");
    if (host == NULL && argc > 1) {
        host = argv[1];
    }
    if (host == NULL) {
        host = "127.0.0.1";
    }
    
    const char *port_str = getenv("CERT_X_GEN_TARGET_PORT");
    if (port_str != NULL) {
        port = atoi(port_str);
    } else if (argc > 2) {
        port = atoi(argv[2]);
    }
    
    /* Perform VNC check */
    result = check_vnc_auth(host, port, version, sec_types, 
                            &num_sec_types, &no_auth_available);
    
    /* Output result as JSON */
    output_json(host, port, version, sec_types, num_sec_types,
                no_auth_available, result);
    
    /* Return 0 on successful execution (findings are in JSON output) */
    return 0;
}
