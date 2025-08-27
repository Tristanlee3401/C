#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <arpa/inet.h>

typedef struct {
    uint32_t ip;
    uint32_t netmask;
    uint32_t network;
    uint32_t broadcast;
    uint32_t usable_hosts;
    int prefix_len;
} subnet_info_t;

// Convert IP string to 32-bit integer
uint32_t ip_to_int(const char* ip_str) {
    struct in_addr addr;
    if (inet_pton(AF_INET, ip_str, &addr) == 0) {
        perror("inet_pton failed");
        return 0; // Invalid IP
    }
    return ntohl(addr.s_addr);
}

// Convert 32-bit integer to IP string
void int_to_ip(uint32_t ip, char* buffer) {
    struct in_addr addr;
    addr.s_addr = htonl(ip);
    strcpy(buffer, inet_ntoa(addr));
}

// Convert CIDR prefix to netmask
uint32_t prefix_to_netmask(int prefix) {
    if (prefix < 0 || prefix > 32) return 0;
    if (prefix == 0) return 0;
    return (0xFFFFFFFF << (32 - prefix));
}

// Convert netmask to CIDR prefix
int netmask_to_prefix(uint32_t netmask) {
    int prefix = 0;
    uint32_t mask = netmask;
    
    // Count consecutive 1s from the left
    while (mask & 0x80000000) {
        prefix++;
        mask <<= 1;
    }
    
    // Verify it's a valid netmask (no 1s after 0s)
    if (mask != 0) return -1;
    
    return prefix;
}

// Parse different netmask formats
uint32_t parse_netmask(const char* mask_str) {
    uint32_t netmask = 0;
    
    if (mask_str[0] == '/') {
        // CIDR format (/24)
        int prefix = atoi(mask_str + 1);
        netmask = prefix_to_netmask(prefix);
    } else if (strncmp(mask_str, "0x", 2) == 0) {
        // Hexadecimal format (0xffffff00)
        netmask = (uint32_t)strtoul(mask_str, NULL, 16);
    } else if (strchr(mask_str, '.')) {
        // Dotted decimal format (255.255.255.0)
        netmask = ip_to_int(mask_str);
    } else {
        // Assume it's a decimal prefix
        int prefix = atoi(mask_str);
        netmask = prefix_to_netmask(prefix);
    }
    
    return netmask;
}

// Calculate subnet information
void calculate_subnet(const char* ip_str, const char* mask_str, subnet_info_t* info) {
    info->ip = ip_to_int(ip_str);
    info->netmask = parse_netmask(mask_str);
    
    if (info->ip == 0 || info->netmask == 0) {
        printf("Error: Invalid IP address or netmask\n");
        return;
    }
    
    info->prefix_len = netmask_to_prefix(info->netmask);
    info->network = info->ip & info->netmask;
    info->broadcast = info->network | (~info->netmask);
    
    // Calculate usable hosts (total - network - broadcast)
    uint32_t host_bits = 32 - info->prefix_len;
    if (host_bits >= 2) {
        info->usable_hosts = (1ULL << host_bits) - 2;
    } else {
        info->usable_hosts = 0; // /31 and /32 networks
    }
}

// Print subnet information
void print_subnet_info(const subnet_info_t* info) {
    char ip_str[16], netmask_str[16], network_str[16], broadcast_str[16];
    
    int_to_ip(info->ip, ip_str);
    int_to_ip(info->netmask, netmask_str);
    int_to_ip(info->network, network_str);
    int_to_ip(info->broadcast, broadcast_str);
    
    printf("\n--- Subnet Information ---\n");
    printf("IP Address:        %s\n", ip_str);
    printf("Netmask:           %s (/%d)\n", netmask_str, info->prefix_len);
    printf("Network Address:   %s\n", network_str);
    printf("Broadcast Address: %s\n", broadcast_str);
    printf("Usable Hosts:      %u\n", info->usable_hosts);
    printf("Host Range:        ");
    
    if (info->usable_hosts > 0) {
        char first_host[16], last_host[16];
        int_to_ip(info->network + 1, first_host);
        int_to_ip(info->broadcast - 1, last_host);
        printf("%s - %s\n", first_host, last_host);
    } else {
        printf("None (point-to-point or host route)\n");
    }
}

void print_usage(const char* program_name) {
    printf("Usage: %s <ip_address> <netmask>\n\n", program_name);
    printf("Netmask formats supported:\n");
    printf("  CIDR notation:     /24, /16, /8\n");
    printf("  Decimal notation:  255.255.255.0\n");
    printf("  Hexadecimal:       0xffffff00\n");
    printf("  Prefix length:     24\n\n");
    printf("Examples:\n");
    printf("  %s 192.168.1.100 /24\n", program_name);
    printf("  %s 192.168.1.100 255.255.255.0\n", program_name);
    printf("  %s 192.168.1.100 0xffffff00\n", program_name);
    printf("  %s 10.0.0.1 8\n", program_name);
}

int main(int argc, char* argv[]) {
    if (argc != 3) {
        print_usage(argv[0]);
        return 1;
    }
    
    subnet_info_t info;
    calculate_subnet(argv[1], argv[2], &info);
    print_subnet_info(&info);
    
    return 0;
}
