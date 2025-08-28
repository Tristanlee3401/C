#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <arpa/inet.h>
#include <ctype.h>

typedef struct {
    uint32_t ip;
    uint32_t netmask;
    uint32_t network;
    uint32_t broadcast;
    uint32_t usable_hosts;
    int prefix_len;
    int show_binary;
} subnet_info_t;

// Convert IP string to 32-bit integer
uint32_t ip_to_int(const char* ip_str) {
    struct in_addr addr;
    if (inet_aton(AF_INET, ip_str, &addr) == 0) {
        perror("inet_pton failed");
        return 0; // Invalid IP
    }
    return ntohl(addr.s_addr);
}

// Convert binary string to 32-bit integer
uint32_t binary_to_int(const char* binary_str) {
    uint32_t result = 0;
    int len = strlen(binary_str);
    
    // Remove any spaces or dots from binary string
    char clean_binary[33] = {0};
    int clean_idx = 0;
    
    for (int i = 0; i < len && clean_idx < 32; i++) {
        if (binary_str[i] == '0' || binary_str[i] == '1') {
            clean_binary[clean_idx++] = binary_str[i];
        }
    }
    
    // Convert binary string to integer
    for (int i = 0; i < clean_idx && i < 32; i++) {
        if (clean_binary[i] == '1') {
            result |= (1U << (31 - i));
        }
    }
    
    return result;
}

// Check if string is binary format
int is_binary_string(const char* str) {
    int binary_chars = 0;
    int total_chars = 0;
    
    for (int i = 0; str[i]; i++) {
        if (str[i] == '0' || str[i] == '1') {
            binary_chars++;
            total_chars++;
        } else if (str[i] == '.' || str[i] == ' ') {
            // Allow separators
            continue;
        } else if (!isspace(str[i])) {
            total_chars++;
        }
    }
    
    // Consider it binary if it's mostly 0s and 1s and has reasonable length
    return (binary_chars >= 8 && binary_chars <= 32 && 
            (float)binary_chars / total_chars > 0.8);
}

// Parse IP address (supports dotted decimal and binary)
uint32_t parse_ip_address(const char* ip_str) {
    if (is_binary_string(ip_str)) {
        return binary_to_int(ip_str);
    } else {
        return ip_to_int(ip_str);
    }
}

// Convert 32-bit integer to IP string
void int_to_ip(uint32_t ip, char* buffer) {
    struct in_addr addr;
    addr.s_addr = htonl(ip);
    strcpy(buffer, inet_ntoa(addr));
}

// Convert 32-bit integer to binary string
void int_to_binary(uint32_t ip, char* buffer, int show_dots) {
    if (show_dots) {
        // Format: 11000000.10101000.00000001.01100100
        for (int i = 0; i < 32; i++) {
            buffer[i + (i / 8)] = (ip & (1U << (31 - i))) ? '1' : '0';
            if (i % 8 == 7 && i < 31) {
                buffer[i + (i / 8) + 1] = '.';
            }
        }
        buffer[35] = '\0';
    } else {
        // Format: 11000000101010000000000101100100
        for (int i = 0; i < 32; i++) {
            buffer[i] = (ip & (1U << (31 - i))) ? '1' : '0';
        }
        buffer[32] = '\0';
    }
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

// Parse different netmask formats (including binary)
uint32_t parse_netmask(const char* mask_str) {
    uint32_t netmask = 0;
    
    if (mask_str[0] == '/') {
        // CIDR format (/24)
        int prefix = atoi(mask_str + 1);
        netmask = prefix_to_netmask(prefix);
    } else if (strncmp(mask_str, "0x", 2) == 0) {
        // Hexadecimal format (0xffffff00)
        netmask = (uint32_t)strtoul(mask_str, NULL, 16);
    } else if (is_binary_string(mask_str)) {
        // Binary format (11111111111111111111111100000000)
        netmask = binary_to_int(mask_str);
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
    info->ip = parse_ip_address(ip_str);
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
    char ip_bin[36], netmask_bin[36], network_bin[36], broadcast_bin[36];
    
    int_to_ip(info->ip, ip_str);
    int_to_ip(info->netmask, netmask_str);
    int_to_ip(info->network, network_str);
    int_to_ip(info->broadcast, broadcast_str);
    
    printf("\n--- Subnet Information ---\n");
    printf("IP Address:        %s", ip_str);
    if (info->show_binary) {
        int_to_binary(info->ip, ip_bin, 1);
        printf(" (%s)", ip_bin);
    }
    printf("\n");
    
    printf("Netmask:           %s (/%d)", netmask_str, info->prefix_len);
    if (info->show_binary) {
        int_to_binary(info->netmask, netmask_bin, 1);
        printf(" (%s)", netmask_bin);
    }
    printf("\n");
    
    printf("Network Address:   %s", network_str);
    if (info->show_binary) {
        int_to_binary(info->network, network_bin, 1);
        printf(" (%s)", network_bin);
    }
    printf("\n");
    
    printf("Broadcast Address: %s", broadcast_str);
    if (info->show_binary) {
        int_to_binary(info->broadcast, broadcast_bin, 1);
        printf(" (%s)", broadcast_bin);
    }
    printf("\n");
    
    printf("Usable Hosts:      %u\n", info->usable_hosts);
    printf("Host Range:        ");
    
    if (info->usable_hosts > 0) {
        char first_host[16], last_host[16];
        int_to_ip(info->network + 1, first_host);
        int_to_ip(info->broadcast - 1, last_host);
        printf("%s - %s", first_host, last_host);
        
        if (info->show_binary) {
            char first_bin[36], last_bin[36];
            int_to_binary(info->network + 1, first_bin, 1);
            int_to_binary(info->broadcast - 1, last_bin, 1);
            printf("\n                   %s - %s", first_bin, last_bin);
        }
        printf("\n");
    } else {
        printf("None (point-to-point or host route)\n");
    }
}

void print_usage(const char* program_name) {
    printf("Usage: %s [options] <ip_address> <netmask>\n\n", program_name);
    printf("Options:\n");
    printf("  -b, --binary      Show binary representation of addresses\n");
    printf("  -h, --help        Show this help message\n\n");
    printf("IP Address formats supported:\n");
    printf("  Dotted decimal:    192.168.1.100\n");
    printf("  Binary (32-bit):   11000000101010000000000101100100\n");
    printf("  Binary (dotted):   11000000.10101000.00000001.01100100\n\n");
    printf("Netmask formats supported:\n");
    printf("  CIDR notation:     /24, /16, /8\n");
    printf("  Decimal notation:  255.255.255.0\n");
    printf("  Hexadecimal:       0xffffff00\n");
    printf("  Binary:            11111111111111111111111100000000\n");
    printf("  Binary (dotted):   11111111.11111111.11111111.00000000\n");
    printf("  Prefix length:     24\n\n");
    printf("Examples:\n");
    printf("  %s 192.168.1.100 /24\n", program_name);
    printf("  %s -b 192.168.1.100 255.255.255.0\n", program_name);
    printf("  %s 11000000.10101000.00000001.01100100 /24\n", program_name);
    printf("  %s 192.168.1.100 11111111.11111111.11111111.00000000\n", program_name);
    printf("  %s -b 11000000101010000000000101100100 0xffffff00\n", program_name);
}

int main(int argc, char* argv[]) {
    int show_binary = 0;
    int arg_start = 1;
    
    // Parse command line options
    if (argc > 1) {
        if (strcmp(argv[1], "-b") == 0 || strcmp(argv[1], "--binary") == 0) {
            show_binary = 1;
            arg_start = 2;
        } else if (strcmp(argv[1], "-h") == 0 || strcmp(argv[1], "--help") == 0) {
            print_usage(argv[0]);
            return 0;
        }
    }
    
    if (argc < arg_start + 2) {
        print_usage(argv[0]);
        return 1;
    }
    
    subnet_info_t info;
    info.show_binary = show_binary;
    calculate_subnet(argv[arg_start], argv[arg_start + 1], &info);
    print_subnet_info(&info);
    
    return 0;
}
