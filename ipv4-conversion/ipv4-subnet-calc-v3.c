#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <arpa/inet.h>
#include <ctype.h>

// Buffer size constants
#define IP_STR_LEN 16    // Max: "255.255.255.255\0"
#define IP_BIN_LEN 36    // Max: "11111111.11111111.11111111.11111111\0"
#define IP_HEX_LEN 11    // Max: "0xffffffff\0"

typedef struct {
    uint32_t ip;
    uint32_t netmask;
    uint32_t network;
    uint32_t broadcast;
    uint32_t usable_hosts;
    uint32_t total_hosts;
    int prefix_len;
    int show_binary;
} subnet_info_t;

// Convert dotted decimal IP string to 32-bit integer
uint32_t ip_to_int(const char* ip_str) {
    struct in_addr addr;
    if (inet_aton(ip_str, &addr) == 0) {
        return 0; // Invalid IP
    }
    return ntohl(addr.s_addr);
}

// Convert binary string to 32-bit integer
uint32_t binary_to_int(const char* binary_str) {
    uint32_t result = 0;
    int len = strlen(binary_str);
    
    // Remove spaces or dots from binary string
    char clean_binary[33] = {0};
    int clean_idx = 0;
    
    for (int i = 0; i < len && clean_idx < 32; i++) {
        if (binary_str[i] == '0' || binary_str[i] == '1') {
            clean_binary[clean_idx++] = binary_str[i];
        }
    }
    
    // Validate binary string length
    if (clean_idx < 8 || clean_idx > 32) {
        return 0; // Invalid length
    }
    
    // Convert binary string to integer
    for (int i = 0; i < clean_idx; i++) {
        if (clean_binary[i] == '1') {
            result |= (1U << (31 - i));
        }
    }
    
    return result;
}

// Check if string is binary format (0s, 1s, dots, or spaces)
int is_binary_string(const char* str) {
    int binary_chars = 0;
    int total_chars = 0;
    
    for (int i = 0; str[i]; i++) {
        if (str[i] == '0' || str[i] == '1') {
            binary_chars++;
            total_chars++;
        } else if (str[i] == '.' || str[i] == ' ') {
            continue;
        } else if (!isspace(str[i])) {
            total_chars++;
        }
    }
    
    return (binary_chars >= 8 && binary_chars <= 32 && 
            (float)binary_chars / total_chars > 0.8);
}

// Validate hexadecimal string (0x followed by 1-8 hex digits)
int is_valid_hex(const char* str) {
    if (strncmp(str, "0x", 2) != 0) return 0;
    int len = strlen(str + 2);
    if (len < 1 || len > 8) return 0;
    for (int i = 2; str[i]; i++) {
        if (!isxdigit(str[i])) return 0;
    }
    return 1;
}

// Parse IP address (dotted decimal, binary, or hexadecimal)
uint32_t parse_ip_address(const char* ip_str) {
    if (ip_str[0] == '\0') {
        printf("Error: Empty IP address\n");
        return 0;
    }
    if (is_binary_string(ip_str)) {
        uint32_t result = binary_to_int(ip_str);
        if (result == 0) {
            printf("Error: Invalid IP address\n");
        }
        return result;
    } else if (strncmp(ip_str, "0x", 2) == 0) {
        if (!is_valid_hex(ip_str)) {
            printf("Error: Invalid IP address\n");
            return 0;
        }
        return strtoul(ip_str, NULL, 16);
    } else {
        uint32_t result = ip_to_int(ip_str);
        if (result == 0) {
            printf("Error: Invalid IP address\n");
        }
        return result;
    }
}

// Convert 32-bit integer to dotted decimal IP string
void int_to_ip(uint32_t ip, char* buffer) {
    struct in_addr addr;
    addr.s_addr = htonl(ip);
    snprintf(buffer, IP_STR_LEN, "%s", inet_ntoa(addr));
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
        buffer[IP_BIN_LEN - 1] = '\0';
    } else {
        // Format: 11000000101010000000000101100100
        for (int i = 0; i < 32; i++) {
            buffer[i] = (ip & (1U << (31 - i))) ? '1' : '0';
        }
        buffer[32] = '\0';
    }
}

// Convert 32-bit integer to hexadecimal string
void int_to_hex(uint32_t ip, char* buffer, size_t buffer_size) {
    snprintf(buffer, buffer_size, "0x%08x", ip);
}

// Convert CIDR prefix to netmask
uint32_t prefix_to_netmask(int prefix) {
    if (prefix < 0 || prefix > 32) {
        printf("Error: Invalid CIDR prefix (%d)\n", prefix);
        return 0;
    }
    if (prefix == 0) return 0;
    return (0xFFFFFFFF << (32 - prefix));
}

// Convert netmask to CIDR prefix
int netmask_to_prefix(uint32_t netmask) {
    int prefix = 0;
    uint32_t mask = netmask;
    
    while (mask & 0x80000000) {
        prefix++;
        mask <<= 1;
    }
    
    if (mask != 0) return -1; // Non-contiguous 1s
    return prefix;
}

// Parse netmask (CIDR, decimal, hexadecimal, or binary)
uint32_t parse_netmask(const char* mask_str) {
    if (mask_str[0] == '\0') {
        printf("Error: Empty netmask\n");
        return 0;
    }
    uint32_t netmask = 0;
    
    if (mask_str[0] == '/') {
        int prefix = atoi(mask_str + 1);
        netmask = prefix_to_netmask(prefix);
    } else if (strncmp(mask_str, "0x", 2) == 0) {
        if (!is_valid_hex(mask_str)) {
            printf("Error: Invalid netmask\n");
            return 0;
        }
        netmask = strtoul(mask_str, NULL, 16);
    } else if (is_binary_string(mask_str)) {
        netmask = binary_to_int(mask_str);
        if (netmask == 0) {
            printf("Error: Invalid netmask\n");
            return 0;
        }
    } else if (strchr(mask_str, '.')) {
        netmask = ip_to_int(mask_str);
        if (netmask == 0) {
            printf("Error: Invalid netmask\n");
            return 0;
        }
    } else {
        int prefix = atoi(mask_str);
        netmask = prefix_to_netmask(prefix);
    }
    
    if (netmask != 0 && netmask_to_prefix(netmask) == -1) {
        printf("Error: Invalid netmask (non-contiguous 1s)\n");
        return 0;
    }
    
    return netmask;
}

// Calculate subnet information
void calculate_subnet(const char* ip_str, const char* mask_str, subnet_info_t* info) {
    info->ip = parse_ip_address(ip_str);
    info->netmask = (mask_str) ? parse_netmask(mask_str) : prefix_to_netmask(32);
    
    if (info->ip == 0 || info->netmask == 0) {
        info->netmask = 0; // Mark as invalid
        return;
    }
    
    info->prefix_len = netmask_to_prefix(info->netmask);
    info->network = info->ip & info->netmask;
    info->broadcast = info->network | (~info->netmask);
    
    uint32_t host_bits = 32 - info->prefix_len;
    info->total_hosts = (1ULL << host_bits);
    info->usable_hosts = (host_bits >= 2) ? info->total_hosts - 2 : 0;
}

// Print subnet information
void print_subnet_info(const subnet_info_t* info) {
    char ip_str[IP_STR_LEN], netmask_str[IP_STR_LEN], network_str[IP_STR_LEN], broadcast_str[IP_STR_LEN];
    char temp_bin[IP_BIN_LEN];
    char ip_hex[IP_HEX_LEN], netmask_hex[IP_HEX_LEN], network_hex[IP_HEX_LEN], broadcast_hex[IP_HEX_LEN];
    
    int_to_ip(info->ip, ip_str);
    int_to_ip(info->netmask, netmask_str);
    int_to_ip(info->network, network_str);
    int_to_ip(info->broadcast, broadcast_str);
    int_to_hex(info->ip, ip_hex, IP_HEX_LEN);
    int_to_hex(info->netmask, netmask_hex, IP_HEX_LEN);
    int_to_hex(info->network, network_hex, IP_HEX_LEN);
    int_to_hex(info->broadcast, broadcast_hex, IP_HEX_LEN);
    
    printf("\n--- IPv4 Information ---\n");
    printf("1. IP Address:            %s", ip_str);
    if (info->show_binary) {
        int_to_binary(info->ip, temp_bin, 1);
        printf(" (%s)", temp_bin);
    }
    printf("\n   Decimal:               %s", ip_str);
    printf("\n   Hex:                   %s", ip_hex);
    int_to_binary(info->ip, temp_bin, 0);
    printf("\n   Binary:                %s", temp_bin);
    int_to_binary(info->ip, temp_bin, 1);
    printf("\n   Binary (dotted):       %s", temp_bin);
    printf("\n\n");
    
    printf("2. Netmask:               %s (/%d)", netmask_str, info->prefix_len);
    if (info->show_binary) {
        int_to_binary(info->netmask, temp_bin, 1);
        printf(" (%s)", temp_bin);
    }
    printf("\n   Decimal:               %s", netmask_str);
    printf("\n   Hex:                   %s", netmask_hex);
    int_to_binary(info->netmask, temp_bin, 0);
    printf("\n   Binary:                %s", temp_bin);
    int_to_binary(info->netmask, temp_bin, 1);
    printf("\n   Binary (dotted):       %s", temp_bin);
    printf("\n   CIDR:                  /%d", info->prefix_len);
    printf("\n\n");
    
    printf("Network Address:          %s", network_str);
    if (info->show_binary) {
        int_to_binary(info->network, temp_bin, 1);
        printf(" (%s)", temp_bin);
    }
    printf("\n   Hex:                   %s", network_hex);
    printf("\n\n");
    
    printf("Broadcast Address:        %s", broadcast_str);
    if (info->show_binary) {
        int_to_binary(info->broadcast, temp_bin, 1);
        printf(" (%s)", temp_bin);
    }
    printf("\n   Hex:                   %s", broadcast_hex);
    printf("\n\n");
    
    printf("Total Addresses:          %u\n", info->total_hosts);
    printf("Usable Hosts:             %u\n", info->usable_hosts);
    printf("Host Range:               ");
    
    if (info->usable_hosts > 0) {
        char first_host[IP_STR_LEN], last_host[IP_STR_LEN];
        char first_hex[IP_HEX_LEN], last_hex[IP_HEX_LEN];
        int_to_ip(info->network + 1, first_host);
        int_to_ip(info->broadcast - 1, last_host);
        int_to_hex(info->network + 1, first_hex, IP_HEX_LEN);
        int_to_hex(info->broadcast - 1, last_hex, IP_HEX_LEN);
        printf("%s - %s", first_host, last_host);
        
        if (info->show_binary) {
            char first_bin[IP_BIN_LEN], last_bin[IP_BIN_LEN];
            int_to_binary(info->network + 1, first_bin, 1);
            int_to_binary(info->broadcast - 1, last_bin, 1);
            printf("\n   Binary:                %s - %s", first_bin, last_bin);
        }
        printf("\n   Hex:                   %s - %s", first_hex, last_hex);
        printf("\n");
    } else {
        printf("None (point-to-point or host route)\n");
    }
}

void print_usage(const char* program_name) {
    printf("Usage: %s [options] <ip_address> [<netmask>]\n\n", program_name);
    printf("Options:\n");
    printf("  -b, --binary      Include binary representation in output\n");
    printf("  -h, --help        Show this help message\n\n");
    printf("IP Address formats supported:\n");
    printf("  Dotted decimal:    192.168.1.100\n");
    printf("  Binary:            11000000101010000000000101100100\n");
    printf("  Binary (dotted):   11000000.10101000.00000001.01100100\n");
    printf("  Hexadecimal:       0xc0a80164\n\n");
    printf("Netmask formats supported (optional, defaults to /32):\n");
    printf("  CIDR notation:     /24, /16, /8\n");
    printf("  Decimal notation:  255.255.255.0\n");
    printf("  Hexadecimal:       0xffffff00\n");
    printf("  Binary:            11111111111111111111111100000000\n");
    printf("  Binary (dotted):   11111111.11111111.11111111.00000000\n");
    printf("  Prefix length:     24\n\n");
    printf("Examples:\n");
    printf("  %s 192.168.1.100\n", program_name);
    printf("  %s 192.168.1.100 /24\n", program_name);
    printf("  %s -b 192.168.1.100 255.255.255.0\n", program_name);
    printf("  %s 11000000.10101000.00000001.01100100\n", program_name);
    printf("  %s -b 0xc0a80d17 0xffff0000\n", program_name);
}

int main(int argc, char* argv[]) {
    int show_binary = 0;
    int arg_start = 1;
    
    // Parse command-line options
    if (argc > 1) {
        if (strcmp(argv[1], "-b") == 0 || strcmp(argv[1], "--binary") == 0) {
            show_binary = 1;
            arg_start = 2;
        } else if (strcmp(argv[1], "-h") == 0 || strcmp(argv[1], "--help") == 0) {
            print_usage(argv[0]);
            return 0;
        }
    }
    
    if (argc < arg_start + 1) {
        print_usage(argv[0]);
        return 1;
    }
    
    subnet_info_t info = { .show_binary = show_binary };
    
    // Calculate subnet (default netmask /32 if not provided)
    if (argc == arg_start + 1) {
        calculate_subnet(argv[arg_start], "/32", &info);
    } else {
        calculate_subnet(argv[arg_start], argv[arg_start + 1], &info);
    }
    
    if (info.netmask == 0) {
        return 1; // Exit on invalid input
    }
    
    print_subnet_info(&info);
    
    return 0;
}
