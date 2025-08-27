#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <arpa/inet.h>
#include <ctype.h>
#include <gmp.h>

#define IP_STR_LEN 46    // Max for IPv6: "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff\0"
#define IP_BIN_LEN 148   // IPv6: 128 bits + 15 dots + 3 spaces + null
#define IP_HEX_LEN 35    // Max for IPv6: "0x" + 32 hex digits + null

typedef struct {
    uint64_t high;
    uint64_t low;
} ipv6_addr_t;

typedef struct {
    void* ip;         // uint32_t* for IPv4, ipv6_addr_t* for IPv6
    void* netmask;
    void* network;
    void* broadcast;  // For IPv6, this is the last address in the subnet
    mpz_t total_hosts; // Use GMP for large IPv6 subnets
    mpz_t usable_hosts;
    int prefix_len;
    int show_binary;
    int version;      // 4 for IPv4, 6 for IPv6, 0 for invalid
    int is_multicast; // Flag for IPv6 multicast
    int is_unique_local; // Flag for IPv6 unique local
} subnet_info_t;

// Validate that a netmask is contiguous (all 1s followed by all 0s)
int is_contiguous_netmask_ipv4(uint32_t mask) {
    // Find the first 0 bit from the left
    int found_zero = 0;
    for (int i = 31; i >= 0; i--) {
        if (mask & (1U << i)) {
            if (found_zero) return 0; // Found a 1 after a 0
        } else {
            found_zero = 1;
        }
    }
    return 1;
}

int is_contiguous_netmask_ipv6(ipv6_addr_t* mask) {
    int found_zero = 0;
    // Check high 64 bits
    for (int i = 63; i >= 0; i--) {
        if (mask->high & (1ULL << i)) {
            if (found_zero) return 0;
        } else {
            found_zero = 1;
        }
    }
    // Check low 64 bits
    for (int i = 63; i >= 0; i--) {
        if (mask->low & (1ULL << i)) {
            if (found_zero) return 0;
        } else {
            found_zero = 1;
        }
    }
    return 1;
}

// Convert IPv4 string to uint32_t
uint32_t ipv4_to_int(const char* ip_str) {
    struct in_addr addr;
    if (inet_aton(ip_str, &addr) == 0) {
        return 0;
    }
    return ntohl(addr.s_addr);
}

// Convert IPv6 string to ipv6_addr_t
ipv6_addr_t ipv6_to_int(const char* ip_str) {
    ipv6_addr_t result = {0, 0};
    struct in6_addr addr;
    char* ip_copy = strdup(ip_str);
    char* scope = strchr(ip_copy, '%');
    if (scope) *scope = '\0'; // Strip scope identifier
    if (inet_pton(AF_INET6, ip_copy, &addr) == 0) {
        free(ip_copy);
        return result;
    }
    free(ip_copy);
    result.high = ((uint64_t)addr.s6_addr[0] << 56) | ((uint64_t)addr.s6_addr[1] << 48) |
                  ((uint64_t)addr.s6_addr[2] << 40) | ((uint64_t)addr.s6_addr[3] << 32) |
                  ((uint64_t)addr.s6_addr[4] << 24) | ((uint64_t)addr.s6_addr[5] << 16) |
                  ((uint64_t)addr.s6_addr[6] << 8)  | addr.s6_addr[7];
    result.low = ((uint64_t)addr.s6_addr[8] << 56) | ((uint64_t)addr.s6_addr[9] << 48) |
                 ((uint64_t)addr.s6_addr[10] << 40) | ((uint64_t)addr.s6_addr[11] << 32) |
                 ((uint64_t)addr.s6_addr[12] << 24) | ((uint64_t)addr.s6_addr[13] << 16) |
                 ((uint64_t)addr.s6_addr[14] << 8)  | addr.s6_addr[15];
    return result;
}

// Convert binary string to integer
void* binary_to_int(const char* binary_str, int version) {
    if (version == 4) {
        uint32_t* result = malloc(sizeof(uint32_t));
        if (!result) return NULL;
        *result = 0;
        char clean_binary[33] = {0};
        int clean_idx = 0;
        for (int i = 0; binary_str[i] && clean_idx < 32; i++) {
            if (binary_str[i] == '0' || binary_str[i] == '1') {
                clean_binary[clean_idx++] = binary_str[i];
            }
        }
        if (clean_idx < 1 || clean_idx > 32) {
            free(result);
            printf("Error: Invalid binary IP length for IPv4 (1-32 bits required)\n");
            return NULL;
        }
        // Pad with zeros on the left if less than 32 bits
        for (int i = 0; i < clean_idx; i++) {
            if (clean_binary[i] == '1') *result |= (1U << (clean_idx - 1 - i));
        }
        return result;
    } else if (version == 6) {
        ipv6_addr_t* result = malloc(sizeof(ipv6_addr_t));
        if (!result) return NULL;
        result->high = result->low = 0;
        char clean_binary[129] = {0};
        int clean_idx = 0;
        for (int i = 0; binary_str[i] && clean_idx < 128; i++) {
            if (binary_str[i] == '0' || binary_str[i] == '1') {
                clean_binary[clean_idx++] = binary_str[i];
            }
        }
        if (clean_idx != 128) {
            free(result);
            printf("Error: Invalid binary IP length for IPv6 (exactly 128 bits required)\n");
            return NULL;
        }
        for (int i = 0; i < 64; i++) {
            if (clean_binary[i] == '1') result->high |= (1ULL << (63 - i));
        }
        for (int i = 64; i < 128; i++) {
            if (clean_binary[i] == '1') result->low |= (1ULL << (127 - i));
        }
        return result;
    }
    return NULL;
}

// Check if string is binary format
int is_binary_string(const char* str, int version) {
    int min_bits = (version == 4) ? 1 : 32;
    int max_bits = (version == 4) ? 32 : 128;
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
    return (binary_chars >= min_bits && binary_chars <= max_bits && 
            (float)binary_chars / total_chars > 0.8);
}

// Validate hexadecimal string
int is_valid_hex(const char* str, int version) {
    if (strncmp(str, "0x", 2) != 0) return 0;
    int len = strlen(str + 2);
    int max_len = (version == 4) ? 8 : 32;
    if (len < 1 || len > max_len) return 0;
    for (int i = 2; str[i]; i++) {
        if (!isxdigit(str[i])) return 0;
    }
    return 1;
}

// Parse IP address
void* parse_ip_address(const char* ip_str, int* version, int* is_multicast, int* is_unique_local) {
    *is_multicast = *is_unique_local = 0;
    if (ip_str[0] == '\0') {
        printf("Error: Empty IP address\n");
        *version = 0;
        return NULL;
    }
    if (strncmp(ip_str, "::ffff:", 7) == 0) {
        *version = 4;
        uint32_t* result = malloc(sizeof(uint32_t));
        if (!result) return NULL;
        *result = ipv4_to_int(ip_str + 7);
        if (*result == 0) {
            printf("Error: Invalid IPv4-mapped IPv6 address\n");
            free(result);
            *version = 0;
            return NULL;
        }
        return result;
    }
    if (strchr(ip_str, ':')) {
        *version = 6;
        ipv6_addr_t* result = malloc(sizeof(ipv6_addr_t));
        if (!result) return NULL;
        *result = ipv6_to_int(ip_str);
        if (result->high == 0 && result->low == 0 && strcmp(ip_str, "::") != 0) {
            printf("Error: Invalid IPv6 address\n");
            free(result);
            *version = 0;
            return NULL;
        }
        // Check for multicast (ff00::/8)
        if ((result->high >> 56) == 0xff) *is_multicast = 1;
        // Check for unique local (fc00::/7)
        if ((result->high >> 56) == 0xfc || (result->high >> 56) == 0xfd) *is_unique_local = 1;
        return result;
    }
    if (is_binary_string(ip_str, 4)) {
        *version = 4;
        return binary_to_int(ip_str, 4);
    }
    if (is_binary_string(ip_str, 6)) {
        *version = 6;
        return binary_to_int(ip_str, 6);
    }
    if (is_valid_hex(ip_str, 4)) {
        *version = 4;
        uint32_t* result = malloc(sizeof(uint32_t));
        if (!result) return NULL;
        *result = (uint32_t)strtoul(ip_str + 2, NULL, 16);
        return result;
    }
    if (is_valid_hex(ip_str, 6)) {
        *version = 6;
        ipv6_addr_t* result = malloc(sizeof(ipv6_addr_t));
        if (!result) return NULL;
        
        // FIXED: Properly parse IPv6 hex addresses
        char* hex_part = strdup(ip_str + 2); // Skip "0x"
        int len = strlen(hex_part);
        
        // Pad with leading zeros to make it 32 characters
        char padded[33] = {0};
        int pad_count = 32 - len;
        for (int i = 0; i < pad_count; i++) {
            padded[i] = '0';
        }
        strcat(padded, hex_part);
        free(hex_part);
        
        // Parse high 64 bits (first 16 hex chars)
        char high_str[17] = {0};
        strncpy(high_str, padded, 16);
        result->high = strtoull(high_str, NULL, 16);
        
        // Parse low 64 bits (last 16 hex chars)
        char low_str[17] = {0};
        strncpy(low_str, padded + 16, 16);
        result->low = strtoull(low_str, NULL, 16);
        
        // Check for multicast and unique local
        if ((result->high >> 56) == 0xff) *is_multicast = 1;
        if ((result->high >> 56) == 0xfc || (result->high >> 56) == 0xfd) *is_unique_local = 1;
        return result;
    }
    *version = 4;
    uint32_t* result = malloc(sizeof(uint32_t));
    if (!result) return NULL;
    *result = ipv4_to_int(ip_str);
    if (*result == 0 && strcmp(ip_str, "0.0.0.0") != 0) {
        printf("Error: Invalid IP address\n");
        free(result);
        *version = 0;
        return NULL;
    }
    return result;
}

// Convert integer to IP string
void int_to_ip(const void* ip, int version, char* ip_str) {
    if (version == 4) {
        uint32_t addr = *(uint32_t*)ip;
        sprintf(ip_str, "%d.%d.%d.%d",
                (addr >> 24) & 0xFF, (addr >> 16) & 0xFF,
                (addr >> 8) & 0xFF, addr & 0xFF);
    } else {
        ipv6_addr_t* addr = (ipv6_addr_t*)ip;
        struct in6_addr in6;
        in6.s6_addr[0] = addr->high >> 56; in6.s6_addr[1] = addr->high >> 48;
        in6.s6_addr[2] = addr->high >> 40; in6.s6_addr[3] = addr->high >> 32;
        in6.s6_addr[4] = addr->high >> 24; in6.s6_addr[5] = addr->high >> 16;
        in6.s6_addr[6] = addr->high >> 8;  in6.s6_addr[7] = addr->high;
        in6.s6_addr[8] = addr->low >> 56;  in6.s6_addr[9] = addr->low >> 48;
        in6.s6_addr[10] = addr->low >> 40; in6.s6_addr[11] = addr->low >> 32;
        in6.s6_addr[12] = addr->low >> 24; in6.s6_addr[13] = addr->low >> 16;
        in6.s6_addr[14] = addr->low >> 8;  in6.s6_addr[15] = addr->low;
        inet_ntop(AF_INET6, &in6, ip_str, IP_STR_LEN);
    }
}

// Convert integer to hex string
void int_to_hex(const void* ip, int version, char* hex_str) {
    if (version == 4) {
        sprintf(hex_str, "0x%08x", *(uint32_t*)ip);
    } else {
        ipv6_addr_t* addr = (ipv6_addr_t*)ip;
        sprintf(hex_str, "0x%016lx%016lx", addr->high, addr->low);
    }
}

// Convert integer to binary string
void int_to_binary(const void* ip, int version, char* bin_str, int dotted) {
    if (version == 4) {
        uint32_t addr = *(uint32_t*)ip;
        if (dotted) {
            char temp[33];
            for (int i = 0; i < 32; i++) {
                temp[i] = (addr & (1U << (31 - i))) ? '1' : '0';
            }
            temp[32] = '\0';
            sprintf(bin_str, "%.8s.%.8s.%.8s.%.8s", temp, temp + 8, temp + 16, temp + 24);
        } else {
            for (int i = 0; i < 32; i++) {
                bin_str[i] = (addr & (1U << (31 - i))) ? '1' : '0';
            }
            bin_str[32] = '\0';
        }
    } else {
        ipv6_addr_t* addr = (ipv6_addr_t*)ip;
        char temp[129];
        for (int i = 0; i < 64; i++) {
            temp[i] = (addr->high & (1ULL << (63 - i))) ? '1' : '0';
        }
        for (int i = 0; i < 64; i++) {
            temp[i + 64] = (addr->low & (1ULL << (63 - i))) ? '1' : '0';
        }
        temp[128] = '\0';
        if (dotted) {
            sprintf(bin_str, "%.8s.%.8s.%.8s.%.8s %.8s.%.8s.%.8s.%.8s %.8s.%.8s.%.8s.%.8s %.8s.%.8s.%.8s.%.8s",
                    temp, temp + 8, temp + 16, temp + 24, temp + 32, temp + 40, temp + 48, temp + 56,
                    temp + 64, temp + 72, temp + 80, temp + 88, temp + 96, temp + 104, temp + 112, temp + 120);
        } else {
            strcpy(bin_str, temp);
        }
    }
}

// Parse netmask
void* parse_netmask(const char* netmask_str, int version, int* prefix_len) {
    if (!netmask_str) {
        *prefix_len = (version == 4) ? 32 : 128;
        if (version == 4) {
            uint32_t* result = malloc(sizeof(uint32_t));
            if (!result) return NULL;
            *result = 0xffffffff;
            return result;
        } else {
            ipv6_addr_t* result = malloc(sizeof(ipv6_addr_t));
            if (!result) return NULL;
            result->high = result->low = 0xffffffffffffffffULL;
            return result;
        }
    }
    if (netmask_str[0] == '/') {
        int len = atoi(netmask_str + 1);
        if ((version == 4 && len > 32) || (version == 6 && len > 128) || len < 0) {
            printf("Error: Invalid prefix length\n");
            return NULL;
        }
        *prefix_len = len;
        if (version == 4) {
            uint32_t* result = malloc(sizeof(uint32_t));
            if (!result) return NULL;
            *result = len == 0 ? 0 : (~0U) << (32 - len);
            return result;
        } else {
            ipv6_addr_t* result = malloc(sizeof(ipv6_addr_t));
            if (!result) return NULL;
            if (len == 0) {
                result->high = result->low = 0;
            } else if (len <= 64) {
                result->high = (~0ULL) << (64 - len);
                result->low = 0;
            } else {
                result->high = ~0ULL;
                result->low = (~0ULL) << (128 - len);
            }
            return result;
        }
    }
    if (strchr(netmask_str, ':')) {
        if (version != 6) {
            printf("Error: IPv6 netmask used with IPv4 address\n");
            return NULL;
        }
        ipv6_addr_t* result = malloc(sizeof(ipv6_addr_t));
        if (!result) return NULL;
        *result = ipv6_to_int(netmask_str);
        if (result->high == 0 && result->low == 0 && strcmp(netmask_str, "::") != 0) {
            printf("Error: Invalid IPv6 netmask\n");
            free(result);
            return NULL;
        }
        // FIXED: Added netmask contiguity validation
        if (!is_contiguous_netmask_ipv6(result)) {
            printf("Error: IPv6 netmask must be contiguous\n");
            free(result);
            return NULL;
        }
        // Calculate prefix length
        *prefix_len = 0;
        for (int i = 0; i < 64; i++) {
            if (result->high & (1ULL << (63 - i))) (*prefix_len)++;
            else break;
        }
        if (*prefix_len == 64) {
            for (int i = 0; i < 64; i++) {
                if (result->low & (1ULL << (63 - i))) (*prefix_len)++;
                else break;
            }
        }
        return result;
    }
    if (is_binary_string(netmask_str, version)) {
        void* result = binary_to_int(netmask_str, version);
        if (!result) return NULL;
        // Validate contiguity
        if (version == 4) {
            if (!is_contiguous_netmask_ipv4(*(uint32_t*)result)) {
                printf("Error: IPv4 netmask must be contiguous\n");
                free(result);
                return NULL;
            }
            // Calculate prefix length
            *prefix_len = 0;
            for (int i = 0; i < 32; i++) {
                if (*(uint32_t*)result & (1U << (31 - i))) (*prefix_len)++;
                else break;
            }
        } else {
            if (!is_contiguous_netmask_ipv6((ipv6_addr_t*)result)) {
                printf("Error: IPv6 netmask must be contiguous\n");
                free(result);
                return NULL;
            }
        }
        return result;
    }
    if (is_valid_hex(netmask_str, version)) {
        if (version == 4) {
            uint32_t* result = malloc(sizeof(uint32_t));
            if (!result) return NULL;
            *result = (uint32_t)strtoul(netmask_str + 2, NULL, 16);
            // FIXED: Added netmask contiguity validation
            if (!is_contiguous_netmask_ipv4(*result)) {
                printf("Error: IPv4 netmask must be contiguous\n");
                free(result);
                return NULL;
            }
            // Calculate prefix length
            *prefix_len = 0;
            for (int i = 0; i < 32; i++) {
                if (*result & (1U << (31 - i))) (*prefix_len)++;
                else break;
            }
            return result;
        } else {
            ipv6_addr_t* result = malloc(sizeof(ipv6_addr_t));
            if (!result) return NULL;
            
            // FIXED: Properly parse IPv6 hex netmasks (same fix as for IP addresses)
            char* hex_part = strdup(netmask_str + 2);
            int len = strlen(hex_part);
            char padded[33] = {0};
            int pad_count = 32 - len;
            for (int i = 0; i < pad_count; i++) {
                padded[i] = '0';
            }
            strcat(padded, hex_part);
            free(hex_part);
            
            char high_str[17] = {0};
            strncpy(high_str, padded, 16);
            result->high = strtoull(high_str, NULL, 16);
            
            char low_str[17] = {0};
            strncpy(low_str, padded + 16, 16);
            result->low = strtoull(low_str, NULL, 16);
            
            // Validate contiguity
            if (!is_contiguous_netmask_ipv6(result)) {
                printf("Error: IPv6 netmask must be contiguous\n");
                free(result);
                return NULL;
            }
            // Calculate prefix length
            *prefix_len = 0;
            for (int i = 0; i < 64; i++) {
                if (result->high & (1ULL << (63 - i))) (*prefix_len)++;
                else break;
            }
            if (*prefix_len == 64) {
                for (int i = 0; i < 64; i++) {
                    if (result->low & (1ULL << (63 - i))) (*prefix_len)++;
                    else break;
                }
            }
            return result;
        }
    }
    if (version == 4) {
        uint32_t* result = malloc(sizeof(uint32_t));
        if (!result) return NULL;
        *result = ipv4_to_int(netmask_str);
        if (*result == 0 && strcmp(netmask_str, "0.0.0.0") != 0) {
            printf("Error: Invalid netmask\n");
            free(result);
            return NULL;
        }
        // FIXED: Added netmask contiguity validation
        if (!is_contiguous_netmask_ipv4(*result)) {
            printf("Error: IPv4 netmask must be contiguous\n");
            free(result);
            return NULL;
        }
        // Calculate prefix length
        *prefix_len = 0;
        for (int i = 0; i < 32; i++) {
            if (*result & (1U << (31 - i))) (*prefix_len)++;
            else break;
        }
        return result;
    }
    printf("Error: Invalid netmask format\n");
    return NULL;
}

// Calculate subnet information
void calculate_subnet(const char* ip_str, const char* netmask_str, subnet_info_t* info) {
    info->ip = info->netmask = info->network = info->broadcast = NULL;
    info->prefix_len = 0;
    info->version = 0;
    mpz_init(info->total_hosts);
    mpz_init(info->usable_hosts);
    
    info->ip = parse_ip_address(ip_str, &info->version, &info->is_multicast, &info->is_unique_local);
    if (!info->ip) return;
    
    info->netmask = parse_netmask(netmask_str, info->version, &info->prefix_len);
    if (!info->netmask) {
        free(info->ip);
        info->ip = NULL;
        return;
    }
    
    // Calculate network and broadcast/last address
    if (info->version == 4) {
        info->network = malloc(sizeof(uint32_t));
        info->broadcast = malloc(sizeof(uint32_t));
        if (!info->network || !info->broadcast) {
            free(info->ip);
            free(info->netmask);
            free(info->network);
            free(info->broadcast);
            info->ip = info->netmask = info->network = info->broadcast = NULL;
            return;
        }
        *(uint32_t*)info->network = *(uint32_t*)info->ip & *(uint32_t*)info->netmask;
        *(uint32_t*)info->broadcast = *(uint32_t*)info->network | (~*(uint32_t*)info->netmask);
        
        mpz_set_ui(info->total_hosts, 1ULL << (32 - info->prefix_len));
        if (info->prefix_len <= 30) {
            mpz_sub_ui(info->usable_hosts, info->total_hosts, 2);
        } else {
            mpz_set_ui(info->usable_hosts, info->prefix_len == 31 ? 2 : 1);
        }
    } else {
        info->network = malloc(sizeof(ipv6_addr_t));
        info->broadcast = malloc(sizeof(ipv6_addr_t));
        if (!info->network || !info->broadcast) {
            free(info->ip);
            free(info->netmask);
            free(info->network);
            free(info->broadcast);
            info->ip = info->netmask = info->network = info->broadcast = NULL;
            return;
        }
        ipv6_addr_t* ip = (ipv6_addr_t*)info->ip;
        ipv6_addr_t* mask = (ipv6_addr_t*)info->netmask;
        ipv6_addr_t* net = (ipv6_addr_t*)info->network;
        ipv6_addr_t* brd = (ipv6_addr_t*)info->broadcast;
        net->high = ip->high & mask->high;
        net->low = ip->low & mask->low;
        brd->high = net->high | (~mask->high);
        brd->low = net->low | (~mask->low);
        
        mpz_ui_pow_ui(info->total_hosts, 2, 128 - info->prefix_len);
        if (info->prefix_len == 128) {
            mpz_set_ui(info->usable_hosts, 1);
        } else {
            mpz_sub_ui(info->usable_hosts, info->total_hosts, 1);
        }
    }
}

// Print subnet information
void print_subnet_info(subnet_info_t* info) {
    if (!info->ip || !info->netmask) {
        return;
    }
    
    char ip_str[IP_STR_LEN], netmask_str[IP_STR_LEN], network_str[IP_STR_LEN], broadcast_str[IP_STR_LEN];
    char ip_hex[IP_HEX_LEN], netmask_hex[IP_HEX_LEN], network_hex[IP_HEX_LEN], broadcast_hex[IP_HEX_LEN];
    char temp_bin[IP_BIN_LEN];
    
    int_to_ip(info->ip, info->version, ip_str);
    int_to_ip(info->netmask, info->version, netmask_str);
    int_to_ip(info->network, info->version, network_str);
    int_to_ip(info->broadcast, info->version, broadcast_str);
    int_to_hex(info->ip, info->version, ip_hex);
    int_to_hex(info->netmask, info->version, netmask_hex);
    int_to_hex(info->network, info->version, network_hex);
    int_to_hex(info->broadcast, info->version, broadcast_hex);
    
    printf("--- %s Information ---\n", info->version == 4 ? "IPv4" : "IPv6");
    if (info->is_multicast) {
        printf("Note: This is a multicast address\n");
    }
    if (info->is_unique_local) {
        printf("Note: This is a unique local address\n");
    }
    printf("1. IP Address:            %s", ip_str);
    if (info->show_binary) {
        int_to_binary(info->ip, info->version, temp_bin, 1);
        printf(" (%s)", temp_bin);
    }
    printf("\n   Decimal:               %s", ip_str);
    printf("\n   Hex:                   %s", ip_hex);
    int_to_binary(info->ip, info->version, temp_bin, 0);
    printf("\n   Binary:                %s", temp_bin);
    int_to_binary(info->ip, info->version, temp_bin, 1);
    printf("\n   Binary (dotted):       %s", temp_bin);
    printf("\n\n");
    
    printf("2. Netmask:               %s (/%d)", netmask_str, info->prefix_len);
    if (info->show_binary) {
        int_to_binary(info->netmask, info->version, temp_bin, 1);
        printf(" (%s)", temp_bin);
    }
    printf("\n   Decimal:               %s", netmask_str);
    printf("\n   Hex:                   %s", netmask_hex);
    int_to_binary(info->netmask, info->version, temp_bin, 0);
    printf("\n   Binary:                %s", temp_bin);
    int_to_binary(info->netmask, info->version, temp_bin, 1);
    printf("\n   Binary (dotted):       %s", temp_bin);
    printf("\n   CIDR:                  /%d", info->prefix_len);
    printf("\n\n");
    
    printf("Network Address:          %s", network_str);
    if (info->show_binary) {
        int_to_binary(info->network, info->version, temp_bin, 1);
        printf(" (%s)", temp_bin);
    }
    printf("\n   Hex:                   %s", network_hex);
    printf("\n\n");
    
    printf("%s Address:        %s", info->version == 4 ? "Broadcast" : "Last", broadcast_str);
    if (info->show_binary) {
        int_to_binary(info->broadcast, info->version, temp_bin, 1);
        printf(" (%s)", temp_bin);
    }
    printf("\n   Hex:                   %s", broadcast_hex);
    printf("\n\n");
    
    gmp_printf("Total Addresses:          %Zd\n", info->total_hosts);
    gmp_printf("Usable Hosts:             %Zd\n", info->usable_hosts);
    printf("Host Range:               ");
    
    if (mpz_cmp_ui(info->usable_hosts, 0) > 0) {
        char first_host[IP_STR_LEN], last_host[IP_STR_LEN];
        char first_hex[IP_HEX_LEN], last_hex[IP_HEX_LEN];
        void* first = malloc(info->version == 4 ? sizeof(uint32_t) : sizeof(ipv6_addr_t));
        void* last = malloc(info->version == 4 ? sizeof(uint32_t) : sizeof(ipv6_addr_t));
        if (!first || !last) {
            free(first);
            free(last);
            return;
        }
        if (info->version == 4) {
            *(uint32_t*)first = *(uint32_t*)info->network + 1;
            *(uint32_t*)last = *(uint32_t*)info->broadcast - 1;
        } else {
            // FIXED: IPv6 host range overflow handling
            ipv6_addr_t* net = (ipv6_addr_t*)info->network;
            ipv6_addr_t* brd = (ipv6_addr_t*)info->broadcast;
            ipv6_addr_t* f = (ipv6_addr_t*)first;
            ipv6_addr_t* l = (ipv6_addr_t*)last;
            
            // Calculate first host (network + 1)
            f->high = net->high;
            f->low = net->low;
            if (net->low == UINT64_MAX) {
                f->high++;
                f->low = 0;
            } else {
                f->low++;
            }
            
            // Calculate last host (broadcast - 1)  
            l->high = brd->high;
            l->low = brd->low;
            if (brd->low == 0) {
                l->high--;
                l->low = UINT64_MAX;
            } else {
                l->low--;
            }
        }
        int_to_ip(first, info->version, first_host);
        int_to_ip(last, info->version, last_host);
        int_to_hex(first, info->version, first_hex);
        int_to_hex(last, info->version, last_hex);
        printf("%s - %s", first_host, last_host);
        
        if (info->show_binary) {
            char first_bin[IP_BIN_LEN], last_bin[IP_BIN_LEN];
            int_to_binary(first, info->version, first_bin, 1);
            int_to_binary(last, info->version, last_bin, 1);
            printf("\n   Binary:                %s - %s", first_bin, last_bin);
        }
        printf("\n   Hex:                   %s - %s", first_hex, last_hex);
        printf("\n");
        free(first);
        free(last);
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
    printf("  IPv4 Dotted decimal:   192.168.1.100\n");
    printf("  IPv4-Mapped IPv6:      ::ffff:192.168.1.1\n");
    printf("  IPv6:                  2001:db8::1\n");
    printf("  Binary:                11000000101010000000000101100100\n");
    printf("  Binary (dotted):       11000000.10101000.00000001.01100100\n");
    printf("  Hexadecimal:           0xc0a80164\n\n");
    printf("Netmask formats supported (optional, defaults to /32 or /128):\n");
    printf("  CIDR notation:         /24, /64\n");
    printf("  Decimal notation:      255.255.255.0\n");
    printf("  IPv6 netmask:          ffff:ffff:ffff:ffff::\n");
    printf("  Hexadecimal:           0xffffff00\n");
    printf("  Binary:                11111111111111111111111100000000\n");
    printf("  Binary (dotted):       11111111.11111111.11111111.00000000\n\n");
    printf("Examples:\n");
    printf("  %s 192.168.1.100 /24\n", program_name);
    printf("  %s -b ::ffff:192.168.1.1 /112\n", program_name);
    printf("  %s 2001:db8::1 /64\n", program_name);
    printf("  %s fe80::1%%eth0 /10\n", program_name);
}

int main(int argc, char* argv[]) {
    int show_binary = 0;
    int arg_start = 1;
    
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
    
    calculate_subnet(argv[arg_start], argc > arg_start + 1 ? argv[arg_start + 1] : NULL, &info);
    
    print_subnet_info(&info);
    
    if (info.ip) free(info.ip);
    if (info.netmask) free(info.netmask);
    if (info.network) free(info.network);
    if (info.broadcast) free(info.broadcast);
    mpz_clear(info.total_hosts);
    mpz_clear(info.usable_hosts);
    
    return 0;
}
