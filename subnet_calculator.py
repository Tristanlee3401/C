#!/usr/bin/env python3
"""
IPv4 Subnet Calculator
A command line tool to subnet IPv4 networks into a specified number of subnets.
"""

import ipaddress
import math
import sys


def validate_network(network_str):
    """Validate and parse the network input."""
    try:
        network = ipaddress.IPv4Network(network_str, strict=False)
        return network
    except ipaddress.AddressValueError:
        print(f"Error: Invalid network address '{network_str}'")
        return None
    except ipaddress.NetmaskValueError:
        print(f"Error: Invalid subnet mask in '{network_str}'")
        return None
    except ValueError as e:
        print(f"Error: {e}")
        return None


def calculate_subnet_bits(num_subnets):
    """Calculate the number of additional bits needed for subnetting."""
    if num_subnets <= 0:
        return None
    
    # Find the minimum number of bits needed
    # 2^n >= num_subnets
    subnet_bits = math.ceil(math.log2(num_subnets))
    return subnet_bits


def subnet_network(network, num_subnets):
    """Subnet the given network into the specified number of subnets."""
    # Calculate required subnet bits
    subnet_bits = calculate_subnet_bits(num_subnets)
    if subnet_bits is None:
        return None
    
    # Calculate new prefix length
    new_prefix_length = network.prefixlen + subnet_bits
    
    # Check if we have enough bits available
    if new_prefix_length > 30:  # Leave at least 2 bits for host addresses
        print(f"Error: Cannot create {num_subnets} subnets from {network}")
        print(f"Not enough host bits available (would need /{new_prefix_length})")
        return None
    
    # Calculate actual number of subnets we can create
    actual_subnets = 2 ** subnet_bits
    
    # Calculate hosts per subnet
    host_bits = 32 - new_prefix_length
    hosts_per_subnet = (2 ** host_bits) - 2  # Subtract network and broadcast
    
    # Generate subnets
    subnets = list(network.subnets(new_prefix=new_prefix_length))
    
    return {
        'subnets': subnets[:num_subnets],  # Return only requested number
        'subnet_bits': subnet_bits,
        'new_prefix_length': new_prefix_length,
        'hosts_per_subnet': hosts_per_subnet,
        'actual_subnets': actual_subnets
    }


def display_results(original_network, num_requested, result):
    """Display the subnetting results in a formatted manner."""
    print("\n" + "="*60)
    print(f"SUBNET CALCULATION RESULTS")
    print("="*60)
    
    print(f"Original Network:     {original_network}")
    print(f"Requested Subnets:    {num_requested}")
    print(f"Subnet Bits Borrowed: {result['subnet_bits']}")
    print(f"New Subnet Mask:      /{result['new_prefix_length']} ({ipaddress.IPv4Network(f'0.0.0.0/{result["new_prefix_length"]}').netmask})")
    print(f"Hosts per Subnet:     {result['hosts_per_subnet']}")
    print(f"Total Subnets Created: {result['actual_subnets']}")
    
    print(f"\nSUBNET ADDRESSES:")
    print("-" * 60)
    
    for i, subnet in enumerate(result['subnets'], 1):
        network_addr = subnet.network_address
        broadcast_addr = subnet.broadcast_address
        first_host = network_addr + 1
        last_host = broadcast_addr - 1
        
        print(f"{i:2d}. {subnet}")
        print(f"    Network:    {network_addr}")
        print(f"    Broadcast:  {broadcast_addr}")
        print(f"    Host Range: {first_host} - {last_host}")
        print()


def get_user_input():
    """Get network and number of subnets from user input."""
    while True:
        try:
            # Get network input
            network_input = input("Enter IPv4 network (e.g., 192.168.1.0/24): ").strip()
            if not network_input:
                print("Please enter a network address.")
                continue
            
            network = validate_network(network_input)
            if network is None:
                continue
            
            # Get number of subnets
            num_subnets_input = input("Enter number of subnets needed: ").strip()
            if not num_subnets_input:
                print("Please enter the number of subnets.")
                continue
            
            try:
                num_subnets = int(num_subnets_input)
                if num_subnets <= 0:
                    print("Number of subnets must be positive.")
                    continue
            except ValueError:
                print("Please enter a valid number.")
                continue
            
            return network, num_subnets
            
        except KeyboardInterrupt:
            print("\n\nExiting...")
            sys.exit(0)
        except EOFError:
            print("\n\nExiting...")
            sys.exit(0)


def main():
    """Main program function."""
    print("IPv4 Subnet Calculator")
    print("=" * 30)
    print("This tool helps you subnet IPv4 networks into smaller subnets.")
    print("Press Ctrl+C to exit at any time.\n")
    
    while True:
        try:
            # Get user input
            network, num_subnets = get_user_input()
            
            # Calculate subnets
            result = subnet_network(network, num_subnets)
            
            if result is not None:
                # Display results
                display_results(network, num_subnets, result)
            
            # Ask if user wants to continue
            print("-" * 60)
            continue_choice = input("Calculate another subnet? (y/n): ").strip().lower()
            if continue_choice not in ['y', 'yes']:
                break
            print()
            
        except KeyboardInterrupt:
            print("\n\nExiting...")
            break
        except Exception as e:
            print(f"An unexpected error occurred: {e}")
            continue
    
    print("Thank you for using the IPv4 Subnet Calculator!")


if __name__ == "__main__":
    main()
