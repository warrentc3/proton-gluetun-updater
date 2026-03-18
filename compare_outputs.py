#!/usr/bin/env python3
"""
Compare original vs improved ProtonVPN Gluetun transformer output.

Usage:
    python compare_outputs.py original.json improved.json
"""
import json
import sys
from collections import defaultdict


def analyze_servers(data):
    """Analyze server list and return statistics."""
    servers = data.get("protonvpn", {}).get("servers", [])
    
    stats = {
        'total': len(servers),
        'openvpn': 0,
        'wireguard': 0,
        'wireguard_with_tcp_udp': 0,  # Bug indicator
        'has_free': 0,
        'has_secure_core': 0,
        'has_tor': 0,
        'has_stream': 0,
        'has_port_forward': 0,
        'countries': set(),
        'false_flags': 0,  # Properties explicitly set to false
    }
    
    for server in servers:
        vpn = server.get("vpn", "")
        if vpn == "openvpn":
            stats['openvpn'] += 1
        elif vpn == "wireguard":
            stats['wireguard'] += 1
            # Check for bug: Wireguard shouldn't have tcp/udp
            if 'tcp' in server or 'udp' in server:
                stats['wireguard_with_tcp_udp'] += 1
        
        # Count feature flags
        if server.get("free"):
            stats['has_free'] += 1
        if server.get("secure_core"):
            stats['has_secure_core'] += 1
        if server.get("tor"):
            stats['has_tor'] += 1
        if server.get("stream"):
            stats['has_stream'] += 1
        if server.get("port_forward"):
            stats['has_port_forward'] += 1
        
        # Count false flags (should be omitted)
        for flag in ['free', 'secure_core', 'tor', 'stream', 'port_forward']:
            if flag in server and server[flag] is False:
                stats['false_flags'] += 1
        
        stats['countries'].add(server.get("country", "UNKNOWN"))
    
    return stats


def compare_files(original_path, improved_path):
    """Compare two server files and report differences."""
    with open(original_path) as f:
        original = json.load(f)
    
    with open(improved_path) as f:
        improved = json.load(f)
    
    print("=" * 80)
    print("ProtonVPN Gluetun Transformer Comparison")
    print("=" * 80)
    
    # Version comparison
    orig_ver = original.get("protonvpn", {}).get("version")
    impr_ver = improved.get("protonvpn", {}).get("version")
    print(f"\nProtonVPN Object Version:")
    print(f"  Original: {orig_ver}")
    print(f"  Improved: {impr_ver}")
    if orig_ver != impr_ver:
        print(f"  ⚠️  Version mismatch!")
    
    # Analyze both
    orig_stats = analyze_servers(original)
    impr_stats = analyze_servers(improved)
    
    print("\n" + "=" * 80)
    print("SERVER COUNTS")
    print("=" * 80)
    
    print(f"\nTotal Servers:")
    print(f"  Original: {orig_stats['total']}")
    print(f"  Improved: {impr_stats['total']}")
    print(f"  Difference: {impr_stats['total'] - orig_stats['total']:+d}")
    
    print(f"\nOpenVPN Entries:")
    print(f"  Original: {orig_stats['openvpn']}")
    print(f"  Improved: {impr_stats['openvpn']}")
    
    print(f"\nWireguard Entries:")
    print(f"  Original: {orig_stats['wireguard']}")
    print(f"  Improved: {impr_stats['wireguard']}")
    
    print("\n" + "=" * 80)
    print("BUG DETECTION")
    print("=" * 80)
    
    print(f"\n🐛 Wireguard with TCP/UDP (WRONG):")
    print(f"  Original: {orig_stats['wireguard_with_tcp_udp']}")
    print(f"  Improved: {impr_stats['wireguard_with_tcp_udp']}")
    if orig_stats['wireguard_with_tcp_udp'] > 0 and impr_stats['wireguard_with_tcp_udp'] == 0:
        print(f"  ✅ BUG FIXED!")
    
    print(f"\n❌ Properties explicitly set to false (should be omitted):")
    print(f"  Original: {orig_stats['false_flags']}")
    print(f"  Improved: {impr_stats['false_flags']}")
    if orig_stats['false_flags'] > 0 and impr_stats['false_flags'] == 0:
        print(f"  ✅ IMPROVED!")
    
    print("\n" + "=" * 80)
    print("FEATURE FLAGS")
    print("=" * 80)
    
    print(f"\nFree Tier Servers:")
    print(f"  Original: {orig_stats['has_free']}")
    print(f"  Improved: {impr_stats['has_free']}")
    if impr_stats['has_free'] > orig_stats['has_free']:
        print(f"  ✅ NOW DETECTED!")
    
    print(f"\nSecure Core Servers:")
    print(f"  Original: {orig_stats['has_secure_core']}")
    print(f"  Improved: {impr_stats['has_secure_core']}")
    if impr_stats['has_secure_core'] > orig_stats['has_secure_core']:
        print(f"  ✅ NOW DETECTED!")
    
    print(f"\nTor Servers:")
    print(f"  Original: {orig_stats['has_tor']}")
    print(f"  Improved: {impr_stats['has_tor']}")
    if impr_stats['has_tor'] > orig_stats['has_tor']:
        print(f"  ✅ NOW DETECTED!")
    
    print(f"\nStreaming Servers:")
    print(f"  Original: {orig_stats['has_stream']}")
    print(f"  Improved: {impr_stats['has_stream']}")
    
    print(f"\nPort Forward Servers:")
    print(f"  Original: {orig_stats['has_port_forward']}")
    print(f"  Improved: {impr_stats['has_port_forward']}")
    
    print("\n" + "=" * 80)
    print("COUNTRY COVERAGE")
    print("=" * 80)
    
    print(f"\nUnique Countries:")
    print(f"  Original: {len(orig_stats['countries'])}")
    print(f"  Improved: {len(impr_stats['countries'])}")
    
    # Show countries only in one or the other
    only_orig = orig_stats['countries'] - impr_stats['countries']
    only_impr = impr_stats['countries'] - orig_stats['countries']
    
    if only_orig:
        print(f"\n  Only in Original: {', '.join(sorted(only_orig))}")
    if only_impr:
        print(f"\n  Only in Improved: {', '.join(sorted(only_impr))}")
    
    print("\n" + "=" * 80)
    print("SUMMARY")
    print("=" * 80)
    
    issues_fixed = []
    if orig_stats['wireguard_with_tcp_udp'] > 0 and impr_stats['wireguard_with_tcp_udp'] == 0:
        issues_fixed.append("Wireguard TCP/UDP bug")
    if impr_stats['has_free'] > orig_stats['has_free']:
        issues_fixed.append("Free tier detection")
    if impr_stats['has_secure_core'] > orig_stats['has_secure_core']:
        issues_fixed.append("Secure core detection")
    if impr_stats['has_tor'] > orig_stats['has_tor']:
        issues_fixed.append("Tor detection")
    if orig_stats['false_flags'] > 0 and impr_stats['false_flags'] == 0:
        issues_fixed.append("Conditional properties")
    
    if issues_fixed:
        print("\n✅ Issues Fixed:")
        for issue in issues_fixed:
            print(f"  • {issue}")
    
    print("\n" + "=" * 80)


if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Usage: python compare_outputs.py original.json improved.json")
        sys.exit(1)
    
    compare_files(sys.argv[1], sys.argv[2])
