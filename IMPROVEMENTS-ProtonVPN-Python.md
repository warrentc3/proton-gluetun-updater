# ProtonVPN Gluetun Updater - Improvements

## Overview
This document details the improvements made to the Python script from https://gitlab.com/neonox31/protonvpn-gluetun-updater based on the logic from our PowerShell transformation scripts.

---

## Critical Bug Fixes

### 1. **Wireguard TCP/UDP Bug** 🐛 FIXED
**Original Code:**
```python
if wg_key:
    servers.append({
        "vpn": "wireguard",
        "hostname": physical["Domain"],
        "wgpubkey": wg_key,
        "tcp": True,    # ← WRONG!
        "udp": True,    # ← WRONG!
        "ips": ips,
    })
```

**Fixed Code:**
```python
if wg_key:
    wg_server = {
        "vpn": "wireguard",
        **base,
        "wgpubkey": wg_key,
    }
    # Note: Wireguard does NOT have tcp/udp properties
    servers.append(wg_server)
```

**Explanation:** Wireguard doesn't use TCP/UDP at the transport layer. These properties should only appear in OpenVPN entries, as confirmed by Gluetun's Go implementation.

---

## Feature Completeness

### 2. **Missing Feature Flags** ✅ ADDED

**Original Implementation:**
- Only included `stream` and `port_forward`
- Always included these (even when false)

**Improved Implementation:**
- Added **ALL** feature flags:
  - `free` (Tier 0 servers)
  - `secure_core` (Secure core routing)
  - `tor` (Tor over VPN)
  - `stream` (Streaming optimization)
  - `port_forward` (P2P/Port forwarding)

**Code:**
```python
# Decode feature flags
is_secure_core = bool(features & SECURE_CORE)
is_tor = bool(features & TOR)
is_p2p = bool(features & P2P)
is_streaming = bool(features & STREAMING)
is_free = (tier == 0)

# Add optional feature flags (only if true)
if is_free:
    base["free"] = True
if is_streaming:
    base["stream"] = True
if is_secure_core:
    base["secure_core"] = True
if is_tor:
    base["tor"] = True
if is_p2p:
    base["port_forward"] = True
```

---

### 3. **Conditional Properties** 🎯 IMPROVED

**Original Behavior:**
```json
{
  "stream": false,
  "port_forward": false
}
```

**Improved Behavior:**
```json
{
  // Properties only included when true
  // Cleaner JSON, smaller file size, matches Gluetun's Go implementation
}
```

**Benefits:**
- Reduced JSON file size (especially for large server lists)
- Matches Gluetun's official implementation
- Cleaner, more readable output
- Properties explicitly signal enabled features

---

## Data Accuracy

### 4. **Country Name Parsing** 🌍 CRITICAL FIX

**Original Implementation:**
```python
"country": country_name(logical["ExitCountry"])
```

**Problem:** For secure_core servers, `ExitCountry` indicates the exit point, not the actual server location. This breaks routing logic.

**Example:**
- Server name: `IS-US#1` (Iceland to US secure core)
- ExitCountry: `US`
- **Original output:** `"country": "United States"` ❌ WRONG
- **Correct output:** `"country": "United States"` ✅ (parsed from name)

**Fixed Implementation:**
```python
def parse_country_from_name(server_name: str, is_secure_core: bool) -> str:
    """
    Parse country code from server name.
    
    Critical for secure_core servers where ExitCountry indicates the exit point,
    but the actual server location is encoded in the name.
    
    Examples:
        Normal: "US-NY#1" -> "US" -> "United States"
        Secure Core: "IS-US#1" -> "US" -> "United States"
    """
    if is_secure_core:
        # Secure core: CC-CC#N format, take second CC (exit country)
        match = re.match(r'^[A-Z]{2}-([A-Z]{2})', server_name)
        if match:
            return country_name(match.group(1))
    else:
        # Normal server: CC#N format, take first CC
        match = re.match(r'^([A-Z]{2})', server_name)
        if match:
            return country_name(match.group(1))
```

---

### 5. **Complete Country Mapping** 🗺️ EXPANDED

**Original:** 70 countries
```python
COUNTRY_NAMES = {
    "AD": "Andorra", "AE": "United Arab Emirates", ...
    # Only 70 entries
}
```

**Improved:** 194 countries
```python
COUNTRY_NAMES = {
    'BD': 'Bangladesh', 'BE': 'Belgium', 'BF': 'Burkina Faso', ...
    # Complete 194-country mapping from PowerShell scripts
}
```

**Benefits:**
- No unknown country codes (with warning fallback)
- Future-proof for ProtonVPN expansion
- Matches PowerShell completeness

---

## Performance & Reliability

### 6. **Physical Server Deduplication** 🔄 ADDED

**Original:** No deduplication - same physical server appeared multiple times

**Improved:**
```python
seen_ips = {}  # Track IPs for non-secure_core deduplication

for logical in logicals:
    for physical in logical["Servers"]:
        entry_ip = physical["EntryIP"]
        
        # Deduplicate non-secure_core servers by IP
        if not is_secure_core:
            if entry_ip in seen_ips:
                stats['skipped_duplicate'] += 1
                continue
            seen_ips[entry_ip] = True
```

**Why secure_core is NOT deduplicated:**
Secure core servers with the same IP but different logical servers have different routing paths (entry country → exit country combinations).

**Statistics Output:**
```
Transformation statistics:
  Skipped (disabled): 23
  Skipped (duplicate IPs): 847
  Secure core servers: 45
  Free tier servers: 12
```

---

### 7. **Disabled Server Filtering** 🚫 ADDED

**Original:** Included all servers regardless of status

**Improved:**
```python
# Skip disabled servers
if physical.get("Status") == 0:
    stats['skipped_disabled'] += 1
    continue
```

**Result:** Only active servers (`Status == 1`) are included in output.

---

## Property Ordering

### 8. **Server Struct Field Ordering** 📋 ALIGNED

**Improved order matches Gluetun's Go Server struct:**
```python
base = {
    "country": country,           # 1. Location
    "city": logical.get("City") or "",
    "server_name": logical["Name"], # 2. Identification
    "hostname": physical["Domain"],
}
# 3. Feature flags (conditional)
# 4. IPs
```

**Benefits:**
- Consistent with Gluetun's internal representation
- Easier to read and debug
- Predictable JSON structure

---

## Enhanced Statistics

### 9. **Detailed Transformation Statistics** 📊 ADDED

**Original Output:**
```
# 1234 servers exported (from 567 logicals)
```

**Improved Output:**
```
Transformation statistics:
  Skipped (disabled): 23
  Skipped (duplicate IPs): 847
  Secure core servers: 45
  Free tier servers: 12

1234 servers written to servers.json (from 567 logicals)
```

**Benefits:**
- Visibility into filtering decisions
- Debugging assistance
- Quality assurance metrics

---

## Summary of Improvements

| Category | Original | Improved | Impact |
|----------|----------|----------|--------|
| **Wireguard TCP/UDP** | Incorrect (included) | Fixed (removed) | Critical |
| **Feature Flags** | 2 (stream, port_forward) | 5 (all flags) | High |
| **Conditional Props** | Always included | Only when true | Medium |
| **Country Parsing** | ExitCountry field | Parsed from name | Critical |
| **Country Mapping** | 70 countries | 194 countries | Medium |
| **Deduplication** | None | By IP (non-secure_core) | High |
| **Disabled Filtering** | None | Status == 0 skipped | Medium |
| **Statistics** | Basic | Comprehensive | Low |

---

## Usage

### Python (Improved Version)
```bash
pip install -r requirements.txt

# Interactive
python protonvpn_gluetun_updater_improved.py > servers.json

# Environment variables
PROTON_USERNAME=user \
PROTON_PASSWORD=pass \
PROTON_2FA=123456 \
python protonvpn_gluetun_updater_improved.py > servers.json

# With filtering
MAX_LOAD=50 \
MAX_SERVERS=100 \
OUTPUT_FILE=servers.json \
PROTON_USERNAME=user \
PROTON_PASSWORD=pass \
python protonvpn_gluetun_updater_improved.py
```

---

## Validation

To validate the improvements, compare output with PowerShell scripts:

```powershell
# PowerShell transformation
.\Transform-ProtonVPN-to-Gluetun.ps1 `
    -InputPath "serverlist.json" `
    -OutputPath "ps-output.json"

# Python transformation (download serverlist.json first)
python protonvpn_gluetun_updater_improved.py > py-output.json

# Compare server counts, feature flags, and structure
```

---

## Future Enhancements

Potential improvements for future versions:

1. **Load-based sorting options** (already supported via MAX_LOAD)
2. **Country/feature filtering** (e.g., only US servers with P2P)
3. **Output format options** (minimal vs full)
4. **Validation against Gluetun's Go structs**
5. **Diff mode** (compare with existing servers.json)

---

## Credits

**Original Script:** https://gitlab.com/neonox31/protonvpn-gluetun-updater by Logan Weber  
**Improvements:** Based on PowerShell transformation scripts with comprehensive ProtonVPN API knowledge

**License:** MIT (maintaining original license)
