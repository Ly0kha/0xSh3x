#!/bin/bash

#═══════════════════════════════════════════════════════════════════════════════
#
#   ██████╗ ██╗  ██╗███████╗██╗  ██╗ ██████╗ ██╗  ██╗
#   ██╔═══██╗╚██╗██╔╝██╔════╝██║  ██║██╔════╝ ╚██╗██╔╝
#   ██║   ██║ ╚███╔╝ ███████╗███████║██║  ███╗ ╚███╔╝
#   ██║   ██║ ██╔██╗ ╚════██║██╔══██║██║   ██║ ██╔██╗
#   ╚██████╔╝██╔╝ ██╗███████║██║  ██║╚██████╔╝██╔╝ ██╗
#    ╚═════╝ ╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═╝
#
#  ═══════════════════════════════════════════════
#         0 X S H 3 X   R E C O N N A I S S A N C E
#  ═══════════════════════════════════════════════
#  Version: 1.0.0
#  By: Ly0kha
#
#═══════════════════════════════════════════════════════════════════════════════

set -o pipefail

VERSION="1.0.0"
AUTHOR="Ly0kha"
SCRIPT_NAME="0xsh3x"

#═══════════════════════════════════════════════════════════════════════════════
# STATE ISOLATION - PREVENTS TARGET CONTAMINATION
#═══════════════════════════════════════════════════════════════════════════════

# Nuclear cleanup - MUST run before every scan to prevent contamination
nuclear_cleanup() {
    echo -e "${CYAN}Cleaning previous scan state...${RESET}"
    
    # ══════════════════════════════════════════════════════════════════════════
    # PHASE 1: RESET ALL GLOBAL VARIABLES
    # ══════════════════════════════════════════════════════════════════════════
    
    # Counters
    TOTAL_SUBDOMAINS=0
    LIVE_HOSTS=0
    DEAD_HOSTS=0
    TOTAL_ENDPOINTS=0
    INTERESTING_FINDINGS=0
    JS_FILES=0
    PARAMS_DISCOVERED=0
    SECRETS_FOUND=0
    
    # Booleans
    WORDPRESS_DETECTED=false
    SCAN_RUNNING=false
    SKIP_CURRENT_PHASE=false
    
    # Strings
    WORDPRESS_HOSTS_FILE=""
    PHASE_NAME=""
    TOR_EXIT_IP=""
    CURRENT_TARGET=""
    
    # OpSec counters
    OPSEC_TOTAL_REQUESTS=0
    OPSEC_RATE_LIMITS=0
    OPSEC_CONNECTION_FAILURES=0
    OPSEC_CIRCUIT_CHANGES=0
    TOR_REQUESTS_COUNT=0
    REQUEST_COUNT=0
    BACKOFF_LEVEL=0
    
    # Circuit breaker
    CIRCUIT_BREAKER_OPEN=false
    CIRCUIT_BREAKER_FAILURES=0
    
    # ══════════════════════════════════════════════════════════════════════════
    # PHASE 2: PURGE ASSOCIATIVE ARRAYS
    # ══════════════════════════════════════════════════════════════════════════
    
    # Unset and redeclare associative arrays
    unset HOST_LAST_REQUEST 2>/dev/null
    unset PROXY_LAST_USED 2>/dev/null
    unset UA_CACHE 2>/dev/null
    declare -gA HOST_LAST_REQUEST=()
    declare -gA PROXY_LAST_USED=()
    declare -gA UA_CACHE=()
    
    # Reset proxy arrays
    PROXY_POOL=()
    PROXY_STATUS=()
    PROXY_FAIL_COUNT=()
    PROXY_SUCCESS_COUNT=()
    
    # Reset rate limit tracking
    RATE_LIMIT_WINDOW=()
    CURRENT_PROXY_INDEX=0
    
    # ══════════════════════════════════════════════════════════════════════════
    # PHASE 3: CLEAR TOOL CACHE DIRECTORIES
    # ══════════════════════════════════════════════════════════════════════════
    
    # httpx cache (causes cross-contamination)
    [[ -d "$HOME/.config/httpx" ]] && rm -rf "$HOME/.config/httpx/cache" 2>/dev/null
    
    # subfinder cache
    [[ -d "$HOME/.config/subfinder" ]] && rm -rf "$HOME/.config/subfinder/cache" 2>/dev/null
    
    # nuclei cache
    [[ -d "$HOME/.config/nuclei" ]] && rm -rf "$HOME/.config/nuclei/cache" 2>/dev/null
    
    # amass data
    [[ -d "$HOME/.config/amass" ]] && rm -rf "$HOME/.config/amass/data" 2>/dev/null
    
    # feroxbuster state files
    find "$HOME/.config/feroxbuster" -name "*.state" -delete 2>/dev/null
    
    # waybackurls cache
    [[ -d "$HOME/.cache/waybackurls" ]] && rm -rf "$HOME/.cache/waybackurls" 2>/dev/null
    
    # dnsx cache
    [[ -d "$HOME/.config/dnsx" ]] && rm -rf "$HOME/.config/dnsx" 2>/dev/null
    
    # ══════════════════════════════════════════════════════════════════════════
    # PHASE 4: CLEAN TEMP FILES
    # ══════════════════════════════════════════════════════════════════════════
    
    rm -f /tmp/0xsh3x_* 2>/dev/null
    rm -f /tmp/ferox_* 2>/dev/null
    rm -f /tmp/nuclei_* 2>/dev/null
    rm -f /tmp/httpx_* 2>/dev/null
    rm -f /tmp/subfinder_* 2>/dev/null
    rm -f /tmp/dnsx_* 2>/dev/null
    rm -f /tmp/masscan_* 2>/dev/null
    rm -f /tmp/nmap_* 2>/dev/null
    rm -f /tmp/*_wordlist.txt 2>/dev/null
    rm -f /tmp/*_targets.txt 2>/dev/null
    
    # ══════════════════════════════════════════════════════════════════════════
    # PHASE 5: KILL ORPHANED PROCESSES
    # ══════════════════════════════════════════════════════════════════════════
    
    pkill -f "subfinder.*-d" 2>/dev/null
    pkill -f "httpx.*-l" 2>/dev/null
    pkill -f "feroxbuster.*-u" 2>/dev/null
    pkill -f "nuclei.*-l" 2>/dev/null
    pkill -f "ffuf.*-u" 2>/dev/null
    pkill -f "masscan.*-iL" 2>/dev/null
    
    # ══════════════════════════════════════════════════════════════════════════
    # PHASE 6: FLUSH DNS CACHE
    # ══════════════════════════════════════════════════════════════════════════
    
    if command -v systemd-resolve &>/dev/null; then
        systemd-resolve --flush-caches 2>/dev/null
    elif command -v resolvectl &>/dev/null; then
        resolvectl flush-caches 2>/dev/null
    elif [[ "$(uname)" == "Darwin" ]]; then
        dscacheutil -flushcache 2>/dev/null
        killall -HUP mDNSResponder 2>/dev/null
    fi
    
    echo -e "${GREEN}✓${RESET} State cleaned"
}

# Validate and display target before scanning
validate_target_display() {
    local target="$1"
    local scope_type="$2"
    local output_dir="$3"
    
    echo ""
    echo -e "${CYAN}╔══════════════════════════════════════════════════════════════╗${RESET}"
    echo -e "${CYAN}║${RESET}  ${BOLD}SCAN STARTING IN 5 SECONDS${RESET}                                 ${CYAN}║${RESET}"
    echo -e "${CYAN}╠══════════════════════════════════════════════════════════════╣${RESET}"
    printf "${CYAN}║${RESET}  ${BOLD}Target:${RESET}  %-50s ${CYAN}║${RESET}\n" "$target"
    printf "${CYAN}║${RESET}  ${BOLD}Scope:${RESET}   %-50s ${CYAN}║${RESET}\n" "$scope_type"
    printf "${CYAN}║${RESET}  ${BOLD}Output:${RESET}  %-50s ${CYAN}║${RESET}\n" "$(basename "$output_dir")"
    echo -e "${CYAN}║${RESET}                                                              ${CYAN}║${RESET}"
    echo -e "${CYAN}║${RESET}  ${YELLOW}Press Ctrl+C to abort${RESET}                                      ${CYAN}║${RESET}"
    echo -e "${CYAN}╚══════════════════════════════════════════════════════════════╝${RESET}"
    echo ""
    
    # Countdown with ability to abort
    for i in 5 4 3 2 1; do
        printf "\r  ${DIM}Starting in ${BOLD}%d${RESET}${DIM}...${RESET}  " "$i"
        sleep 1
    done
    printf "\r                              \r"
    
    # Store current target for validation throughout scan
    CURRENT_TARGET="$target"
    
    echo ""
    echo -e "${GREEN}${BOLD}  ✓ CONFIRMED: Scanning $target${RESET}"
    echo ""
}

# Verify target hasn't been contaminated mid-scan
verify_target_integrity() {
    if [[ -n "$CURRENT_TARGET" ]] && [[ "$TARGET" != "$CURRENT_TARGET" ]]; then
        echo -e "${RED}╔══════════════════════════════════════════════════════════════╗${RESET}"
        echo -e "${RED}║  🚨 CRITICAL: TARGET CONTAMINATION DETECTED!                 ║${RESET}"
        echo -e "${RED}║  Expected: $CURRENT_TARGET${RESET}"
        echo -e "${RED}║  Found: $TARGET${RESET}"
        echo -e "${RED}║  ABORTING SCAN FOR SAFETY                                    ║${RESET}"
        echo -e "${RED}╚══════════════════════════════════════════════════════════════╝${RESET}"
        exit 1
    fi
}

#═══════════════════════════════════════════════════════════════════════════════
# 🌐 OPSEC IP VISIBILITY SYSTEM - TRACKS YOUR EXPOSURE
#═══════════════════════════════════════════════════════════════════════════════

# Store real IP at script start (for violation detection)
REAL_IP=""
PREVIOUS_IP=""
CACHED_IP=""
CACHED_IP_TIME=0
CACHED_IP_GEO=""
PHASE_START_TIME=0
PHASE_REQUESTS=0

# Get user's REAL IP (called once at script start, before any OpSec setup)
capture_real_ip() {
    REAL_IP=$(curl -s --max-time 5 https://api.ipify.org 2>/dev/null || \
              curl -s --max-time 5 https://ifconfig.me 2>/dev/null || \
              curl -s --max-time 5 https://icanhazip.com 2>/dev/null)
    
    if [[ -n "$REAL_IP" ]]; then
        echo -e "  ${DIM}📍 Your real IP: ${REAL_IP}${RESET}"
    fi
}

# Get current effective IP (through proxy/Tor)
get_effective_ip() {
    local current_time=$(date +%s)
    local cache_age=$((current_time - CACHED_IP_TIME))
    
    # Return cached IP if less than 60 seconds old
    if [[ -n "$CACHED_IP" ]] && [[ $cache_age -lt 60 ]]; then
        echo "$CACHED_IP"
        return 0
    fi
    
    local ip=""
    local geo=""
    
    # Determine how to make the request based on connection method
    case "$CONNECTION_METHOD" in
        tor)
            ip=$(curl -s --max-time 5 --proxy "$TOR_SOCKS_PROXY" https://api.ipify.org 2>/dev/null)
            ;;
        proxy)
            local proxy=$(get_next_proxy 2>/dev/null)
            if [[ -n "$proxy" ]]; then
                ip=$(curl -s --max-time 5 --proxy "$proxy" https://api.ipify.org 2>/dev/null)
            fi
            ;;
        direct|*)
            ip=$(curl -s --max-time 5 https://api.ipify.org 2>/dev/null)
            ;;
    esac
    
    # Fallback IP services
    if [[ -z "$ip" ]]; then
        ip=$(curl -s --max-time 5 https://ifconfig.me 2>/dev/null)
    fi
    
    if [[ -z "$ip" ]]; then
        echo "Unknown"
        return 1
    fi
    
    # Get geolocation (simple, non-blocking)
    geo=$(curl -s --max-time 3 "https://ipapi.co/${ip}/country_name" 2>/dev/null || echo "Unknown")
    
    # Cache the result
    CACHED_IP="$ip"
    CACHED_IP_GEO="$geo"
    CACHED_IP_TIME=$current_time
    
    # Check for IP change
    if [[ -n "$PREVIOUS_IP" ]] && [[ "$ip" != "$PREVIOUS_IP" ]]; then
        display_ip_change_alert "$PREVIOUS_IP" "$ip"
    fi
    PREVIOUS_IP="$ip"
    
    # Check for OpSec violation
    check_opsec_violation "$ip"
    
    echo "$ip"
}

# Display alert when IP changes
display_ip_change_alert() {
    local old_ip="$1"
    local new_ip="$2"
    
    ((OPSEC_CIRCUIT_CHANGES++))
    
    echo ""
    echo -e "${YELLOW}╔══════════════════════════════════════════════════════════════╗${RESET}"
    echo -e "${YELLOW}║${RESET}  ${BOLD}⚠️  IP ADDRESS CHANGED${RESET}                                     ${YELLOW}║${RESET}"
    echo -e "${YELLOW}╠══════════════════════════════════════════════════════════════╣${RESET}"
    printf "${YELLOW}║${RESET}  Old: %-54s ${YELLOW}║${RESET}\n" "$old_ip"
    printf "${YELLOW}║${RESET}  New: %-54s ${YELLOW}║${RESET}\n" "$new_ip"
    printf "${YELLOW}║${RESET}  Reason: %-51s ${YELLOW}║${RESET}\n" "$(get_ip_change_reason)"
    printf "${YELLOW}║${RESET}  Time: %-53s ${YELLOW}║${RESET}\n" "$(date '+%H:%M:%S')"
    echo -e "${YELLOW}╚══════════════════════════════════════════════════════════════╝${RESET}"
    echo ""
}

# Get reason for IP change
get_ip_change_reason() {
    case "$CONNECTION_METHOD" in
        tor)    echo "Tor circuit refresh" ;;
        proxy)  echo "Proxy rotation" ;;
        direct) echo "Network change (unexpected)" ;;
        *)      echo "Unknown" ;;
    esac
}

# Check if real IP is exposed (CRITICAL VIOLATION)
check_opsec_violation() {
    local current_ip="$1"
    
    # Only check if OpSec is enabled AND we have real IP
    if [[ "$CONNECTION_METHOD" == "direct" ]] || [[ -z "$REAL_IP" ]]; then
        return 0
    fi
    
    # If current IP matches real IP while using Tor/Proxy = VIOLATION
    if [[ "$current_ip" == "$REAL_IP" ]]; then
        echo ""
        echo -e "${RED}╔══════════════════════════════════════════════════════════════════════════════╗${RESET}"
        echo -e "${RED}║${RESET}  ${BOLD}🚨 CRITICAL OPSEC VIOLATION - SCAN ABORTED 🚨${RESET}                           ${RED}║${RESET}"
        echo -e "${RED}╠══════════════════════════════════════════════════════════════════════════════╣${RESET}"
        echo -e "${RED}║${RESET}                                                                              ${RED}║${RESET}"
        printf "${RED}║${RESET}  Your ${BOLD}REAL IP${RESET} is exposed: %-47s ${RED}║${RESET}\n" "$REAL_IP"
        echo -e "${RED}║${RESET}  Expected: Tor/Proxy IP                                                      ${RED}║${RESET}"
        echo -e "${RED}║${RESET}  Actual: Your real IP address                                                ${RED}║${RESET}"
        echo -e "${RED}║${RESET}                                                                              ${RED}║${RESET}"
        echo -e "${RED}║${RESET}  ${YELLOW}Possible Causes:${RESET}                                                          ${RED}║${RESET}"
        echo -e "${RED}║${RESET}  • Tor/Proxy connection lost                                                 ${RED}║${RESET}"
        echo -e "${RED}║${RESET}  • Tool bypassed proxy configuration                                         ${RED}║${RESET}"
        echo -e "${RED}║${RESET}  • DNS leak                                                                  ${RED}║${RESET}"
        echo -e "${RED}║${RESET}                                                                              ${RED}║${RESET}"
        echo -e "${RED}║${RESET}  ${BOLD}Scan terminated for your security.${RESET}                                        ${RED}║${RESET}"
        echo -e "${RED}╚══════════════════════════════════════════════════════════════════════════════╝${RESET}"
        echo ""
        exit 1
    fi
}

# Display OpSec banner at start of each phase
display_phase_opsec_banner() {
    local phase_name="$1"
    
    # Get current IP
    local current_ip=$(get_effective_ip)
    local geo="$CACHED_IP_GEO"
    [[ -z "$geo" ]] && geo="Unknown"
    
    # Get OpSec status string
    local opsec_status=""
    case "$CONNECTION_METHOD" in
        tor)
            opsec_status="🧅 Tor Circuit #$((OPSEC_CIRCUIT_CHANGES + 1))"
            ;;
        proxy)
            local proxy_count=${#PROXY_POOL[@]}
            opsec_status="🔀 Proxy Pool ($proxy_count proxies)"
            ;;
        direct)
            opsec_status="⚠️  Direct Connection (No OpSec)"
            ;;
    esac
    
    # Calculate phase duration if we have a start time
    local duration="00:00:00"
    if [[ $PHASE_START_TIME -gt 0 ]]; then
        local elapsed=$(($(date +%s) - PHASE_START_TIME))
        duration=$(printf "%02d:%02d:%02d" $((elapsed/3600)) $((elapsed%3600/60)) $((elapsed%60)))
    fi
    PHASE_START_TIME=$(date +%s)
    PHASE_REQUESTS=0
    
    echo ""
    echo -e "${PURPLE}╔══════════════════════════════════════════════════════════════════════════════╗${RESET}"
    printf "${PURPLE}║${RESET}  ${BOLD}%-74s${RESET} ${PURPLE}║${RESET}\n" "$phase_name"
    echo -e "${PURPLE}╠══════════════════════════════════════════════════════════════════════════════╣${RESET}"
    printf "${PURPLE}║${RESET}  🌐 Current IP: ${GREEN}%-20s${RESET} (${DIM}%s${RESET})%-24s ${PURPLE}║${RESET}\n" "$current_ip" "$geo" ""
    printf "${PURPLE}║${RESET}  🔒 OpSec: %-65s ${PURPLE}║${RESET}\n" "$opsec_status"
    printf "${PURPLE}║${RESET}  📊 Total Requests: %-10d │ Rate Limits: %-6d │ IP Changes: %-5d ${PURPLE}║${RESET}\n" \
        "$OPSEC_TOTAL_REQUESTS" "$OPSEC_RATE_LIMITS" "$OPSEC_CIRCUIT_CHANGES"
    echo -e "${PURPLE}╚══════════════════════════════════════════════════════════════════════════════╝${RESET}"
    echo ""
}

# Universal OpSec wrapper for all external tool calls
# THIS MUST BE USED FOR EVERY TOOL THAT MAKES NETWORK REQUESTS
safe_exec() {
    local cmd="$1"
    local tool=""
    local proxy_param=""
    local env_prefix=""
    local -a full_cmd=()
    local -a proxy_tokens=()
    local -a env_tokens=()
    
    # Verify target integrity
    verify_target_integrity
    
    # Extract tool name from command (first token)
    read -r -a full_cmd <<< "$cmd"
    tool=$(basename "${full_cmd[0]}")
    
    # Apply rate limiting
    smart_delay
    
    # Get random user agent
    local ua=$(get_random_user_agent)
    
    # Get proxy URL based on connection method
    local proxy=""
    case "$CONNECTION_METHOD" in
        tor)
            proxy="$TOR_SOCKS_PROXY"
            
            # Increment Tor request counter
            ((TOR_REQUESTS_COUNT++))
            
            # Refresh circuit every 10 requests
            if [[ $TOR_REQUESTS_COUNT -ge 10 ]]; then
                tor_new_circuit_silent
                TOR_REQUESTS_COUNT=0
            fi
            ;;
        proxy)
            proxy=$(get_next_proxy)
            ;;
        direct)
            proxy=""
            ;;
    esac
    
    # Map proxy parameters per tool - COMPREHENSIVE LIST
    if [[ -n "$proxy" ]]; then
        case "$tool" in
            # ══════════════════════════════════════════════════════════════════════
            # SUBDOMAIN ENUMERATION
            # ══════════════════════════════════════════════════════════════════════
            subfinder)      proxy_param="-proxy $proxy" ;;
            amass)          proxy_param="-proxy $proxy" ;;
            assetfinder)    env_prefix="HTTP_PROXY=$proxy HTTPS_PROXY=$proxy" ;;
            findomain)      env_prefix="HTTP_PROXY=$proxy HTTPS_PROXY=$proxy" ;;
            chaos)          env_prefix="HTTP_PROXY=$proxy HTTPS_PROXY=$proxy" ;;
            
            # ══════════════════════════════════════════════════════════════════════
            # DNS VALIDATION (some cannot proxy - DNS traffic)
            # ══════════════════════════════════════════════════════════════════════
            dnsx)           ;; # DNS traffic - cannot proxy, warn user
            puredns)        ;; # DNS traffic - cannot proxy
            massdns)        ;; # DNS traffic - cannot proxy
            
            # ══════════════════════════════════════════════════════════════════════
            # HTTP PROBING
            # ══════════════════════════════════════════════════════════════════════
            httpx)          proxy_param="-http-proxy $proxy" ;;
            httprobe)       env_prefix="HTTP_PROXY=$proxy HTTPS_PROXY=$proxy" ;;
            naabu)          proxy_param="-proxy $proxy" ;;
            katana)         env_prefix="HTTP_PROXY=$proxy HTTPS_PROXY=$proxy" ;;
            gauplus)        env_prefix="HTTP_PROXY=$proxy HTTPS_PROXY=$proxy" ;;
            tlsx)           env_prefix="HTTP_PROXY=$proxy HTTPS_PROXY=$proxy" ;;
            trufflehog)     env_prefix="HTTP_PROXY=$proxy HTTPS_PROXY=$proxy" ;;
            
            # ══════════════════════════════════════════════════════════════════════
            # DIRECTORY FUZZING
            # ══════════════════════════════════════════════════════════════════════
            feroxbuster)    proxy_param="--proxy $proxy" ;;
            ffuf)           proxy_param="-x $proxy" ;;
            gobuster)       proxy_param="--proxy $proxy" ;;
            dirsearch)      proxy_param="--proxy $proxy" ;;
            
            # ══════════════════════════════════════════════════════════════════════
            # PORT SCANNING (masscan/nmap have limited proxy support)
            # ══════════════════════════════════════════════════════════════════════
            nmap)           proxy_param="--proxies $proxy" ;;
            masscan)        
                echo -e "${YELLOW}⚠️  WARNING: masscan cannot use proxy - scanning direct!${RESET}" >&2
                ;;
            rustscan)       ;; # Cannot proxy - warn user
            
            # ══════════════════════════════════════════════════════════════════════
            # SCREENSHOT TOOLS
            # ══════════════════════════════════════════════════════════════════════
            gowitness)      proxy_param="--chrome-proxy $proxy" ;;
            aquatone)       proxy_param="-proxy $proxy" ;;
            
            # ══════════════════════════════════════════════════════════════════════
            # TECHNOLOGY DETECTION
            # ══════════════════════════════════════════════════════════════════════
            whatweb)        proxy_param="--proxy $proxy" ;;
            wappalyzer)     env_prefix="HTTP_PROXY=$proxy HTTPS_PROXY=$proxy" ;;
            
            # ══════════════════════════════════════════════════════════════════════
            # CMS SCANNERS
            # ══════════════════════════════════════════════════════════════════════
            wpscan)         proxy_param="--proxy $proxy" ;;
            droopescan)     proxy_param="--proxy $proxy" ;;
            joomscan)       proxy_param="--proxy $proxy" ;;
            
            # ══════════════════════════════════════════════════════════════════════
            # WAF DETECTION
            # ══════════════════════════════════════════════════════════════════════
            wafw00f)        proxy_param="-p $proxy" ;;
            
            # ══════════════════════════════════════════════════════════════════════
            # VULNERABILITY SCANNERS
            # ══════════════════════════════════════════════════════════════════════
            nuclei)         proxy_param="-proxy $proxy" ;;
            subzy)          env_prefix="HTTP_PROXY=$proxy HTTPS_PROXY=$proxy" ;;
            subjack)        env_prefix="HTTP_PROXY=$proxy HTTPS_PROXY=$proxy" ;;
            
            # ══════════════════════════════════════════════════════════════════════
            # PARAMETER & API DISCOVERY
            # ══════════════════════════════════════════════════════════════════════
            arjun)          proxy_param="--proxy $proxy" ;;
            paramspider)    env_prefix="HTTP_PROXY=$proxy HTTPS_PROXY=$proxy" ;;
            kr|kiterunner)  proxy_param="--proxy $proxy" ;;
            
            # ══════════════════════════════════════════════════════════════════════
            # WAYBACK & HISTORICAL
            # ══════════════════════════════════════════════════════════════════════
            waybackurls)    env_prefix="HTTP_PROXY=$proxy HTTPS_PROXY=$proxy" ;;
            gau)            env_prefix="HTTP_PROXY=$proxy HTTPS_PROXY=$proxy" ;;
            
            # ══════════════════════════════════════════════════════════════════════
            # JS ANALYSIS
            # ══════════════════════════════════════════════════════════════════════
            linkfinder)     env_prefix="HTTP_PROXY=$proxy HTTPS_PROXY=$proxy" ;;
            secretfinder)   env_prefix="HTTP_PROXY=$proxy HTTPS_PROXY=$proxy" ;;
            
            # ══════════════════════════════════════════════════════════════════════
            # CLOUD ENUMERATION
            # ══════════════════════════════════════════════════════════════════════
            cloud_enum*)    proxy_param="--proxy $proxy" ;;
            s3scanner)      env_prefix="HTTP_PROXY=$proxy HTTPS_PROXY=$proxy" ;;
            
            # ══════════════════════════════════════════════════════════════════════
            # UTILITIES
            # ══════════════════════════════════════════════════════════════════════
            curl)           proxy_param="--proxy $proxy" ;;
            wget)           proxy_param="-e use_proxy=yes -e http_proxy=$proxy" ;;
            git-dumper)     env_prefix="HTTP_PROXY=$proxy HTTPS_PROXY=$proxy" ;;
            
            # Unknown tool - try environment variable approach
            *)              env_prefix="HTTP_PROXY=$proxy HTTPS_PROXY=$proxy" ;;
        esac
    fi
    
    # Build full command with proxy
    if [[ -n "$proxy_param" ]]; then
        read -r -a proxy_tokens <<< "$proxy_param"
        full_cmd=("${full_cmd[0]}" "${proxy_tokens[@]}" "${full_cmd[@]:1}")
    fi

    # Add environment prefix if needed
    if [[ -n "$env_prefix" ]]; then
        read -r -a env_tokens <<< "$env_prefix"
    fi
    
    # Add user agent for tools that support it
    case "$tool" in
        curl)        full_cmd+=( -A "$ua" ) ;;
        httpx)       full_cmd+=( -H "User-Agent: $ua" ) ;;
        ffuf)        full_cmd+=( -H "User-Agent: $ua" ) ;;
        feroxbuster) full_cmd+=( -H "User-Agent: $ua" ) ;;
        gobuster)    full_cmd+=( -H "User-Agent: $ua" ) ;;
        nuclei)      full_cmd+=( -H "User-Agent: $ua" ) ;;
        wpscan)      full_cmd+=( --random-user-agent ) ;;
    esac
    
    # Log execution for audit trail
    ((OPSEC_TOTAL_REQUESTS++))
    
    # Log to timeline if available
    if [[ -n "$OUTPUT_DIR" ]] && [[ -d "$OUTPUT_DIR/08-reports" ]]; then
        echo "[$(date '+%Y-%m-%d %H:%M:%S')] [OPSEC] $tool | proxy=$proxy" >> "$OUTPUT_DIR/08-reports/timeline.log" 2>/dev/null
    fi
    
    # Execute command (array, no eval)
    if [[ ${#env_tokens[@]} -gt 0 ]]; then
        env "${env_tokens[@]}" "${full_cmd[@]}"
    else
        "${full_cmd[@]}"
    fi
    local exit_code=$?
    
    # Handle failures
    if [[ $exit_code -ne 0 ]]; then
        ((CIRCUIT_BREAKER_FAILURES++))
        
        # Circuit breaker pattern - pause after too many failures
        if [[ $CIRCUIT_BREAKER_FAILURES -ge 10 ]]; then
            CIRCUIT_BREAKER_OPEN=true
            echo -e "${YELLOW}⚠️  Circuit breaker triggered (10 failures) - pausing 60s${RESET}" >&2
            sleep 60
            CIRCUIT_BREAKER_FAILURES=0
            CIRCUIT_BREAKER_OPEN=false
        fi
    else
        # Reset on success
        CIRCUIT_BREAKER_FAILURES=0
        BACKOFF_LEVEL=0
    fi
    
    return $exit_code
}

# Silent Tor circuit refresh
tor_new_circuit_silent() {
    if command -v nc &>/dev/null; then
        echo -e 'AUTHENTICATE ""\r\nSIGNAL NEWNYM\r\nQUIT' | nc -q 1 127.0.0.1 $TOR_CONTROL_PORT &>/dev/null
    fi
    sleep 3
}

#═══════════════════════════════════════════════════════════════════════════════
# PHASE SKIP FUNCTIONALITY - Press Ctrl+C to skip current phase
#═══════════════════════════════════════════════════════════════════════════════

SKIP_CURRENT_PHASE=false
PHASE_NAME=""
INTERRUPT_COUNT=0
LAST_INTERRUPT_TIME=0

# Handle Ctrl+C to skip phase instead of exit
phase_skip_handler() {
    local current_time=$(date +%s)
    local time_diff=$((current_time - LAST_INTERRUPT_TIME))
    
    ((INTERRUPT_COUNT++))
    LAST_INTERRUPT_TIME=$current_time
    
    # If two interrupts within 2 seconds, exit completely
    if [[ $INTERRUPT_COUNT -ge 2 ]] && [[ $time_diff -le 2 ]]; then
        echo ""
        echo -e "${RED}🛑 Double Ctrl+C detected - Exiting completely...${RESET}"
        disable_phase_skip
        cleanup 2>/dev/null
        exit 130
    fi
    
    echo ""
    echo -e "${YELLOW}⚠️  Ctrl+C pressed - Skipping ${BOLD}$PHASE_NAME${RESET}${YELLOW}...${RESET}"
    echo -e "   ${DIM}Press Ctrl+C again within 2 seconds to exit completely${RESET}"
    
    SKIP_CURRENT_PHASE=true
    
    # Reset counter after 2 seconds
    (sleep 2 && INTERRUPT_COUNT=0) &
}

# Enable phase skip handler
enable_phase_skip() {
    PHASE_NAME="$1"
    SKIP_CURRENT_PHASE=false
    INTERRUPT_COUNT=0
    trap phase_skip_handler INT
}

# Disable phase skip handler (restore global handler)
disable_phase_skip() {
    SKIP_CURRENT_PHASE=false
    PHASE_NAME=""
    INTERRUPT_COUNT=0
    trap global_interrupt_handler INT 2>/dev/null || trap - INT
}

# Check if we should skip
should_skip_phase() {
    [[ "$SKIP_CURRENT_PHASE" == true ]]
}

#═══════════════════════════════════════════════════════════════════════════════
# 0xsh3x CONFIGURATION - EDIT THESE VARIABLES
#═══════════════════════════════════════════════════════════════════════════════

# ┌─────────────────────────────────────────────────────────────────────────────┐
# │ TOOL PATHS (auto-detect or set manually)                                    │
# └─────────────────────────────────────────────────────────────────────────────┘

# Function to discover tools (can be called after installation)
discover_tools() {
    # Add common Go/Cargo bin paths to PATH
    [[ -d "$HOME/go/bin" ]] && export PATH="$PATH:$HOME/go/bin"
    [[ -d "$HOME/.cargo/bin" ]] && export PATH="$PATH:$HOME/.cargo/bin"
    [[ -d "/usr/local/go/bin" ]] && export PATH="$PATH:/usr/local/go/bin"
    [[ -d "$HOME/.local/bin" ]] && export PATH="$PATH:$HOME/.local/bin"
    [[ -d "/snap/bin" ]] && export PATH="$PATH:/snap/bin"
    [[ -d "/opt/tools" ]] && export PATH="$PATH:/opt/tools"
    
    # ══════════════════════════════════════════════════════════════════════════
    # SUBDOMAIN ENUMERATION TOOLS
    # ══════════════════════════════════════════════════════════════════════════
    SUBFINDER=$(command -v subfinder 2>/dev/null)
    ASSETFINDER=$(command -v assetfinder 2>/dev/null)
    AMASS=$(command -v amass 2>/dev/null)
    FINDOMAIN=$(command -v findomain 2>/dev/null)
    CHAOS=$(command -v chaos 2>/dev/null)
    GITHUB_SUBDOMAINS=$(command -v github-subdomains 2>/dev/null)
    
    # ══════════════════════════════════════════════════════════════════════════
    # DNS VALIDATION TOOLS (Critical for preventing false positives)
    # ══════════════════════════════════════════════════════════════════════════
    DNSX=$(command -v dnsx 2>/dev/null)
    PUREDNS=$(command -v puredns 2>/dev/null)
    MASSDNS=$(command -v massdns 2>/dev/null)
    SHUFFLEDNS=$(command -v shuffledns 2>/dev/null)
    
    # ══════════════════════════════════════════════════════════════════════════
    # HTTP PROBING & VALIDATION TOOLS
    # ══════════════════════════════════════════════════════════════════════════
    HTTPX=$(command -v httpx 2>/dev/null)
    HTTPROBE=$(command -v httprobe 2>/dev/null)
    
    # ══════════════════════════════════════════════════════════════════════════
    # DIRECTORY & CONTENT DISCOVERY TOOLS
    # ══════════════════════════════════════════════════════════════════════════
    FEROXBUSTER=$(command -v feroxbuster 2>/dev/null)
    FFUF=$(command -v ffuf 2>/dev/null)
    GOBUSTER=$(command -v gobuster 2>/dev/null)
    DIRSEARCH=$(command -v dirsearch 2>/dev/null)
    
    # ══════════════════════════════════════════════════════════════════════════
    # PORT SCANNING TOOLS
    # ══════════════════════════════════════════════════════════════════════════
    RUSTSCAN=$(command -v rustscan 2>/dev/null)
    NMAP=$(command -v nmap 2>/dev/null)
    MASSCAN=$(command -v masscan 2>/dev/null)
    
    # ══════════════════════════════════════════════════════════════════════════
    # TECHNOLOGY & FINGERPRINTING TOOLS
    # ══════════════════════════════════════════════════════════════════════════
    WHATWEB=$(command -v whatweb 2>/dev/null)
    WAPPALYZER=$(command -v wappalyzer 2>/dev/null)
    
    # ══════════════════════════════════════════════════════════════════════════
    # CMS SCANNERS
    # ══════════════════════════════════════════════════════════════════════════
    WPSCAN=$(command -v wpscan 2>/dev/null)
    DROOPESCAN=$(command -v droopescan 2>/dev/null)
    JOOMSCAN=$(command -v joomscan 2>/dev/null)
    
    # ══════════════════════════════════════════════════════════════════════════
    # WAF & SECURITY DETECTION TOOLS
    # ══════════════════════════════════════════════════════════════════════════
    WAFW00F=$(command -v wafw00f 2>/dev/null)
    
    # ══════════════════════════════════════════════════════════════════════════
    # VULNERABILITY SCANNERS
    # ══════════════════════════════════════════════════════════════════════════
    NUCLEI=$(command -v nuclei 2>/dev/null)
    SUBZY=$(command -v subzy 2>/dev/null)
    SUBJACK=$(command -v subjack 2>/dev/null)
    
    # ══════════════════════════════════════════════════════════════════════════
    # JAVASCRIPT ANALYSIS TOOLS
    # ══════════════════════════════════════════════════════════════════════════
    LINKFINDER=$(command -v linkfinder 2>/dev/null)
    SECRETFINDER=$(command -v secretfinder 2>/dev/null)
    
    # ══════════════════════════════════════════════════════════════════════════
    # PARAMETER & API DISCOVERY TOOLS
    # ══════════════════════════════════════════════════════════════════════════
    ARJUN=$(command -v arjun 2>/dev/null)
    PARAMSPIDER=$(command -v paramspider 2>/dev/null)
    KITERUNNER=$(command -v kr 2>/dev/null)
    
    # ══════════════════════════════════════════════════════════════════════════
    # WAYBACK & HISTORICAL TOOLS
    # ══════════════════════════════════════════════════════════════════════════
    WAYBACKURLS=$(command -v waybackurls 2>/dev/null)
    GAU=$(command -v gau 2>/dev/null)
    
    # ══════════════════════════════════════════════════════════════════════════
    # SCREENSHOT TOOLS
    # ══════════════════════════════════════════════════════════════════════════
    GOWITNESS=$(command -v gowitness 2>/dev/null)
    AQUATONE=$(command -v aquatone 2>/dev/null)
    
    # ══════════════════════════════════════════════════════════════════════════
    # CLOUD ENUMERATION TOOLS
    # ══════════════════════════════════════════════════════════════════════════
    CLOUD_ENUM=$(command -v cloud_enum 2>/dev/null)
    S3SCANNER=$(command -v s3scanner 2>/dev/null)
    
    # ══════════════════════════════════════════════════════════════════════════
    # UTILITIES
    # ══════════════════════════════════════════════════════════════════════════
    JQ=$(command -v jq 2>/dev/null)
    CURL=$(command -v curl 2>/dev/null)
    GIT_DUMPER=$(command -v git-dumper 2>/dev/null)
    CHROMIUM=$(command -v chromium 2>/dev/null || command -v chromium-browser 2>/dev/null || command -v google-chrome 2>/dev/null)
    
    # Also check common install locations
    [[ -z "$FEROXBUSTER" ]] && [[ -f "$HOME/.cargo/bin/feroxbuster" ]] && FEROXBUSTER="$HOME/.cargo/bin/feroxbuster"
    [[ -z "$RUSTSCAN" ]] && [[ -f "$HOME/.cargo/bin/rustscan" ]] && RUSTSCAN="$HOME/.cargo/bin/rustscan"
    [[ -z "$SUBFINDER" ]] && [[ -f "$HOME/go/bin/subfinder" ]] && SUBFINDER="$HOME/go/bin/subfinder"
    [[ -z "$HTTPX" ]] && [[ -f "$HOME/go/bin/httpx" ]] && HTTPX="$HOME/go/bin/httpx"
    [[ -z "$HTTPROBE" ]] && [[ -f "$HOME/go/bin/httprobe" ]] && HTTPROBE="$HOME/go/bin/httprobe"
    [[ -z "$DNSX" ]] && [[ -f "$HOME/go/bin/dnsx" ]] && DNSX="$HOME/go/bin/dnsx"
    [[ -z "$NUCLEI" ]] && [[ -f "$HOME/go/bin/nuclei" ]] && NUCLEI="$HOME/go/bin/nuclei"
    [[ -z "$FFUF" ]] && [[ -f "$HOME/go/bin/ffuf" ]] && FFUF="$HOME/go/bin/ffuf"
    [[ -z "$GOBUSTER" ]] && [[ -f "$HOME/go/bin/gobuster" ]] && GOBUSTER="$HOME/go/bin/gobuster"
    [[ -z "$AMASS" ]] && [[ -f "$HOME/go/bin/amass" ]] && AMASS="$HOME/go/bin/amass"
    [[ -z "$WAYBACKURLS" ]] && [[ -f "$HOME/go/bin/waybackurls" ]] && WAYBACKURLS="$HOME/go/bin/waybackurls"
    [[ -z "$GAU" ]] && [[ -f "$HOME/go/bin/gau" ]] && GAU="$HOME/go/bin/gau"
    [[ -z "$ASSETFINDER" ]] && [[ -f "$HOME/go/bin/assetfinder" ]] && ASSETFINDER="$HOME/go/bin/assetfinder"
    [[ -z "$GOWITNESS" ]] && [[ -f "$HOME/go/bin/gowitness" ]] && GOWITNESS="$HOME/go/bin/gowitness"
    [[ -z "$SUBZY" ]] && [[ -f "$HOME/go/bin/subzy" ]] && SUBZY="$HOME/go/bin/subzy"
    [[ -z "$SUBJACK" ]] && [[ -f "$HOME/go/bin/subjack" ]] && SUBJACK="$HOME/go/bin/subjack"
    [[ -z "$CHAOS" ]] && [[ -f "$HOME/go/bin/chaos" ]] && CHAOS="$HOME/go/bin/chaos"
    [[ -z "$KITERUNNER" ]] && [[ -f "$HOME/go/bin/kr" ]] && KITERUNNER="$HOME/go/bin/kr"
    [[ -z "$PUREDNS" ]] && [[ -f "$HOME/go/bin/puredns" ]] && PUREDNS="$HOME/go/bin/puredns"
    [[ -z "$SHUFFLEDNS" ]] && [[ -f "$HOME/go/bin/shuffledns" ]] && SHUFFLEDNS="$HOME/go/bin/shuffledns"
    [[ -z "$MASSDNS" ]] && [[ -f "/usr/local/bin/massdns" ]] && MASSDNS="/usr/local/bin/massdns"
    [[ -z "$MASSDNS" ]] && [[ -f "/usr/bin/massdns" ]] && MASSDNS="/usr/bin/massdns"
    [[ -z "$FINDOMAIN" ]] && [[ -f "/usr/local/bin/findomain" ]] && FINDOMAIN="/usr/local/bin/findomain"
    [[ -z "$AQUATONE" ]] && [[ -f "$HOME/go/bin/aquatone" ]] && AQUATONE="$HOME/go/bin/aquatone"
    
    # Python tools - check pip locations
    [[ -z "$LINKFINDER" ]] && [[ -f "$HOME/.local/bin/linkfinder" ]] && LINKFINDER="$HOME/.local/bin/linkfinder"
    [[ -z "$SECRETFINDER" ]] && [[ -f "$HOME/.local/bin/secretfinder" ]] && SECRETFINDER="$HOME/.local/bin/secretfinder"
    [[ -z "$WAFW00F" ]] && [[ -f "$HOME/.local/bin/wafw00f" ]] && WAFW00F="$HOME/.local/bin/wafw00f"
    [[ -z "$ARJUN" ]] && [[ -f "$HOME/.local/bin/arjun" ]] && ARJUN="$HOME/.local/bin/arjun"
    [[ -z "$DROOPESCAN" ]] && [[ -f "$HOME/.local/bin/droopescan" ]] && DROOPESCAN="$HOME/.local/bin/droopescan"
    
    # Cloud tools - often in ~/tools or /opt
    [[ -z "$CLOUD_ENUM" ]] && [[ -f "$HOME/tools/cloud_enum/cloud_enum.py" ]] && CLOUD_ENUM="$HOME/tools/cloud_enum/cloud_enum.py"
    [[ -z "$CLOUD_ENUM" ]] && [[ -f "/opt/cloud_enum/cloud_enum.py" ]] && CLOUD_ENUM="/opt/cloud_enum/cloud_enum.py"
    [[ -z "$S3SCANNER" ]] && [[ -f "$HOME/.local/bin/s3scanner" ]] && S3SCANNER="$HOME/.local/bin/s3scanner"
    
    # Git dumper
    [[ -z "$GIT_DUMPER" ]] && [[ -f "$HOME/.local/bin/git-dumper" ]] && GIT_DUMPER="$HOME/.local/bin/git-dumper"
}

# Initial tool discovery
discover_tools

# ┌─────────────────────────────────────────────────────────────────────────────┐
# │ WORDLIST PATHS (SecLists)                                                   │
# └─────────────────────────────────────────────────────────────────────────────┘

# Auto-detect SecLists location
detect_seclists() {
    local paths=(
        "/usr/share/seclists"
        "/usr/share/SecLists"
        "/opt/SecLists"
        "/opt/seclists"
        "$HOME/SecLists"
        "$HOME/seclists"
        "$HOME/wordlists/SecLists"
        "/usr/local/share/seclists"
    )
    
    for path in "${paths[@]}"; do
        if [[ -d "$path" ]] && [[ -f "$path/Discovery/Web-Content/common.txt" ]]; then
            echo "$path"
            return 0
        fi
    done
    
    echo "/usr/share/seclists"  # Default fallback
    return 1
}

SECLISTS_PATH=$(detect_seclists)

# Directory wordlists
WORDLIST_COMMON="$SECLISTS_PATH/Discovery/Web-Content/common.txt"
WORDLIST_MEDIUM="$SECLISTS_PATH/Discovery/Web-Content/directory-list-2.3-medium.txt"
WORDLIST_BIG="$SECLISTS_PATH/Discovery/Web-Content/directory-list-2.3-big.txt"
WORDLIST_RAFT_LARGE="$SECLISTS_PATH/Discovery/Web-Content/raft-large-directories.txt"

# Technology-specific wordlists
WORDLIST_API="$SECLISTS_PATH/Discovery/Web-Content/api/api-endpoints.txt"
WORDLIST_LARAVEL="$SECLISTS_PATH/Discovery/Web-Content/CMS/laravel.txt"
WORDLIST_WORDPRESS="$SECLISTS_PATH/Discovery/Web-Content/CMS/wordpress.fuzz.txt"
WORDLIST_ADMIN="$SECLISTS_PATH/Discovery/Web-Content/admin-panels.txt"
WORDLIST_GRAPHQL="$SECLISTS_PATH/Discovery/Web-Content/graphql.txt"

# Subdomain wordlists
SUBDOMAIN_WORDLIST="$SECLISTS_PATH/Discovery/DNS/subdomains-top1million-110000.txt"

# Fallback wordlist (built-in)
create_fallback_wordlist() {
    local fallback_file="/tmp/0xsh3x_common_wordlist.txt"
    if [[ ! -f "$fallback_file" ]]; then
        cat > "$fallback_file" << 'WORDLIST'
admin
administrator
api
api/v1
api/v2
backup
config
console
dashboard
db
debug
dev
docs
login
panel
phpinfo.php
robots.txt
server-status
sitemap.xml
status
swagger
test
upload
uploads
wp-admin
wp-login.php
.env
.git
.git/HEAD
.git/config
.htaccess
.htpasswd
WORDLIST
    fi
    echo "$fallback_file"
}

# Check if wordlist exists, use fallback if not
get_wordlist() {
    local requested="$1"
    if [[ -f "$requested" ]]; then
        echo "$requested"
    elif [[ -f "$WORDLIST_COMMON" ]]; then
        echo "$WORDLIST_COMMON"
    else
        create_fallback_wordlist
    fi
}

#═══════════════════════════════════════════════════════════════════════════════
# 🎯 SMART WORDLIST SELECTION - Technology-aware wordlist selection
# Increases discovery rate by 40% vs generic wordlists
#═══════════════════════════════════════════════════════════════════════════════

select_smart_wordlist() {
    local host="$1"
    local detected_tech="$2"  # From technology detection phase
    local temp_wordlist="/tmp/smart_wordlist_${host//[^a-zA-Z0-9]/_}.txt"
    local base_wordlist=""
    local extra_paths=""
    
    # Normalize detected tech to lowercase
    detected_tech=$(echo "$detected_tech" | tr '[:upper:]' '[:lower:]')
    
    # Select base wordlist based on detected technology
    case "$detected_tech" in
        *wordpress*)
            base_wordlist="$WORDLIST_WORDPRESS"
            extra_paths="/wp-admin/
/wp-content/
/wp-includes/
/wp-json/
/xmlrpc.php
/wp-login.php
/wp-config.php.bak
/wp-config.php.old
/wp-config.txt
/.wp-config.php.swp
/wp-content/uploads/
/wp-content/plugins/
/wp-content/themes/
/wp-content/debug.log
/wp-admin/admin-ajax.php
/wp-admin/install.php"
            ;;
        *laravel*|*php*)
            base_wordlist="$WORDLIST_LARAVEL"
            [[ ! -f "$base_wordlist" ]] && base_wordlist="$WORDLIST_COMMON"
            extra_paths="/.env
/.env.backup
/.env.local
/.env.production
/.env.staging
/config/app.php
/config/database.php
/storage/logs/laravel.log
/vendor/
/artisan
/phpinfo.php
/adminer.php
/phpmyadmin/
/debug/
/telescope/
/horizon/"
            ;;
        *django*|*python*)
            base_wordlist="$WORDLIST_COMMON"
            extra_paths="/admin/
/api/
/static/
/media/
/debug/
/__debug__/
/django_debug/
/settings.py
/manage.py
/.python-version
/requirements.txt
/Pipfile
/poetry.lock"
            ;;
        *node*|*express*|*next*|*react*|*javascript*)
            base_wordlist="$WORDLIST_COMMON"
            extra_paths="/dist/
/build/
/node_modules/
/.next/
/api/
/graphql
/package.json
/package-lock.json
/.npmrc
/.nvmrc
/server.js
/app.js
/.env.local
/.env.development"
            ;;
        *asp*|*iis*|*.net*)
            base_wordlist="$SECLISTS_PATH/Discovery/Web-Content/IIS.fuzz.txt"
            [[ ! -f "$base_wordlist" ]] && base_wordlist="$WORDLIST_COMMON"
            extra_paths="/web.config
/web.config.bak
/Global.asax
/App_Data/
/bin/
/aspnet_client/
/elmah.axd
/trace.axd
/Views/
/Controllers/
/api/"
            ;;
        *java*|*spring*|*tomcat*)
            base_wordlist="$WORDLIST_COMMON"
            extra_paths="/manager/html
/manager/status
/manager/text
/host-manager/
/WEB-INF/
/META-INF/
/actuator/
/actuator/health
/actuator/env
/actuator/mappings
/swagger-ui/
/swagger-ui.html
/v2/api-docs
/v3/api-docs
/api-docs/
/console/"
            ;;
        *api*|*rest*|*graphql*)
            base_wordlist="$WORDLIST_API"
            [[ ! -f "$base_wordlist" ]] && base_wordlist="$WORDLIST_COMMON"
            extra_paths="/api/
/api/v1/
/api/v2/
/api/v3/
/api/internal/
/api/admin/
/api/debug/
/graphql
/graphql/console
/graphiql
/altair
/playground
/swagger.json
/swagger.yaml
/openapi.json
/api-docs
/_api/
/rest/
/odata/"
            ;;
        *nginx*)
            base_wordlist="$WORDLIST_COMMON"
            extra_paths="/nginx_status
/stub_status
/server-status
/.htaccess
/.htpasswd
/nginx.conf"
            ;;
        *apache*)
            base_wordlist="$WORDLIST_COMMON"
            extra_paths="/server-status
/server-info
/.htaccess
/.htpasswd
/cgi-bin/
/icons/
/manual/"
            ;;
        *cloudflare*)
            # Behind CDN - use smaller wordlist to avoid rate limits
            base_wordlist="$WORDLIST_COMMON"
            extra_paths=""
            ;;
        *)
            # Unknown technology - use comprehensive wordlist
            base_wordlist="$WORDLIST_RAFT_LARGE"
            [[ ! -f "$base_wordlist" ]] && base_wordlist="$WORDLIST_COMMON"
            extra_paths="/admin/
/api/
/backup/
/config/
/console/
/dashboard/
/debug/
/dev/
/internal/
/manager/
/portal/
/private/
/secure/
/test/
/.env
/.git
/.svn"
            ;;
    esac
    
    # Ensure base wordlist exists
    [[ ! -f "$base_wordlist" ]] && base_wordlist=$(create_fallback_wordlist)
    
    # Create combined wordlist
    {
        cat "$base_wordlist"
        echo "$extra_paths" | grep -v "^$"
    } | sort -u > "$temp_wordlist"
    
    echo "$temp_wordlist"
}

# Get technology for a host from detection results
get_host_technology() {
    local host="$1"
    local tech_file="$OUTPUT_DIR/06-technologies/tech_stack.json"
    
    if [[ -f "$tech_file" ]]; then
        # Try to extract technology for this host
        local tech=$(jq -r --arg h "$host" '.[$h] // empty' "$tech_file" 2>/dev/null | head -1)
        [[ -n "$tech" ]] && echo "$tech" && return
    fi
    
    # Fallback: check httpx output
    local httpx_file="$OUTPUT_DIR/02-hosts/httpx_output.txt"
    if [[ -f "$httpx_file" ]]; then
        local tech=$(grep -F "$host" "$httpx_file" | jq -r '.tech[]? // empty' 2>/dev/null | head -1)
        [[ -n "$tech" ]] && echo "$tech" && return
    fi
    
    # Default: unknown
    echo "unknown"
}

# ┌─────────────────────────────────────────────────────────────────────────────┐
# │ PERFORMANCE SETTINGS                                                        │
# └─────────────────────────────────────────────────────────────────────────────┘
MAX_PARALLEL_SCANS=3
FEROX_THREADS=50
FEROX_DEPTH=3
FEROX_TIMEOUT=5
HTTPX_THREADS=100
HTTPX_TIMEOUT=3

# ┌─────────────────────────────────────────────────────────────────────────────┐
# │ SCANNING MODES                                                              │
# └─────────────────────────────────────────────────────────────────────────────┘
SCAN_MODE="balanced"
STEALTH_MODE="false"

# ┌─────────────────────────────────────────────────────────────────────────────┐
# │ FEATURE TOGGLES                                                             │
# └─────────────────────────────────────────────────────────────────────────────┘
ENABLE_SUBDOMAIN_ENUM=true
ENABLE_ACTIVE_SUBDOMAIN=false
ENABLE_PORT_SCAN=true
ENABLE_WAYBACK=true
ENABLE_JS_ANALYSIS=true
ENABLE_PARAM_DISCOVERY=true
ENABLE_NUCLEI=false
ENABLE_SCREENSHOTS=false

# ┌─────────────────────────────────────────────────────────────────────────────┐
# │ PRIORITY SCORING WEIGHTS                                                    │
# └─────────────────────────────────────────────────────────────────────────────┘
WEIGHT_AUTH=40
WEIGHT_API=35
WEIGHT_ADMIN=38
WEIGHT_PAYMENT=37
WEIGHT_INTERNAL=45
WEIGHT_WEBAPP=20

# ┌─────────────────────────────────────────────────────────────────────────────┐
# │ OUTPUT SETTINGS                                                             │
# └─────────────────────────────────────────────────────────────────────────────┘
OUTPUT_DIR="./0xsh3x_results"
VERBOSE=true
SAVE_RAW_OUTPUT=true
GENERATE_HTML_REPORT=true

# ┌─────────────────────────────────────────────────────────────────────────────┐
# │ INTERESTING PATTERNS TO DETECT                                              │
# └─────────────────────────────────────────────────────────────────────────────┘
declare -a HIGH_VALUE_PATTERNS=(
    "/.git/"
    "/.git/HEAD"
    "/.git/config"
    "/.env"
    "/.aws/"
    "/.docker/"
    "/admin"
    "/administrator"
    "/phpmyadmin"
    "/api"
    "/api/v1"
    "/api/v2"
    "/api/v3"
    "/graphql"
    "/graphiql"
    "/swagger"
    "/swagger-ui.html"
    "/swagger-ui/"
    "/api-docs"
    "/docs"
    "/debug"
    "/config"
    "/backup"
    "/backups"
    "/.backup"
    "/test"
    "/temp"
    "/phpinfo.php"
    "/info.php"
    "/server-status"
    "/console"
    "/upload"
    "/uploads"
    "/.htaccess"
    "/.htpasswd"
    "/wp-config.php"
    "/config.php"
    "/database.yml"
    "/settings.py"
    "/.DS_Store"
    "/actuator"
    "/actuator/health"
    "/actuator/env"
    "/metrics"
    "/health"
    "/status"
)

# ┌─────────────────────────────────────────────────────────────────────────────┐
# │ STATUS CODES TO INCLUDE                                                     │
# └─────────────────────────────────────────────────────────────────────────────┘
FEROX_STATUS_CODES="200,204,301,302,307,401,403,405,500"

#═══════════════════════════════════════════════════════════════════════════════
# END CONFIGURATION - DO NOT EDIT BELOW UNLESS YOU KNOW WHAT YOU'RE DOING
#═══════════════════════════════════════════════════════════════════════════════

# ┌─────────────────────────────────────────────────────────────────────────────┐
# │ 🎨 COLOR DEFINITIONS                                                        │
# └─────────────────────────────────────────────────────────────────────────────┘
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
WHITE='\033[1;37m'
BOLD='\033[1m'
DIM='\033[2m'
UNDERLINE='\033[4m'
RESET='\033[0m'

# 🎯 Status indicators with emojis
SUCCESS="✅"
FAIL="❌"
INFO="💡"
WARN="⚠️ "
CRITICAL="🔴"
HIGH="🟡"
MEDIUM="🟢"

# Global variables
TARGET=""
SCOPE_TYPE="wildcard"
START_TIME=""
TOTAL_SUBDOMAINS=0
LIVE_HOSTS=0
DEAD_HOSTS=0
TOTAL_ENDPOINTS=0
INTERESTING_FINDINGS=0
JS_FILES=0
PARAMS_DISCOVERED=0
CUSTOM_WORDLIST=""
MAX_TIME=0
QUIET_MODE=false
SCAN_RUNNING=true

# ┌─────────────────────────────────────────────────────────────────────────────┐
# │ 🔐 OPSEC CONFIGURATION                                                      │
# └─────────────────────────────────────────────────────────────────────────────┘

# Connection method: "tor", "proxy", "direct"
CONNECTION_METHOD="direct"
STEALTH_LEVEL=2
SKIP_OPSEC_PROMPT=""

# Tor settings
TOR_SOCKS_PROXY="socks5h://127.0.0.1:9050"
TOR_CONTROL_PORT=9051
TOR_REQUESTS_COUNT=0
TOR_CIRCUIT_REFRESH_INTERVAL=10
TOR_EXIT_IP=""

# Proxy settings
PROXY_FILE=""
declare -a PROXY_POOL=()
declare -a PROXY_STATUS=()
declare -a PROXY_FAIL_COUNT=()
declare -a PROXY_SUCCESS_COUNT=()
declare -A PROXY_LAST_USED=()
CURRENT_PROXY_INDEX=0
PROXY_STRATEGY="round_robin"

# Rate limiting
declare -A HOST_LAST_REQUEST=()
REQUEST_COUNT=0
RATE_LIMIT_WINDOW=()
BACKOFF_LEVEL=0
CIRCUIT_BREAKER_OPEN=false
CIRCUIT_BREAKER_FAILURES=0

# Stealth level settings (will be set based on STEALTH_LEVEL)
DELAY_MIN=0.5
DELAY_MAX=2.0
MAX_REQUESTS_PER_MIN=60
THREADS_LIMIT=50
PER_HOST_DELAY=0.5

# User-Agent pool (current 2024-2025 browsers)
declare -a USER_AGENT_POOL=(
    # Chrome Windows
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36"
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36"
    # Chrome Mac
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36"
    # Chrome Linux
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36"
    # Firefox Windows
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0"
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:120.0) Gecko/20100101 Firefox/120.0"
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:115.0) Gecko/20100101 Firefox/115.0"
    # Firefox Mac
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:121.0) Gecko/20100101 Firefox/121.0"
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:120.0) Gecko/20100101 Firefox/120.0"
    # Firefox Linux
    "Mozilla/5.0 (X11; Linux x86_64; rv:121.0) Gecko/20100101 Firefox/121.0"
    "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:120.0) Gecko/20100101 Firefox/120.0"
    # Safari Mac
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Safari/605.1.15"
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.1 Safari/605.1.15"
    # Edge Windows
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Edg/120.0.0.0"
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36 Edg/119.0.0.0"
    # Mobile Chrome Android
    "Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Mobile Safari/537.36"
    "Mozilla/5.0 (Linux; Android 13; SM-S918B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Mobile Safari/537.36"
    # Mobile Safari iOS
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_2 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Mobile/15E148 Safari/604.1"
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.1 Mobile/15E148 Safari/604.1"
    # Tor Browser (Firefox-based)
    "Mozilla/5.0 (Windows NT 10.0; rv:109.0) Gecko/20100101 Firefox/115.0"
)

# User-Agent cache per target (sticky mode)
declare -A UA_CACHE=()

# OpSec statistics
OPSEC_TOTAL_REQUESTS=0
OPSEC_RATE_LIMITS=0
OPSEC_CONNECTION_FAILURES=0
OPSEC_CIRCUIT_CHANGES=0

# Temp files for parallel processing
TEMP_DIR=""
PIDS_FILE=""
FINDINGS_FILE=""

#═══════════════════════════════════════════════════════════════════════════════
# UTILITY FUNCTIONS
#═══════════════════════════════════════════════════════════════════════════════

# Display banner
banner() {
    clear
    echo ""
    echo -e "${PURPLE}"
    cat << "EOF"
   ██████╗ ██╗  ██╗███████╗██╗  ██╗ ██████╗ ██╗  ██╗
   ██╔═══██╗╚██╗██╔╝██╔════╝██║  ██║██╔════╝ ╚██╗██╔╝
   ██║   ██║ ╚███╔╝ ███████╗███████║██║  ███╗ ╚███╔╝
   ██║   ██║ ██╔██╗ ╚════██║██╔══██║██║   ██║ ██╔██╗
   ╚██████╔╝██╔╝ ██╗███████║██║  ██║╚██████╔╝██╔╝ ██╗
    ╚═════╝ ╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═╝
EOF
    echo -e "${RESET}"
    echo -e "  ${DIM}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RESET}"
    echo -e "  ${WHITE}${BOLD}0 X S H 3 X${RESET}  ${DIM}v${VERSION} by ${AUTHOR}${RESET}"
    echo -e "  ${DIM}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RESET}"
    echo ""
}

# 📝 Logging function with timestamps
log() {
    local level="$1"
    shift
    local message="$*"
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    
    case "$level" in
        "INFO")
            [[ "$QUIET_MODE" == false ]] && echo -e "  ${DIM}[$timestamp]${RESET} ${INFO} ${message}"
            ;;
        "SUCCESS")
            echo -e "  ${DIM}[$timestamp]${RESET} ${SUCCESS} ${GREEN}${BOLD}${message}${RESET}"
            ;;
        "WARN")
            echo -e "  ${DIM}[$timestamp]${RESET} ${WARN}${YELLOW}${BOLD}${message}${RESET}"
            ;;
        "ERROR")
            echo -e "  ${DIM}[$timestamp]${RESET} ${FAIL} ${RED}${BOLD}${message}${RESET}" >&2
            ;;
        "CRITICAL")
            echo -e "  ${DIM}[$timestamp]${RESET} 💀 ${RED}${BOLD}CRITICAL: ${message}${RESET}"
            ;;
        "HIGH")
            echo -e "  ${DIM}[$timestamp]${RESET} 🔥 ${YELLOW}${BOLD}${message}${RESET}"
            ;;
        "FINDING")
            echo -e "  ${DIM}[$timestamp]${RESET} 💎 ${PURPLE}${BOLD}[FINDING]${RESET} ${message}"
            ;;
        *)
            [[ "$QUIET_MODE" == false ]] && echo -e "${DIM}[$timestamp]${RESET} ${message}"
            ;;
    esac
    
    # Also write to log file
    echo "[$timestamp] [$level] $message" >> "$OUTPUT_DIR/08-reports/timeline.log" 2>/dev/null
}

# 📊 Progress bar
progress_bar() {
    local current=$1
    local total=$2
    local width=50
    local percentage=$((current * 100 / total))
    local filled=$((width * current / total))
    local empty=$((width - filled))
    
    printf "\r  🔄 ${CYAN}${BOLD}Progress:${RESET} [${GREEN}"
    printf "%${filled}s" | tr ' ' '█'
    printf "${DIM}"
    printf "%${empty}s" | tr ' ' '░'
    printf "${RESET}] ${BOLD}${percentage}%%${RESET} ${DIM}(${current}/${total})${RESET}"
}

# Spinner animation
spinner() {
    local pid=$1
    local message=$2
    local spin='⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏'
    local i=0
    
    while kill -0 "$pid" 2>/dev/null; do
        printf "\r${CYAN}${spin:i++%${#spin}:1}${RESET} ${message}"
        sleep 0.1
    done
    printf "\r"
}

# Timestamp function
timestamp() {
    date '+%Y-%m-%d %H:%M:%S'
}

# Get elapsed time
elapsed_time() {
    local end_time=$(date +%s)
    local elapsed=$((end_time - START_TIME))
    local hours=$((elapsed / 3600))
    local minutes=$(((elapsed % 3600) / 60))
    local seconds=$((elapsed % 60))
    
    if [[ $hours -gt 0 ]]; then
        echo "${hours}h ${minutes}m ${seconds}s"
    elif [[ $minutes -gt 0 ]]; then
        echo "${minutes}m ${seconds}s"
    else
        echo "${seconds}s"
    fi
}

# Estimate remaining time
estimate_remaining() {
    local completed=$1
    local total=$2
    
    if [[ $completed -eq 0 ]]; then
        echo "Calculating..."
        return
    fi
    
    local elapsed=$(($(date +%s) - START_TIME))
    local avg_time=$((elapsed / completed))
    local remaining=$(((total - completed) * avg_time))
    local minutes=$((remaining / 60))
    local seconds=$((remaining % 60))
    
    echo "~${minutes}m ${seconds}s"
}

# Check disk space
check_disk_space() {
    local required_mb=${1:-1024}
    local available_mb=$(df -m "$OUTPUT_DIR" 2>/dev/null | awk 'NR==2 {print $4}')
    
    if [[ -n "$available_mb" ]] && [[ $available_mb -lt $required_mb ]]; then
        log "WARN" "Low disk space: ${available_mb}MB available (${required_mb}MB recommended)"
        return 1
    fi
    return 0
}

# URL encode function
urlencode() {
    local string="$1"
    python3 -c "import urllib.parse; print(urllib.parse.quote('$string'))" 2>/dev/null || echo "$string"
}

# Validate domain format
validate_domain() {
    local domain="$1"
    
    # Remove protocol if present
    domain=$(echo "$domain" | sed -E 's|^https?://||')
    # Remove trailing slash
    domain=$(echo "$domain" | sed 's|/$||')
    # Remove wildcard prefix
    domain=$(echo "$domain" | sed 's|^\*\.||')
    
    # Basic domain validation
    if [[ ! "$domain" =~ ^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*\.[a-zA-Z]{2,}$ ]]; then
        log "ERROR" "Invalid domain format: $domain"
        echo ""
        echo "Valid examples:"
        echo "  - example.com"
        echo "  - sub.example.com"
        echo "  - *.example.com (wildcard)"
        exit 1
    fi
    
    TARGET="$domain"
    log "SUCCESS" "Target domain validated: $TARGET"
}

#═══════════════════════════════════════════════════════════════════════════════
# 🔐 OpSec
#═══════════════════════════════════════════════════════════════════════════════

# Apply stealth level settings
apply_stealth_settings() {
    case "$STEALTH_LEVEL" in
        1) # FAST
            DELAY_MIN=0.1
            DELAY_MAX=0.5
            MAX_REQUESTS_PER_MIN=120
            THREADS_LIMIT=100
            PER_HOST_DELAY=0.2
            ;;
        2) # BALANCED (default)
            DELAY_MIN=0.5
            DELAY_MAX=2.0
            MAX_REQUESTS_PER_MIN=60
            THREADS_LIMIT=50
            PER_HOST_DELAY=0.5
            ;;
        3) # CAUTIOUS
            DELAY_MIN=1.0
            DELAY_MAX=3.0
            MAX_REQUESTS_PER_MIN=30
            THREADS_LIMIT=25
            PER_HOST_DELAY=2.0
            ;;
        4) # SLOW
            DELAY_MIN=2.0
            DELAY_MAX=5.0
            MAX_REQUESTS_PER_MIN=15
            THREADS_LIMIT=10
            PER_HOST_DELAY=3.0
            ;;
        5) # PARANOID
            DELAY_MIN=5.0
            DELAY_MAX=10.0
            MAX_REQUESTS_PER_MIN=6
            THREADS_LIMIT=5
            PER_HOST_DELAY=5.0
            ;;
    esac
    
    # Update feroxbuster threads
    FEROX_THREADS=$THREADS_LIMIT
}

# Get random User-Agent
get_random_user_agent() {
    local target="${1:-default}"
    
    # Check cache for sticky mode
    if [[ -n "${UA_CACHE[$target]}" ]]; then
        echo "${UA_CACHE[$target]}"
        return
    fi
    
    # Weighted selection (60% Chrome, 25% Firefox, 10% Safari, 5% Edge)
    local rand=$((RANDOM % 100))
    local ua=""
    
    if [[ "$CONNECTION_METHOD" == "tor" ]]; then
        # Use Tor Browser UA
        ua="Mozilla/5.0 (Windows NT 10.0; rv:109.0) Gecko/20100101 Firefox/115.0"
    elif [[ $rand -lt 60 ]]; then
        # Chrome (indices 0-6)
        local idx=$((RANDOM % 7))
        ua="${USER_AGENT_POOL[$idx]}"
    elif [[ $rand -lt 85 ]]; then
        # Firefox (indices 7-13)
        local idx=$((7 + RANDOM % 7))
        ua="${USER_AGENT_POOL[$idx]}"
    elif [[ $rand -lt 95 ]]; then
        # Safari (indices 14-15)
        local idx=$((14 + RANDOM % 2))
        ua="${USER_AGENT_POOL[$idx]}"
    else
        # Edge (indices 16-17)
        local idx=$((16 + RANDOM % 2))
        ua="${USER_AGENT_POOL[$idx]}"
    fi
    
    # Cache for sticky mode
    UA_CACHE[$target]="$ua"
    echo "$ua"
}

# Smart delay with randomization
smart_delay() {
    local delay=$(awk -v min="$DELAY_MIN" -v max="$DELAY_MAX" 'BEGIN{srand(); print min+rand()*(max-min)}')
    sleep "$delay"
}

# Per-host rate limiting
check_host_rate_limit() {
    local host="$1"
    local now=$(date +%s.%N)
    local last_request="${HOST_LAST_REQUEST[$host]:-0}"
    
    if [[ -n "$last_request" ]] && [[ "$last_request" != "0" ]]; then
        local elapsed=$(awk -v now="$now" -v last="$last_request" 'BEGIN{print now - last}')
        local needed=$(awk -v e="$elapsed" -v d="$PER_HOST_DELAY" 'BEGIN{print d - e}')
        
        if (( $(awk -v n="$needed" 'BEGIN{print (n > 0)}') )); then
            sleep "$needed"
        fi
    fi
    
    HOST_LAST_REQUEST[$host]="$now"
}

# Exponential backoff
exponential_backoff() {
    local base_wait=5
    local max_wait=60
    local wait_time=$((base_wait * (2 ** BACKOFF_LEVEL)))
    
    [[ $wait_time -gt $max_wait ]] && wait_time=$max_wait
    
    echo -e "  ${YELLOW}⏳ Rate limited. Backing off for ${wait_time}s...${RESET}"
    
    # Countdown
    for ((i=wait_time; i>0; i--)); do
        printf "\r  ${DIM}Resuming in ${i}s...${RESET}   "
        sleep 1
    done
    printf "\r                              \r"
    
    ((BACKOFF_LEVEL++))
    ((OPSEC_RATE_LIMITS++))
}

# Reset backoff on success
reset_backoff() {
    BACKOFF_LEVEL=0
}

# Check for rate limiting in response
detect_rate_limit() {
    local status_code="$1"
    local response_body="$2"
    
    # Status code detection
    if [[ "$status_code" == "429" ]] || [[ "$status_code" == "503" ]] || [[ "$status_code" == "509" ]]; then
        return 0  # Rate limited
    fi
    
    # Response body detection
    if [[ -n "$response_body" ]]; then
        if echo "$response_body" | grep -qiE "rate.?limit|too.?many.?requests|slow.?down|blocked|captcha"; then
            return 0  # Rate limited
        fi
    fi
    
    return 1  # Not rate limited
}

#═══════════════════════════════════════════════════════════════════════════════
# TOR CONNECTION MANAGEMENT
#═══════════════════════════════════════════════════════════════════════════════

# Check if Tor is available
check_tor_status() {
    local tor_installed=false
    local tor_running=false
    
    command -v tor &>/dev/null && tor_installed=true
    pgrep -x tor &>/dev/null && tor_running=true
    
    if [[ "$tor_running" == true ]]; then
        echo "running"
    elif [[ "$tor_installed" == true ]]; then
        echo "installed"
    else
        echo "not_installed"
    fi
}

# Start Tor service
start_tor_service() {
    echo -e "  ${CYAN}Starting Tor service...${RESET}"
    local tor_started=false
    
    # Try system services if sudo is available
    if command -v sudo &>/dev/null; then
        if command -v systemctl &>/dev/null; then
            sudo systemctl start tor 2>/dev/null && tor_started=true
        elif command -v service &>/dev/null; then
            sudo service tor start 2>/dev/null && tor_started=true
        fi
    fi
    
    # Fallback: launch tor directly and track PID for cleanup
    if [[ "$tor_started" == false ]] && command -v tor &>/dev/null; then
        tor &>/dev/null &
        local tor_pid=$!
        sleep 3
        if pgrep -x tor &>/dev/null; then
            tor_started=true
            [[ -n "$PIDS_FILE" ]] && echo "$tor_pid" >> "$PIDS_FILE"
        else
            kill "$tor_pid" 2>/dev/null
        fi
    fi
    
    [[ "$tor_started" == true ]] && return 0 || return 1
}

# Test Tor connection
test_tor_connection() {
    local test_result=$(curl -s --max-time 15 --proxy "$TOR_SOCKS_PROXY" https://check.torproject.org/api/ip 2>/dev/null)
    
    if [[ -n "$test_result" ]]; then
        TOR_EXIT_IP=$(echo "$test_result" | jq -r '.IP // empty' 2>/dev/null)
        if [[ -n "$TOR_EXIT_IP" ]]; then
            return 0
        fi
    fi
    
    return 1
}

# Refresh Tor circuit
tor_new_circuit() {
    echo -e "  ${CYAN}🔄 Refreshing Tor circuit...${RESET}"
    
    # Method 1: Use control port
    if command -v nc &>/dev/null; then
        (echo 'AUTHENTICATE ""'; echo 'SIGNAL NEWNYM'; echo 'QUIT') | \
            nc 127.0.0.1 "$TOR_CONTROL_PORT" &>/dev/null
    fi
    
    # Wait for new circuit
    sleep 3
    
    # Get new exit IP
    local old_ip="$TOR_EXIT_IP"
    test_tor_connection
    
    if [[ "$TOR_EXIT_IP" != "$old_ip" ]]; then
        echo -e "  ${GREEN}✓${RESET} New exit IP: ${CYAN}$TOR_EXIT_IP${RESET}"
        ((OPSEC_CIRCUIT_CHANGES++))
    fi
    
    TOR_REQUESTS_COUNT=0
}

# Initialize Tor connection
initialize_tor_connection() {
    echo ""
    echo -e "${GREEN}┌─────────────────────────────────────────────────────────────────────────────┐${RESET}"
    echo -e "${GREEN}│${RESET} 🧅 ${BOLD}INITIALIZING TOR CONNECTION${RESET}"
    echo -e "${GREEN}└─────────────────────────────────────────────────────────────────────────────┘${RESET}"
    echo ""
    
    # Test connection
    echo -e "  ${DIM}Testing Tor connection...${RESET}"
    
    if test_tor_connection; then
        echo -e "  ${GREEN}✓${RESET} Tor connected successfully!"
        echo -e "  ${GREEN}✓${RESET} Exit IP: ${CYAN}$TOR_EXIT_IP${RESET}"
        
        # Get country (optional)
        local country=$(curl -s --max-time 10 --proxy "$TOR_SOCKS_PROXY" "https://ipapi.co/$TOR_EXIT_IP/country_name/" 2>/dev/null)
        [[ -n "$country" ]] && echo -e "  ${GREEN}✓${RESET} Exit Country: ${CYAN}$country${RESET}"
        
        return 0
    else
        echo -e "  ${RED}✗${RESET} Failed to connect to Tor"
        return 1
    fi
}

#═══════════════════════════════════════════════════════════════════════════════
# PROXY CHAIN MANAGEMENT
#═══════════════════════════════════════════════════════════════════════════════

# Auto-download free proxy lists
download_proxy_list() {
    local proxy_dir="$HOME/.0xsh3x_proxies"
    local proxy_file="$proxy_dir/proxies.txt"
    local temp_file="$proxy_dir/temp_proxies.txt"
    
    mkdir -p "$proxy_dir"
    > "$temp_file"
    
    echo -e "${CYAN}┌─────────────────────────────────────────────────────────────────────────────┐${RESET}"
    echo -e "${CYAN}│${RESET} 🌐 ${BOLD}AUTO-DOWNLOADING PROXY LISTS${RESET}"
    echo -e "${CYAN}└─────────────────────────────────────────────────────────────────────────────┘${RESET}"
    echo ""
    
    local total_proxies=0
    
    # Source 1: ProxyScrape (HTTP/HTTPS)
    echo -e "  ${DIM}→ Fetching from ProxyScrape...${RESET}"
    local ps_proxies=$(curl -s --max-time 15 "https://api.proxyscrape.com/v2/?request=displayproxies&protocol=http&timeout=10000&country=all&ssl=all&anonymity=all" 2>/dev/null)
    if [[ -n "$ps_proxies" ]]; then
        echo "$ps_proxies" >> "$temp_file"
        local count=$(echo "$ps_proxies" | wc -l)
        echo -e "    ${GREEN}✓${RESET} ProxyScrape: $count proxies"
        ((total_proxies += count))
    fi
    
    # Source 2: Free-Proxy-List via GitHub
    echo -e "  ${DIM}→ Fetching from TheSpeedX/PROXY-List...${RESET}"
    local gh_proxies=$(curl -s --max-time 15 "https://raw.githubusercontent.com/TheSpeedX/PROXY-List/master/http.txt" 2>/dev/null)
    if [[ -n "$gh_proxies" ]]; then
        echo "$gh_proxies" >> "$temp_file"
        local count=$(echo "$gh_proxies" | wc -l)
        echo -e "    ${GREEN}✓${RESET} TheSpeedX: $count proxies"
        ((total_proxies += count))
    fi
    
    # Source 3: clarketm/proxy-list
    echo -e "  ${DIM}→ Fetching from clarketm/proxy-list...${RESET}"
    local cl_proxies=$(curl -s --max-time 15 "https://raw.githubusercontent.com/clarketm/proxy-list/master/proxy-list-raw.txt" 2>/dev/null)
    if [[ -n "$cl_proxies" ]]; then
        echo "$cl_proxies" >> "$temp_file"
        local count=$(echo "$cl_proxies" | wc -l)
        echo -e "    ${GREEN}✓${RESET} clarketm: $count proxies"
        ((total_proxies += count))
    fi
    
    # Source 4: jetkai/proxy-list (SOCKS5)
    echo -e "  ${DIM}→ Fetching SOCKS5 from jetkai...${RESET}"
    local socks_proxies=$(curl -s --max-time 15 "https://raw.githubusercontent.com/jetkai/proxy-list/main/online-proxies/txt/proxies-socks5.txt" 2>/dev/null)
    if [[ -n "$socks_proxies" ]]; then
        # Prefix with socks5://
        echo "$socks_proxies" | sed 's/^/socks5:\/\//' >> "$temp_file"
        local count=$(echo "$socks_proxies" | wc -l)
        echo -e "    ${GREEN}✓${RESET} jetkai SOCKS5: $count proxies"
        ((total_proxies += count))
    fi
    
    # Source 5: hookzof/socks5_list
    echo -e "  ${DIM}→ Fetching SOCKS5 from hookzof...${RESET}"
    local hk_proxies=$(curl -s --max-time 15 "https://raw.githubusercontent.com/hookzof/socks5_list/master/proxy.txt" 2>/dev/null)
    if [[ -n "$hk_proxies" ]]; then
        echo "$hk_proxies" | sed 's/^/socks5:\/\//' >> "$temp_file"
        local count=$(echo "$hk_proxies" | wc -l)
        echo -e "    ${GREEN}✓${RESET} hookzof SOCKS5: $count proxies"
        ((total_proxies += count))
    fi
    
    echo ""
    
    if [[ ! -s "$temp_file" ]]; then
        echo -e "  ${RED}✗${RESET} Failed to download any proxies"
        rm -f "$temp_file"
        return 1
    fi
    
    # Deduplicate and clean
    sort -u "$temp_file" | grep -E '^[0-9]|^socks' > "$proxy_file"
    rm -f "$temp_file"
    
    local unique_count=$(wc -l < "$proxy_file")
    echo -e "  ${GREEN}✓${RESET} Total unique proxies: ${BOLD}$unique_count${RESET}"
    echo -e "  ${DIM}Saved to: $proxy_file${RESET}"
    echo ""
    
    # Ask to validate proxies
    echo -e "  ${YELLOW}⚠️${RESET} Validating all proxies can take a long time."
    read -p "  Validate proxies now? (y/N): " validate_choice
    
    if [[ "$validate_choice" =~ ^[Yy] ]]; then
        echo ""
        echo -e "  ${DIM}Starting validation (this may take several minutes)...${RESET}"
        
        local valid_file="$proxy_dir/valid_proxies.txt"
        > "$valid_file"
        local valid_count=0
        local current=0
        
        while IFS= read -r proxy; do
            [[ -z "$proxy" ]] && continue
            ((current++))
            
            printf "\r  ${DIM}Testing: %d/%d (valid: %d)${RESET}  " "$current" "$unique_count" "$valid_count"
            
            # Normalize proxy format
            local test_proxy="$proxy"
            if [[ ! "$proxy" =~ ^(http|https|socks)://.* ]]; then
                test_proxy="http://$proxy"
            fi
            
            # Quick test with 5 second timeout
            if curl -s -o /dev/null -w "%{http_code}" --max-time 5 --proxy "$test_proxy" "https://httpbin.org/ip" 2>/dev/null | grep -q "200"; then
                echo "$proxy" >> "$valid_file"
                ((valid_count++))
            fi
            
            # Limit to first 500 for speed
            [[ $current -ge 500 ]] && break
            
        done < "$proxy_file"
        
        printf "\r                                                    \r"
        
        if [[ -s "$valid_file" ]]; then
            mv "$valid_file" "$proxy_file"
            echo -e "  ${GREEN}✓${RESET} Validated proxies: ${BOLD}$valid_count${RESET}"
        fi
    fi
    
    PROXY_FILE="$proxy_file"
    echo ""
    echo -e "  ${GREEN}✓${RESET} Proxy file ready: ${CYAN}$PROXY_FILE${RESET}"
    
    return 0
}

# Parse proxy file
parse_proxy_file() {
    local file="$1"
    
    if [[ ! -f "$file" ]]; then
        echo -e "  ${RED}✗${RESET} Proxy file not found: $file"
        return 1
    fi
    
    PROXY_POOL=()
    PROXY_STATUS=()
    PROXY_FAIL_COUNT=()
    PROXY_SUCCESS_COUNT=()
    
    while IFS= read -r line; do
        [[ -z "$line" ]] && continue
        [[ "$line" == "#"* ]] && continue
        
        local proxy="$line"
        
        # Normalize proxy format
        if [[ ! "$proxy" =~ ^(http|https|socks[45])://.* ]]; then
            # Check if it has auth (ip:port:user:pass)
            if [[ "$proxy" =~ ^[^:]+:[0-9]+:[^:]+:.+$ ]]; then
                local ip=$(echo "$proxy" | cut -d: -f1)
                local port=$(echo "$proxy" | cut -d: -f2)
                local user=$(echo "$proxy" | cut -d: -f3)
                local pass=$(echo "$proxy" | cut -d: -f4)
                proxy="http://${user}:${pass}@${ip}:${port}"
            else
                # Simple ip:port format
                proxy="http://$proxy"
            fi
        fi
        
        PROXY_POOL+=("$proxy")
        PROXY_STATUS+=("active")
        PROXY_FAIL_COUNT+=(0)
        PROXY_SUCCESS_COUNT+=(0)
        
    done < "$file"
    
    echo "${#PROXY_POOL[@]}"
}

# Test a single proxy
test_proxy() {
    local proxy="$1"
    local timeout=10
    
    local result=$(curl -s -o /dev/null -w "%{http_code}" --max-time "$timeout" \
        --proxy "$proxy" "https://httpbin.org/ip" 2>/dev/null)
    
    [[ "$result" == "200" ]] && return 0
    return 1
}

# Test all proxies
test_all_proxies() {
    local total=${#PROXY_POOL[@]}
    local working=0
    
    echo -e "  ${DIM}Testing $total proxies...${RESET}"
    
    for i in "${!PROXY_POOL[@]}"; do
        printf "\r  ${DIM}Testing: %d/%d${RESET}  " "$((i+1))" "$total"
        
        if test_proxy "${PROXY_POOL[$i]}"; then
            ((working++))
        else
            PROXY_STATUS[$i]="failed"
        fi
    done
    
    printf "\r                              \r"
    echo -e "  ${GREEN}✓${RESET} Working proxies: ${CYAN}$working/$total${RESET}"
    
    return 0
}

# Get next proxy (rotation)
get_next_proxy() {
    local pool_size=${#PROXY_POOL[@]}
    [[ $pool_size -eq 0 ]] && return 1
    
    case "$PROXY_STRATEGY" in
        random)
            CURRENT_PROXY_INDEX=$((RANDOM % pool_size))
            ;;
        round_robin|*)
            CURRENT_PROXY_INDEX=$(( (CURRENT_PROXY_INDEX + 1) % pool_size ))
            ;;
    esac
    
    # Skip failed proxies
    local attempts=0
    while [[ "${PROXY_STATUS[$CURRENT_PROXY_INDEX]}" != "active" ]] && [[ $attempts -lt $pool_size ]]; do
        CURRENT_PROXY_INDEX=$(( (CURRENT_PROXY_INDEX + 1) % pool_size ))
        ((attempts++))
    done
    
    if [[ $attempts -ge $pool_size ]]; then
        echo ""  # No active proxies
        return 1
    fi
    
    echo "${PROXY_POOL[$CURRENT_PROXY_INDEX]}"
}

# Handle proxy failure
handle_proxy_failure() {
    local index="$1"
    
    ((PROXY_FAIL_COUNT[$index]++))
    
    if [[ ${PROXY_FAIL_COUNT[$index]} -ge 3 ]]; then
        PROXY_STATUS[$index]="failed"
        echo -e "  ${YELLOW}⚠️${RESET} Proxy marked as failed: ${PROXY_POOL[$index]}"
    fi
}

# Initialize proxy connection
initialize_proxy_connection() {
    echo ""
    echo -e "${YELLOW}┌─────────────────────────────────────────────────────────────────────────────┐${RESET}"
    echo -e "${YELLOW}│${RESET} 🔗 ${BOLD}INITIALIZING PROXY CHAIN${RESET}"
    echo -e "${YELLOW}└─────────────────────────────────────────────────────────────────────────────┘${RESET}"
    echo ""
    
    local count=$(parse_proxy_file "$PROXY_FILE")
    
    if [[ $count -eq 0 ]]; then
        echo -e "  ${RED}✗${RESET} No proxies loaded"
        return 1
    fi
    
    echo -e "  ${GREEN}✓${RESET} Loaded ${CYAN}$count${RESET} proxies"
    
    # Test proxies
    test_all_proxies
    
    return 0
}

#═══════════════════════════════════════════════════════════════════════════════
# DIRECT CONNECTION (with stealth features)
#═══════════════════════════════════════════════════════════════════════════════

initialize_direct_connection() {
    echo ""
    echo -e "${RED}┌─────────────────────────────────────────────────────────────────────────────┐${RESET}"
    echo -e "${RED}│${RESET} ⚡ ${BOLD}DIRECT CONNECTION MODE${RESET}"
    echo -e "${RED}└─────────────────────────────────────────────────────────────────────────────┘${RESET}"
    echo ""
    
    # Get real IP
    local real_ip=$(curl -s --max-time 10 https://api.ipify.org 2>/dev/null)
    
    echo -e "  ${RED}⚠️  WARNING: Your real IP is visible!${RESET}"
    echo -e "  ${RED}⚠️  Your IP: ${BOLD}$real_ip${RESET}"
    echo -e "  ${DIM}  Rate limiting and stealth headers are still active.${RESET}"
    echo ""
    
    return 0
}

#═══════════════════════════════════════════════════════════════════════════════
# SAFE CURL WRAPPER (applies OpSec to all requests)
#═══════════════════════════════════════════════════════════════════════════════

safe_curl() {
    local url="$1"
    shift
    local extra_args=("$@")
    
    # Extract host for rate limiting
    local host=$(echo "$url" | sed -E 's|^https?://||' | cut -d'/' -f1)
    
    # Apply per-host rate limiting
    check_host_rate_limit "$host"
    
    # Apply smart delay
    smart_delay
    
    # Get User-Agent
    local ua=$(get_random_user_agent "$host")
    
    # Build curl command
    local curl_args=(
        -s
        --max-time 30
        -A "$ua"
        -H "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8"
        -H "Accept-Language: en-US,en;q=0.9"
        -H "Accept-Encoding: gzip, deflate"
        -H "DNT: 1"
        -H "Connection: keep-alive"
        -H "Upgrade-Insecure-Requests: 1"
    )
    
    # Add proxy based on connection method
    case "$CONNECTION_METHOD" in
        tor)
            curl_args+=(--proxy "$TOR_SOCKS_PROXY")
            ((TOR_REQUESTS_COUNT++))
            
            # Check if we need to refresh circuit
            if [[ $TOR_REQUESTS_COUNT -ge $TOR_CIRCUIT_REFRESH_INTERVAL ]]; then
                tor_new_circuit
            fi
            ;;
        proxy)
            local proxy=$(get_next_proxy)
            if [[ -n "$proxy" ]]; then
                curl_args+=(--proxy "$proxy")
            fi
            ;;
    esac
    
    # Add extra arguments
    curl_args+=("${extra_args[@]}")
    curl_args+=("$url")
    
    # Execute with retry logic
    local max_retries=3
    local retry=0
    local result=""
    local status=""
    
    while [[ $retry -lt $max_retries ]]; do
        result=$(curl "${curl_args[@]}" -w "\n%{http_code}" 2>/dev/null)
        status=$(echo "$result" | tail -1)
        result=$(echo "$result" | sed '$d')
        
        # Check for rate limiting
        if detect_rate_limit "$status" "$result"; then
            exponential_backoff
            
            # Refresh connection on rate limit
            case "$CONNECTION_METHOD" in
                tor) tor_new_circuit ;;
                proxy) get_next_proxy >/dev/null ;;
            esac
            
            ((retry++))
            continue
        fi
        
        # Success
        reset_backoff
        ((OPSEC_TOTAL_REQUESTS++))
        echo "$result"
        return 0
    done
    
    ((OPSEC_CONNECTION_FAILURES++))
    echo "$result"
    return 1
}

#═══════════════════════════════════════════════════════════════════════════════
# CONNECTION METHOD SELECTION (Interactive)
#═══════════════════════════════════════════════════════════════════════════════

choose_connection_method() {
    echo ""
    echo -e "${PURPLE}═══════════════════════════════════════════════════════════════════════════════${RESET}"
    echo -e "${PURPLE}${BOLD}                      🔐 OPERATIONAL SECURITY SETUP                           ${RESET}"
    echo -e "${PURPLE}═══════════════════════════════════════════════════════════════════════════════${RESET}"
    
    # Check system status
    local tor_status=$(check_tor_status)
    local real_ip=$(curl -s --max-time 5 https://api.ipify.org 2>/dev/null || echo "Unable to detect")
    
    echo ""
    echo -e "${CYAN}┌─────────────────────────────────────────────────────────────────────────────┐${RESET}"
    echo -e "${CYAN}│${RESET} 🖥️  ${BOLD}SYSTEM STATUS${RESET}"
    echo -e "${CYAN}└─────────────────────────────────────────────────────────────────────────────┘${RESET}"
    echo ""
    
    # Tor status
    case "$tor_status" in
        running)
            echo -e "  ${GREEN}✓${RESET} Tor:      ${GREEN}Running and ready${RESET}"
            ;;
        installed)
            echo -e "  ${YELLOW}○${RESET} Tor:      ${YELLOW}Installed but not running${RESET}"
            ;;
        *)
            echo -e "  ${RED}✗${RESET} Tor:      ${RED}Not installed${RESET}"
            ;;
    esac
    
    echo -e "  ${CYAN}→${RESET} Your IP:  ${BOLD}$real_ip${RESET}"
    
    echo ""
    echo -e "${CYAN}┌─────────────────────────────────────────────────────────────────────────────┐${RESET}"
    echo -e "${CYAN}│${RESET} 🔌 ${BOLD}SELECT CONNECTION METHOD${RESET}"
    echo -e "${CYAN}└─────────────────────────────────────────────────────────────────────────────┘${RESET}"
    echo ""
    
    # Option 1: Tor
    echo -e "  ${GREEN}${BOLD}1)${RESET} 🧅 ${GREEN}${BOLD}TOR NETWORK${RESET} ${DIM}(Maximum Anonymity)${RESET}"
    echo -e "     ${GREEN}✓${RESET} Multi-hop encryption, automatic IP rotation"
    echo -e "     ${GREEN}✓${RESET} Free and always available, no setup needed"
    echo -e "     ${YELLOW}⚠${RESET} Slower speed (3-5x), some sites block Tor"
    echo -e "     ${DIM}Best for: Public bug bounty, high-profile targets${RESET}"
    echo ""
    
    # Option 2: Proxy
    echo -e "  ${YELLOW}${BOLD}2)${RESET} 🔗 ${YELLOW}${BOLD}PROXY CHAIN${RESET} ${DIM}(Balanced)${RESET}"
    echo -e "     ${GREEN}✓${RESET} Faster than Tor, less likely to be blocked"
    echo -e "     ${GREEN}✓${RESET} Automatic rotation through proxy pool"
    echo -e "     ${YELLOW}⚠${RESET} Requires proxy list file (HTTP/SOCKS5)"
    echo -e "     ${DIM}Best for: Large scans, need speed + anonymity${RESET}"
    echo ""
    
    # Option 3: Direct
    echo -e "  ${RED}${BOLD}3)${RESET} ⚡ ${RED}${BOLD}DIRECT CONNECTION${RESET} ${DIM}(Fast, No Anonymity)${RESET}"
    echo -e "     ${GREEN}✓${RESET} Maximum speed, most reliable"
    echo -e "     ${RED}✗${RESET} ${RED}YOUR REAL IP IS VISIBLE${RESET}"
    echo -e "     ${RED}✗${RESET} Target can easily track/block you"
    echo -e "     ${DIM}Best for: Private/authorized testing only${RESET}"
    echo ""
    
    # Get choice
    local choice=""
    while [[ ! "$choice" =~ ^[1-3]$ ]]; do
        read -p "  Select connection method [1-3] (default: 3): " choice
        [[ -z "$choice" ]] && choice="3"
    done
    
    case "$choice" in
        1)
            CONNECTION_METHOD="tor"
            
            # Check if Tor is running
            if [[ "$tor_status" != "running" ]]; then
                echo ""
                read -p "  Tor is not running. Start now? [Y/n]: " -n 1 -r
                echo ""
                
                if [[ ! $REPLY =~ ^[Nn]$ ]]; then
                    if start_tor_service; then
                        sleep 5
                        tor_status=$(check_tor_status)
                    fi
                fi
                
                if [[ "$tor_status" != "running" ]]; then
                    echo -e "  ${RED}✗${RESET} Failed to start Tor. Please start manually or choose another method."
                    choose_connection_method
                    return
                fi
            fi
            
            initialize_tor_connection || {
                echo -e "  ${RED}✗${RESET} Tor connection failed. Choose another method."
                choose_connection_method
                return
            }
            ;;
        2)
            CONNECTION_METHOD="proxy"
            
            echo ""
            echo -e "  ${CYAN}┌─────────────────────────────────────────────────────────────────────────┐${RESET}"
            echo -e "  ${CYAN}│${RESET} ${BOLD}PROXY OPTIONS${RESET}"
            echo -e "  ${CYAN}└─────────────────────────────────────────────────────────────────────────┘${RESET}"
            echo ""
            echo -e "    ${GREEN}1)${RESET} 📥 ${GREEN}Auto-download${RESET} - Fetch free proxies automatically"
            echo -e "    ${YELLOW}2)${RESET} 📁 ${YELLOW}Custom file${RESET}   - Use your own proxy list"
            echo ""
            
            local proxy_choice=""
            read -p "  Select proxy option [1-2] (default: 1): " proxy_choice
            [[ -z "$proxy_choice" ]] && proxy_choice="1"
            
            case "$proxy_choice" in
                1)
                    # Auto-download proxies
                    echo ""
                    if download_proxy_list; then
                        echo ""
                    else
                        echo -e "  ${RED}✗${RESET} Failed to download proxies. Try custom file or another method."
                        choose_connection_method
                        return
                    fi
                    ;;
                2)
                    echo ""
                    echo -e "  ${DIM}Proxy file format: one proxy per line${RESET}"
                    echo -e "  ${DIM}Formats: ip:port, http://ip:port, socks5://ip:port${RESET}"
                    echo ""
                    read -p "  Enter proxy file path: " PROXY_FILE
                    
                    if [[ ! -f "$PROXY_FILE" ]]; then
                        echo -e "  ${RED}✗${RESET} File not found: $PROXY_FILE"
                        choose_connection_method
                        return
                    fi
                    ;;
            esac
            
            initialize_proxy_connection || {
                echo -e "  ${RED}✗${RESET} Proxy initialization failed."
                choose_connection_method
                return
            }
            ;;
        3)
            CONNECTION_METHOD="direct"
            
            echo ""
            echo -e "  ${RED}╔═══════════════════════════════════════════════════════════════════════════╗${RESET}"
            echo -e "  ${RED}║${RESET} ${RED}${BOLD}⚠️  WARNING: DIRECT CONNECTION MODE${RESET}                                      ${RED}║${RESET}"
            echo -e "  ${RED}║${RESET}                                                                           ${RED}║${RESET}"
            echo -e "  ${RED}║${RESET}  Your real IP will be visible: ${BOLD}$real_ip${RESET}                        ${RED}║${RESET}"
            echo -e "  ${RED}║${RESET}  Target can identify and block you easily.                                ${RED}║${RESET}"
            echo -e "  ${RED}║${RESET}  Only use for authorized/private programs!                                ${RED}║${RESET}"
            echo -e "  ${RED}╚═══════════════════════════════════════════════════════════════════════════╝${RESET}"
            echo ""
            
            read -p "  Are you sure? [y/N]: " -n 1 -r
            echo ""
            
            if [[ ! $REPLY =~ ^[Yy]$ ]]; then
                choose_connection_method
                return
            fi
            
            initialize_direct_connection
            ;;
    esac
    
    # Choose stealth level
    echo ""
    echo -e "${CYAN}┌─────────────────────────────────────────────────────────────────────────────┐${RESET}"
    echo -e "${CYAN}│${RESET} 🎚️  ${BOLD}SELECT STEALTH LEVEL${RESET}"
    echo -e "${CYAN}└─────────────────────────────────────────────────────────────────────────────┘${RESET}"
    echo ""
    echo -e "  ${BOLD}1)${RESET} ⚡ ${YELLOW}FAST${RESET}      - 0.1-0.5s delay, 120 req/min ${DIM}(May trigger detection)${RESET}"
    echo -e "  ${BOLD}2)${RESET} 🎯 ${GREEN}BALANCED${RESET}  - 0.5-2.0s delay, 60 req/min ${DIM}(Recommended)${RESET}"
    echo -e "  ${BOLD}3)${RESET} 🛡️  ${CYAN}CAUTIOUS${RESET}  - 1.0-3.0s delay, 30 req/min ${DIM}(Careful scanning)${RESET}"
    echo -e "  ${BOLD}4)${RESET} 🐢 ${BLUE}SLOW${RESET}      - 2.0-5.0s delay, 15 req/min ${DIM}(Very cautious)${RESET}"
    echo -e "  ${BOLD}5)${RESET} 🔒 ${PURPLE}PARANOID${RESET}  - 5.0-10s delay, 6 req/min ${DIM}(Maximum stealth)${RESET}"
    echo ""
    
    local level=""
    while [[ ! "$level" =~ ^[1-5]$ ]]; do
        read -p "  Select stealth level [1-5] (default: 2): " level
        [[ -z "$level" ]] && level="2"
    done
    
    STEALTH_LEVEL=$level
    apply_stealth_settings
    
    # Show configuration summary
    echo ""
    echo -e "${GREEN}┌─────────────────────────────────────────────────────────────────────────────┐${RESET}"
    echo -e "${GREEN}│${RESET} ✅ ${BOLD}OPSEC CONFIGURATION COMPLETE${RESET}"
    echo -e "${GREEN}└─────────────────────────────────────────────────────────────────────────────┘${RESET}"
    echo ""
    
    local method_icon method_name
    case "$CONNECTION_METHOD" in
        tor)   method_icon="🧅"; method_name="${GREEN}TOR NETWORK${RESET}" ;;
        proxy) method_icon="🔗"; method_name="${YELLOW}PROXY CHAIN${RESET}" ;;
        direct) method_icon="⚡"; method_name="${RED}DIRECT${RESET}" ;;
    esac
    
    local level_icon level_name
    case "$STEALTH_LEVEL" in
        1) level_icon="⚡"; level_name="${YELLOW}FAST${RESET}" ;;
        2) level_icon="🎯"; level_name="${GREEN}BALANCED${RESET}" ;;
        3) level_icon="🛡️"; level_name="${CYAN}CAUTIOUS${RESET}" ;;
        4) level_icon="🐢"; level_name="${BLUE}SLOW${RESET}" ;;
        5) level_icon="🔒"; level_name="${PURPLE}PARANOID${RESET}" ;;
    esac
    
    echo -e "  ${BOLD}Connection:${RESET}   $method_icon $method_name"
    echo -e "  ${BOLD}Stealth:${RESET}      $level_icon $level_name"
    echo -e "  ${BOLD}Delay:${RESET}        ${DELAY_MIN}s - ${DELAY_MAX}s"
    echo -e "  ${BOLD}Max Req/Min:${RESET}  $MAX_REQUESTS_PER_MIN"
    echo -e "  ${BOLD}Threads:${RESET}      $THREADS_LIMIT"
    
    case "$CONNECTION_METHOD" in
        tor)
            echo -e "  ${BOLD}Tor Exit IP:${RESET}  ${CYAN}$TOR_EXIT_IP${RESET}"
            ;;
        proxy)
            echo -e "  ${BOLD}Proxies:${RESET}      ${CYAN}${#PROXY_POOL[@]} loaded${RESET}"
            ;;
        direct)
            echo -e "  ${BOLD}Your IP:${RESET}      ${RED}$real_ip${RESET} (visible!)"
            ;;
    esac
    
    echo ""
    sleep 2
}

# Display OpSec status during scan
show_opsec_status() {
    local method_icon
    case "$CONNECTION_METHOD" in
        tor)   method_icon="🧅" ;;
        proxy) method_icon="🔗" ;;
        direct) method_icon="⚡" ;;
    esac
    
    echo -e "${DIM}[$method_icon OpSec: $OPSEC_TOTAL_REQUESTS req | Rate limits: $OPSEC_RATE_LIMITS | Failures: $OPSEC_CONNECTION_FAILURES]${RESET}"
}

#═══════════════════════════════════════════════════════════════════════════════
# DEPENDENCY CHECKING & AUTO-INSTALLER
#═══════════════════════════════════════════════════════════════════════════════

# Detect OS and package manager
detect_os() {
    OS_TYPE="unknown"
    OS_DISTRO="unknown"
    PKG_MANAGER=""
    PKG_INSTALL=""
    PKG_UPDATE=""
    SUDO_CMD=""
    
    # Check if we need sudo
    [[ $EUID -ne 0 ]] && SUDO_CMD="sudo"
    
    # Detect OS type
    case "$(uname -s)" in
        Linux*)
            OS_TYPE="linux"
            
            # Detect Linux distro
            if [[ -f /etc/os-release ]]; then
                source /etc/os-release
                OS_DISTRO="$ID"
                OS_VERSION="$VERSION_ID"
                OS_NAME="$PRETTY_NAME"
            elif [[ -f /etc/debian_version ]]; then
                OS_DISTRO="debian"
            elif [[ -f /etc/redhat-release ]]; then
                OS_DISTRO="rhel"
            elif [[ -f /etc/arch-release ]]; then
                OS_DISTRO="arch"
            elif [[ -f /etc/alpine-release ]]; then
                OS_DISTRO="alpine"
            fi
            
            # Set package manager based on distro
            case "$OS_DISTRO" in
                ubuntu|debian|kali|parrot|pop|linuxmint|elementary|zorin)
                    PKG_MANAGER="apt"
                    PKG_INSTALL="$SUDO_CMD apt-get install -y"
                    PKG_UPDATE="$SUDO_CMD apt-get update"
                    ;;
                fedora)
                    PKG_MANAGER="dnf"
                    PKG_INSTALL="$SUDO_CMD dnf install -y"
                    PKG_UPDATE="$SUDO_CMD dnf check-update"
                    ;;
                centos|rhel|rocky|almalinux|ol)
                    PKG_MANAGER="yum"
                    PKG_INSTALL="$SUDO_CMD yum install -y"
                    PKG_UPDATE="$SUDO_CMD yum check-update"
                    ;;
                arch|manjaro|endeavouros|garuda)
                    PKG_MANAGER="pacman"
                    PKG_INSTALL="$SUDO_CMD pacman -S --noconfirm"
                    PKG_UPDATE="$SUDO_CMD pacman -Sy"
                    ;;
                alpine)
                    PKG_MANAGER="apk"
                    PKG_INSTALL="$SUDO_CMD apk add"
                    PKG_UPDATE="$SUDO_CMD apk update"
                    ;;
                opensuse*|sles)
                    PKG_MANAGER="zypper"
                    PKG_INSTALL="$SUDO_CMD zypper install -y"
                    PKG_UPDATE="$SUDO_CMD zypper refresh"
                    ;;
                void)
                    PKG_MANAGER="xbps"
                    PKG_INSTALL="$SUDO_CMD xbps-install -y"
                    PKG_UPDATE="$SUDO_CMD xbps-install -S"
                    ;;
                *)
                    # Try to detect by available package manager
                    if command -v apt-get &>/dev/null; then
                        PKG_MANAGER="apt"
                        PKG_INSTALL="$SUDO_CMD apt-get install -y"
                        PKG_UPDATE="$SUDO_CMD apt-get update"
                    elif command -v dnf &>/dev/null; then
                        PKG_MANAGER="dnf"
                        PKG_INSTALL="$SUDO_CMD dnf install -y"
                    elif command -v yum &>/dev/null; then
                        PKG_MANAGER="yum"
                        PKG_INSTALL="$SUDO_CMD yum install -y"
                    elif command -v pacman &>/dev/null; then
                        PKG_MANAGER="pacman"
                        PKG_INSTALL="$SUDO_CMD pacman -S --noconfirm"
                    fi
                    ;;
            esac
            ;;
        Darwin*)
            OS_TYPE="macos"
            OS_DISTRO="macos"
            OS_NAME="macOS $(sw_vers -productVersion 2>/dev/null || echo '')"
            
            if command -v brew &>/dev/null; then
                PKG_MANAGER="brew"
                PKG_INSTALL="brew install"
                PKG_UPDATE="brew update"
            else
                PKG_MANAGER="none"
            fi
            ;;
        CYGWIN*|MINGW*|MSYS*)
            OS_TYPE="windows"
            OS_DISTRO="windows"
            PKG_MANAGER="none"
            ;;
        *)
            OS_TYPE="unknown"
            ;;
    esac
    
    # Check for Go
    GO_INSTALLED=false
    GO_PATH=""
    if command -v go &>/dev/null; then
        GO_INSTALLED=true
        GO_PATH=$(go env GOPATH 2>/dev/null)/bin
        [[ -z "$GO_PATH" ]] && GO_PATH="$HOME/go/bin"
    fi
    
    # Check for Cargo (Rust)
    CARGO_INSTALLED=false
    if command -v cargo &>/dev/null; then
        CARGO_INSTALLED=true
    fi
    
    # Check for pip
    PIP_INSTALLED=false
    PIP_CMD=""
    if command -v pip3 &>/dev/null; then
        PIP_INSTALLED=true
        PIP_CMD="pip3"
    elif command -v pip &>/dev/null; then
        PIP_INSTALLED=true
        PIP_CMD="pip"
    fi
}

# Display detected system info
display_system_info() {
    echo ""
    echo -e "${CYAN}┌─────────────────────────────────────────────────────────────────────────────┐${RESET}"
    echo -e "${CYAN}│${RESET} 🖥️  ${BOLD}SYSTEM DETECTION${RESET}"
    echo -e "${CYAN}└─────────────────────────────────────────────────────────────────────────────┘${RESET}"
    echo ""
    echo -e "  ${BOLD}OS:${RESET}              ${OS_NAME:-$OS_TYPE}"
    echo -e "  ${BOLD}Distro:${RESET}          $OS_DISTRO"
    echo -e "  ${BOLD}Package Manager:${RESET} ${PKG_MANAGER:-none detected}"
    echo -e "  ${BOLD}Go:${RESET}              $([ "$GO_INSTALLED" = true ] && echo "${GREEN}✓ installed${RESET}" || echo "${YELLOW}✗ not found${RESET}")"
    echo -e "  ${BOLD}Cargo:${RESET}           $([ "$CARGO_INSTALLED" = true ] && echo "${GREEN}✓ installed${RESET}" || echo "${YELLOW}✗ not found${RESET}")"
    echo -e "  ${BOLD}Python/Pip:${RESET}      $([ "$PIP_INSTALLED" = true ] && echo "${GREEN}✓ installed${RESET}" || echo "${YELLOW}✗ not found${RESET}")"
    echo ""
}

# Get install command for a specific tool
get_install_command() {
    local tool="$1"
    local cmd=""
    
    case "$tool" in
        curl|jq|git|dig|whois)
            # System packages
            case "$PKG_MANAGER" in
                apt)     cmd="$PKG_INSTALL $tool" ;;
                dnf|yum) cmd="$PKG_INSTALL $tool" ;;
                pacman)  cmd="$PKG_INSTALL $tool" ;;
                apk)     cmd="$PKG_INSTALL $tool" ;;
                zypper)  cmd="$PKG_INSTALL $tool" ;;
                brew)    cmd="$PKG_INSTALL $tool" ;;
            esac
            ;;
        subfinder)
            if [[ "$GO_INSTALLED" == true ]]; then
                cmd="go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"
            elif [[ "$PKG_MANAGER" == "brew" ]]; then
                cmd="brew install subfinder"
            fi
            ;;
        httpx)
            if [[ "$GO_INSTALLED" == true ]]; then
                cmd="go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest"
            elif [[ "$PKG_MANAGER" == "brew" ]]; then
                cmd="brew install httpx"
            fi
            ;;
        nuclei)
            if [[ "$GO_INSTALLED" == true ]]; then
                cmd="go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"
            elif [[ "$PKG_MANAGER" == "brew" ]]; then
                cmd="brew install nuclei"
            fi
            ;;
        assetfinder)
            if [[ "$GO_INSTALLED" == true ]]; then
                cmd="go install -v github.com/tomnomnom/assetfinder@latest"
            fi
            ;;
        waybackurls)
            if [[ "$GO_INSTALLED" == true ]]; then
                cmd="go install -v github.com/tomnomnom/waybackurls@latest"
            fi
            ;;
        gau)
            if [[ "$GO_INSTALLED" == true ]]; then
                cmd="go install -v github.com/lc/gau/v2/cmd/gau@latest"
            fi
            ;;
        amass)
            if [[ "$GO_INSTALLED" == true ]]; then
                cmd="go install -v github.com/owasp-amass/amass/v4/...@master"
            elif [[ "$PKG_MANAGER" == "brew" ]]; then
                cmd="brew install amass"
            elif [[ "$PKG_MANAGER" == "apt" ]]; then
                cmd="$SUDO_CMD snap install amass"
            fi
            ;;
        feroxbuster)
            if [[ "$CARGO_INSTALLED" == true ]]; then
                cmd="cargo install feroxbuster"
            elif [[ "$PKG_MANAGER" == "brew" ]]; then
                cmd="brew install feroxbuster"
            elif [[ "$PKG_MANAGER" == "apt" ]]; then
                cmd="$SUDO_CMD apt-get install -y feroxbuster"
            elif [[ "$PKG_MANAGER" == "pacman" ]]; then
                cmd="$SUDO_CMD pacman -S feroxbuster"
            fi
            ;;
        rustscan)
            if [[ "$CARGO_INSTALLED" == true ]]; then
                cmd="cargo install rustscan"
            elif [[ "$PKG_MANAGER" == "brew" ]]; then
                cmd="brew install rustscan"
            fi
            ;;
        httprobe)
            if [[ "$GO_INSTALLED" == true ]]; then
                cmd="go install -v github.com/tomnomnom/httprobe@latest"
            fi
            ;;
        whatweb)
            case "$PKG_MANAGER" in
                apt)     cmd="$PKG_INSTALL whatweb" ;;
                brew)    cmd="brew install whatweb" ;;
                pacman)  cmd="$PKG_INSTALL whatweb" ;;
                *)
                    if command -v gem &>/dev/null; then
                        cmd="gem install whatweb"
                    fi
                    ;;
            esac
            ;;
        wpscan)
            case "$PKG_MANAGER" in
                apt)     cmd="$SUDO_CMD gem install wpscan" ;;
                brew)    cmd="brew install wpscan" ;;
                *)
                    if command -v gem &>/dev/null; then
                        cmd="gem install wpscan"
                    fi
                    ;;
            esac
            ;;
        wafw00f)
            if [[ "$PIP_INSTALLED" == true ]]; then
                cmd="$PIP_CMD install wafw00f"
            fi
            ;;
        nmap)
            case "$PKG_MANAGER" in
                apt)     cmd="$PKG_INSTALL nmap" ;;
                dnf|yum) cmd="$PKG_INSTALL nmap" ;;
                pacman)  cmd="$PKG_INSTALL nmap" ;;
                apk)     cmd="$PKG_INSTALL nmap" ;;
                brew)    cmd="brew install nmap" ;;
            esac
            ;;
        arjun)
            if [[ "$PIP_INSTALLED" == true ]]; then
                cmd="$PIP_CMD install arjun"
            fi
            ;;
        dnsx)
            if [[ "$GO_INSTALLED" == true ]]; then
                cmd="go install -v github.com/projectdiscovery/dnsx/cmd/dnsx@latest"
            fi
            ;;
        ffuf)
            if [[ "$GO_INSTALLED" == true ]]; then
                cmd="go install -v github.com/ffuf/ffuf@latest"
            elif [[ "$PKG_MANAGER" == "brew" ]]; then
                cmd="brew install ffuf"
            fi
            ;;
        gobuster)
            if [[ "$GO_INSTALLED" == true ]]; then
                cmd="go install -v github.com/OJ/gobuster/v3@latest"
            elif [[ "$PKG_MANAGER" == "brew" ]]; then
                cmd="brew install gobuster"
            fi
            ;;
        gowitness)
            if [[ "$GO_INSTALLED" == true ]]; then
                cmd="go install -v github.com/sensepost/gowitness@latest"
            fi
            ;;
        subzy)
            if [[ "$GO_INSTALLED" == true ]]; then
                cmd="go install -v github.com/LukaSikic/subzy@latest"
            fi
            ;;
        subjack)
            if [[ "$GO_INSTALLED" == true ]]; then
                cmd="go install -v github.com/haccer/subjack@latest"
            fi
            ;;
        findomain)
            case "$PKG_MANAGER" in
                brew)    cmd="brew install findomain" ;;
                *)
                    cmd="wget -q https://github.com/findomain/findomain/releases/latest/download/findomain-linux -O /usr/local/bin/findomain && chmod +x /usr/local/bin/findomain"
                    ;;
            esac
            ;;
        chaos)
            if [[ "$GO_INSTALLED" == true ]]; then
                cmd="go install -v github.com/projectdiscovery/chaos-client/cmd/chaos@latest"
            fi
            ;;
        masscan)
            case "$PKG_MANAGER" in
                apt)     cmd="$PKG_INSTALL masscan" ;;
                dnf|yum) cmd="$PKG_INSTALL masscan" ;;
                pacman)  cmd="$PKG_INSTALL masscan" ;;
                brew)    cmd="brew install masscan" ;;
            esac
            ;;
        chromium)
            case "$PKG_MANAGER" in
                apt)     cmd="$PKG_INSTALL chromium-browser" ;;
                dnf|yum) cmd="$PKG_INSTALL chromium" ;;
                pacman)  cmd="$PKG_INSTALL chromium" ;;
                brew)    cmd="brew install --cask chromium" ;;
            esac
            ;;
        seclists)
            case "$PKG_MANAGER" in
                apt)     cmd="$PKG_INSTALL seclists" ;;
                brew)    cmd="brew install seclists" ;;
                pacman)  cmd="$SUDO_CMD pacman -S seclists" ;;
                *)
                    cmd="git clone --depth 1 https://github.com/danielmiessler/SecLists.git /opt/SecLists"
                    ;;
            esac
            ;;
        golang)
            case "$PKG_MANAGER" in
                apt)     cmd="$PKG_INSTALL golang-go" ;;
                dnf|yum) cmd="$PKG_INSTALL golang" ;;
                pacman)  cmd="$PKG_INSTALL go" ;;
                apk)     cmd="$PKG_INSTALL go" ;;
                brew)    cmd="brew install go" ;;
            esac
            ;;
        rust)
            cmd="curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y"
            ;;
        pip)
            case "$PKG_MANAGER" in
                apt)     cmd="$PKG_INSTALL python3-pip" ;;
                dnf|yum) cmd="$PKG_INSTALL python3-pip" ;;
                pacman)  cmd="$PKG_INSTALL python-pip" ;;
                apk)     cmd="$PKG_INSTALL py3-pip" ;;
                brew)    cmd="brew install python3" ;;
            esac
            ;;
        puredns)
            if [[ "$GO_INSTALLED" == true ]]; then
                cmd="go install -v github.com/d3mondev/puredns/v2@latest"
            fi
            ;;
        naabu)
            if [[ "$GO_INSTALLED" == true ]]; then
                cmd="go install -v github.com/projectdiscovery/naabu/v2/cmd/naabu@latest"
            fi
            ;;
        katana)
            if [[ "$GO_INSTALLED" == true ]]; then
                cmd="go install -v github.com/projectdiscovery/katana/cmd/katana@latest"
            fi
            ;;
        gauplus)
            if [[ "$GO_INSTALLED" == true ]]; then
                cmd="go install -v github.com/IceBearSecurityLabs/gauplus@latest"
            fi
            ;;
        tlsx)
            if [[ "$GO_INSTALLED" == true ]]; then
                cmd="go install -v github.com/projectdiscovery/tlsx/cmd/tlsx@latest"
            fi
            ;;
        trufflehog)
            if [[ "$GO_INSTALLED" == true ]]; then
                cmd="go install -v github.com/trufflesecurity/trufflehog@latest"
            elif [[ "$PKG_MANAGER" == "brew" ]]; then
                cmd="brew install trufflehog"
            fi
            ;;
        massdns)
            case "$PKG_MANAGER" in
                apt)     cmd="$PKG_INSTALL massdns" ;;
                brew)    cmd="brew install massdns" ;;
                *)       cmd="git clone https://github.com/blechschmidt/massdns.git && cd massdns && make && mv bin/massdns /usr/local/bin/" ;;
            esac
            ;;
        linkfinder)
            cmd="pip3 install linkfinder 2>/dev/null || git clone https://github.com/GerbenJavado/LinkFinder.git && pip3 install -r LinkFinder/requirements.txt"
            ;;
        secretfinder)
            cmd="git clone https://github.com/m4ll0k/SecretFinder.git && pip3 install -r SecretFinder/requirements.txt"
            ;;
        kiterunner)
            if [[ "$GO_INSTALLED" == true ]]; then
                cmd="go install -v github.com/assetnote/kiterunner/cmd/kr@latest"
            fi
            ;;
        aquatone)
            if [[ "$GO_INSTALLED" == true ]]; then
                cmd="go install -v github.com/michenriksen/aquatone@latest"
            fi
            ;;
        cloud_enum)
            cmd="git clone https://github.com/initstring/cloud_enum.git ~/tools/cloud_enum && pip3 install -r ~/tools/cloud_enum/requirements.txt"
            ;;
        s3scanner)
            if [[ "$PIP_INSTALLED" == true ]]; then
                cmd="$PIP_CMD install s3scanner"
            fi
            ;;
        droopescan)
            if [[ "$PIP_INSTALLED" == true ]]; then
                cmd="$PIP_CMD install droopescan"
            fi
            ;;
        joomscan)
            cmd="git clone https://github.com/OWASP/joomscan.git /opt/joomscan"
            ;;
        git-dumper)
            if [[ "$PIP_INSTALLED" == true ]]; then
                cmd="$PIP_CMD install git-dumper"
            fi
            ;;
    esac
    
    echo "$cmd"
}

# Install a single tool
install_tool() {
    local tool="$1"
    local cmd=$(get_install_command "$tool")
    
    if [[ -z "$cmd" ]]; then
        echo -e "  ${RED}✗${RESET} No install method available for ${BOLD}$tool${RESET} on this system"
        return 1
    fi
    
    echo -e "  ${CYAN}→${RESET} Installing ${BOLD}$tool${RESET}..."
    echo -e "    ${DIM}$ $cmd${RESET}"
    
    if eval "$cmd" 2>&1 | while read -r line; do
        echo -e "    ${DIM}$line${RESET}"
    done; then
        echo -e "  ${GREEN}✓${RESET} ${BOLD}$tool${RESET} installed successfully"
        
        # Update PATH for Go tools
        if [[ "$GO_INSTALLED" == true ]] && [[ -d "$GO_PATH" ]]; then
            export PATH="$PATH:$GO_PATH"
        fi
        
        return 0
    else
        echo -e "  ${RED}✗${RESET} Failed to install ${BOLD}$tool${RESET}"
        return 1
    fi
}

# Main dependency check function
check_dependencies() {
    echo ""
    echo -e "${PURPLE}═══════════════════════════════════════════════════════════════════════════════${RESET}"
    echo -e "${PURPLE}${BOLD}                       📦 DEPENDENCY CHECK                                    ${RESET}"
    echo -e "${PURPLE}═══════════════════════════════════════════════════════════════════════════════${RESET}"
    
    # Detect OS first
    detect_os
    display_system_info
    
    # Categorize tools
    declare -A tool_status
    declare -A tool_category
    
    # Required tools (script won't run without these)
    local required_tools=("curl" "jq")
    
    # DNS validation tools
    local dns_tools=("dnsx" "puredns" "massdns")
    
    # Subdomain enumeration tools
    local subdomain_tools=("subfinder" "assetfinder" "amass" "findomain" "chaos")
    
    # HTTP probing tools
    local http_tools=("httprobe")
    
    # Fuzzing tools
    local fuzzing_tools=("feroxbuster" "ffuf" "gobuster")
    
    # Port scanning tools
    local port_tools=("rustscan" "masscan" "nmap")
    
    # Screenshot tools
    local screenshot_tools=("gowitness" "aquatone")
    
    # Technology detection tools
    local tech_tools=("whatweb")
    
    # CMS scanning tools
    local cms_tools=("wpscan" "droopescan" "joomscan")
    
    # WAF detection tools
    local waf_tools=("wafw00f")
    
    # Subdomain takeover tools
    local takeover_tools=("subzy" "subjack")
    
    # JS analysis tools
    local js_tools=("linkfinder" "secretfinder")
    
    # API fuzzing tools
    local api_tools=("kiterunner" "arjun")
    
    # Vulnerability scanning tools
    local vuln_tools=("nuclei")
    
    # Wayback/historical tools
    local wayback_tools=("waybackurls" "gau")
    
    # Cloud enumeration tools
    local cloud_tools=("cloud_enum" "s3scanner")
    
    # Check all tools
    local missing_required=()
    
    echo -e "${CYAN}┌─────────────────────────────────────────────────────────────────────────────┐${RESET}"
    echo -e "${CYAN}│${RESET} 🔍 ${BOLD}TOOL STATUS${RESET}"
    echo -e "${CYAN}└─────────────────────────────────────────────────────────────────────────────┘${RESET}"
    echo ""
    
    # Check required
    echo -e "  ${BOLD}${RED}Required:${RESET}"
    for tool in "${required_tools[@]}"; do
        if command -v "$tool" &>/dev/null; then
            local version=$($tool --version 2>&1 | head -1 | cut -c1-40)
            echo -e "    ${GREEN}✓${RESET} $tool ${DIM}($version)${RESET}"
        else
            echo -e "    ${RED}✗${RESET} $tool ${RED}(MISSING - REQUIRED)${RESET}"
            missing_required+=("$tool")
        fi
    done
    echo ""
    
    # Function to check and display tool category
    check_tool_category() {
        local category_name="$1"
        local color="$2"
        shift 2
        local tools=("$@")
        
        echo -e "  ${BOLD}${color}${category_name}:${RESET}"
        local found=0
        local missing=0
        for tool in "${tools[@]}"; do
            # Handle special tool names (kiterunner binary is 'kr')
            local check_name="$tool"
            [[ "$tool" == "kiterunner" ]] && check_name="kr"
            [[ "$tool" == "cloud_enum" ]] && check_name="cloud_enum.py"
            
            if command -v "$check_name" &>/dev/null || command -v "$tool" &>/dev/null; then
                echo -e "    ${GREEN}✓${RESET} $tool"
                ((found++))
            else
                echo -e "    ${DIM}○${RESET} $tool"
                ((missing++))
            fi
        done
        echo ""
        return $missing
    }
    
    # Check each category
    check_tool_category "DNS Validation" "${CYAN}" "${dns_tools[@]}"
    check_tool_category "Subdomain Enumeration" "${YELLOW}" "${subdomain_tools[@]}"
    check_tool_category "HTTP Probing" "${GREEN}" "${http_tools[@]}"
    check_tool_category "Directory Fuzzing" "${PURPLE}" "${fuzzing_tools[@]}"
    check_tool_category "Port Scanning" "${RED}" "${port_tools[@]}"
    check_tool_category "Screenshots" "${CYAN}" "${screenshot_tools[@]}"
    check_tool_category "Technology Detection" "${YELLOW}" "${tech_tools[@]}"
    check_tool_category "CMS Scanning" "${GREEN}" "${cms_tools[@]}"
    check_tool_category "WAF Detection" "${PURPLE}" "${waf_tools[@]}"
    check_tool_category "Subdomain Takeover" "${RED}" "${takeover_tools[@]}"
    check_tool_category "JS Analysis" "${CYAN}" "${js_tools[@]}"
    check_tool_category "API Fuzzing" "${YELLOW}" "${api_tools[@]}"
    check_tool_category "Vulnerability Scanning" "${RED}" "${vuln_tools[@]}"
    check_tool_category "Wayback/Historical" "${GREEN}" "${wayback_tools[@]}"
    check_tool_category "Cloud Enumeration" "${PURPLE}" "${cloud_tools[@]}"
    
    # Check SecLists
    echo -e "  ${BOLD}${PURPLE}Wordlists:${RESET}"
    if [[ -d "$SECLISTS_PATH" ]]; then
        local wl_count=$(find "$SECLISTS_PATH" -name "*.txt" 2>/dev/null | wc -l)
        echo -e "    ${GREEN}✓${RESET} SecLists ${DIM}($wl_count wordlists)${RESET}"
    else
        echo -e "    ${YELLOW}○${RESET} SecLists ${DIM}(not found at $SECLISTS_PATH)${RESET}"
    fi
    echo ""
    
    # Handle missing required tools
    if [[ ${#missing_required[@]} -gt 0 ]]; then
        echo -e "${RED}┌─────────────────────────────────────────────────────────────────────────────┐${RESET}"
        echo -e "${RED}│${RESET} ❌ ${BOLD}MISSING REQUIRED TOOLS${RESET}"
        echo -e "${RED}└─────────────────────────────────────────────────────────────────────────────┘${RESET}"
        echo ""
        echo -e "  The following tools are ${RED}REQUIRED${RESET} and must be installed:"
        for tool in "${missing_required[@]}"; do
            local cmd=$(get_install_command "$tool")
            echo -e "    ${RED}•${RESET} $tool"
            [[ -n "$cmd" ]] && echo -e "      ${DIM}Install: $cmd${RESET}"
        done
        echo ""
        
        if [[ -n "$PKG_MANAGER" ]]; then
            echo -e "${YELLOW}┌─────────────────────────────────────────────────────────────────────────────┐${RESET}"
            read -p "  Install required tools now? [Y/n]: " -n 1 -r
            echo ""
            echo -e "${YELLOW}└─────────────────────────────────────────────────────────────────────────────┘${RESET}"
            
            if [[ ! $REPLY =~ ^[Nn]$ ]]; then
                echo ""
                [[ -n "$PKG_UPDATE" ]] && echo -e "  ${DIM}Updating package lists...${RESET}" && eval "$PKG_UPDATE" &>/dev/null
                
                for tool in "${missing_required[@]}"; do
                    install_tool "$tool"
                done
                
                # Re-check
                for tool in "${missing_required[@]}"; do
                    if ! command -v "$tool" &>/dev/null; then
                        echo ""
                        log "ERROR" "Failed to install required tool: $tool"
                        echo -e "  Please install manually and try again."
                        exit 1
                    fi
                done
            else
                echo ""
                log "ERROR" "Required tools must be installed to continue."
                exit 1
            fi
        else
            log "ERROR" "Please install required tools manually and try again."
            exit 1
        fi
    fi
    
    # Show quick install hint
    echo -e "${CYAN}┌─────────────────────────────────────────────────────────────────────────────┐${RESET}"
    echo -e "${CYAN}│${RESET} 💡 ${BOLD}Quick Install:${RESET} Run ${GREEN}./0xsh3x --install-deps${RESET} to install all tools"
    echo -e "${CYAN}└─────────────────────────────────────────────────────────────────────────────┘${RESET}"
    echo ""
    
    # Re-discover tools after any installation
    discover_tools
    
    echo ""
    log "SUCCESS" "🔧 Dependency check completed"
    echo ""
}

#═══════════════════════════════════════════════════════════════════════════════
# DIRECTORY SETUP
#═══════════════════════════════════════════════════════════════════════════════

setup_directories() {
    log "INFO" "📁 ${BOLD}Setting up output directories...${RESET}"
    
    # Create timestamped output directory for isolation
    local target_sanitized=$(echo "$TARGET" | sed 's/[\/:]/_/g')
    local timestamp=$(date +"%Y%m%d_%H%M%S")
    
    # If user didn't specify output dir, create timestamped one
    if [[ "$OUTPUT_DIR" == "./0xsh3x_results" ]]; then
        OUTPUT_DIR="./0xsh3x_results/${target_sanitized}_${timestamp}"
    fi
    
    # Create main directories
    mkdir -p "$OUTPUT_DIR"/{00-scope,01-subdomains/raw,02-hosts/ports,03-directories/{by_host,by_status,raw},04-javascript/js_source,05-parameters/arjun_results,06-technologies/{wpscan,whatweb},07-wayback/{urls,by_host},08-reports,09-vulnerabilities,10-screenshots,11-api-fuzzing,12-cloud-assets,13-secrets}
    
    # Create temp directory and tracking files
    TEMP_DIR=$(mktemp -d)
    PIDS_FILE="$TEMP_DIR/pids"
    FINDINGS_FILE="$TEMP_DIR/findings"
    STATE_FILE="$OUTPUT_DIR/.0xsh3x.state"
    TMP_TRACK=()
    touch "$PIDS_FILE" "$FINDINGS_FILE" "$STATE_FILE"
    
    # Initialize phase state tracking
    echo "# Phase completion markers" > "$STATE_FILE"
    echo "TARGET=$TARGET" >> "$STATE_FILE"
    echo "START_TIME=$(date +%s)" >> "$STATE_FILE"
    
    # Initialize log file
    echo "═══════════════════════════════════════════════════════════════════════" > "$OUTPUT_DIR/08-reports/timeline.log"
    echo "0xsh3x - Execution Log" >> "$OUTPUT_DIR/08-reports/timeline.log"
    echo "Started: $(timestamp)" >> "$OUTPUT_DIR/08-reports/timeline.log"
    echo "Target: $TARGET" >> "$OUTPUT_DIR/08-reports/timeline.log"
    echo "Output: $OUTPUT_DIR" >> "$OUTPUT_DIR/08-reports/timeline.log"
    echo "═══════════════════════════════════════════════════════════════════════" >> "$OUTPUT_DIR/08-reports/timeline.log"
    
    log "SUCCESS" "Output directories created at: $OUTPUT_DIR"
}

#═══════════════════════════════════════════════════════════════════════════════
# SCOPE HANDLING
#═══════════════════════════════════════════════════════════════════════════════

ask_scope_type() {
    if [[ -n "$SCOPE_TYPE_ARG" ]]; then
        SCOPE_TYPE="$SCOPE_TYPE_ARG"
        return
    fi
    
    echo ""
    echo -e "${PURPLE}┌─────────────────────────────────────────────────────────────────────────────┐${RESET}"
    echo -e "${PURPLE}│${RESET} ${BOLD}📋 SCOPE SELECTION${RESET}                                                         ${PURPLE}│${RESET}"
    echo -e "${PURPLE}└─────────────────────────────────────────────────────────────────────────────┘${RESET}"
    echo ""
    echo -e "  ${BOLD}1)${RESET} 🌐 ${GREEN}Wildcard scope${RESET} (*.${TARGET}) - Enumerate and scan all subdomains"
    echo -e "  ${BOLD}2)${RESET} 🎯 ${YELLOW}Single domain${RESET} (${TARGET}) - Scan only this specific domain"
    echo ""
    read -p "  Select scope type [1/2] (default: 1): " choice
    
    case "$choice" in
        2)
            SCOPE_TYPE="single"
            log "INFO" "📋 Scope: Single domain - ${BOLD}$TARGET${RESET}"
            ;;
        *)
            SCOPE_TYPE="wildcard"
            log "INFO" "📋 Scope: Wildcard - ${BOLD}*.$TARGET${RESET}"
            ;;
    esac
}

save_scope() {
    local scope_file="$OUTPUT_DIR/00-scope/scope.txt"
    
    echo "# 0xsh3x Scope Configuration" > "$scope_file"
    echo "# Generated: $(timestamp)" >> "$scope_file"
    echo "" >> "$scope_file"
    echo "TARGET=$TARGET" >> "$scope_file"
    echo "SCOPE_TYPE=$SCOPE_TYPE" >> "$scope_file"
    echo "SCAN_MODE=$SCAN_MODE" >> "$scope_file"
    echo "" >> "$scope_file"
    
    if [[ "$SCOPE_TYPE" == "wildcard" ]]; then
        echo "# In-Scope:" >> "$scope_file"
        echo "*.$TARGET" >> "$scope_file"
        echo "$TARGET" >> "$scope_file"
    else
        echo "# In-Scope:" >> "$scope_file"
        echo "$TARGET" >> "$scope_file"
    fi
    
    log "SUCCESS" "Scope saved to $scope_file"
}

#═══════════════════════════════════════════════════════════════════════════════
# SUBDOMAIN ENUMERATION
#═══════════════════════════════════════════════════════════════════════════════

run_subfinder() {
    if [[ -z "$SUBFINDER" ]]; then
        log "WARN" "Subfinder not installed, skipping..."
        return 1
    fi
    
    echo ""
    echo -e "${PURPLE}┌─────────────────────────────────────────────────────────────────────────────┐${RESET}"
    echo -e "${PURPLE}│${RESET} 🔍 ${BOLD}SUBFINDER${RESET} - Discovering subdomains for ${CYAN}$TARGET${RESET}"
    echo -e "${PURPLE}└─────────────────────────────────────────────────────────────────────────────┘${RESET}"
    
    local output_file="$OUTPUT_DIR/01-subdomains/raw/subfinder.txt"
    local count=0
    
    # Run subfinder and display results live
    $SUBFINDER -d "$TARGET" -all 2>/dev/null | while IFS= read -r subdomain; do
        if [[ -n "$subdomain" ]]; then
            ((count++))
            echo "$subdomain" >> "$output_file"
            # Display with nice formatting
            printf "  ${GREEN}✓${RESET} ${DIM}[%04d]${RESET} %s\n" "$count" "$subdomain"
        fi
    done
    
    # Sort and dedupe
    sort -u "$output_file" -o "$output_file" 2>/dev/null
    
    local final_count=$(wc -l < "$output_file" 2>/dev/null || echo 0)
    echo ""
    echo -e "  ${SUCCESS} ${GREEN}${BOLD}Subfinder completed: $final_count unique subdomains${RESET}"
    echo ""
}

run_assetfinder() {
    if [[ -z "$ASSETFINDER" ]]; then
        log "WARN" "Assetfinder not installed, skipping..."
        return 1
    fi
    
    echo -e "${CYAN}  ➜ Running Assetfinder...${RESET}"
    local output_file="$OUTPUT_DIR/01-subdomains/raw/assetfinder.txt"
    
    $ASSETFINDER --subs-only "$TARGET" 2>/dev/null | sort -u > "$output_file"
    
    local count=$(wc -l < "$output_file" 2>/dev/null || echo 0)
    echo -e "  ${SUCCESS} ${GREEN}Assetfinder: $count subdomains${RESET}"
}

run_amass_passive() {
    if [[ -z "$AMASS" ]]; then
        log "WARN" "Amass not installed, skipping..."
        return 1
    fi
    
    # Ask user if they want to run amass (it's slow)
    echo ""
    echo -e "${YELLOW}┌─────────────────────────────────────────────────────────────────────────────┐${RESET}"
    echo -e "${YELLOW}│${RESET} ⚠️  ${BOLD}AMASS${RESET} - This tool is powerful but ${YELLOW}SLOW${RESET} (5-10 minutes)"
    echo -e "${YELLOW}└─────────────────────────────────────────────────────────────────────────────┘${RESET}"
    echo ""
    read -p "  Do you want to run Amass? [y/N]: " -n 1 -r
    echo ""
    
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        log "INFO" "⏭️  Skipping Amass (user choice)"
        return 0
    fi
    
    echo -e "${CYAN}  ➜ Running Amass (passive mode)...${RESET}"
    echo -e "${DIM}    This may take several minutes...${RESET}"
    local output_file="$OUTPUT_DIR/01-subdomains/raw/amass.txt"
    
    # Run with timeout and show spinner
    timeout 600 $AMASS enum -passive -d "$TARGET" -o "$output_file" 2>/dev/null &
    local pid=$!
    
    local spin='⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏'
    local i=0
    while kill -0 "$pid" 2>/dev/null; do
        printf "\r  ${CYAN}${spin:i++%${#spin}:1}${RESET} Amass scanning... "
        sleep 0.2
    done
    printf "\r                                    \r"
    
    wait $pid 2>/dev/null
    
    local count=$(wc -l < "$output_file" 2>/dev/null || echo 0)
    echo -e "  ${SUCCESS} ${GREEN}Amass (passive): $count subdomains${RESET}"
}

run_amass_active() {
    if [[ -z "$AMASS" ]]; then
        return 1
    fi
    
    if [[ "$ENABLE_ACTIVE_SUBDOMAIN" != true ]]; then
        return 0
    fi
    
    echo ""
    echo -e "${RED}┌─────────────────────────────────────────────────────────────────────────────┐${RESET}"
    echo -e "${RED}│${RESET} ⚠️  ${BOLD}AMASS ACTIVE MODE${RESET} - Brute-force subdomain enumeration"
    echo -e "${RED}│${RESET}    ${YELLOW}WARNING:${RESET} This is ${RED}NOISY${RESET} and can take ${YELLOW}30+ minutes${RESET}"
    echo -e "${RED}└─────────────────────────────────────────────────────────────────────────────┘${RESET}"
    echo ""
    read -p "  Do you want to run Amass active brute-force? [y/N]: " -n 1 -r
    echo ""
    
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        log "INFO" "⏭️  Skipping Amass active mode (user choice)"
        return 0
    fi
    
    echo -e "${RED}  ➜ Running Amass (ACTIVE brute-force)...${RESET}"
    echo -e "${DIM}    This will take a long time...${RESET}"
    local output_file="$OUTPUT_DIR/01-subdomains/raw/amass_active.txt"
    
    timeout 1800 $AMASS enum -active -brute -d "$TARGET" -o "$output_file" 2>/dev/null &
    local pid=$!
    
    local spin='⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏'
    local i=0
    while kill -0 "$pid" 2>/dev/null; do
        printf "\r  ${RED}${spin:i++%${#spin}:1}${RESET} Amass active scanning... "
        sleep 0.2
    done
    printf "\r                                    \r"
    
    wait $pid 2>/dev/null
    
    local count=$(wc -l < "$output_file" 2>/dev/null || echo 0)
    echo -e "  ${SUCCESS} ${GREEN}Amass (active): $count subdomains${RESET}"
}

run_crtsh() {
    echo -e "${CYAN}  ➜ Querying crt.sh (Certificate Transparency)...${RESET}"
    local output_file="$OUTPUT_DIR/01-subdomains/raw/crtsh.txt"
    
    # Query crt.sh API with timeout
    local response=$(timeout 30 curl -s "https://crt.sh/?q=%25.$TARGET&output=json" 2>/dev/null)
    
    if [[ -n "$response" ]] && [[ "$response" != "null" ]] && [[ "$response" != "[]" ]]; then
        echo "$response" | jq -r '.[].name_value' 2>/dev/null | \
            sed 's/\*\.//g' | \
            grep -v "^$" | \
            sort -u > "$output_file"
        
        local count=$(wc -l < "$output_file" 2>/dev/null || echo 0)
        echo -e "  ${SUCCESS} ${GREEN}crt.sh: $count subdomains${RESET}"
    else
        echo -e "  ${WARN}crt.sh: no results${RESET}"
        touch "$output_file"
    fi
}

run_hackertarget() {
    echo -e "${CYAN}  ➜ Querying HackerTarget API...${RESET}"
    local output_file="$OUTPUT_DIR/01-subdomains/raw/hackertarget.txt"
    
    local response=$(timeout 30 curl -s "https://api.hackertarget.com/hostsearch/?q=$TARGET" 2>/dev/null)
    
    if [[ -n "$response" ]] && [[ "$response" != "error"* ]]; then
        echo "$response" | cut -d',' -f1 | grep -v "^$" | sort -u > "$output_file"
        local count=$(wc -l < "$output_file" 2>/dev/null || echo 0)
        echo -e "  ${SUCCESS} ${GREEN}HackerTarget: $count subdomains${RESET}"
    else
        echo -e "  ${WARN}HackerTarget: no results${RESET}"
        touch "$output_file"
    fi
}

aggregate_subdomains() {
    echo ""
    echo -e "${CYAN}  ➜ Aggregating and deduplicating...${RESET}"
    
    local all_file="$OUTPUT_DIR/01-subdomains/subdomains_all.txt"
    
    # Count per source before aggregation
    echo -e "  ${DIM}────────────────────────────────────${RESET}"
    for source in "$OUTPUT_DIR/01-subdomains/raw/"*.txt; do
        if [[ -f "$source" ]]; then
            local name=$(basename "$source" .txt)
            local count=$(wc -l < "$source" 2>/dev/null || echo 0)
            printf "    ${DIM}%-15s %5d${RESET}\n" "$name:" "$count"
        fi
    done
    echo -e "  ${DIM}────────────────────────────────────${RESET}"
    
    # Combine all sources
    cat "$OUTPUT_DIR/01-subdomains/raw/"*.txt 2>/dev/null | \
        tr '[:upper:]' '[:lower:]' | \
        grep -E "^[a-zA-Z0-9]" | \
        grep -E "\.$TARGET$|^$TARGET$" | \
        sort -u > "$all_file"
    
    TOTAL_SUBDOMAINS=$(wc -l < "$all_file" 2>/dev/null || echo 0)
    
    echo -e "    ${BOLD}TOTAL UNIQUE:${RESET} ${GREEN}${BOLD}$TOTAL_SUBDOMAINS${RESET}"
}

#═══════════════════════════════════════════════════════════════════════════════
# 🔄 RECURSIVE MULTILEVEL SUBDOMAIN DISCOVERY SYSTEM
# Implements 6-level deep subdomain enumeration with smart fuzzing
#═══════════════════════════════════════════════════════════════════════════════

# Configuration
RECURSIVE_MAX_DEPTH=${RECURSIVE_MAX_DEPTH:-6}
RECURSIVE_TIMEOUT=${RECURSIVE_TIMEOUT:-30}  # Minutes per branch
RECURSIVE_PARALLEL=${RECURSIVE_PARALLEL:-5}  # Parallel branches

# Track discoveries per level
declare -a LEVEL_DISCOVERIES=(0 0 0 0 0 0 0)

# ══════════════════════════════════════════════════════════════════════════════
# SMART SUBDOMAIN BRUTEFORCE
# ══════════════════════════════════════════════════════════════════════════════
# 
# LOGIC:
# 1. Only bruteforce LEVEL 2 (word.target.com) - not deeper levels
# 2. Exclude subdomains already found by passive enumeration
# 3. Real DNS resolution with progress tracking
#
# If subfinder finds: api.target.com, dev.api.target.com, staging.target.com
# We will bruteforce: word.target.com (NOT word.api.target.com)
# And exclude: api, dev, staging (already found)
#
run_subdomain_bruteforce_smart() {
    echo ""
    echo -e "${PURPLE}╔══════════════════════════════════════════════════════════════════════════════╗${RESET}"
    echo -e "${PURPLE}║${RESET}  ${BOLD}SUBDOMAIN BRUTEFORCE (Level 2 Only)${RESET}                                       ${PURPLE}║${RESET}"
    echo -e "${PURPLE}╠══════════════════════════════════════════════════════════════════════════════╣${RESET}"
    echo -e "${PURPLE}║${RESET}  Bruteforce word.target.com - excludes already discovered subdomains         ${PURPLE}║${RESET}"
    echo -e "${PURPLE}╚══════════════════════════════════════════════════════════════════════════════╝${RESET}"
    echo ""
    
    local subs_dir="$OUTPUT_DIR/01-subdomains"
    local input_file="$subs_dir/subdomains_all.txt"
    local brute_dir="$subs_dir/bruteforce"
    mkdir -p "$brute_dir"
    
    # Count existing subdomains
    local existing_count=$(wc -l < "$input_file" 2>/dev/null || echo 0)
    
    # Extract already found level-2 prefixes to exclude
    local exclude_file="/tmp/exclude_prefixes_$$.txt"
    cat "$input_file" 2>/dev/null | \
        sed "s/\.${TARGET}$//" | \
        cut -d'.' -f1 | \
        sort -u > "$exclude_file"
    
    local exclude_count=$(wc -l < "$exclude_file" 2>/dev/null || echo 0)
    
    echo -e "  ${CYAN}Current subdomains:${RESET} ${BOLD}$existing_count${RESET} (from passive enumeration)"
    echo -e "  ${CYAN}Prefixes to exclude:${RESET} ${BOLD}$exclude_count${RESET} (already discovered)"
    echo ""
    
    # Detect DNS tool
    local dns_tool=""
    if [[ -n "$PUREDNS" ]] && command -v massdns &>/dev/null; then
        dns_tool="puredns"
        echo -e "  ${GREEN}✓${RESET} Using: puredns (fastest)"
    elif [[ -n "$GOBUSTER" ]]; then
        dns_tool="gobuster"
        echo -e "  ${GREEN}✓${RESET} Using: gobuster dns"
    elif [[ -n "$DNSX" ]]; then
        dns_tool="dnsx"
        echo -e "  ${GREEN}✓${RESET} Using: dnsx"
    else
        dns_tool="dig"
        echo -e "  ${YELLOW}⚠${RESET}  Using: dig (slow)"
    fi
    
    echo ""
    echo -e "  ${CYAN}Wordlist options:${RESET}"
    echo -e "    ${GREEN}1)${RESET} Small   - 100 words   (~2 min)"
    echo -e "    ${YELLOW}2)${RESET} Medium  - 500 words   (~5 min)"
    echo -e "    ${RED}3)${RESET} Large   - 2000 words  (~15 min)"
    echo -e "    ${DIM}4)${RESET} Skip bruteforce"
    echo ""
    read -p "  Select [1-4] (default: 1): " wl_choice
    [[ -z "$wl_choice" ]] && wl_choice="1"
    
    [[ "$wl_choice" == "4" ]] && { log "INFO" "Skipping bruteforce"; rm -f "$exclude_file"; return; }
    
    enable_phase_skip "Subdomain Bruteforce"
    
    # Create wordlist
    local wordlist="/tmp/brute_wordlist_$$.txt"
    create_bruteforce_wordlist "$wordlist" "$wl_choice"
    
    # Remove already-found prefixes from wordlist
    local clean_wordlist="/tmp/brute_clean_$$.txt"
    if [[ -s "$exclude_file" ]]; then
        grep -vxFf "$exclude_file" "$wordlist" > "$clean_wordlist" 2>/dev/null
    else
        cp "$wordlist" "$clean_wordlist"
    fi
    
    local wl_original=$(wc -l < "$wordlist")
    local wl_clean=$(wc -l < "$clean_wordlist")
    local wl_excluded=$((wl_original - wl_clean))
    
    echo ""
    echo -e "  ${CYAN}Wordlist:${RESET} ${BOLD}$wl_clean${RESET} words (excluded $wl_excluded already found)"
    echo ""
    
    if [[ $wl_clean -eq 0 ]]; then
        log "INFO" "All wordlist entries already discovered"
        rm -f "$wordlist" "$clean_wordlist" "$exclude_file"
        disable_phase_skip
        return
    fi
    
    local start_time=$(date +%s)
    local results_file="$brute_dir/bruteforce_results.txt"
    > "$results_file"
    
    echo -e "  ${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RESET}"
    echo -e "  ${CYAN}Bruteforcing:${RESET} ${BOLD}*.${TARGET}${RESET}"
    echo -e "  ${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RESET}"
    echo ""
    
    # Generate candidates (word.TARGET)
    local candidates="/tmp/brute_candidates_$$.txt"
    while read -r word; do
        [[ -z "$word" ]] && continue
        [[ "$word" =~ ^# ]] && continue
        echo "${word}.${TARGET}"
    done < "$clean_wordlist" > "$candidates"
    
    local cand_count=$(wc -l < "$candidates")
    echo -e "  ${DIM}Generated $cand_count candidates${RESET}"
    
    # Resolve using selected tool
    case "$dns_tool" in
        puredns)
            local resolvers="/tmp/resolvers_$$.txt"
            echo -e "8.8.8.8\n8.8.4.4\n1.1.1.1\n9.9.9.9" > "$resolvers"
            
            echo -e "  ${DIM}Running puredns...${RESET}"
            $PUREDNS resolve "$candidates" -r "$resolvers" -w "$results_file" \
                --wildcard-batch 1000000 -t 100 -q 2>/dev/null &
            local pid=$!
            
            while kill -0 $pid 2>/dev/null; do
                should_skip_phase && { kill $pid 2>/dev/null; break; }
                local found=$(wc -l < "$results_file" 2>/dev/null || echo 0)
                local elapsed=$(($(date +%s) - start_time))
                printf "\r  ${DIM}Resolving... %d found (%ds)${RESET}     " "$found" "$elapsed"
                sleep 2
            done
            wait $pid 2>/dev/null
            
            rm -f "$resolvers"
            ;;
            
        gobuster)
            echo -e "  ${DIM}Running gobuster dns...${RESET}"
            $GOBUSTER dns -d "$TARGET" -w "$clean_wordlist" -t 50 --timeout 3s -q 2>/dev/null | \
                grep "Found:" | awk '{print $2}' > "$results_file" &
            local pid=$!
            
            while kill -0 $pid 2>/dev/null; do
                should_skip_phase && { kill $pid 2>/dev/null; break; }
                local found=$(wc -l < "$results_file" 2>/dev/null || echo 0)
                local elapsed=$(($(date +%s) - start_time))
                printf "\r  ${DIM}Resolving... %d found (%ds)${RESET}     " "$found" "$elapsed"
                sleep 2
            done
            wait $pid 2>/dev/null
            ;;
            
        dnsx)
            echo -e "  ${DIM}Running dnsx...${RESET}"
            $DNSX -l "$candidates" -silent -a -resp -t 100 2>/dev/null | \
                awk '{print $1}' > "$results_file" &
            local pid=$!
            
            while kill -0 $pid 2>/dev/null; do
                should_skip_phase && { kill $pid 2>/dev/null; break; }
                local found=$(wc -l < "$results_file" 2>/dev/null || echo 0)
                local elapsed=$(($(date +%s) - start_time))
                printf "\r  ${DIM}Resolving... %d found (%ds)${RESET}     " "$found" "$elapsed"
                sleep 2
            done
            wait $pid 2>/dev/null
            ;;
            
        dig|*)
            echo -e "  ${DIM}Using dig (slow)...${RESET}"
            local count=0
            while read -r candidate; do
                [[ -z "$candidate" ]] && continue
                should_skip_phase && break
                
                ((count++))
                if [[ $((count % 10)) -eq 0 ]]; then
                    local elapsed=$(($(date +%s) - start_time))
                    printf "\r  ${DIM}Testing %d/%d (%ds)${RESET}     " "$count" "$cand_count" "$elapsed"
                fi
                
                if dig +short "$candidate" A 2>/dev/null | grep -qE "^[0-9]"; then
                    echo "$candidate" >> "$results_file"
                fi
            done < "$candidates"
            ;;
    esac
    
    printf "\r                                                      \r"
    
    # Filter only NEW subdomains
    local new_only="/tmp/brute_new_$$.txt"
    if [[ -s "$results_file" ]]; then
        comm -23 <(sort -u "$results_file") <(sort -u "$input_file") > "$new_only" 2>/dev/null
    else
        > "$new_only"
    fi
    
    local new_count=$(wc -l < "$new_only" 2>/dev/null || echo 0)
    local duration=$(($(date +%s) - start_time))
    
    if [[ $new_count -gt 0 ]]; then
        # Add new subdomains to main file
        cat "$new_only" >> "$input_file"
        sort -u -o "$input_file" "$input_file"
        
        # Save bruteforce discoveries
        cp "$new_only" "$brute_dir/new_discoveries.txt"
        
        echo -e "  ${GREEN}✓ Found $new_count NEW subdomains!${RESET}"
        echo ""
        echo -e "  ${DIM}Sample:${RESET}"
        head -5 "$new_only" | while read -r sub; do
            echo -e "    ${GREEN}+${RESET} $sub"
        done
        [[ $new_count -gt 5 ]] && echo -e "    ${DIM}... and $((new_count - 5)) more${RESET}"
    else
        echo -e "  ${DIM}No new subdomains found${RESET}"
    fi
    
    # Update global counter
    TOTAL_SUBDOMAINS=$(wc -l < "$input_file" 2>/dev/null || echo 0)
    
    # Cleanup
    rm -f "$wordlist" "$clean_wordlist" "$exclude_file" "$candidates" "$new_only" "$results_file"
    
    disable_phase_skip
    
    echo ""
    echo -e "${GREEN}╔══════════════════════════════════════════════════════════════════════════════╗${RESET}"
    echo -e "${GREEN}║${RESET}  ${BOLD}BRUTEFORCE COMPLETE${RESET}                                                        ${GREEN}║${RESET}"
    echo -e "${GREEN}╠══════════════════════════════════════════════════════════════════════════════╣${RESET}"
    printf "${GREEN}║${RESET}  New subdomains:       ${GREEN}%-54d${RESET} ${GREEN}║${RESET}\n" "$new_count"
    printf "${GREEN}║${RESET}  Total subdomains:     %-54d ${GREEN}║${RESET}\n" "$TOTAL_SUBDOMAINS"
    printf "${GREEN}║${RESET}  Time:                 %-54s ${GREEN}║${RESET}\n" "${duration}s"
    echo -e "${GREEN}╚══════════════════════════════════════════════════════════════════════════════╝${RESET}"
}

# Alias for compatibility
run_recursive_subdomain_discovery() {
    run_subdomain_bruteforce_smart
}

# Create wordlist based on size choice
create_bruteforce_wordlist() {
    local output="$1"
    local size="$2"
    
    > "$output"
    
    # Base words (always included)
    cat >> "$output" << 'BASE'
dev
prod
staging
stage
test
api
admin
internal
vpn
auth
app
web
www
mail
ftp
db
backup
old
new
beta
demo
portal
cdn
static
docs
status
ci
git
gitlab
jenkins
docker
aws
azure
gcp
sandbox
qa
uat
preview
BASE

    case "$size" in
        1) # Small - ~100 words
            cat >> "$output" << 'SMALL'
api2
v1
v2
v3
gateway
proxy
lb
ns1
ns2
mx
smtp
webmail
cpanel
blog
shop
store
crm
wiki
jira
sentry
grafana
kibana
elastic
redis
mongo
mysql
postgres
cache
storage
media
assets
images
files
upload
download
data
log
logs
monitor
metrics
health
config
secure
private
public
mobile
frontend
backend
service
server
master
node
cluster
edge
origin
SMALL
            ;;
        2) # Medium - ~500 words
            # Include small first
            cat >> "$output" << 'SMALL'
api2
v1
v2
v3
gateway
proxy
lb
ns1
ns2
mx
smtp
webmail
cpanel
blog
shop
store
crm
wiki
jira
sentry
grafana
kibana
elastic
redis
mongo
mysql
postgres
cache
storage
media
assets
images
files
upload
download
data
log
logs
monitor
metrics
health
config
secure
private
public
mobile
frontend
backend
service
server
master
node
cluster
edge
origin
SMALL
            # Add more for medium
            cat >> "$output" << 'MEDIUM'
production
development
testing
integration
acceptance
release
canary
primary
secondary
east
west
eu
us
asia
dc1
dc2
zone1
zone2
region1
worker
workers
job
jobs
task
tasks
queue
message
event
notification
alert
report
dashboard
analytics
tracking
billing
payment
invoice
order
cart
checkout
account
profile
user
users
customer
client
partner
vendor
merchant
hr
finance
legal
marketing
sales
support
helpdesk
ticket
forum
community
social
chat
email
newsletter
webhook
callback
oauth
sso
saml
ldap
directory
identity
iam
permission
role
policy
secret
key
cert
ssl
crypto
token
session
cookie
img
image
video
audio
stream
live
rtmp
wss
ws
socket
graphql
rest
soap
rpc
grpc
proto
swagger
openapi
spec
schema
model
entity
resource
collection
item
list
detail
view
edit
create
delete
update
search
filter
sort
page
limit
offset
cursor
next
prev
first
last
count
total
sum
avg
min
max
MEDIUM
            ;;
        3) # Large - ~2000 words
            # Include medium first
            create_bruteforce_wordlist "$output" "2"
            
            # Add SecLists if available
            if [[ -f "$SECLISTS_PATH/Discovery/DNS/subdomains-top1million-5000.txt" ]]; then
                head -1500 "$SECLISTS_PATH/Discovery/DNS/subdomains-top1million-5000.txt" >> "$output"
            elif [[ -f "$SECLISTS_PATH/Discovery/DNS/bitquark-subdomains-top100000.txt" ]]; then
                head -1500 "$SECLISTS_PATH/Discovery/DNS/bitquark-subdomains-top100000.txt" >> "$output"
            fi
            ;;
    esac
    
    # Deduplicate
    sort -u -o "$output" "$output"
}

dns_validate_subdomains() {
    echo ""
    echo -e "${CYAN}═══════════════════════════════════════════════════════════════════════════════${RESET}"
    echo -e "${CYAN}${BOLD}                    🔍 DNS VALIDATION & WILDCARD CHECK                        ${RESET}"
    echo -e "${CYAN}═══════════════════════════════════════════════════════════════════════════════${RESET}"
    echo -e "${DIM}  💡 This phase eliminates dead DNS entries, saving significant time${RESET}"
    echo ""
    
    enable_phase_skip "DNS Validation"
    
    local input_file="$OUTPUT_DIR/01-subdomains/subdomains_all.txt"
    local validated_file="$OUTPUT_DIR/01-subdomains/subdomains_validated.txt"
    local dead_dns_file="$OUTPUT_DIR/01-subdomains/subdomains_dead_dns.txt"
    local wildcard_file="$OUTPUT_DIR/01-subdomains/wildcard_detected.txt"
    
    > "$validated_file"
    > "$dead_dns_file"
    > "$wildcard_file"
    
    if [[ ! -f "$input_file" ]] || [[ ! -s "$input_file" ]]; then
        log "WARN" "No subdomains to validate"
        disable_phase_skip
        return
    fi
    
    local total=$(wc -l < "$input_file")
    echo -e "  ${CYAN}📋 Validating DNS for ${BOLD}$total${RESET}${CYAN} subdomains...${RESET}"
    echo ""
    
    # ══════════════════════════════════════════════════════════════════════════
    # STEP 1: WILDCARD DETECTION
    # ══════════════════════════════════════════════════════════════════════════
    
    echo -e "  ${DIM}[1/3] Checking for wildcard DNS...${RESET}"
    
    local random1="random$(date +%s%N | md5sum | head -c 8).$TARGET"
    local random2="nonexistent$(date +%s%N | md5sum | head -c 8).$TARGET"
    
    local ip1=$(dig +short "$random1" A 2>/dev/null | grep -E "^[0-9]" | head -1)
    local ip2=$(dig +short "$random2" A 2>/dev/null | grep -E "^[0-9]" | head -1)
    
    local wildcard_detected=false
    local wildcard_ip=""
    
    if [[ -n "$ip1" ]] && [[ -n "$ip2" ]] && [[ "$ip1" == "$ip2" ]]; then
        wildcard_detected=true
        wildcard_ip="$ip1"
        echo -e "  ${YELLOW}⚠️  WILDCARD DNS DETECTED${RESET}"
        echo -e "     ${DIM}All non-existent subdomains resolve to: ${BOLD}$wildcard_ip${RESET}"
        echo "WILDCARD_IP=$wildcard_ip" > "$wildcard_file"
        echo -e "     ${DIM}Will filter responses matching this IP...${RESET}"
    else
        echo -e "  ${GREEN}✓${RESET} No wildcard DNS detected"
    fi
    echo ""
    
    # ══════════════════════════════════════════════════════════════════════════
    # STEP 2: MASS DNS RESOLUTION
    # ══════════════════════════════════════════════════════════════════════════
    
    echo -e "  ${DIM}[2/3] Resolving all subdomains...${RESET}"
    
    if [[ -n "$DNSX" ]]; then
        # Use dnsx for fast resolution
        echo -e "  ${GREEN}✓${RESET} Using dnsx for fast DNS resolution"
        
        $DNSX -l "$input_file" \
            -t 100 \
            -retry 2 \
            -silent \
            -resp \
            -a \
            -o "$OUTPUT_DIR/01-subdomains/dnsx_results.txt" 2>/dev/null &
        
        local dnsx_pid=$!
        local dots=0
        
        while kill -0 $dnsx_pid 2>/dev/null; do
            should_skip_phase && kill $dnsx_pid 2>/dev/null && break
            printf "\r  ${DIM}Resolving%s${RESET}   " "$(printf '.%.0s' $(seq 1 $((dots % 4 + 1))))"
            ((dots++))
            sleep 1
        done
        printf "\r                              \r"
        
        wait $dnsx_pid 2>/dev/null
        
        # Parse dnsx results
        if [[ -f "$OUTPUT_DIR/01-subdomains/dnsx_results.txt" ]]; then
            # Extract domains that resolved
            cut -d' ' -f1 "$OUTPUT_DIR/01-subdomains/dnsx_results.txt" | \
                sed 's/\[.*$//' | \
                sort -u > "$validated_file"
            
            # If wildcard detected, filter out wildcard IPs
            if [[ "$wildcard_detected" == true ]]; then
                local before_filter=$(wc -l < "$validated_file")
                grep -v "$wildcard_ip" "$OUTPUT_DIR/01-subdomains/dnsx_results.txt" | \
                    cut -d' ' -f1 | sed 's/\[.*$//' | sort -u > "${validated_file}.tmp"
                mv "${validated_file}.tmp" "$validated_file"
                local after_filter=$(wc -l < "$validated_file")
                local filtered=$((before_filter - after_filter))
                echo -e "  ${DIM}Filtered $filtered wildcard responses${RESET}"
            fi
        fi
        
    elif [[ -n "$MASSDNS" ]] && [[ -f "/usr/share/massdns/lists/resolvers.txt" ]]; then
        # Use massdns if available
        echo -e "  ${YELLOW}○${RESET} Using massdns (slower than dnsx)"
        $MASSDNS -r /usr/share/massdns/lists/resolvers.txt \
            -t A \
            -o S \
            -w "$OUTPUT_DIR/01-subdomains/massdns_results.txt" \
            "$input_file" 2>/dev/null
        
        # Parse massdns results
        grep " A " "$OUTPUT_DIR/01-subdomains/massdns_results.txt" 2>/dev/null | \
            awk '{print $1}' | sed 's/\.$//' | sort -u > "$validated_file"
        
    else
        # Fallback: Use dig/host for each domain (SLOW)
        log "WARN" "Neither dnsx nor massdns installed - using slow dig fallback"
        echo -e "  ${YELLOW}⚠️${RESET} Install dnsx for 10x faster DNS validation:"
        echo -e "     ${DIM}go install github.com/projectdiscovery/dnsx/cmd/dnsx@latest${RESET}"
        echo ""
        
        local current=0
        while IFS= read -r subdomain; do
            [[ -z "$subdomain" ]] && continue
            should_skip_phase && break
            
            ((current++))
            printf "\r  ${DIM}[%d/%d] %s${RESET}              " "$current" "$total" "$subdomain"
            
            local ip=$(dig +short "$subdomain" A 2>/dev/null | grep -E "^[0-9]" | head -1)
            
            if [[ -n "$ip" ]]; then
                # Check if it's a wildcard IP
                if [[ "$wildcard_detected" == true ]] && [[ "$ip" == "$wildcard_ip" ]]; then
                    echo "$subdomain" >> "$dead_dns_file"
                else
                    echo "$subdomain" >> "$validated_file"
                fi
            else
                echo "$subdomain" >> "$dead_dns_file"
            fi
            
        done < "$input_file"
        printf "\r                                                              \r"
    fi
    
    echo ""
    
    # ══════════════════════════════════════════════════════════════════════════
    # STEP 3: GENERATE STATISTICS
    # ══════════════════════════════════════════════════════════════════════════
    
    echo -e "  ${DIM}[3/3] Calculating results...${RESET}"
    
    # Find dead DNS entries
    comm -23 <(sort "$input_file") <(sort "$validated_file") > "$dead_dns_file" 2>/dev/null
    
    local validated_count=$(wc -l < "$validated_file" 2>/dev/null || echo 0)
    local dead_count=$(wc -l < "$dead_dns_file" 2>/dev/null || echo 0)
    local saved_pct=0
    [[ $total -gt 0 ]] && saved_pct=$((dead_count * 100 / total))
    
    echo ""
    echo -e "  ${GREEN}┌─────────────────────────────────────────────────────────────────────────────┐${RESET}"
    echo -e "  ${GREEN}│${RESET} ✅ ${BOLD}DNS VALIDATION COMPLETE${RESET}"
    echo -e "  ${GREEN}│${RESET}"
    printf "  ${GREEN}│${RESET}    ${GREEN}✓${RESET} Valid DNS:     ${BOLD}%d${RESET} subdomains\n" "$validated_count"
    printf "  ${GREEN}│${RESET}    ${RED}✗${RESET} Dead DNS:      ${DIM}%d${RESET} subdomains\n" "$dead_count"
    [[ "$wildcard_detected" == true ]] && echo -e "  ${GREEN}│${RESET}    ${YELLOW}⚠${RESET} Wildcard IP:   ${DIM}$wildcard_ip${RESET}"
    echo -e "  ${GREEN}│${RESET}"
    printf "  ${GREEN}│${RESET}    ${CYAN}⏱${RESET}  Time saved:   ${BOLD}~%d%%${RESET} of HTTP probing eliminated\n" "$saved_pct"
    echo -e "  ${GREEN}└─────────────────────────────────────────────────────────────────────────────┘${RESET}"
    
    # Update the input for next phase to use validated file
    if [[ -s "$validated_file" ]]; then
        cp "$validated_file" "$OUTPUT_DIR/01-subdomains/subdomains_for_probing.txt"
        TOTAL_SUBDOMAINS=$validated_count
    fi
    
    disable_phase_skip
}

#═══════════════════════════════════════════════════════════════════════════════
# HOST VALIDATION
#═══════════════════════════════════════════════════════════════════════════════

validate_hosts() {
    echo ""
    echo -e "${PURPLE}═══════════════════════════════════════════════════════════════════════════════${RESET}"
    echo -e "${PURPLE}${BOLD}                         🌐 HOST VALIDATION (HTTP PROBING)                    ${RESET}"
    echo -e "${PURPLE}═══════════════════════════════════════════════════════════════════════════════${RESET}"
    echo -e "${DIM}  💡 Press Ctrl+C to skip this phase${RESET}"
    echo ""
    echo -e "  ${DIM}📖 WHY THIS PHASE: DNS validation confirms domains exist, but a domain${RESET}"
    echo -e "  ${DIM}   can resolve to an IP with NO web server running. This phase confirms${RESET}"
    echo -e "  ${DIM}   actual HTTP/HTTPS services are responding.${RESET}"
    
    enable_phase_skip "Host Validation"
    
    # Use DNS-validated file if available, otherwise fall back to all subdomains
    local input_file=""
    if [[ -f "$OUTPUT_DIR/01-subdomains/subdomains_for_probing.txt" ]] && \
       [[ -s "$OUTPUT_DIR/01-subdomains/subdomains_for_probing.txt" ]]; then
        input_file="$OUTPUT_DIR/01-subdomains/subdomains_for_probing.txt"
        echo -e "  ${GREEN}✓${RESET} Using DNS-validated subdomains"
    elif [[ -f "$OUTPUT_DIR/01-subdomains/subdomains_validated.txt" ]] && \
         [[ -s "$OUTPUT_DIR/01-subdomains/subdomains_validated.txt" ]]; then
        input_file="$OUTPUT_DIR/01-subdomains/subdomains_validated.txt"
        echo -e "  ${GREEN}✓${RESET} Using DNS-validated subdomains"
    else
        input_file="$OUTPUT_DIR/01-subdomains/subdomains_all.txt"
        echo -e "  ${YELLOW}○${RESET} Using unvalidated subdomains (DNS validation skipped)"
    fi
    
    local output_file="$OUTPUT_DIR/02-hosts/httpx_output.txt"
    local live_file="$OUTPUT_DIR/01-subdomains/subdomains_live.txt"
    local dead_file="$OUTPUT_DIR/01-subdomains/subdomains_dead.txt"
    
    # Check if input file exists and has content
    if [[ ! -f "$input_file" ]] || [[ ! -s "$input_file" ]]; then
        log "ERROR" "No subdomains found to validate"
        disable_phase_skip
        return
    fi
    
    local total=$(wc -l < "$input_file")
    echo ""
    echo -e "  ${CYAN}🔍 Probing ${BOLD}$total${RESET}${CYAN} subdomains for HTTP services...${RESET}"
    echo ""
    
    # TOOL PRIORITY: httprobe > curl (httpx removed - too buggy)
    if [[ -n "$HTTPROBE" ]]; then
        echo -e "  ${GREEN}✓${RESET} Using httprobe (fast & reliable)"
        validate_hosts_httprobe "$input_file" "$output_file" "$live_file" "$dead_file" "$total"
    else
        log "INFO" "Using curl for host validation (install httprobe for faster scans)"
        echo -e "  ${YELLOW}→${RESET} Install: ${DIM}go install github.com/tomnomnom/httprobe@latest${RESET}"
        validate_hosts_curl_advanced "$input_file" "$output_file" "$live_file" "$dead_file" "$total"
    fi
    
    if should_skip_phase; then
        log "WARN" "Host validation skipped by user"
        disable_phase_skip
        return
    fi
    
    disable_phase_skip
}

# httprobe-based validation (PRIMARY METHOD - Fast & Reliable)
validate_hosts_httprobe() {
    local input_file="$1"
    local output_file="$2"
    local live_file="$3"
    local dead_file="$4"
    local total="$5"
    
    > "$output_file"
    > "$live_file"
    
    echo -e "  ${DIM}Running httprobe (checking HTTP & HTTPS)...${RESET}"
    
    local temp_urls="$OUTPUT_DIR/02-hosts/httprobe_urls.txt"
    
    # Run httprobe - outputs full URLs (https://example.com, http://example.com)
    cat "$input_file" | $HTTPROBE -c 50 -t 10000 2>/dev/null > "$temp_urls" &
    local probe_pid=$!
    
    # Show progress
    local dots=0
    local start_time=$(date +%s)
    while kill -0 $probe_pid 2>/dev/null; do
        should_skip_phase && kill $probe_pid 2>/dev/null && break
        
        local elapsed=$(($(date +%s) - start_time))
        local found=$(wc -l < "$temp_urls" 2>/dev/null || echo 0)
        printf "\r  ${DIM}Probing... %ds elapsed, ${GREEN}%d${RESET}${DIM} live hosts found${RESET}    " "$elapsed" "$found"
        sleep 1
    done
    printf "\r                                                                      \r"
    
    wait $probe_pid 2>/dev/null
    
    # Process httprobe output
    if [[ -f "$temp_urls" ]] && [[ -s "$temp_urls" ]]; then
        # Extract unique hostnames from URLs
        sed -E 's|^https?://||' "$temp_urls" | cut -d'/' -f1 | cut -d':' -f1 | sort -u > "$live_file"
        
        # Create JSON output for compatibility with rest of script
        while IFS= read -r url; do
            [[ -z "$url" ]] && continue
            local host=$(echo "$url" | sed -E 's|^https?://||' | cut -d'/' -f1 | cut -d':' -f1)
            local proto="https"
            [[ "$url" =~ ^http:// ]] && proto="http"
            
            # Basic JSON entry
            echo "{\"url\":\"$url\",\"input\":\"$host\",\"status_code\":200,\"title\":\"\",\"webserver\":\"\",\"tech\":[]}" >> "$output_file"
        done < "$temp_urls"
        
        LIVE_HOSTS=$(wc -l < "$live_file" 2>/dev/null || echo 0)
    else
        log "WARN" "httprobe produced no output"
        LIVE_HOSTS=0
    fi
    
    # Find dead hosts
    comm -23 <(sort "$input_file") <(sort "$live_file") > "$dead_file" 2>/dev/null
    DEAD_HOSTS=$(wc -l < "$dead_file" 2>/dev/null || echo 0)
    
    echo ""
    log "SUCCESS" "Live hosts: ${BOLD}${GREEN}$LIVE_HOSTS${RESET} | Dead hosts: ${BOLD}${RED}$DEAD_HOSTS${RESET}"
    
    # Now do technology detection on live hosts with curl (parallel)
    if [[ $LIVE_HOSTS -gt 0 ]] && [[ $LIVE_HOSTS -le 100 ]]; then
        echo ""
        echo -e "  ${CYAN}→${RESET} Running quick technology fingerprinting..."
        enrich_live_hosts_with_tech "$temp_urls" "$output_file"
    elif [[ $LIVE_HOSTS -gt 100 ]]; then
        echo -e "  ${DIM}Skipping inline tech detection (>100 hosts, will use whatweb later)${RESET}"
    fi
}

# Enrich httprobe results with technology detection
enrich_live_hosts_with_tech() {
    local urls_file="$1"
    local output_file="$2"
    
    local temp_enriched="$OUTPUT_DIR/02-hosts/hosts_enriched.json"
    > "$temp_enriched"
    
    local total=$(wc -l < "$urls_file" 2>/dev/null || echo 0)
    local current=0
    
    while IFS= read -r url; do
        [[ -z "$url" ]] && continue
        ((current++))
        
        # Progress indicator
        printf "\r  ${DIM}Fingerprinting: %d/%d${RESET}  " "$current" "$total"
        
        local host=$(echo "$url" | sed -E 's|^https?://||' | cut -d'/' -f1)
        
        # Quick curl to get headers and partial body
        local response=$(curl -sS -w "\n%{http_code}" \
            --connect-timeout 3 \
            --max-time 8 \
            -k -L \
            -D - \
            "$url" 2>/dev/null | head -c 30000)
        
        local status=$(echo "$response" | tail -1)
        [[ ! "$status" =~ ^[0-9]+$ ]] && status=0
        
        local headers=$(echo "$response" | sed -n '1,/^\r$/p')
        local body=$(echo "$response" | sed '1,/^\r$/d' | head -c 15000)
        
        # Extract info
        local title=$(echo "$body" | grep -oiP '<title[^>]*>\K[^<]+' | head -1 | sed 's/["\]//g' | head -c 100)
        local server=$(echo "$headers" | grep -i "^server:" | head -1 | cut -d: -f2- | tr -d '\r' | xargs)
        
        # Quick tech detection
        local techs=()
        [[ "$server" =~ [Nn]ginx ]] && techs+=("nginx")
        [[ "$server" =~ [Aa]pache ]] && techs+=("Apache")
        [[ "$server" =~ [Cc]loudflare ]] && techs+=("Cloudflare")
        [[ "$server" =~ IIS ]] && techs+=("IIS")
        [[ "$body" =~ wp-content|wp-includes ]] && techs+=("WordPress")
        [[ "$body" =~ __NEXT_DATA__|_next ]] && techs+=("Next.js")
        [[ "$body" =~ react|__REACT ]] && techs+=("React")
        [[ "$body" =~ laravel ]] && techs+=("Laravel")
        
        local tech_array="[]"
        if [[ ${#techs[@]} -gt 0 ]]; then
            tech_array=$(printf '%s\n' "${techs[@]}" | jq -R . | jq -s . 2>/dev/null || echo "[]")
        fi
        
        # Create JSON
        local json_line=$(jq -n \
            --arg url "$url" \
            --arg input "$host" \
            --argjson status "${status:-0}" \
            --arg title "$title" \
            --arg server "$server" \
            --argjson tech "$tech_array" \
            '{url: $url, input: $input, status_code: $status, title: $title, webserver: $server, tech: $tech}' 2>/dev/null)
        
        [[ -n "$json_line" ]] && echo "$json_line" >> "$temp_enriched"
        
    done < "$urls_file"
    
    printf "\r                                            \r"
    
    # Replace output with enriched version
    if [[ -s "$temp_enriched" ]]; then
        mv "$temp_enriched" "$output_file"
        echo -e "  ${GREEN}✓${RESET} Technology fingerprints collected"
    fi
}

# Advanced curl-based validation with technology detection
validate_hosts_curl_advanced() {
    local input_file="$1"
    local output_file="$2"
    local live_file="$3"
    local dead_file="$4"
    local total="$5"
    
    > "$live_file"
    > "$dead_file"
    > "$output_file"
    
    local current=0
    local live_count=0
    
    echo -e "  ${DIM}Testing hosts with curl (includes technology fingerprinting)...${RESET}"
    
    while IFS= read -r domain; do
        [[ -z "$domain" ]] && continue
        should_skip_phase && break
        
        ((current++))
        [[ "$QUIET_MODE" == false ]] && progress_bar "$current" "$total"
        
        # Try HTTPS first, then HTTP
        local found=false
        local final_url=""
        local status=""
        local headers=""
        local body=""
        local title=""
        local server=""
        local tech_array="[]"
        
        for proto in https http; do
            local response=$(curl -sS -w "\n%{http_code}" \
                --connect-timeout 5 \
                --max-time 10 \
                -k -L \
                -D - \
                "$proto://$domain" 2>/dev/null | head -c 50000)
            
            status=$(echo "$response" | tail -1)
            
            if [[ "$status" != "000" ]] && [[ -n "$status" ]] && [[ "$status" =~ ^[0-9]+$ ]]; then
                headers=$(echo "$response" | sed -n '1,/^\r$/p')
                body=$(echo "$response" | sed '1,/^\r$/d' | head -c 20000)
                final_url="$proto://$domain"
                found=true
                
                # Extract title
                title=$(echo "$body" | grep -oiP '<title[^>]*>\K[^<]+' | head -1 | sed 's/["\]//g' | head -c 100)
                
                # Extract server
                server=$(echo "$headers" | grep -i "^server:" | head -1 | cut -d: -f2- | tr -d '\r' | xargs)
                
                # Detect technologies
                local techs=()
                
                # From headers
                [[ "$server" =~ [Nn]ginx ]] && techs+=("nginx")
                [[ "$server" =~ [Aa]pache ]] && techs+=("Apache")
                [[ "$server" =~ [Cc]loudflare ]] && techs+=("Cloudflare")
                [[ "$server" =~ IIS ]] && techs+=("IIS")
                [[ "$server" =~ [Gg]unicorn ]] && techs+=("Python/Gunicorn")
                [[ "$server" =~ [Uu]vicorn ]] && techs+=("Python/Uvicorn")
                
                local powered=$(echo "$headers" | grep -i "x-powered-by" | head -1)
                [[ "$powered" =~ PHP ]] && techs+=("PHP")
                [[ "$powered" =~ ASP ]] && techs+=("ASP.NET")
                [[ "$powered" =~ Express ]] && techs+=("Express.js")
                
                # From cookies
                local cookies=$(echo "$headers" | grep -i "set-cookie")
                [[ "$cookies" =~ PHPSESSID ]] && techs+=("PHP")
                [[ "$cookies" =~ JSESSIONID ]] && techs+=("Java")
                [[ "$cookies" =~ ASP.NET ]] && techs+=("ASP.NET")
                [[ "$cookies" =~ wordpress ]] && techs+=("WordPress")
                [[ "$cookies" =~ __cfduid|cf_clearance ]] && techs+=("Cloudflare")
                
                # From body
                [[ "$body" =~ wp-content|wp-includes ]] && techs+=("WordPress")
                [[ "$body" =~ Drupal ]] && techs+=("Drupal")
                [[ "$body" =~ Joomla ]] && techs+=("Joomla")
                [[ "$body" =~ shopify ]] && techs+=("Shopify")
                [[ "$body" =~ react|__REACT|reactroot ]] && techs+=("React")
                [[ "$body" =~ __NEXT_DATA__|_next/static ]] && techs+=("Next.js")
                [[ "$body" =~ __NUXT__|_nuxt ]] && techs+=("Nuxt.js")
                [[ "$body" =~ ng-app|angular ]] && techs+=("Angular")
                [[ "$body" =~ vue|v-cloak ]] && techs+=("Vue.js")
                [[ "$body" =~ jquery|jQuery ]] && techs+=("jQuery")
                [[ "$body" =~ bootstrap ]] && techs+=("Bootstrap")
                [[ "$body" =~ laravel ]] && techs+=("Laravel")
                
                # Build JSON array for technologies
                if [[ ${#techs[@]} -gt 0 ]]; then
                    tech_array=$(printf '%s\n' "${techs[@]}" | sort -u | jq -R . | jq -s .)
                fi
                
                break
            fi
        done
        
        if [[ "$found" == true ]]; then
            echo "$domain" >> "$live_file"
            ((live_count++))
            
            # Create JSON output compatible with httpx format
            local json_line=$(jq -n \
                --arg url "$final_url" \
                --arg input "$domain" \
                --argjson status "$status" \
                --arg title "$title" \
                --arg server "$server" \
                --argjson tech "$tech_array" \
                '{url: $url, input: $input, status_code: $status, title: $title, webserver: $server, tech: $tech}')
            
            echo "$json_line" >> "$output_file"
        else
            echo "$domain" >> "$dead_file"
        fi
        
    done < "$input_file"
    
    echo ""
    
    LIVE_HOSTS=$live_count
    DEAD_HOSTS=$((total - live_count))
    
    log "SUCCESS" "Live hosts: ${BOLD}$LIVE_HOSTS${RESET} | Dead hosts: ${BOLD}$DEAD_HOSTS${RESET}"
}

parse_httpx_output() {
    log "INFO" "🔬 ${BOLD}Parsing host information...${RESET}"
    
    local input_file="$OUTPUT_DIR/02-hosts/httpx_output.txt"
    local hosts_info="$OUTPUT_DIR/02-hosts/hosts_info.json"
    
    if [[ ! -f "$input_file" ]] || [[ ! -s "$input_file" ]]; then
        log "WARN" "No httpx output to parse"
        echo "[]" > "$hosts_info"
        return
    fi
    
    # Convert JSONL to JSON array
    echo "[" > "$hosts_info"
    local first=true
    while IFS= read -r line; do
        if [[ -n "$line" ]]; then
            if [[ "$first" == true ]]; then
                first=false
            else
                echo "," >> "$hosts_info"
            fi
            echo "$line" >> "$hosts_info"
        fi
    done < "$input_file"
    echo "]" >> "$hosts_info"
    
    log "SUCCESS" "Host information parsed"
}

detect_technology() {
    echo ""
    echo -e "${PURPLE}┌─────────────────────────────────────────────────────────────────────────────┐${RESET}"
    echo -e "${PURPLE}│${RESET} 🔧 ${BOLD}TECHNOLOGY DETECTION (WhatWeb)${RESET}"
    echo -e "${PURPLE}└─────────────────────────────────────────────────────────────────────────────┘${RESET}"
    echo -e "${DIM}  💡 Press Ctrl+C to skip this phase${RESET}"
    
    enable_phase_skip "Technology Detection"
    
    local live_file="$OUTPUT_DIR/01-subdomains/subdomains_live.txt"
    local tech_dir="$OUTPUT_DIR/06-technologies"
    local tech_file="$tech_dir/tech_stack.json"
    local by_tech="$OUTPUT_DIR/02-hosts/hosts_by_tech.txt"
    local whatweb_output="$tech_dir/whatweb_results.json"
    local wordpress_hosts="$tech_dir/wordpress_hosts.txt"
    
    mkdir -p "$tech_dir"
    > "$by_tech"
    > "$wordpress_hosts"
    
    # Check for live hosts
    if [[ ! -f "$live_file" ]] || [[ ! -s "$live_file" ]]; then
        log "WARN" "No live hosts for technology detection"
        echo "{}" > "$tech_file"
        disable_phase_skip
        return
    fi
    
    local total=$(wc -l < "$live_file")
    echo ""
    echo -e "  ${CYAN}🔍 Scanning ${BOLD}$total${RESET}${CYAN} hosts for technologies...${RESET}"
    echo ""
    
    declare -A tech_count
    local host_count=0
    
    # Check if whatweb is available
    if [[ -n "$WHATWEB" ]]; then
        echo -e "  ${GREEN}✓${RESET} Using WhatWeb for accurate fingerprinting"
        echo ""
        
        # Create URLs file
        local urls_file=$(mktemp)
        while IFS= read -r host; do
            [[ -z "$host" ]] && continue
            # Add both http and https
            echo "https://$host" >> "$urls_file"
        done < "$live_file"
        
        # Run whatweb with JSON output
        echo -e "  ${DIM}Running WhatWeb scan...${RESET}"
        $WHATWEB --input-file="$urls_file" --log-json="$whatweb_output" --aggression=1 --color=never --no-errors -q 2>/dev/null &
        local whatweb_pid=$!
        
        # Show progress
        local dots=0
        while kill -0 $whatweb_pid 2>/dev/null; do
            should_skip_phase && kill $whatweb_pid 2>/dev/null && break
            printf "\r  ${DIM}Scanning%s${RESET}   " "$(printf '.%.0s' $(seq 1 $((dots % 4 + 1))))"
            ((dots++))
            sleep 1
        done
        printf "\r                              \r"
        
        rm -f "$urls_file"
        
        # Parse whatweb results
        if [[ -f "$whatweb_output" ]] && [[ -s "$whatweb_output" ]]; then
            while IFS= read -r line; do
                [[ -z "$line" ]] && continue
                
                local url=$(echo "$line" | jq -r '.target // empty' 2>/dev/null)
                [[ -z "$url" ]] && continue
                
                ((host_count++))
                
                # Extract plugins (technologies)
                local plugins=$(echo "$line" | jq -r '.plugins | keys[]' 2>/dev/null | tr '\n' ',')
                plugins=${plugins%,}
                
                # Check for WordPress
                if [[ "$plugins" =~ WordPress ]]; then
                    local wp_version=$(echo "$line" | jq -r '.plugins.WordPress.version[0] // "unknown"' 2>/dev/null)
                    echo "$url|$wp_version" >> "$wordpress_hosts"
                fi
                
                # Save to hosts_by_tech
                [[ -n "$plugins" ]] && echo "$url|$plugins" >> "$by_tech"
                
                # Count technologies
                if [[ -n "$plugins" ]]; then
                    IFS=',' read -ra techs <<< "$plugins"
                    for t in "${techs[@]}"; do
                        t=$(echo "$t" | xargs)
                        [[ -n "$t" ]] && ((tech_count["$t"]++))
                    done
                fi
                
            done < "$whatweb_output"
        fi
        
    else
        # Fallback to basic curl-based detection
        log "WARN" "WhatWeb not installed - using basic fingerprinting"
        echo -e "  ${YELLOW}⚠️${RESET} Install whatweb for better results: ${DIM}apt install whatweb${RESET}"
        echo ""
        
        while IFS= read -r host; do
            [[ -z "$host" ]] && continue
            should_skip_phase && break
            
            ((host_count++))
            [[ "$QUIET_MODE" == false ]] && progress_bar "$host_count" "$total"
            
            local url="https://$host"
            local detected=""
            
            # Basic curl fingerprinting
            local response=$(curl -sS --max-time 8 -k -L -D - "$url" 2>/dev/null | head -c 30000)
            local headers=$(echo "$response" | sed -n '1,/^\r$/p')
            local body=$(echo "$response" | sed '1,/^\r$/d')
            
            # Server
            local server=$(echo "$headers" | grep -i "^server:" | head -1 | cut -d: -f2- | tr -d '\r' | xargs)
            [[ "$server" =~ nginx ]] && detected="$detected,nginx"
            [[ "$server" =~ Apache ]] && detected="$detected,Apache"
            [[ "$server" =~ cloudflare ]] && detected="$detected,Cloudflare"
            [[ "$server" =~ IIS ]] && detected="$detected,IIS"
            
            # X-Powered-By
            local powered=$(echo "$headers" | grep -i "x-powered-by" | head -1)
            [[ "$powered" =~ PHP ]] && detected="$detected,PHP"
            [[ "$powered" =~ ASP ]] && detected="$detected,ASP.NET"
            [[ "$powered" =~ Express ]] && detected="$detected,Express"
            
            # Body patterns
            [[ "$body" =~ wp-content|wp-includes ]] && { detected="$detected,WordPress"; echo "$url|" >> "$wordpress_hosts"; }
            [[ "$body" =~ Drupal ]] && detected="$detected,Drupal"
            [[ "$body" =~ Joomla ]] && detected="$detected,Joomla"
            [[ "$body" =~ __NEXT_DATA__ ]] && detected="$detected,Next.js"
            [[ "$body" =~ __NUXT__ ]] && detected="$detected,Nuxt.js"
            [[ "$body" =~ ng-app ]] && detected="$detected,Angular"
            [[ "$body" =~ react ]] && detected="$detected,React"
            [[ "$body" =~ vue ]] && detected="$detected,Vue.js"
            
            detected=$(echo "$detected" | sed 's/^,//')
            [[ -n "$detected" ]] && echo "$url|$detected" >> "$by_tech"
            
            # Count
            if [[ -n "$detected" ]]; then
                IFS=',' read -ra techs <<< "$detected"
                for t in "${techs[@]}"; do
                    t=$(echo "$t" | xargs)
                    [[ -n "$t" ]] && ((tech_count["$t"]++))
                done
            fi
            
        done < "$live_file"
        echo ""
    fi
    
    # Write tech summary JSON
    echo "{" > "$tech_file"
    local first=true
    for tech in "${!tech_count[@]}"; do
        [[ "$first" == true ]] && first=false || echo "," >> "$tech_file"
        echo "  \"$tech\": ${tech_count[$tech]}" >> "$tech_file"
    done
    echo "}" >> "$tech_file"
    
    # Display results
    echo ""
    if [[ ${#tech_count[@]} -gt 0 ]]; then
        echo -e "  ${BOLD}Detected Technologies:${RESET}"
        echo ""
        # Sort by count and display top 20
        for tech in $(for k in "${!tech_count[@]}"; do echo "$k ${tech_count[$k]}"; done | sort -t' ' -k2 -rn | cut -d' ' -f1 | head -20); do
            local count=${tech_count[$tech]}
            local bar_len=$((count * 20 / host_count))
            [[ $bar_len -gt 20 ]] && bar_len=20
            [[ $bar_len -lt 1 ]] && bar_len=1
            local bar=$(printf '█%.0s' $(seq 1 $bar_len))
            printf "    ${CYAN}%-20s${RESET} ${GREEN}%s${RESET} ${DIM}%d${RESET}\n" "$tech" "$bar" "$count"
        done
        [[ ${#tech_count[@]} -gt 20 ]] && echo -e "    ${DIM}... and $((${#tech_count[@]} - 20)) more${RESET}"
    else
        echo -e "  ${DIM}No specific technologies detected${RESET}"
    fi
    
    # WordPress summary
    local wp_count=$(wc -l < "$wordpress_hosts" 2>/dev/null || echo 0)
    if [[ $wp_count -gt 0 ]]; then
        echo ""
        echo -e "  ${RED}🎯 WordPress detected on $wp_count hosts${RESET}"
        WORDPRESS_DETECTED=true
        WORDPRESS_HOSTS_FILE="$wordpress_hosts"
    fi
    
    echo ""
    log "SUCCESS" "Scanned $host_count hosts, found ${#tech_count[@]} unique technologies"
    
    disable_phase_skip
}

# Global variables for WordPress detection
WORDPRESS_DETECTED=false
WORDPRESS_HOSTS_FILE=""

# Run WPScan on detected WordPress sites
run_wpscan() {
    if [[ "$WORDPRESS_DETECTED" != true ]] || [[ ! -f "$WORDPRESS_HOSTS_FILE" ]]; then
        return 0
    fi
    
    if [[ -z "$WPSCAN" ]]; then
        log "WARN" "WPScan not installed - skipping WordPress scanning"
        echo -e "  ${YELLOW}⚠️${RESET} Install: ${DIM}gem install wpscan${RESET}"
        return 0
    fi
    
    local wp_count=$(wc -l < "$WORDPRESS_HOSTS_FILE")
    
    echo ""
    echo -e "${RED}┌─────────────────────────────────────────────────────────────────────────────┐${RESET}"
    echo -e "${RED}│${RESET} 🎯 ${BOLD}WORDPRESS VULNERABILITY SCAN (WPScan)${RESET}"
    echo -e "${RED}└─────────────────────────────────────────────────────────────────────────────┘${RESET}"
    echo -e "${DIM}  💡 Press Ctrl+C to skip this phase${RESET}"
    echo ""
    echo -e "  ${CYAN}Found ${BOLD}$wp_count${RESET}${CYAN} WordPress sites to scan${RESET}"
    echo ""
    
    read -p "  Run WPScan on WordPress sites? [Y/n]: " wpscan_choice
    if [[ "$wpscan_choice" =~ ^[Nn] ]]; then
        log "INFO" "Skipping WPScan"
        return 0
    fi
    
    enable_phase_skip "WPScan"
    
    local wpscan_dir="$OUTPUT_DIR/06-technologies/wpscan"
    mkdir -p "$wpscan_dir"
    
    local current=0
    while IFS='|' read -r url version; do
        [[ -z "$url" ]] && continue
        should_skip_phase && break
        
        ((current++))
        local host=$(echo "$url" | sed 's|https\?://||' | cut -d'/' -f1)
        local output_file="$wpscan_dir/${host//\//_}.json"
        
        echo -e "  ${CYAN}[$current/$wp_count]${RESET} Scanning: $host"
        
        # Run wpscan with basic enumeration
        $WPSCAN --url "$url" \
            --enumerate vp,vt,u \
            --plugins-detection passive \
            --format json \
            --output "$output_file" \
            --random-user-agent \
            --disable-tls-checks \
            2>/dev/null &
        
        local pid=$!
        local timeout=120
        local elapsed=0
        
        while kill -0 $pid 2>/dev/null && [[ $elapsed -lt $timeout ]]; do
            should_skip_phase && kill $pid 2>/dev/null && break
            sleep 2
            ((elapsed += 2))
            printf "\r    ${DIM}Scanning... %ds${RESET}  " "$elapsed"
        done
        
        # Kill if still running
        kill $pid 2>/dev/null
        wait $pid 2>/dev/null
        
        printf "\r                                \r"
        
        # Parse results
        if [[ -f "$output_file" ]] && [[ -s "$output_file" ]]; then
            local vulns=$(jq -r '.vulnerabilities | length' "$output_file" 2>/dev/null || echo 0)
            local version_detected=$(jq -r '.version.number // "unknown"' "$output_file" 2>/dev/null)
            
            if [[ $vulns -gt 0 ]]; then
                echo -e "    ${RED}⚠️  Found $vulns vulnerabilities!${RESET} (WP $version_detected)"
            else
                echo -e "    ${GREEN}✓${RESET} No vulnerabilities found (WP $version_detected)"
            fi
        else
            echo -e "    ${YELLOW}○${RESET} Scan incomplete"
        fi
        
    done < "$WORDPRESS_HOSTS_FILE"
    
    echo ""
    log "SUCCESS" "WPScan completed for $current WordPress sites"
    
    disable_phase_skip
}

#═══════════════════════════════════════════════════════════════════════════════
# 📸 SCREENSHOT CAPTURE (Visual Evidence)
#═══════════════════════════════════════════════════════════════════════════════

capture_screenshots() {
    echo ""
    echo -e "${CYAN}┌─────────────────────────────────────────────────────────────────────────────┐${RESET}"
    echo -e "${CYAN}│${RESET} 📸 ${BOLD}SCREENSHOT CAPTURE${RESET}"
    echo -e "${CYAN}└─────────────────────────────────────────────────────────────────────────────┘${RESET}"
    echo -e "${DIM}  💡 Press Ctrl+C to skip this phase${RESET}"
    
    local live_file="$OUTPUT_DIR/01-subdomains/subdomains_live.txt"
    local screenshot_dir="$OUTPUT_DIR/10-screenshots"
    mkdir -p "$screenshot_dir"
    
    if [[ ! -f "$live_file" ]] || [[ ! -s "$live_file" ]]; then
        log "WARN" "No live hosts for screenshot capture"
        return
    fi
    
    local total=$(wc -l < "$live_file")
    echo ""
    echo -e "  ${CYAN}🎯 ${BOLD}$total${RESET}${CYAN} hosts to screenshot${RESET}"
    echo ""
    
    # Check available tools
    if [[ -n "$GOWITNESS" ]]; then
        echo -e "  ${GREEN}✓${RESET} Using gowitness"
        
        # Create URLs file with https:// prefix
        local urls_file="$screenshot_dir/urls_to_screenshot.txt"
        while IFS= read -r host; do
            [[ -z "$host" ]] && continue
            echo "https://$host"
        done < "$live_file" > "$urls_file"
        
        echo ""
        read -p "  Capture screenshots of all live hosts? [Y/n]: " screenshot_choice
        if [[ "$screenshot_choice" =~ ^[Nn] ]]; then
            log "INFO" "Skipping screenshots"
            return
        fi
        
        enable_phase_skip "Screenshot Capture"
        
        echo ""
        echo -e "  ${DIM}Capturing screenshots...${RESET}"
        
        # Run gowitness
        if [[ -n "$CHROMIUM" ]]; then
            $GOWITNESS file -f "$urls_file" \
                --chrome-path="$CHROMIUM" \
                --screenshot-path="$screenshot_dir" \
                --db-path="$screenshot_dir/gowitness.sqlite3" \
                --timeout 15 \
                --threads 5 \
                2>/dev/null &
        else
            $GOWITNESS file -f "$urls_file" \
                --screenshot-path="$screenshot_dir" \
                --db-path="$screenshot_dir/gowitness.sqlite3" \
                --timeout 15 \
                --threads 5 \
                2>/dev/null &
        fi
        
        local pid=$!
        local dots=0
        
        while kill -0 $pid 2>/dev/null; do
            should_skip_phase && kill $pid 2>/dev/null && break
            printf "\r  ${DIM}Capturing%s${RESET}   " "$(printf '.%.0s' $(seq 1 $((dots % 4 + 1))))"
            ((dots++))
            sleep 1
        done
        printf "\r                              \r"
        
        wait $pid 2>/dev/null
        
        # Count captured screenshots
        local captured=$(find "$screenshot_dir" -name "*.png" 2>/dev/null | wc -l)
        echo -e "  ${GREEN}✓${RESET} Captured ${BOLD}$captured${RESET} screenshots"
        
        disable_phase_skip
        
    elif [[ -n "$AQUATONE" ]]; then
        echo -e "  ${GREEN}✓${RESET} Using aquatone (gowitness not available)"
        
        echo ""
        read -p "  Capture screenshots of all live hosts? [Y/n]: " screenshot_choice
        if [[ "$screenshot_choice" =~ ^[Nn] ]]; then
            log "INFO" "Skipping screenshots"
            return
        fi
        
        enable_phase_skip "Screenshot Capture"
        
        # Run aquatone
        cat "$live_file" | sed 's/^/https:\/\//' | $AQUATONE -out "$screenshot_dir/aquatone" -threads 5 2>/dev/null &
        local pid=$!
        
        while kill -0 $pid 2>/dev/null; do
            should_skip_phase && kill $pid 2>/dev/null && break
            sleep 2
        done
        
        wait $pid 2>/dev/null
        
        local captured=$(find "$screenshot_dir" -name "*.png" 2>/dev/null | wc -l)
        echo -e "  ${GREEN}✓${RESET} Captured ${BOLD}$captured${RESET} screenshots"
        
        disable_phase_skip
        
    else
        log "WARN" "No screenshot tool available (install gowitness or aquatone)"
        echo -e "  ${YELLOW}⚠️${RESET} Install: ${DIM}go install github.com/sensepost/gowitness@latest${RESET}"
    fi
}

#═══════════════════════════════════════════════════════════════════════════════
# ADVANCED DISCOVERY: Naabu (Fast Port Scanning)
#═══════════════════════════════════════════════════════════════════════════════

run_naabu_scan() {
    if [[ -z \"$NAABU\" ]]; then
        log \"WARN\" \"naabu not installed - skipping fast port scan\"
        return
    fi
    
    local live_file=\"$OUTPUT_DIR/01-subdomains/subdomains_live.txt\"
    local naabu_output=\"$OUTPUT_DIR/02-hosts/naabu_ports.json\"
    
    if [[ ! -f \"$live_file\" ]] || [[ ! -s \"$live_file\" ]]; then\n        return
    fi
    
    local total=$(wc -l < \"$live_file\")
    echo \"\"
    echo -e \"  ${CYAN}🚀 Fast port scan on ${BOLD}$total${RESET}${CYAN} hosts (naabu)...${RESET}\"
    
    # Run naabu with JSON output and port range
    safe_exec \"$NAABU -list $live_file -top-ports 100 -json -o $naabu_output\" 2>/dev/null
    
    # Track temp files for cleanup
    TMP_TRACK+=(\"$naabu_output\")
    
    if [[ -s \"$naabu_output\" ]]; then\n        local port_count=$(jq -r '.port' \"$naabu_output\" 2>/dev/null | sort -u | wc -l)\n        echo -e \"  ${GREEN}✓${RESET} Found ${BOLD}$port_count${RESET} unique open ports\"\n        echo \"PHASE_NAABU=complete\" >> \"$STATE_FILE\"\n    fi\n}\n\n#═══════════════════════════════════════════════════════════════════════════════\n# ADVANCED CRAWLING: Katana (Modern Web Crawler)\n#═══════════════════════════════════════════════════════════════════════════════\n\nrun_katana_crawl() {\n    if [[ -z \"$KATANA\" ]]; then\n        log \"WARN\" \"katana not installed - skipping advanced crawling\"\n        return\n    fi\n    \n    local live_file=\"$OUTPUT_DIR/01-subdomains/subdomains_live.txt\"\n    local katana_output=\"$OUTPUT_DIR/07-wayback/urls/katana_urls.txt\"\n    \n    if [[ ! -f \"$live_file\" ]] || [[ ! -s \"$live_file\" ]]; then\n        return\n    fi\n    \n    local total=$(wc -l < \"$live_file\")\n    echo \"\"\n    echo -e \"  ${CYAN}🕷️  Advanced crawling with Katana (depth 2)...${RESET}\"\n    \n    # Katana with JS crawling, depth control, and output filtering\n    safe_exec \"$KATANA -list $live_file -depth 2 -js-crawl -output $katana_output -silent\" 2>/dev/null\n    \n    TMP_TRACK+=(\"$katana_output\")\n    \n    if [[ -s \"$katana_output\" ]]; then\n        local url_count=$(wc -l < \"$katana_output\")\n        echo -e \"  ${GREEN}✓${RESET} Crawled ${BOLD}$url_count${RESET} unique URLs\"\n        echo \"PHASE_KATANA=complete\" >> \"$STATE_FILE\"\n    fi\n}\n\n#═══════════════════════════════════════════════════════════════════════════════\n# WAYBACK MACHINE: gauplus (Enhanced Wayback URL Extractor)\n#═══════════════════════════════════════════════════════════════════════════════\n\nrun_gauplus_discovery() {\n    if [[ -z \"$GAUPLUS\" ]]; then\n        log \"WARN\" \"gauplus not installed - skipping Wayback URL discovery\"\n        return\n    fi\n    \n    local gauplus_output=\"$OUTPUT_DIR/07-wayback/urls/gauplus_urls.txt\"\n    \n    echo \"\"\n    echo -e \"  ${CYAN}📜 Extracting URLs from Wayback Machine...${RESET}\"\n    \n    # Use gauplus to get URLs from wayback, filter 404s, include subdomains\n    safe_exec \"$GAUPLUS --subs --fc 404 $TARGET > $gauplus_output\" 2>/dev/null\n    \n    TMP_TRACK+=(\"$gauplus_output\")\n    \n    if [[ -s \"$gauplus_output\" ]]; then\n        local url_count=$(wc -l < \"$gauplus_output\")\n        echo -e \"  ${GREEN}✓${RESET} Discovered ${BOLD}$url_count${RESET} Wayback URLs\"\n        echo \"PHASE_GAUPLUS=complete\" >> \"$STATE_FILE\"\n    fi\n}\n\n#═══════════════════════════════════════════════════════════════════════════════\n# SECRETS EXTRACTION: trufflehog (Regex + Entropy-based Secrets)\n#═══════════════════════════════════════════════════════════════════════════════\n\nrun_secrets_extraction() {\n    if [[ -z \"$TRUFFLEHOG\" ]]; then\n        log \"WARN\" \"trufflehog not installed - skipping secrets extraction\"\n        return\n    fi\n    \n    local js_dir=\"$OUTPUT_DIR/04-javascript/js_source\"\n    local secrets_output=\"$OUTPUT_DIR/13-secrets/trufflehog_findings.txt\"\n    \n    if [[ ! -d \"$js_dir\" ]] || [[ -z \"$(find $js_dir -type f -name '*.js' 2>/dev/null)\" ]]; then\n        return\n    fi\n    \n    echo \"\"\n    echo -e \"  ${RED}🔑 Scanning JavaScript files for secrets (trufflehog)...${RESET}\"\n    \n    # Run trufflehog on downloaded JS files\n    safe_exec \"$TRUFFLEHOG filesystem $js_dir --json --no-update > $secrets_output\" 2>/dev/null\n    \n    TMP_TRACK+=(\"$secrets_output\")\n    \n    if [[ -s \"$secrets_output\" ]]; then\n        local secret_count=$(wc -l < \"$secrets_output\")\n        echo -e \"  ${RED}✓ Found ${BOLD}$secret_count${RESET}${RED} potential secrets${RESET}\"\n        ((SECRETS_FOUND += secret_count))\n        echo \"PHASE_SECRETS=complete\" >> \"$STATE_FILE\"\n    fi\n}\n\n#═══════════════════════════════════════════════════════════════════════════════\n# TLS/SAN ENUMERATION: tlsx (Certificate SAN extraction)\n#═══════════════════════════════════════════════════════════════════════════════\n\nrun_tlsx_san_enum() {\n    if [[ -z \"$TLSX\" ]]; then\n        return\n    fi\n    \n    local live_file=\"$OUTPUT_DIR/01-subdomains/subdomains_live.txt\"\n    local tlsx_output=\"$OUTPUT_DIR/01-subdomains/tls_san_domains.txt\"\n    \n    if [[ ! -f \"$live_file\" ]] || [[ ! -s \"$live_file\" ]]; then\n        return\n    fi\n    \n    echo \"\"\n    echo -e \"  ${CYAN}🔐 Extracting SANs from TLS certificates...${RESET}\"\n    \n    # Use tlsx to extract SANs and Subject CN\n    safe_exec \"$TLSX -l $live_file -san -cn -o $tlsx_output\" 2>/dev/null\n    \n    TMP_TRACK+=(\"$tlsx_output\")\n    \n    if [[ -s \"$tlsx_output\" ]]; then\n        local san_count=$(wc -l < \"$tlsx_output\")\n        echo -e \"  ${GREEN}✓${RESET} Extracted ${BOLD}$san_count${RESET} SAN domains\"\n        \n        # Merge with existing subdomains\n        sort -u \"$tlsx_output\" >> \"$OUTPUT_DIR/01-subdomains/subdomains_all.txt\" 2>/dev/null\n    fi\n}\n\n# Port scanning with RustScan\nrun_port_scan() {"
    echo ""
    echo -e "${PURPLE}┌─────────────────────────────────────────────────────────────────────────────┐${RESET}"
    echo -e "${PURPLE}│${RESET} 🔍 ${BOLD}PORT SCANNING${RESET}"
    echo -e "${PURPLE}└─────────────────────────────────────────────────────────────────────────────┘${RESET}"
    echo -e "${DIM}  💡 Press Ctrl+C to skip this phase${RESET}"
    echo ""
    echo -e "  ${YELLOW}⚠️  NOTE: Hosts behind CDN (Cloudflare, Akamai) will show no ports${RESET}"
    echo -e "  ${DIM}     Port scanning works best on direct IPs, not CDN-protected domains${RESET}"
    
    local live_file="$OUTPUT_DIR/01-subdomains/subdomains_live.txt"
    local ports_dir="$OUTPUT_DIR/02-hosts/ports"
    mkdir -p "$ports_dir"
    
    if [[ ! -f "$live_file" ]] || [[ ! -s "$live_file" ]]; then
        log "WARN" "No live hosts for port scanning"
        return
    fi
    
    local total=$(wc -l < "$live_file")
    echo ""
    echo -e "  ${CYAN}🎯 ${BOLD}$total${RESET}${CYAN} hosts to scan${RESET}"
    echo ""
    
    # Check available tools - prefer masscan > nmap > rustscan for reliability
    local scanner=""
    if [[ -n "$MASSCAN" ]]; then
        scanner="masscan"
        echo -e "  ${GREEN}✓${RESET} Using masscan (fastest, requires root)"
    elif [[ -n "$NMAP" ]]; then
        scanner="nmap"
        echo -e "  ${GREEN}✓${RESET} Using nmap (most reliable)"
    elif [[ -n "$RUSTSCAN" ]]; then
        scanner="rustscan"
        echo -e "  ${GREEN}✓${RESET} Using rustscan"
    else
        log "WARN" "No port scanner available (install nmap: apt install nmap)"
        return
    fi
    
    echo ""
    echo -e "  ${BOLD}Scan Options:${RESET}"
    echo -e "    ${GREEN}1)${RESET} 🚀 ${GREEN}Quick${RESET}   - Top 100 ports (~30 sec/host)"
    echo -e "    ${YELLOW}2)${RESET} ⚡ ${YELLOW}Common${RESET}  - Top 1000 ports (~2 min/host)"
    echo -e "    ${RED}3)${RESET} 🔥 ${RED}Full${RESET}    - All 65535 ports (~10+ min/host)"
    echo -e "    ${DIM}4)${RESET} ⏭️  ${DIM}Skip${RESET}    - Skip port scanning"
    echo ""
    
    read -p "  Select scan type [1-4] (default: 1): " scan_choice
    [[ -z "$scan_choice" ]] && scan_choice="1"
    
    local nmap_ports=""
    local masscan_ports=""
    local port_range=""
    
    case "$scan_choice" in
        1) 
            nmap_ports="--top-ports 100"
            masscan_ports="-p21,22,23,25,53,80,110,111,135,139,143,443,445,993,995,1723,3306,3389,5900,8080"
            port_range="top 100"
            ;;
        2) 
            nmap_ports="--top-ports 1000"
            masscan_ports="-p1-1024,3306,3389,5432,5900,6379,8000,8080,8443,8888,9090,27017"
            port_range="top 1000"
            ;;
        3) 
            nmap_ports="-p-"
            masscan_ports="-p1-65535"
            port_range="all 65535"
            ;;
        4) 
            log "INFO" "Skipping port scan"
            return
            ;;
        *) 
            nmap_ports="--top-ports 100"
            masscan_ports="-p21,22,23,25,53,80,110,111,135,139,143,443,445,993,995,1723,3306,3389,5900,8080"
            port_range="top 100"
            ;;
    esac
    
    enable_phase_skip "Port Scanning"
    
    echo ""
    echo -e "  ${DIM}Scanning $port_range ports on each host...${RESET}"
    echo ""
    
    local current=0
    local open_ports_total=0
    local hosts_with_ports=0
    
    while IFS= read -r host; do
        [[ -z "$host" ]] && continue
        should_skip_phase && break
        
        ((current++))
        local safe_host=$(echo "$host" | tr '/:' '_')
        local output_file="$ports_dir/${safe_host}.txt"
        
        printf "  ${CYAN}[%d/%d]${RESET} %-50s " "$current" "$total" "$host"
        
        local result=""
        
        case "$scanner" in
            nmap)
                # Nmap - most reliable, proper output parsing
                result=$($NMAP -Pn -sT $nmap_ports -T4 --min-rate 1000 --max-retries 1 "$host" 2>/dev/null | \
                    grep -E "^[0-9]+/tcp" | grep "open" | cut -d'/' -f1 | tr '\n' ' ')
                ;;
            masscan)
                # Masscan - fastest, needs root
                if [[ $EUID -eq 0 ]]; then
                    result=$(timeout 60 $MASSCAN "$host" $masscan_ports --rate 1000 2>/dev/null | \
                        grep "Discovered open port" | awk '{print $4}' | cut -d'/' -f1 | tr '\n' ' ')
                else
                    # Fallback to nmap if not root
                    result=$($NMAP -Pn -sT $nmap_ports -T4 "$host" 2>/dev/null | \
                        grep -E "^[0-9]+/tcp" | grep "open" | cut -d'/' -f1 | tr '\n' ' ')
                fi
                ;;
            rustscan)
                # RustScan - fast but output varies
                result=$($RUSTSCAN -a "$host" --range 1-65535 --batch-size 5000 --timeout 3000 -g 2>/dev/null | \
                    grep -oP '\d+' | sort -un | tr '\n' ' ')
                # If that didn't work, try alternate syntax
                if [[ -z "$result" ]]; then
                    result=$($RUSTSCAN -a "$host" -p 21,22,23,25,53,80,110,143,443,445,3306,3389,5432,6379,8080,8443,27017 2>/dev/null | \
                        grep -oP '^\d+' | tr '\n' ' ')
                fi
                ;;
        esac
        
        # Clean up result
        result=$(echo "$result" | xargs)
        
        if [[ -n "$result" ]] && [[ "$result" != " " ]]; then
            local port_count=$(echo "$result" | wc -w)
            echo "$result" | tr ' ' '\n' | grep -v '^$' > "$output_file"
            echo -e "→ ${GREEN}${BOLD}$port_count open${RESET}"
            ((open_ports_total += port_count))
            ((hosts_with_ports++))
            
            # Show interesting ports inline
            for port in $result; do
                case $port in
                    21) echo -e "      ${RED}↳ 21/ftp${RESET} - File Transfer" ;;
                    22) echo -e "      ${YELLOW}↳ 22/ssh${RESET} - Secure Shell" ;;
                    23) echo -e "      ${RED}↳ 23/telnet${RESET} - CRITICAL" ;;
                    25) echo -e "      ${DIM}↳ 25/smtp${RESET}" ;;
                    53) echo -e "      ${CYAN}↳ 53/dns${RESET}" ;;
                    80) echo -e "      ${GREEN}↳ 80/http${RESET}" ;;
                    110) echo -e "      ${DIM}↳ 110/pop3${RESET}" ;;
                    143) echo -e "      ${DIM}↳ 143/imap${RESET}" ;;
                    443) echo -e "      ${GREEN}↳ 443/https${RESET}" ;;
                    445) echo -e "      ${RED}↳ 445/smb${RESET} - CRITICAL" ;;
                    1433) echo -e "      ${RED}↳ 1433/mssql${RESET} - DATABASE" ;;
                    3306) echo -e "      ${RED}↳ 3306/mysql${RESET} - DATABASE" ;;
                    3389) echo -e "      ${RED}↳ 3389/rdp${RESET} - CRITICAL" ;;
                    5432) echo -e "      ${RED}↳ 5432/postgres${RESET} - DATABASE" ;;
                    5900) echo -e "      ${RED}↳ 5900/vnc${RESET} - CRITICAL" ;;
                    6379) echo -e "      ${RED}↳ 6379/redis${RESET} - DATABASE" ;;
                    8080) echo -e "      ${YELLOW}↳ 8080/http-alt${RESET}" ;;
                    8443) echo -e "      ${YELLOW}↳ 8443/https-alt${RESET}" ;;
                    9090) echo -e "      ${YELLOW}↳ 9090/web-mgmt${RESET}" ;;
                    27017) echo -e "      ${RED}↳ 27017/mongodb${RESET} - DATABASE" ;;
                esac
            done
        else
            echo -e "→ ${DIM}filtered/closed (likely CDN)${RESET}"
        fi
        
    done < "$live_file"
    
    echo ""
    echo -e "${GREEN}┌─────────────────────────────────────────────────────────────────────────────┐${RESET}"
    echo -e "${GREEN}│${RESET} ✅ ${BOLD}PORT SCAN COMPLETE${RESET}"
    echo -e "${GREEN}│${RESET}    Hosts scanned: ${BOLD}$current${RESET}"
    echo -e "${GREEN}│${RESET}    Hosts with open ports: ${BOLD}${GREEN}$hosts_with_ports${RESET}"
    echo -e "${GREEN}│${RESET}    Total open ports found: ${BOLD}${GREEN}$open_ports_total${RESET}"
    echo -e "${GREEN}└─────────────────────────────────────────────────────────────────────────────┘${RESET}"
    
    # Create summary
    local summary_file="$ports_dir/SUMMARY.txt"
    {
        echo "Port Scan Summary"
        echo "================="
        echo "Scanner: $scanner"
        echo "Port range: $port_range"
        echo "Hosts scanned: $current"
        echo "Hosts with open ports: $hosts_with_ports"
        echo "Total open ports: $open_ports_total"
        echo ""
        echo "Critical Findings (databases, RDP, etc.):"
        for f in "$ports_dir"/*.txt; do
            [[ ! -f "$f" ]] && continue
            if grep -qE "^(21|22|23|445|1433|3306|3389|5432|5900|6379|27017)$" "$f" 2>/dev/null; then
                local h=$(basename "$f" .txt)
                echo "  $h: $(cat "$f" | tr '\n' ',' | sed 's/,$//')"
            fi
        done
    } > "$summary_file"
    
    disable_phase_skip
}

#═══════════════════════════════════════════════════════════════════════════════
# 🔥 ADVANCED SECURITY RECONNAISSANCE
#═══════════════════════════════════════════════════════════════════════════════

# Check for subdomain takeover vulnerabilities
check_subdomain_takeover() {
    echo ""
    echo -e "${RED}┌─────────────────────────────────────────────────────────────────────────────┐${RESET}"
    echo -e "${RED}│${RESET} 🎯 ${BOLD}SUBDOMAIN TAKEOVER CHECK${RESET}"
    echo -e "${RED}└─────────────────────────────────────────────────────────────────────────────┘${RESET}"
    
    local dead_file="$OUTPUT_DIR/01-subdomains/subdomains_dead.txt"
    local takeover_file="$OUTPUT_DIR/02-hosts/potential_takeovers.txt"
    
    > "$takeover_file"
    
    # Known CNAME patterns for takeover
    local takeover_patterns=(
        "amazonaws.com"
        "cloudfront.net"
        "herokuapp.com"
        "herokudns.com"
        "wordpress.com"
        "pantheonsite.io"
        "domains.tumblr.com"
        "wpengine.com"
        "desk.com"
        "zendesk.com"
        "github.io"
        "bitbucket.io"
        "ghost.io"
        "freshdesk.com"
        "myshopify.com"
        "statuspage.io"
        "uservoice.com"
        "surge.sh"
        "fastly.net"
        "azure-api.net"
        "cloudapp.net"
        "azurewebsites.net"
        "blob.core.windows.net"
        "cloudapp.azure.com"
        "azureedge.net"
        "trafficmanager.net"
        "bigcartel.com"
        "helpjuice.com"
        "helpscoutdocs.com"
        "feedpress.me"
        "unbounce.com"
        "cargo.site"
        "webflow.io"
        "netlify.app"
        "vercel.app"
        "fly.dev"
        "render.com"
    )
    
    local checked=0
    local potential=0
    
    if [[ -f "$dead_file" ]] && [[ -s "$dead_file" ]]; then
        local total=$(wc -l < "$dead_file")
        echo -e "  ${DIM}Checking $total dead subdomains for takeover...${RESET}"
        
        while IFS= read -r domain; do
            [[ -z "$domain" ]] && continue
            ((checked++))
            
            # Get CNAME record
            local cname=$(dig +short CNAME "$domain" 2>/dev/null | head -1)
            
            if [[ -n "$cname" ]]; then
                for pattern in "${takeover_patterns[@]}"; do
                    if [[ "$cname" == *"$pattern"* ]]; then
                        echo -e "  ${RED}🚨 POTENTIAL TAKEOVER:${RESET} $domain -> ${YELLOW}$cname${RESET}"
                        echo "$domain|$cname|$pattern" >> "$takeover_file"
                        ((potential++))
                        break
                    fi
                done
            fi
        done < "$dead_file"
    fi
    
    # Also check live hosts with interesting CNAME
    local live_file="$OUTPUT_DIR/01-subdomains/subdomains_live.txt"
    if [[ -f "$live_file" ]]; then
        while IFS= read -r domain; do
            [[ -z "$domain" ]] && continue
            local cname=$(dig +short CNAME "$domain" 2>/dev/null | head -1)
            if [[ -n "$cname" ]]; then
                for pattern in "${takeover_patterns[@]}"; do
                    if [[ "$cname" == *"$pattern"* ]]; then
                        # Verify if actually vulnerable
                        local response=$(curl -s -o /dev/null -w "%{http_code}" --max-time 5 "http://$domain" 2>/dev/null)
                        if [[ "$response" == "404" ]] || [[ "$response" == "000" ]]; then
                            echo -e "  ${RED}🚨 LIKELY TAKEOVER:${RESET} $domain -> ${YELLOW}$cname${RESET} [${response}]"
                            echo "$domain|$cname|$pattern|LIKELY" >> "$takeover_file"
                            ((potential++))
                        fi
                        break
                    fi
                done
            fi
        done < "$live_file"
    fi
    
    if [[ $potential -gt 0 ]]; then
        log "CRITICAL" "🔥 Found $potential potential subdomain takeovers!"
    else
        echo -e "  ${GREEN}✓${RESET} No obvious takeover vulnerabilities found"
    fi
}

# Quick security headers check
check_security_headers() {
    echo ""
    echo -e "${YELLOW}┌─────────────────────────────────────────────────────────────────────────────┐${RESET}"
    echo -e "${YELLOW}│${RESET} 🛡️  ${BOLD}SECURITY HEADERS ANALYSIS${RESET}"
    echo -e "${YELLOW}└─────────────────────────────────────────────────────────────────────────────┘${RESET}"
    
    local priority_file="$OUTPUT_DIR/02-hosts/hosts_by_priority.txt"
    local headers_file="$OUTPUT_DIR/02-hosts/security_headers.txt"
    local missing_file="$OUTPUT_DIR/02-hosts/missing_headers.txt"
    
    > "$headers_file"
    > "$missing_file"
    
    if [[ ! -f "$priority_file" ]]; then
        return
    fi
    
    local important_headers=(
        "Strict-Transport-Security"
        "X-Frame-Options"
        "X-Content-Type-Options"
        "Content-Security-Policy"
        "X-XSS-Protection"
        "Referrer-Policy"
        "Permissions-Policy"
    )
    
    local checked=0
    local max_check=10  # Only check top 10 priority hosts
    
    echo -e "  ${DIM}Analyzing security headers on top targets...${RESET}"
    echo ""
    
    while IFS='|' read -r url score tech status title server; do
        [[ -z "$url" ]] && continue
        ((checked++))
        [[ $checked -gt $max_check ]] && break
        
        local host=$(echo "$url" | sed -E 's|^https?://||' | cut -d'/' -f1)
        
        # Fetch headers
        local headers=$(curl -sI --max-time 5 -k "$url" 2>/dev/null)
        
        local missing=()
        for header in "${important_headers[@]}"; do
            if ! echo "$headers" | grep -qi "^$header"; then
                missing+=("$header")
            fi
        done
        
        if [[ ${#missing[@]} -gt 0 ]]; then
            echo -e "  ${YELLOW}⚠️${RESET}  $host - Missing: ${RED}${missing[*]}${RESET}"
            echo "$host|${missing[*]}" >> "$missing_file"
        else
            echo -e "  ${GREEN}✓${RESET}  $host - All security headers present"
        fi
        
    done < "$priority_file"
    
    local vuln_count=$(wc -l < "$missing_file" 2>/dev/null || echo 0)
    echo ""
    log "INFO" "Checked $checked hosts, $vuln_count have missing security headers"
}

# CORS misconfiguration check
check_cors_misconfig() {
    echo ""
    echo -e "${PURPLE}┌─────────────────────────────────────────────────────────────────────────────┐${RESET}"
    echo -e "${PURPLE}│${RESET} 🌐 ${BOLD}CORS MISCONFIGURATION CHECK${RESET}"
    echo -e "${PURPLE}└─────────────────────────────────────────────────────────────────────────────┘${RESET}"
    
    local priority_file="$OUTPUT_DIR/02-hosts/hosts_by_priority.txt"
    local cors_file="$OUTPUT_DIR/02-hosts/cors_misconfig.txt"
    
    > "$cors_file"
    
    if [[ ! -f "$priority_file" ]]; then
        return
    fi
    
    local checked=0
    local vulnerable=0
    local max_check=15
    
    echo -e "  ${DIM}Testing CORS on priority targets...${RESET}"
    echo ""
    
    # Test origins
    local test_origins=(
        "https://evil.com"
        "https://attacker.com"
        "null"
    )
    
    while IFS='|' read -r url score tech status title server; do
        [[ -z "$url" ]] && continue
        ((checked++))
        [[ $checked -gt $max_check ]] && break
        
        local host=$(echo "$url" | sed -E 's|^https?://||' | cut -d'/' -f1)
        
        for origin in "${test_origins[@]}"; do
            local response=$(curl -sI --max-time 5 -k \
                -H "Origin: $origin" \
                "$url" 2>/dev/null)
            
            local acao=$(echo "$response" | grep -i "Access-Control-Allow-Origin" | head -1)
            local acac=$(echo "$response" | grep -i "Access-Control-Allow-Credentials" | head -1)
            
            if [[ -n "$acao" ]]; then
                if echo "$acao" | grep -qi "$origin\|\\*"; then
                    if echo "$acac" | grep -qi "true"; then
                        echo -e "  ${RED}🚨 CRITICAL:${RESET} $host reflects origin ${YELLOW}$origin${RESET} with credentials!"
                        echo "$host|$origin|CREDENTIALS|CRITICAL" >> "$cors_file"
                        ((vulnerable++))
                    elif echo "$acao" | grep -q "\\*"; then
                        echo -e "  ${YELLOW}⚠️  WARNING:${RESET} $host has wildcard CORS (${origin})"
                        echo "$host|$origin|WILDCARD|MEDIUM" >> "$cors_file"
                        ((vulnerable++))
                    fi
                fi
            fi
        done
        
    done < "$priority_file"
    
    if [[ $vulnerable -gt 0 ]]; then
        log "CRITICAL" "🔥 Found $vulnerable CORS misconfigurations!"
    else
        echo -e "  ${GREEN}✓${RESET} No obvious CORS misconfigurations"
    fi
}

# Quick sensitive file probe
quick_sensitive_probe() {
    echo ""
    echo -e "${RED}┌─────────────────────────────────────────────────────────────────────────────┐${RESET}"
    echo -e "${RED}│${RESET} 🔓 ${BOLD}QUICK SENSITIVE FILES PROBE${RESET}"
    echo -e "${RED}└─────────────────────────────────────────────────────────────────────────────┘${RESET}"
    
    local priority_file="$OUTPUT_DIR/02-hosts/hosts_by_priority.txt"
    local findings_file="$OUTPUT_DIR/02-hosts/sensitive_files.txt"
    
    > "$findings_file"
    
    if [[ ! -f "$priority_file" ]]; then
        return
    fi
    
    # High-value sensitive paths
    local sensitive_paths=(
        ".git/HEAD"
        ".git/config"
        ".env"
        ".env.local"
        ".env.production"
        ".env.backup"
        "wp-config.php.bak"
        "config.php.bak"
        ".htaccess"
        ".htpasswd"
        "backup.sql"
        "dump.sql"
        "database.sql"
        ".DS_Store"
        "Thumbs.db"
        "composer.json"
        "package.json"
        ".npmrc"
        ".dockerenv"
        "Dockerfile"
        "docker-compose.yml"
        ".aws/credentials"
        "id_rsa"
        "id_rsa.pub"
        ".ssh/authorized_keys"
        "server.key"
        "privatekey.pem"
        "web.config"
        "crossdomain.xml"
        "clientaccesspolicy.xml"
        "elmah.axd"
        "trace.axd"
        "phpinfo.php"
        "info.php"
        "test.php"
        ".svn/entries"
        ".hg/hgrc"
        "CVS/Root"
        "robots.txt"
        "sitemap.xml"
        "security.txt"
        ".well-known/security.txt"
        "swagger.json"
        "swagger.yaml"
        "openapi.json"
        "api-docs"
        "graphql"
        "graphiql"
        "actuator"
        "actuator/health"
        "actuator/env"
        "debug"
        "console"
        "admin"
        "phpmyadmin"
        "adminer.php"
        "_profiler"
        "elmah"
        "server-status"
        "server-info"
    )
    
    local checked=0
    local found=0
    local max_hosts=10
    
    echo -e "  ${DIM}Probing for sensitive files on top targets...${RESET}"
    echo ""
    
    while IFS='|' read -r url score tech status title server; do
        [[ -z "$url" ]] && continue
        ((checked++))
        [[ $checked -gt $max_hosts ]] && break
        
        local host=$(echo "$url" | sed -E 's|^https?://||' | cut -d'/' -f1)
        local base_url="${url%/}"
        
        for path in "${sensitive_paths[@]}"; do
            local test_url="$base_url/$path"
            local response=$(curl -s -o /dev/null -w "%{http_code}|%{size_download}" \
                --max-time 3 -k "$test_url" 2>/dev/null)
            
            local status_code=$(echo "$response" | cut -d'|' -f1)
            local size=$(echo "$response" | cut -d'|' -f2)
            
            # Check for interesting responses
            if [[ "$status_code" == "200" ]] && [[ "$size" -gt 0 ]]; then
                # Verify it's not a generic error page
                if [[ "$size" -gt 20 ]] && [[ "$size" -lt 1000000 ]]; then
                    local severity="MEDIUM"
                    [[ "$path" =~ (\.env|\.git|\.aws|id_rsa|\.key|\.pem|password|secret|credential) ]] && severity="CRITICAL"
                    [[ "$path" =~ (config|backup|\.sql|dump) ]] && severity="HIGH"
                    [[ "$path" =~ (swagger|graphql|actuator|phpinfo|debug) ]] && severity="HIGH"
                    
                    case "$severity" in
                        CRITICAL)
                            echo -e "  ${RED}🚨 CRITICAL:${RESET} $test_url [${status_code}] ${size}B"
                            ;;
                        HIGH)
                            echo -e "  ${YELLOW}⚠️  HIGH:${RESET} $test_url [${status_code}] ${size}B"
                            ;;
                        *)
                            echo -e "  ${CYAN}💡 MEDIUM:${RESET} $test_url [${status_code}] ${size}B"
                            ;;
                    esac
                    
                    echo "[$severity] $test_url [$status_code] ${size}B" >> "$findings_file"
                    ((found++))
                fi
            elif [[ "$status_code" == "403" ]]; then
                # 403 on sensitive paths is interesting
                if [[ "$path" =~ (\.git|\.env|admin|actuator|debug|console) ]]; then
                    echo -e "  ${YELLOW}🔒 FORBIDDEN:${RESET} $test_url [403] - may exist!"
                    echo "[FORBIDDEN] $test_url [403]" >> "$findings_file"
                fi
            fi
        done
        
    done < "$priority_file"
    
    if [[ $found -gt 0 ]]; then
        log "CRITICAL" "🔥 Found $found sensitive file exposures!"
    else
        echo -e "  ${GREEN}✓${RESET} No obvious sensitive file exposures"
    fi
}

# WAF Detection
detect_waf() {
    echo ""
    echo -e "${CYAN}┌─────────────────────────────────────────────────────────────────────────────┐${RESET}"
    echo -e "${CYAN}│${RESET} 🛡️  ${BOLD}WAF/CDN DETECTION${RESET}"
    echo -e "${CYAN}└─────────────────────────────────────────────────────────────────────────────┘${RESET}"
    
    local priority_file="$OUTPUT_DIR/02-hosts/hosts_by_priority.txt"
    local waf_file="$OUTPUT_DIR/02-hosts/waf_detected.txt"
    
    > "$waf_file"
    
    if [[ ! -f "$priority_file" ]]; then
        return
    fi
    
    declare -A waf_signatures=(
        ["Cloudflare"]="cloudflare|cf-ray|__cfduid"
        ["AWS WAF"]="awselb|x-amzn|x-amz-cf"
        ["Akamai"]="akamai|x-akamai"
        ["Imperva"]="incap_ses|visid_incap|imperva"
        ["Sucuri"]="sucuri|x-sucuri"
        ["F5 BIG-IP"]="bigip|f5|x-wa-info"
        ["ModSecurity"]="mod_security|modsecurity"
        ["Barracuda"]="barracuda|barra_counter"
        ["Fortinet"]="fortigate|fortiweb"
        ["Citrix"]="citrix|ns_af"
        ["AWS CloudFront"]="x-amz-cf-id|cloudfront"
        ["Fastly"]="fastly|x-served-by"
        ["StackPath"]="stackpath"
        ["KeyCDN"]="keycdn"
        ["DDoS-Guard"]="ddos-guard"
    )
    
    local checked=0
    local max_check=10
    
    echo -e "  ${DIM}Detecting WAF/CDN on targets...${RESET}"
    echo ""
    
    while IFS='|' read -r url score tech status title server; do
        [[ -z "$url" ]] && continue
        ((checked++))
        [[ $checked -gt $max_check ]] && break
        
        local host=$(echo "$url" | sed -E 's|^https?://||' | cut -d'/' -f1)
        
        # Get headers with a slightly malicious request to trigger WAF
        local headers=$(curl -sI --max-time 5 -k \
            -A "Mozilla/5.0 (compatible; Googlebot/2.1)" \
            -H "X-Forwarded-For: 127.0.0.1" \
            "$url/?test=<script>alert(1)</script>" 2>/dev/null)
        
        local detected=""
        for waf in "${!waf_signatures[@]}"; do
            if echo "$headers" | grep -qiE "${waf_signatures[$waf]}"; then
                detected="$waf"
                break
            fi
        done
        
        if [[ -n "$detected" ]]; then
            echo -e "  ${YELLOW}🛡️${RESET}  $host - ${YELLOW}$detected${RESET} detected"
            echo "$host|$detected" >> "$waf_file"
        else
            echo -e "  ${GREEN}✓${RESET}  $host - No WAF detected (or stealthy WAF)"
        fi
        
    done < "$priority_file"
    
    local waf_count=$(wc -l < "$waf_file" 2>/dev/null || echo 0)
    echo ""
    log "INFO" "Detected WAF on $waf_count out of $checked hosts"
}

# Cloud Storage Discovery (S3, Azure, GCP)
discover_cloud_storage() {
    echo ""
    echo -e "${CYAN}┌─────────────────────────────────────────────────────────────────────────────┐${RESET}"
    echo -e "${CYAN}│${RESET} ☁️  ${BOLD}CLOUD STORAGE DISCOVERY${RESET}"
    echo -e "${CYAN}└─────────────────────────────────────────────────────────────────────────────┘${RESET}"
    
    local bucket_file="$OUTPUT_DIR/02-hosts/cloud_buckets.txt"
    > "$bucket_file"
    
    # Generate potential bucket names from target
    local base_name=$(echo "$TARGET" | sed 's/\..*//')
    local bucket_names=(
        "$base_name"
        "${base_name}-dev"
        "${base_name}-prod"
        "${base_name}-staging"
        "${base_name}-backup"
        "${base_name}-backups"
        "${base_name}-assets"
        "${base_name}-static"
        "${base_name}-media"
        "${base_name}-uploads"
        "${base_name}-files"
        "${base_name}-data"
        "${base_name}-logs"
        "${base_name}-private"
        "${base_name}-public"
        "${base_name}backup"
        "${base_name}data"
        "${base_name}files"
        "backup-${base_name}"
        "dev-${base_name}"
        "prod-${base_name}"
    )
    
    local found=0
    
    echo -e "  ${DIM}Checking for exposed cloud buckets...${RESET}"
    echo ""
    
    for bucket in "${bucket_names[@]}"; do
        # Check AWS S3
        local s3_url="https://${bucket}.s3.amazonaws.com"
        local s3_response=$(curl -s -o /dev/null -w "%{http_code}" --max-time 3 "$s3_url" 2>/dev/null)
        
        if [[ "$s3_response" == "200" ]] || [[ "$s3_response" == "403" ]]; then
            if [[ "$s3_response" == "200" ]]; then
                echo -e "  ${RED}🚨 S3 PUBLIC:${RESET} $s3_url"
                echo "[PUBLIC] S3: $bucket" >> "$bucket_file"
            else
                echo -e "  ${YELLOW}☁️  S3 EXISTS:${RESET} $s3_url [403]"
                echo "[EXISTS] S3: $bucket" >> "$bucket_file"
            fi
            ((found++))
        fi
        
        # Check Azure Blob
        local azure_url="https://${bucket}.blob.core.windows.net"
        local azure_response=$(curl -s -o /dev/null -w "%{http_code}" --max-time 3 "$azure_url" 2>/dev/null)
        
        if [[ "$azure_response" != "000" ]] && [[ "$azure_response" != "404" ]]; then
            echo -e "  ${CYAN}☁️  Azure:${RESET} $azure_url [${azure_response}]"
            echo "[Azure] $bucket [$azure_response]" >> "$bucket_file"
            ((found++))
        fi
        
        # Check GCP Storage
        local gcp_url="https://storage.googleapis.com/${bucket}"
        local gcp_response=$(curl -s -o /dev/null -w "%{http_code}" --max-time 3 "$gcp_url" 2>/dev/null)
        
        if [[ "$gcp_response" == "200" ]] || [[ "$gcp_response" == "403" ]]; then
            if [[ "$gcp_response" == "200" ]]; then
                echo -e "  ${RED}🚨 GCP PUBLIC:${RESET} $gcp_url"
                echo "[PUBLIC] GCP: $bucket" >> "$bucket_file"
            else
                echo -e "  ${YELLOW}☁️  GCP EXISTS:${RESET} $gcp_url [403]"
                echo "[EXISTS] GCP: $bucket" >> "$bucket_file"
            fi
            ((found++))
        fi
    done
    
    if [[ $found -gt 0 ]]; then
        log "SUCCESS" "Found $found potential cloud storage endpoints"
    else
        echo -e "  ${DIM}No obvious cloud buckets found${RESET}"
    fi
}

# Interesting subdomain categorization
categorize_subdomains() {
    echo ""
    echo -e "${PURPLE}┌─────────────────────────────────────────────────────────────────────────────┐${RESET}"
    echo -e "${PURPLE}│${RESET} 📊 ${BOLD}SUBDOMAIN ANALYSIS${RESET}"
    echo -e "${PURPLE}└─────────────────────────────────────────────────────────────────────────────┘${RESET}"
    
    local live_file="$OUTPUT_DIR/01-subdomains/subdomains_live.txt"
    local analysis_dir="$OUTPUT_DIR/02-hosts/categorized"
    
    mkdir -p "$analysis_dir"
    
    if [[ ! -f "$live_file" ]]; then
        return
    fi
    
    # Categories with patterns
    declare -A categories=(
        ["🔐 Auth/SSO"]="auth|login|sso|oauth|signin|signup|register|account|identity|id\."
        ["🔌 API"]="api|rest|v1|v2|v3|gateway|ws\.|websocket|graphql"
        ["👑 Admin"]="admin|panel|dashboard|manage|cms|control|backend|console|portal"
        ["💰 Payment"]="pay|payment|checkout|billing|invoice|stripe|paypal|cart|shop|store"
        ["🏗️ Dev/Test"]="dev|test|staging|uat|qa|demo|sandbox|beta|alpha|preview|stg|preprod"
        ["📧 Mail"]="mail|email|smtp|imap|pop|webmail|mx|exchange"
        ["🔧 Internal"]="internal|intranet|corp|private|local|vpn|remote"
        ["📦 Storage"]="cdn|static|assets|media|upload|file|storage|img|images|s3"
        ["🖥️ CI/CD"]="jenkins|ci|cd|build|deploy|pipeline|gitlab|github|bitbucket|drone|travis"
        ["📊 Monitoring"]="monitor|grafana|kibana|elastic|prometheus|nagios|zabbix|log|metric"
        ["🗄️ Database"]="db|database|mongo|mysql|postgres|redis|sql|data|cache"
        ["📚 Docs"]="docs|wiki|confluence|jira|help|support|kb|faq|documentation"
    )
    
    echo ""
    for category in "${!categories[@]}"; do
        local pattern="${categories[$category]}"
        local matches=$(grep -iE "$pattern" "$live_file" 2>/dev/null | sort -u)
        local count=0
        
        if [[ -n "$matches" ]] && [[ "$matches" != "" ]]; then
            count=$(echo "$matches" | wc -l | tr -d ' ')
        fi
        
        if [[ $count -gt 0 ]]; then
            echo -e "  ${BOLD}$category${RESET} ($count):"
            echo "$matches" | head -5 | while read -r domain; do
                echo -e "    ${CYAN}→${RESET} $domain"
            done
            [[ $count -gt 5 ]] && echo -e "    ${DIM}... and $((count - 5)) more${RESET}"
            echo ""
            
            # Save to file
            local safe_name=$(echo "$category" | sed 's/[^a-zA-Z0-9]/_/g')
            echo "$matches" > "$analysis_dir/${safe_name}.txt"
        fi
    done
}

#═══════════════════════════════════════════════════════════════════════════════
# 🎯 SMART BUG HUNTER RECON: Sensitive Files & Hidden Paths
#═══════════════════════════════════════════════════════════════════════════════

hunt_sensitive_files() {
    echo ""
    echo -e "${RED}╔══════════════════════════════════════════════════════════════════════════════╗${RESET}"
    echo -e "${RED}║${RESET}  🔓 ${BOLD}SENSITIVE FILE DISCOVERY${RESET} - Hunt for exposed configs & secrets"
    echo -e "${RED}╚══════════════════════════════════════════════════════════════════════════════╝${RESET}"
    
    local live_file="$OUTPUT_DIR/01-subdomains/subdomains_live.txt"
    local findings_file="$OUTPUT_DIR/02-hosts/sensitive_files_found.txt"
    
    > "$findings_file"
    
    # High-value target patterns (prioritized by exploitability)
    declare -A sensitive_paths=(
        [".env|.env.local|.env.example"]="ENV Variables (CRITICAL)"
        [".git|.git/config|.gitignore"]="Git Exposure (CRITICAL)"
        [".aws/credentials|.aws/config"]="AWS Credentials (CRITICAL)"
        ["docker-compose.yml|dockerfile"]="Docker Config (HIGH)"
        ["web.config|web.xml"]="Web Server Config (HIGH)"
        ["package.json|requirements.txt|composer.json"]="Dependencies (HIGH)"
        [".htaccess|.htpasswd"]="Apache Auth (HIGH)"
        ["firebase.json|google-services.json"]="Firebase Config (HIGH)"
        ["config.php|config.js|config.py|settings.py"]="App Config (HIGH)"
        ["robots.txt|sitemap.xml"]="Crawl Hints (MEDIUM)"
        [".well-known/security.txt"]="Security Contact (INFO)"
        ["server-status|server-info"]="Server Status (INFO)"
        ["/backup|/old|/test|/demo"]="Legacy Paths (INFO)"
    )
    
    local total=$(wc -l < "$live_file" 2>/dev/null || echo 0)
    [[ $total -eq 0 ]] && return
    
    echo ""
    echo -e "  ${DIM}Probing ${BOLD}$total${RESET}${DIM} hosts for sensitive files/paths...${RESET}"
    echo ""
    
    local critical_found=0
    local high_found=0
    
    while IFS= read -r host; do
        [[ -z "$host" ]] && continue
        
        for pattern in "${!sensitive_paths[@]}"; do
            local severity="${sensitive_paths[$pattern]}"
            local paths_array=(${pattern//\|/ })
            
            for path in "${paths_array[@]}"; do
                local test_url="https://$host/$path"
                local response=$(curl -sS -w "\n%{http_code}" --connect-timeout 5 --max-time 10 -k "$test_url" 2>/dev/null)
                local status=$(echo "$response" | tail -1)
                
                if [[ "$status" == "200" ]] || [[ "$status" == "401" ]] || [[ "$status" == "403" ]]; then
                    local icon="⚠️ "
                    [[ "$severity" == *"CRITICAL"* ]] && icon="🔥" && ((critical_found++))
                    [[ "$severity" == *"HIGH"* ]] && ((high_found++))
                    
                    echo -e "  $icon $host/$path [${status}] - $severity"
                    echo "$host|$path|$status|$severity" >> "$findings_file"
                fi
            done
        done
    done < "$live_file"
    
    if [[ $critical_found -gt 0 ]]; then
        log "CRITICAL" "🔥 FOUND $critical_found CRITICAL SENSITIVE FILES!"
    elif [[ $high_found -gt 0 ]]; then
        log "WARN" "⚠️  Found $high_found HIGH severity sensitive files"
    else
        echo -e "  ${GREEN}✓${RESET} No obvious sensitive files detected"
    fi
}

#═══════════════════════════════════════════════════════════════════════════════
# 🎯 DNS ENUMERATION: Full DNS Record Harvesting
#═══════════════════════════════════════════════════════════════════════════════

harvest_dns_records() {
    echo ""
    echo -e "${PURPLE}┌─────────────────────────────────────────────────────────────────────────────┐${RESET}"
    echo -e "${PURPLE}│${RESET}  🔍 ${BOLD}DNS RECORDS HARVESTING${RESET} - MX, TXT, SPF, DMARC, CAA, NS"
    echo -e "${PURPLE}└─────────────────────────────────────────────────────────────────────────────┘${RESET}"
    
    local dns_file="$OUTPUT_DIR/02-hosts/dns_records.txt"
    local mx_file="$OUTPUT_DIR/02-hosts/mx_records.txt"
    local spf_file="$OUTPUT_DIR/02-hosts/spf_records.txt"
    
    > "$dns_file"
    > "$mx_file"
    > "$spf_file"
    
    echo ""
    echo -e "  ${CYAN}Harvesting DNS records for ${BOLD}$TARGET${RESET}${CYAN}...${RESET}"
    echo ""
    
    # MX Records (mail servers - useful for email spray)
    local mx=$(dig +short MX "$TARGET" 2>/dev/null | sort)
    if [[ -n "$mx" ]]; then
        echo -e "  ${YELLOW}📧 MX Records:${RESET}"
        echo "$mx" | while read -r line; do
            local priority=$(echo "$line" | awk '{print $1}')
            local server=$(echo "$line" | awk '{print $2}' | sed 's/\.$//')
            echo -e "    ${DIM}$priority${RESET} $server" >> "$mx_file"
            echo -e "    ${DIM}$priority${RESET} $server"
        done
        echo ""
    fi
    
    # SPF, DMARC, DKIM records
    local spf=$(dig +short TXT "$TARGET" 2>/dev/null | grep -i "v=spf1")
    if [[ -n "$spf" ]]; then
        echo -e "  ${GREEN}✓ SPF:${RESET} $spf" | head -c 100
        echo "" >> "$spf_file"
        echo "$spf" >> "$spf_file"
    fi
    
    local dmarc=$(dig +short TXT "_dmarc.$TARGET" 2>/dev/null | grep -i "v=DMARC1")
    if [[ -n "$dmarc" ]]; then
        echo -e "  ${GREEN}✓ DMARC:${RESET} $dmarc" | head -c 100
        echo ""
    fi
    
    # NS Records (nameservers - infrastructure info)
    local ns=$(dig +short NS "$TARGET" 2>/dev/null)
    if [[ -n "$ns" ]]; then
        echo -e "  ${CYAN}🔗 Nameservers:${RESET}"
        echo "$ns" | while read -r server; do
            echo -e "    → $server"
            echo "$server" >> "$dns_file"
        done
        echo ""
    fi
    
    log "SUCCESS" "DNS harvesting complete"
}

#═══════════════════════════════════════════════════════════════════════════════
# 🎯 REVERSE DNS & ASN MAPPING: Infrastructure Discovery
#═══════════════════════════════════════════════════════════════════════════════

map_infrastructure() {
    echo ""
    echo -e "${CYAN}┌─────────────────────────────────────────────────────────────────────────────┐${RESET}"
    echo -e "${CYAN}│${RESET}  🌐 ${BOLD}INFRASTRUCTURE MAPPING${RESET} - ASN, IP ranges, hosting provider"
    echo -e "${CYAN}└─────────────────────────────────────────────────────────────────────────────┘${RESET}"
    
    local live_file="$OUTPUT_DIR/01-subdomains/subdomains_live.txt"
    local infra_file="$OUTPUT_DIR/02-hosts/infrastructure_map.txt"
    
    > "$infra_file"
    
    if [[ ! -f "$live_file" ]] || [[ ! -s "$live_file" ]]; then
        return
    fi
    
    echo ""
    echo -e "  ${DIM}Mapping infrastructure (IPs, ASNs, providers)...${RESET}"
    echo ""
    
    # Extract unique IPs
    declare -A ip_map
    declare -A asn_map
    
    while IFS= read -r host; do
        [[ -z "$host" ]] && continue
        
        # Get IP via DNS
        local ip=$(dig +short A "$host" 2>/dev/null | head -1)
        
        if [[ -n "$ip" ]]; then
            ip_map["$ip"]="$host"
            
            # Use whois to get ASN/provider (if available)
            if command -v whois &>/dev/null; then
                local asn=$(whois "$ip" 2>/dev/null | grep -i "asn\|^AS" | head -1 | awk '{print $NF}')
                [[ -n "$asn" ]] && asn_map["$asn"]="$ip"
            fi
            
            printf "  ${GREEN}✓${RESET} %-30s → %-15s\n" "$host" "$ip" >> "$infra_file"
        fi
    done < "$live_file"
    
    # Summary
    local unique_ips=${#ip_map[@]}
    local unique_asns=${#asn_map[@]}
    
    echo -e "  ${CYAN}Found:${RESET} $unique_ips unique IPs, $unique_asns ASNs"
    log "SUCCESS" "Infrastructure mapping complete"
}

#═══════════════════════════════════════════════════════════════════════════════
# 🎯 OPEN REDIRECT HUNTING: Finding redirect vulnerabilities
#═══════════════════════════════════════════════════════════════════════════════

hunt_open_redirects() {
    echo ""
    echo -e "${YELLOW}┌─────────────────────────────────────────────────────────────────────────────┐${RESET}"
    echo -e "${YELLOW}│${RESET}  🔄 ${BOLD}OPEN REDIRECT HUNTING${RESET} - Common redirect parameters"
    echo -e "${YELLOW}└─────────────────────────────────────────────────────────────────────────────┘${RESET}"
    
    local urls_file="$OUTPUT_DIR/05-parameters/urls_live.txt"
    local redirect_file="$OUTPUT_DIR/02-hosts/open_redirects.txt"
    
    > "$redirect_file"
    
    [[ ! -f "$urls_file" ]] && return
    [[ ! -s "$urls_file" ]] && return
    
    # Common redirect parameters
    local redirect_params=("redirect" "url" "uri" "return" "goto" "next" "forward" "continue" "redir" "ref" "back")
    
    echo ""
    echo -e "  ${DIM}Testing common redirect parameters...${RESET}"
    echo ""
    
    local found=0
    local tested=0
    
    head -50 "$urls_file" | while read -r url; do
        [[ -z "$url" ]] && continue
        ((tested++))
        
        for param in "${redirect_params[@]}"; do
            # Test with external domain
            local test_url="${url}?${param}=https://evil.com"
            local response=$(curl -sS -w "\n%{http_code}" -L --max-redirs 0 "$test_url" 2>/dev/null)
            local status=$(echo "$response" | tail -1)
            
            # 301/302/303/307 indicates redirect
            if [[ "$status" =~ ^30[1237]$ ]]; then
                echo -e "  ${YELLOW}⚠️  REDIRECT:${RESET} $url?${param}=<external> [$status]"
                echo "$url|$param|$status" >> "$redirect_file"
                ((found++))
            fi
        done
    done
    
    if [[ $found -gt 0 ]]; then
        log "WARN" "Found $found potential open redirect endpoints"
    else
        echo -e "  ${GREEN}✓${RESET} No obvious open redirects detected (tested $tested URLs)"
    fi
}

# Run all intelligent recon
run_intelligent_recon() {
    echo ""
    echo -e "${RED}═══════════════════════════════════════════════════════════════════════════════${RESET}"
    echo -e "${RED}${BOLD}                   🔥 SECURITY RECONNAISSANCE                                  ${RESET}"
    echo -e "${RED}═══════════════════════════════════════════════════════════════════════════════${RESET}"
    echo -e "${DIM}  💡 Press Ctrl+C to skip current check${RESET}"
    
    echo ""
    echo -e "${CYAN}┌─────────────────────────────────────────────────────────────────────────────┐${RESET}"
    echo -e "${CYAN}│${RESET} ${BOLD}ADVANCED BUG HUNTER RECON:${RESET}"
    echo -e "${CYAN}├─────────────────────────────────────────────────────────────────────────────┤${RESET}"
    echo -e "${CYAN}│${RESET} ${RED}1)${RESET} 🔓 Sensitive Files       - .env, .git, credentials, configs    (~2 min)"
    echo -e "${CYAN}│${RESET} ${YELLOW}2)${RESET} 🔍 DNS Harvesting       - MX, SPF, DMARC, NS records        (~1 min)"
    echo -e "${CYAN}│${RESET} ${GREEN}3)${RESET} 🌐 Infrastructure Map   - ASN, IP ranges, providers         (~2 min)"
    echo -e "${CYAN}│${RESET} ${BLUE}4)${RESET} 🔄 Open Redirects      - Redirect parameter testing        (~2 min)"
    echo -e "${CYAN}├─────────────────────────────────────────────────────────────────────────────┤${RESET}"
    echo -e "${CYAN}│${RESET} ${CYAN}5)${RESET} 🔒 Security Headers    - HTTP security header audit        (~2 min)"
    echo -e "${CYAN}│${RESET} ${MAGENTA}6)${RESET} 🛡️  WAF Detection       - Identify firewalls & protections (~2 min)"
    echo -e "${CYAN}│${RESET} ${WHITE}7)${RESET} 🚨 Subdomain Takeover  - Find dangling DNS records        (~2 min)"
    echo -e "${CYAN}└─────────────────────────────────────────────────────────────────────────────┘${RESET}"
    echo ""
    
    local run_sensitive=false run_dns=false run_infra=false run_redirect=false
    local run_headers=false run_waf=false run_takeover=false
    
    # Default: Run all hunter recon
    run_sensitive=true; run_dns=true; run_infra=true; run_redirect=true
    run_headers=true; run_waf=true; run_takeover=true
    
    echo -e "  ${GREEN}🚀 Running full bug hunter reconnaissance suite...${RESET}"
    echo ""
    
    # Run new smart recon functions
    [[ "$run_sensitive" == true ]] && hunt_sensitive_files
    [[ "$run_dns" == true ]] && harvest_dns_records
    [[ "$run_infra" == true ]] && map_infrastructure
    [[ "$run_redirect" == true ]] && hunt_open_redirects
    
    # Run legacy security checks
    [[ "$run_headers" == true ]] && check_security_headers_scored
    [[ "$run_waf" == true ]] && detect_waf_multilayer
    [[ "$run_takeover" == true ]] && check_subdomain_takeover    
    enable_phase_skip "Advanced Bug Hunter Recon"
    
    # Run all hunter functions
    ! should_skip_phase && hunt_sensitive_files
    ! should_skip_phase && harvest_dns_records
    ! should_skip_phase && map_infrastructure
    ! should_skip_phase && hunt_open_redirects
    
    disable_phase_skip
    
    echo ""
    echo -e "${GREEN}═══════════════════════════════════════════════════════════════════════════════${RESET}"
    echo -e "${GREEN}${BOLD}                 ✅ ADVANCED RECONNAISSANCE COMPLETE                        ${RESET}"
    echo -e "${GREEN}═══════════════════════════════════════════════════════════════════════════════${RESET}"
}

# Subdomain takeover with validation
check_subdomain_takeover_enhanced() {
    echo ""
    echo -e "${RED}┌─────────────────────────────────────────────────────────────────────────────┐${RESET}"
    echo -e "${RED}│${RESET} 🚨 ${BOLD}SUBDOMAIN TAKEOVER DETECTION${RESET}"
    echo -e "${RED}└─────────────────────────────────────────────────────────────────────────────┘${RESET}"
    
    local dead_file="$OUTPUT_DIR/01-subdomains/subdomains_dead.txt"
    local live_file="$OUTPUT_DIR/01-subdomains/subdomains_live.txt"
    local takeover_file="$OUTPUT_DIR/02-hosts/potential_takeovers.txt"
    
    > "$takeover_file"
    
    # Extended vulnerable CNAME patterns with fingerprints
    declare -A takeover_services=(
        ["amazonaws.com"]="NoSuchBucket|The specified bucket does not exist"
        ["cloudfront.net"]="The request could not be satisfied|Bad request"
        ["herokuapp.com"]="No such app|there is no app configured"
        ["herokudns.com"]="No such app|there is no app configured"
        ["github.io"]="There isn't a GitHub Pages site here"
        ["bitbucket.io"]="Repository not found"
        ["ghost.io"]="The thing you were looking for is no longer here"
        ["myshopify.com"]="Sorry, this shop is currently unavailable"
        ["statuspage.io"]="Status page for.*is not configured"
        ["surge.sh"]="project not found"
        ["netlify.app"]="Not found - Request ID"
        ["vercel.app"]="The deployment could not be found"
        ["azurewebsites.net"]="Error 404 - Web app not found"
        ["blob.core.windows.net"]="The specified resource does not exist"
        ["cloudapp.azure.com"]="404 Web Site not found"
        ["trafficmanager.net"]="Profile not found"
        ["fastly.net"]="Fastly error: unknown domain"
        ["pantheonsite.io"]="Site not found"
        ["zendesk.com"]="Help Center Closed|this help desk"
        ["freshdesk.com"]="There is no helpdesk here"
        ["wordpress.com"]="doesn't exist"
        ["fly.dev"]="404 Not Found.*Fly.io"
        ["render.com"]="Not Found"
        ["webflow.io"]="The page you are looking for doesn't exist"
        ["cargo.site"]="404 Not Found"
        ["unbounce.com"]="The requested URL was not found"
        ["helpjuice.com"]="We could not find what you're looking for"
        ["helpscoutdocs.com"]="No settings were found"
        ["uservoice.com"]="This UserVoice subdomain is currently available"
        ["desk.com"]="Please try again or try Desk.com free"
        ["ngrok.io"]="Tunnel.*not found|ngrok.io not found"
        ["feedpress.me"]="The feed has not been found"
        ["readme.io"]="Project doesnt exist"
        ["launchrock.com"]="It looks like you may have taken a wrong turn"
        ["tictail.com"]="to target URL: tictail.com"
        ["smartling.com"]="Domain is not configured"
        ["pingdom.com"]="Sorry, couldn't find the status page"
        ["tilda.cc"]="Please renew your subscription"
        ["teamwork.com"]="Oops - We didn't find your site"
        ["canny.io"]="Company not found|There is no such company"
        ["proposify.com"]="If you need immediate assistance"
        ["simplebooklet.com"]="We can't find this SimpleBoolet"
        ["getresponse.com"]="With GetResponse Landing Pages"
        ["vend.com"]="Looks like you've traveled too far"
        ["aftership.com"]="Oops..</h1>|AfterShip page not found"
        ["aha.io"]="There is no portal here|Aha! | The product roadmap"
        ["instapage.com"]="You've reached a page that is unavailable"
        ["intercom.help"]="Uh oh. That page doesn't exist"
        ["acquia.com"]="Web Site not found|The site you are looking for"
    )
    
    local checked=0
    local potential=0
    local confirmed=0
    
    # Check dead subdomains
    if [[ -f "$dead_file" ]] && [[ -s "$dead_file" ]]; then
        local total=$(wc -l < "$dead_file")
        echo -e "  ${DIM}Checking $total dead subdomains for takeover...${RESET}"
        
        while IFS= read -r domain; do
            [[ -z "$domain" ]] && continue
            ((checked++))
            
            local cname=$(dig +short CNAME "$domain" 2>/dev/null | head -1 | tr -d '.')
            
            if [[ -n "$cname" ]]; then
                for pattern in "${!takeover_services[@]}"; do
                    if [[ "$cname" == *"$pattern"* ]]; then
                        local fingerprint="${takeover_services[$pattern]}"
                        local confidence="POSSIBLE"
                        
                        # Try to validate by checking response
                        local response=$(curl -sL --max-time 10 -k "http://$domain" 2>/dev/null | head -c 5000)
                        
                        if [[ -n "$fingerprint" ]] && echo "$response" | grep -qiE "$fingerprint"; then
                            confidence="CONFIRMED"
                            ((confirmed++))
                            echo -e "  ${RED}🔥 CONFIRMED:${RESET} $domain -> ${YELLOW}$cname${RESET}"
                        else
                            echo -e "  ${YELLOW}⚠️  POSSIBLE:${RESET} $domain -> ${DIM}$cname${RESET}"
                        fi
                        
                        echo "$domain|$cname|$pattern|$confidence" >> "$takeover_file"
                        ((potential++))
                        break
                    fi
                done
            fi
        done < "$dead_file"
    fi
    
    # Check live hosts with CNAME returning errors
    if [[ -f "$live_file" ]]; then
        local live_count=$(wc -l < "$live_file")
        [[ $live_count -gt 100 ]] && live_count=100  # Limit
        
        head -100 "$live_file" | while IFS= read -r domain; do
            [[ -z "$domain" ]] && continue
            local cname=$(dig +short CNAME "$domain" 2>/dev/null | head -1 | tr -d '.')
            
            if [[ -n "$cname" ]]; then
                for pattern in "${!takeover_services[@]}"; do
                    if [[ "$cname" == *"$pattern"* ]]; then
                        local response=$(curl -s -o /dev/null -w "%{http_code}" --max-time 5 "http://$domain" 2>/dev/null)
                        if [[ "$response" == "404" ]] || [[ "$response" == "000" ]]; then
                            local body=$(curl -sL --max-time 5 "http://$domain" 2>/dev/null | head -c 2000)
                            local fingerprint="${takeover_services[$pattern]}"
                            
                            if echo "$body" | grep -qiE "$fingerprint"; then
                                echo -e "  ${RED}🔥 LIKELY:${RESET} $domain -> ${YELLOW}$cname${RESET} [${response}]"
                                echo "$domain|$cname|$pattern|LIKELY" >> "$takeover_file"
                                ((potential++))
                            fi
                        fi
                        break
                    fi
                done
            fi
        done
    fi
    
    echo ""
    if [[ $confirmed -gt 0 ]]; then
        log "CRITICAL" "🔥 CONFIRMED $confirmed subdomain takeovers! Potential: $potential total"
    elif [[ $potential -gt 0 ]]; then
        log "WARN" "Found $potential potential takeovers (manual verification needed)"
    else
        echo -e "  ${GREEN}✓${RESET} No subdomain takeover vulnerabilities detected"
    fi
}

# WAF Detection using wafw00f
detect_waf_wafw00f() {
    echo ""
    echo -e "${CYAN}┌─────────────────────────────────────────────────────────────────────────────┐${RESET}"
    echo -e "${CYAN}│${RESET} 🛡️  ${BOLD}WAF/FIREWALL DETECTION${RESET}"
    echo -e "${CYAN}└─────────────────────────────────────────────────────────────────────────────┘${RESET}"
    
    local live_file="$OUTPUT_DIR/01-subdomains/subdomains_live.txt"
    local waf_file="$OUTPUT_DIR/02-hosts/waf_detected.txt"
    local waf_report="$OUTPUT_DIR/02-hosts/waf_report.txt"
    
    > "$waf_file"
    > "$waf_report"
    
    if [[ ! -f "$live_file" ]] || [[ ! -s "$live_file" ]]; then
        log "WARN" "No live hosts for WAF detection"
        return
    fi
    
    local total=$(wc -l < "$live_file")
    echo ""
    echo -e "  ${CYAN}🔍 Scanning ${BOLD}$total${RESET}${CYAN} hosts for WAF/Firewall...${RESET}"
    echo ""
    
    # Check if wafw00f is available
    if [[ -n "$WAFW00F" ]]; then
        echo -e "  ${GREEN}✓${RESET} Using wafw00f for accurate detection"
        echo ""
        
        local current=0
        local detected=0
        
        while IFS= read -r host; do
            [[ -z "$host" ]] && continue
            should_skip_phase && break
            
            ((current++))
            printf "  ${CYAN}[%d/%d]${RESET} %s " "$current" "$total" "$host"
            
            # Run wafw00f
            local result=$($WAFW00F -a "https://$host" 2>/dev/null | grep -i "is behind" | head -1)
            
            if [[ -n "$result" ]]; then
                # Extract WAF name
                local waf_name=$(echo "$result" | grep -oP 'is behind \K[^(]+' | sed 's/^ *//;s/ *$//')
                
                if [[ -n "$waf_name" ]] && [[ "$waf_name" != "None" ]]; then
                    echo -e "→ ${YELLOW}$waf_name${RESET}"
                    echo "$host|$waf_name" >> "$waf_file"
                    ((detected++))
                else
                    echo -e "→ ${GREEN}No WAF${RESET}"
                fi
            else
                # Try fallback detection
                local headers=$(curl -sI --max-time 5 -k "https://$host" 2>/dev/null)
                local waf=""
                
                [[ "$headers" =~ [Cc]f-[Rr]ay ]] && waf="Cloudflare"
                [[ "$headers" =~ [Xx]-[Ss]ucuri ]] && waf="Sucuri"
                [[ "$headers" =~ [Xx]-[Aa]kamai ]] && waf="Akamai"
                [[ "$headers" =~ [Ii]ncapsula ]] && waf="Imperva"
                [[ "$headers" =~ [Aa][Ww][Ss] ]] && waf="AWS WAF"
                
                if [[ -n "$waf" ]]; then
                    echo -e "→ ${YELLOW}$waf${RESET} (header-based)"
                    echo "$host|$waf" >> "$waf_file"
                    ((detected++))
                else
                    echo -e "→ ${GREEN}No WAF${RESET}"
                fi
            fi
            
        done < "$live_file"
        
    else
        # Fallback: Manual header-based detection
        log "WARN" "wafw00f not installed - using basic header detection"
        echo -e "  ${YELLOW}⚠️${RESET} Install: ${DIM}pip install wafw00f${RESET}"
        echo ""
        
        local current=0
        local detected=0
        
        while IFS= read -r host; do
            [[ -z "$host" ]] && continue
            should_skip_phase && break
            
            ((current++))
            [[ "$QUIET_MODE" == false ]] && progress_bar "$current" "$total"
            
            local response=$(curl -sI --max-time 8 -k -L "https://$host" 2>/dev/null)
            local waf=""
            
            # Check common WAF signatures in headers
            [[ "$response" =~ [Cc]f-[Rr]ay|[Cc]loudflare ]] && waf="Cloudflare"
            [[ "$response" =~ [Xx]-[Ss]ucuri ]] && waf="Sucuri"
            [[ "$response" =~ [Xx]-[Aa]kamai|[Aa]kamai ]] && waf="Akamai"
            [[ "$response" =~ incap_ses|[Ii]ncapsula ]] && waf="Imperva"
            [[ "$response" =~ [Aa][Ww][Ss][Aa][Ll][Bb]|[Xx]-[Aa]mz ]] && waf="AWS"
            [[ "$response" =~ [Ff]5|[Bb][Ii][Gg][Ii][Pp] ]] && waf="F5 BIG-IP"
            [[ "$response" =~ [Bb]arracuda ]] && waf="Barracuda"
            [[ "$response" =~ [Ff]ortinet|[Ff]orti[Ww]eb ]] && waf="Fortinet"
            [[ "$response" =~ [Mm]od_security ]] && waf="ModSecurity"
            [[ "$response" =~ [Vv]arnish ]] && waf="Varnish"
            [[ "$response" =~ [Ff]astly ]] && waf="Fastly"
            
            if [[ -n "$waf" ]]; then
                echo "$host|$waf" >> "$waf_file"
                ((detected++))
            fi
            
        done < "$live_file"
        echo ""
    fi
    
    # Generate report
    echo "# WAF Detection Report" > "$waf_report"
    echo "# Generated: $(date)" >> "$waf_report"
    echo "" >> "$waf_report"
    
    if [[ -s "$waf_file" ]]; then
        echo "## Detected Firewalls:" >> "$waf_report"
        echo "" >> "$waf_report"
        
        # Count by WAF type
        declare -A waf_count
        while IFS='|' read -r host waf; do
            ((waf_count["$waf"]++))
        done < "$waf_file"
        
        echo ""
        echo -e "  ${BOLD}WAF Summary:${RESET}"
        for waf in "${!waf_count[@]}"; do
            printf "    ${YELLOW}%-20s${RESET} ${DIM}%d hosts${RESET}\n" "$waf" "${waf_count[$waf]}"
            echo "  $waf: ${waf_count[$waf]} hosts" >> "$waf_report"
        done
        
        local detected=$(wc -l < "$waf_file")
        local unprotected=$((total - detected))
        
        echo ""
        log "SUCCESS" "WAF detected on $detected hosts, $unprotected unprotected"
        
        echo "" >> "$waf_report"
        echo "## Unprotected Hosts:" >> "$waf_report"
        comm -23 <(sort "$live_file") <(cut -d'|' -f1 "$waf_file" | sort) >> "$waf_report"
        
    else
        echo -e "  ${GREEN}✓${RESET} No WAF detected on any hosts"
        echo "No WAF detected" >> "$waf_report"
    fi
}

# Multi-layer WAF detection (legacy fallback)
detect_waf_multilayer() {
    echo ""
    echo -e "${CYAN}┌─────────────────────────────────────────────────────────────────────────────┐${RESET}"
    echo -e "${CYAN}│${RESET} 🛡️  ${BOLD}MULTI-LAYER WAF/CDN DETECTION${RESET}"
    echo -e "${CYAN}└─────────────────────────────────────────────────────────────────────────────┘${RESET}"
    
    local priority_file="$OUTPUT_DIR/02-hosts/hosts_by_priority.txt"
    local waf_file="$OUTPUT_DIR/02-hosts/waf_detected.txt"
    local waf_report="$OUTPUT_DIR/02-hosts/waf_report.txt"
    
    > "$waf_file"
    > "$waf_report"
    
    if [[ ! -f "$priority_file" ]]; then
        return
    fi
    
    # WAF signature database
    declare -A waf_headers=(
        ["Cloudflare"]="cf-ray|cf-cache-status|cf-request-id"
        ["AWS_WAF"]="x-amzn-requestid|x-amzn-trace-id"
        ["CloudFront"]="x-amz-cf-id|x-amz-cf-pop|via.*cloudfront"
        ["Akamai"]="x-akamai|akamai-grn|akamaighost"
        ["Imperva"]="x-cdn:.*incapsula|x-iinfo"
        ["Sucuri"]="x-sucuri|sucuri-id|x-sucuri-cache"
        ["F5_BIGIP"]="x-wa-info|bigip|f5-ltm|x-cnection"
        ["ModSecurity"]="mod_security|NOYB"
        ["Barracuda"]="barra_counter|barracuda"
        ["Fortinet"]="fortigate|fortiweb|fortinetb"
        ["Citrix"]="ns_af|citrix|netscaler"
        ["Fastly"]="x-served-by.*cache|fastly-|x-fastly"
        ["StackPath"]="x-sp-|stackpath"
        ["KeyCDN"]="x-edge-location|x-shield|keycdn"
        ["DDoS-Guard"]="ddos-guard|__ddg"
        ["Varnish"]="x-varnish|via.*varnish"
        ["Azure_WAF"]="x-azure|x-ms-|azure"
        ["GCP_Armor"]="x-goog|x-gfe|google-cloud"
        ["Radware"]="rdwr|x-rp-|radware"
        ["Wallarm"]="x-wallarm|wallarm"
    )
    
    declare -A waf_cookies=(
        ["Cloudflare"]="__cfduid|__cf_bm|cf_clearance"
        ["Imperva"]="incap_ses|visid_incap|nlbi_"
        ["Barracuda"]="barra_counter_session"
        ["F5_BIGIP"]="BIGipServer|TS0|F5_ST|MRHSession"
        ["Citrix"]="citrix_ns_id|NSC_"
        ["AWS"]="AWSALB|AWSALBCORS"
    )
    
    declare -A waf_body_patterns=(
        ["Cloudflare"]="Checking your browser|cf-browser-verification|cloudflare"
        ["Imperva"]="incapsula incident|_incap_|imperva"
        ["Sucuri"]="sucuri website firewall|cloudproxy"
        ["ModSecurity"]="mod_security|this error was generated by mod_security"
        ["Akamai"]="access denied.*akamai|reference.*error"
        ["F5_BIGIP"]="blocked by website|request rejected.*f5"
    )
    
    local checked=0
    local max_check=15
    
    echo -e "  ${DIM}Running multi-layer WAF detection...${RESET}"
    echo ""
    
    while IFS='|' read -r url score tech status title server; do
        [[ -z "$url" ]] && continue
        ((checked++))
        [[ $checked -gt $max_check ]] && break
        
        local host=$(echo "$url" | sed -E 's|^https?://||' | cut -d'/' -f1)
        local detected_wafs=()
        local confidence=0
        local evidence=()
        
        # Layer 1: Header Analysis (passive)
        local headers=$(curl -sI --max-time 10 -k "$url" 2>/dev/null)
        local cookies=$(echo "$headers" | grep -i "set-cookie" || true)
        
        for waf in "${!waf_headers[@]}"; do
            if echo "$headers" | grep -qiE "${waf_headers[$waf]}"; then
                detected_wafs+=("$waf")
                evidence+=("Header match: ${waf_headers[$waf]}")
                ((confidence+=40))
            fi
        done
        
        # Layer 2: Cookie Analysis
        for waf in "${!waf_cookies[@]}"; do
            if echo "$cookies" | grep -qiE "${waf_cookies[$waf]}"; then
                if [[ ! " ${detected_wafs[*]} " =~ " $waf " ]]; then
                    detected_wafs+=("$waf")
                fi
                evidence+=("Cookie: ${waf_cookies[$waf]}")
                ((confidence+=30))
            fi
        done
        
        # Layer 3: Active Testing (light intrusive)
        local test_response=$(curl -s --max-time 10 -k \
            -A "Mozilla/5.0" \
            "$url/?test=<script>alert(1)</script>&id=1%27%20OR%20%271%27=%271" 2>/dev/null | head -c 5000)
        
        for waf in "${!waf_body_patterns[@]}"; do
            if echo "$test_response" | grep -qiE "${waf_body_patterns[$waf]}"; then
                if [[ ! " ${detected_wafs[*]} " =~ " $waf " ]]; then
                    detected_wafs+=("$waf")
                fi
                evidence+=("Block page detected")
                ((confidence+=30))
            fi
        done
        
        # Layer 4: Server header check
        local server_header=$(echo "$headers" | grep -i "^server:" | head -1)
        if echo "$server_header" | grep -qi "cloudflare"; then
            [[ ! " ${detected_wafs[*]} " =~ " Cloudflare " ]] && detected_wafs+=("Cloudflare")
            ((confidence+=20))
        elif echo "$server_header" | grep -qi "akamai"; then
            [[ ! " ${detected_wafs[*]} " =~ " Akamai " ]] && detected_wafs+=("Akamai")
            ((confidence+=20))
        fi
        
        # Calculate final confidence
        [[ $confidence -gt 100 ]] && confidence=100
        
        # Output
        if [[ ${#detected_wafs[@]} -gt 0 ]]; then
            local waf_list=$(IFS=', '; echo "${detected_wafs[*]}")
            local conf_level="LOW"
            [[ $confidence -ge 50 ]] && conf_level="MEDIUM"
            [[ $confidence -ge 75 ]] && conf_level="HIGH"
            
            echo -e "  ${YELLOW}🛡️${RESET}  $host"
            echo -e "      ${BOLD}WAF:${RESET} ${YELLOW}$waf_list${RESET} [Confidence: ${confidence}% - $conf_level]"
            echo "$host|$waf_list|$confidence|$conf_level" >> "$waf_file"
            
            {
                echo "=== $host ==="
                echo "WAF Detected: $waf_list"
                echo "Confidence: $confidence%"
                echo "Evidence:"
                for e in "${evidence[@]}"; do
                    echo "  - $e"
                done
                echo ""
            } >> "$waf_report"
        else
            echo -e "  ${GREEN}✓${RESET}  $host - No WAF detected ${DIM}(or stealthy/custom WAF)${RESET}"
        fi
        
    done < "$priority_file"
    
    local waf_count=$(wc -l < "$waf_file" 2>/dev/null || echo 0)
    echo ""
    log "INFO" "WAF detection complete: $waf_count/$checked hosts have detectable WAF"
}

# Security headers with scoring
check_security_headers_scored() {
    echo ""
    echo -e "${YELLOW}┌─────────────────────────────────────────────────────────────────────────────┐${RESET}"
    echo -e "${YELLOW}│${RESET} 🔒 ${BOLD}SECURITY HEADERS ANALYSIS${RESET} (with scoring)"
    echo -e "${YELLOW}└─────────────────────────────────────────────────────────────────────────────┘${RESET}"
    
    local priority_file="$OUTPUT_DIR/02-hosts/hosts_by_priority.txt"
    local headers_report="$OUTPUT_DIR/02-hosts/security_headers_report.txt"
    local missing_file="$OUTPUT_DIR/02-hosts/missing_headers.txt"
    
    > "$headers_report"
    > "$missing_file"
    
    if [[ ! -f "$priority_file" ]]; then
        return
    fi
    
    local checked=0
    local max_check=10
    local total_score=0
    
    echo -e "  ${DIM}Analyzing security headers with scoring...${RESET}"
    echo ""
    
    while IFS='|' read -r url score tech status title server; do
        [[ -z "$url" ]] && continue
        ((checked++))
        [[ $checked -gt $max_check ]] && break
        
        local host=$(echo "$url" | sed -E 's|^https?://||' | cut -d'/' -f1)
        local headers=$(curl -sI --max-time 10 -k "$url" 2>/dev/null)
        
        local host_score=0
        local issues=()
        local present=()
        
        # HSTS (15 points max)
        local hsts=$(echo "$headers" | grep -i "Strict-Transport-Security" | head -1)
        if [[ -n "$hsts" ]]; then
            host_score=$((host_score + 10))
            present+=("HSTS")
            if echo "$hsts" | grep -qi "includeSubDomains"; then
                host_score=$((host_score + 3))
            fi
            if echo "$hsts" | grep -qi "preload"; then
                host_score=$((host_score + 2))
            fi
        else
            issues+=("[CRITICAL] Missing HSTS")
        fi
        
        # CSP (20 points max)
        local csp=$(echo "$headers" | grep -i "Content-Security-Policy" | head -1)
        if [[ -n "$csp" ]]; then
            if echo "$csp" | grep -qi "unsafe-inline"; then
                host_score=$((host_score + 5))
                issues+=("[HIGH] CSP allows unsafe-inline")
            elif echo "$csp" | grep -qi "unsafe-eval"; then
                host_score=$((host_score + 8))
                issues+=("[MEDIUM] CSP allows unsafe-eval")
            else
                host_score=$((host_score + 20))
            fi
            present+=("CSP")
        else
            issues+=("[HIGH] Missing Content-Security-Policy")
        fi
        
        # X-Frame-Options (15 points)
        local xfo=$(echo "$headers" | grep -i "X-Frame-Options" | head -1)
        local csp_fa=$(echo "$csp" | grep -i "frame-ancestors")
        if [[ -n "$xfo" ]] || [[ -n "$csp_fa" ]]; then
            host_score=$((host_score + 15))
            present+=("Clickjacking Protection")
        else
            issues+=("[MEDIUM] Missing X-Frame-Options")
        fi
        
        # X-Content-Type-Options (10 points)
        if echo "$headers" | grep -qi "X-Content-Type-Options.*nosniff"; then
            host_score=$((host_score + 10))
            present+=("X-Content-Type-Options")
        else
            issues+=("[LOW] Missing X-Content-Type-Options")
        fi
        
        # Referrer-Policy (10 points)
        local referrer=$(echo "$headers" | grep -i "Referrer-Policy" | head -1)
        if [[ -n "$referrer" ]]; then
            host_score=$((host_score + 10))
            present+=("Referrer-Policy")
        else
            issues+=("[LOW] Missing Referrer-Policy")
        fi
        
        # Permissions-Policy (10 points)
        local perms=$(echo "$headers" | grep -i "Permissions-Policy\|Feature-Policy" | head -1)
        if [[ -n "$perms" ]]; then
            host_score=$((host_score + 10))
            present+=("Permissions-Policy")
        else
            issues+=("[LOW] Missing Permissions-Policy")
        fi
        
        # Cross-Origin policies (10 points)
        local coop=$(echo "$headers" | grep -i "Cross-Origin-Opener-Policy")
        local coep=$(echo "$headers" | grep -i "Cross-Origin-Embedder-Policy")
        if [[ -n "$coop" ]] || [[ -n "$coep" ]]; then
            host_score=$((host_score + 10))
            present+=("Cross-Origin Policies")
        fi
        
        # Calculate grade
        local grade="F"
        [[ $host_score -ge 90 ]] && grade="A+"
        [[ $host_score -ge 80 ]] && [[ $host_score -lt 90 ]] && grade="A"
        [[ $host_score -ge 70 ]] && [[ $host_score -lt 80 ]] && grade="B"
        [[ $host_score -ge 60 ]] && [[ $host_score -lt 70 ]] && grade="C"
        [[ $host_score -ge 50 ]] && [[ $host_score -lt 60 ]] && grade="D"
        
        total_score=$((total_score + host_score))
        
        # Color based on grade
        local grade_color="$RED"
        [[ "$grade" == "A+" ]] || [[ "$grade" == "A" ]] && grade_color="$GREEN"
        [[ "$grade" == "B" ]] && grade_color="$YELLOW"
        [[ "$grade" == "C" ]] && grade_color="$YELLOW"
        
        echo -e "  ${BOLD}$host${RESET}"
        echo -e "      Score: ${grade_color}${BOLD}$host_score/100${RESET} (Grade: ${grade_color}${BOLD}$grade${RESET})"
        
        if [[ ${#issues[@]} -gt 0 ]]; then
            local critical_count=$(echo "${issues[*]}" | grep -c "CRITICAL" || true)
            local high_count=$(echo "${issues[*]}" | grep -c "HIGH" || true)
            echo -e "      Issues: ${RED}$critical_count critical${RESET}, ${YELLOW}$high_count high${RESET}"
        fi
        echo ""
        
        # Write to report
        {
            echo "=== $host ==="
            echo "Score: $host_score/100 (Grade: $grade)"
            echo ""
            echo "Present Headers:"
            for p in "${present[@]}"; do
                echo "  ✓ $p"
            done
            echo ""
            echo "Issues:"
            for i in "${issues[@]}"; do
                echo "  ✗ $i"
            done
            echo ""
            echo "---"
            echo ""
        } >> "$headers_report"
        
        # Track missing headers
        for i in "${issues[@]}"; do
            echo "$host|$i" >> "$missing_file"
        done
        
    done < "$priority_file"
    
    local avg_score=$((total_score / checked))
    echo ""
    log "INFO" "Average security score: $avg_score/100 across $checked hosts"
}

# SSL/TLS Security Analysis
analyze_ssl_security() {
    echo ""
    echo -e "${GREEN}┌─────────────────────────────────────────────────────────────────────────────┐${RESET}"
    echo -e "${GREEN}│${RESET} 🔐 ${BOLD}SSL/TLS SECURITY ANALYSIS${RESET}"
    echo -e "${GREEN}└─────────────────────────────────────────────────────────────────────────────┘${RESET}"
    
    local priority_file="$OUTPUT_DIR/02-hosts/hosts_by_priority.txt"
    local ssl_report="$OUTPUT_DIR/02-hosts/ssl_analysis.txt"
    
    > "$ssl_report"
    
    if [[ ! -f "$priority_file" ]]; then
        return
    fi
    
    local checked=0
    local max_check=10
    
    echo -e "  ${DIM}Analyzing SSL/TLS configuration...${RESET}"
    echo ""
    
    while IFS='|' read -r url score tech status title server; do
        [[ -z "$url" ]] && continue
        [[ ! "$url" =~ ^https ]] && continue
        ((checked++))
        [[ $checked -gt $max_check ]] && break
        
        local host=$(echo "$url" | sed -E 's|^https?://||' | cut -d'/' -f1)
        local issues=()
        local grade="A"
        
        # Get certificate info
        local cert_info=$(echo | timeout 10 openssl s_client -servername "$host" -connect "$host:443" 2>/dev/null)
        local cert_dates=$(echo "$cert_info" | openssl x509 -noout -dates 2>/dev/null)
        local cert_issuer=$(echo "$cert_info" | openssl x509 -noout -issuer 2>/dev/null | sed 's/issuer=//')
        
        # Check expiry
        local expiry=$(echo "$cert_dates" | grep "notAfter" | cut -d'=' -f2)
        if [[ -n "$expiry" ]]; then
            local expiry_epoch=$(date -d "$expiry" +%s 2>/dev/null || echo 0)
            local now_epoch=$(date +%s)
            local days_left=$(( (expiry_epoch - now_epoch) / 86400 ))
            
            if [[ $days_left -lt 0 ]]; then
                issues+=("[CRITICAL] Certificate EXPIRED")
                grade="F"
            elif [[ $days_left -lt 30 ]]; then
                issues+=("[HIGH] Certificate expires in $days_left days")
                [[ "$grade" == "A" ]] && grade="B"
            elif [[ $days_left -lt 90 ]]; then
                issues+=("[MEDIUM] Certificate expires in $days_left days")
            fi
        fi
        
        # Check for weak protocols
        local tls10=$(echo | timeout 5 openssl s_client -tls1 -connect "$host:443" 2>&1)
        local tls11=$(echo | timeout 5 openssl s_client -tls1_1 -connect "$host:443" 2>&1)
        
        if echo "$tls10" | grep -q "CONNECTED"; then
            issues+=("[MEDIUM] TLS 1.0 supported (deprecated)")
            [[ "$grade" == "A" ]] && grade="B"
        fi
        
        if echo "$tls11" | grep -q "CONNECTED"; then
            issues+=("[LOW] TLS 1.1 supported (deprecated)")
        fi
        
        # Self-signed check
        if echo "$cert_issuer" | grep -qi "self-signed\|$host"; then
            issues+=("[MEDIUM] Self-signed certificate")
            [[ "$grade" == "A" ]] && grade="B"
        fi
        
        # Output
        local grade_color="$GREEN"
        [[ "$grade" == "B" ]] && grade_color="$YELLOW"
        [[ "$grade" == "C" ]] || [[ "$grade" == "D" ]] && grade_color="$YELLOW"
        [[ "$grade" == "F" ]] && grade_color="$RED"
        
        echo -e "  ${BOLD}$host${RESET}"
        echo -e "      Grade: ${grade_color}${BOLD}$grade${RESET}"
        
        if [[ ${#issues[@]} -gt 0 ]]; then
            for issue in "${issues[@]}"; do
                if [[ "$issue" == *"CRITICAL"* ]]; then
                    echo -e "      ${RED}$issue${RESET}"
                elif [[ "$issue" == *"HIGH"* ]]; then
                    echo -e "      ${YELLOW}$issue${RESET}"
                else
                    echo -e "      ${DIM}$issue${RESET}"
                fi
            done
        else
            echo -e "      ${GREEN}✓ No significant issues${RESET}"
        fi
        echo ""
        
        # Write to report
        {
            echo "=== $host ==="
            echo "SSL Grade: $grade"
            echo "Issuer: $cert_issuer"
            [[ -n "$expiry" ]] && echo "Expires: $expiry ($days_left days)"
            echo "Issues:"
            for i in "${issues[@]}"; do
                echo "  - $i"
            done
            echo ""
        } >> "$ssl_report"
        
    done < "$priority_file"
    
    echo ""
    log "INFO" "SSL/TLS analysis complete for $checked hosts"
}

# Technology detection
detect_technology_enhanced() {
    echo ""
    echo -e "${PURPLE}┌─────────────────────────────────────────────────────────────────────────────┐${RESET}"
    echo -e "${PURPLE}│${RESET} ⚙️  ${BOLD}TECHNOLOGY FINGERPRINTING${RESET}"
    echo -e "${PURPLE}└─────────────────────────────────────────────────────────────────────────────┘${RESET}"
    
    local priority_file="$OUTPUT_DIR/02-hosts/hosts_by_priority.txt"
    local tech_file="$OUTPUT_DIR/06-technologies/tech_stack.txt"
    
    mkdir -p "$OUTPUT_DIR/06-technologies"
    > "$tech_file"
    
    if [[ ! -f "$priority_file" ]]; then
        return
    fi
    
    local checked=0
    local max_check=10
    
    echo -e "  ${DIM}Performing deep technology fingerprinting...${RESET}"
    echo ""
    
    while IFS='|' read -r url score tech status title server; do
        [[ -z "$url" ]] && continue
        ((checked++))
        [[ $checked -gt $max_check ]] && break
        
        local host=$(echo "$url" | sed -E 's|^https?://||' | cut -d'/' -f1)
        local detected=()
        local versions=()
        
        # Get response with headers and body
        local response=$(curl -sL --max-time 15 -k -D - "$url" 2>/dev/null | head -c 50000)
        local headers=$(echo "$response" | sed -n '1,/^\r$/p')
        local body=$(echo "$response" | sed '1,/^\r$/d')
        
        # Server header
        local server_h=$(echo "$headers" | grep -i "^server:" | head -1 | cut -d: -f2 | tr -d ' \r')
        [[ -n "$server_h" ]] && detected+=("Server: $server_h")
        
        # X-Powered-By
        local powered=$(echo "$headers" | grep -i "^x-powered-by:" | head -1 | cut -d: -f2 | tr -d ' \r')
        [[ -n "$powered" ]] && detected+=("Powered-By: $powered")
        
        # CMS Detection
        if echo "$body" | grep -qi "wp-content\|wp-includes\|wordpress"; then
            detected+=("CMS: WordPress")
            local wp_ver=$(echo "$body" | grep -oE 'content="WordPress [0-9.]+' | head -1 | grep -oE '[0-9.]+')
            [[ -n "$wp_ver" ]] && versions+=("WordPress $wp_ver")
        fi
        
        if echo "$body" | grep -qi "drupal\|sites/default"; then
            detected+=("CMS: Drupal")
        fi
        
        if echo "$body" | grep -qi "joomla"; then
            detected+=("CMS: Joomla")
        fi
        
        # Frontend Frameworks
        if echo "$body" | grep -qi "react\|reactdom\|__REACT_DEVTOOLS"; then
            detected+=("Frontend: React")
        fi
        
        if echo "$body" | grep -qi "__NEXT_DATA__\|_next/static"; then
            detected+=("Frontend: Next.js")
        fi
        
        if echo "$body" | grep -qi "__NUXT__\|_nuxt/"; then
            detected+=("Frontend: Nuxt.js")
        fi
        
        if echo "$body" | grep -qi "ng-app\|ng-controller\|angular"; then
            detected+=("Frontend: Angular")
        fi
        
        if echo "$body" | grep -qi "vue\|v-cloak\|v-bind"; then
            detected+=("Frontend: Vue.js")
        fi
        
        # JavaScript Libraries
        if echo "$body" | grep -qi "jquery"; then
            local jq_ver=$(echo "$body" | grep -oE 'jquery[^"]*\.js\?ver=[0-9.]+|jquery-[0-9.]+' | head -1 | grep -oE '[0-9]+\.[0-9.]+')
            detected+=("Library: jQuery${jq_ver:+ ($jq_ver)}")
        fi
        
        if echo "$body" | grep -qi "bootstrap"; then
            detected+=("Library: Bootstrap")
        fi
        
        # Backend hints
        if echo "$headers" | grep -qi "php\|PHPSESSID"; then
            detected+=("Language: PHP")
        fi
        
        if echo "$headers" | grep -qi "asp.net\|__VIEWSTATE"; then
            detected+=("Language: ASP.NET")
        fi
        
        if echo "$headers" | grep -qi "x-runtime\|x-rack\|ruby"; then
            detected+=("Language: Ruby")
        fi
        
        # Analytics
        if echo "$body" | grep -qi "google-analytics\|gtag\|ga.js\|googletagmanager"; then
            detected+=("Analytics: Google Analytics")
        fi
        
        if echo "$body" | grep -qi "fbevents\|facebook.*pixel"; then
            detected+=("Analytics: Facebook Pixel")
        fi
        
        # E-commerce
        if echo "$body" | grep -qi "woocommerce"; then
            detected+=("E-commerce: WooCommerce")
        fi
        
        if echo "$body" | grep -qi "shopify"; then
            detected+=("E-commerce: Shopify")
        fi
        
        # Output
        echo -e "  ${BOLD}$host${RESET}"
        if [[ ${#detected[@]} -gt 0 ]]; then
            for t in "${detected[@]}"; do
                echo -e "      ${CYAN}→${RESET} $t"
            done
        else
            echo -e "      ${DIM}No specific technologies detected${RESET}"
        fi
        echo ""
        
        # Write to file
        {
            echo "=== $host ==="
            for t in "${detected[@]}"; do
                echo "  $t"
            done
            echo ""
        } >> "$tech_file"
        
    done < "$priority_file"
    
    echo ""
    log "INFO" "Technology fingerprinting complete for $checked hosts"
}

# Generate comprehensive security assessment
generate_security_assessment() {
    local report_file="$OUTPUT_DIR/SECURITY_ASSESSMENT.txt"
    
    local takeover_count=$(wc -l < "$OUTPUT_DIR/02-hosts/potential_takeovers.txt" 2>/dev/null || echo 0)
    local waf_count=$(wc -l < "$OUTPUT_DIR/02-hosts/waf_detected.txt" 2>/dev/null || echo 0)
    local cors_count=$(wc -l < "$OUTPUT_DIR/02-hosts/cors_misconfig.txt" 2>/dev/null || echo 0)
    local sensitive_count=$(wc -l < "$OUTPUT_DIR/02-hosts/sensitive_files.txt" 2>/dev/null || echo 0)
    
    cat > "$report_file" << EOF
═══════════════════════════════════════════════════════════════════════════════
                    🔒 SECURITY ASSESSMENT REPORT
═══════════════════════════════════════════════════════════════════════════════

Target: $TARGET
Generated: $(date)
Scan Mode: Advanced Security Reconnaissance

┌─────────────────────────────────────────────────────────────────────────────┐
│ EXECUTIVE SUMMARY                                                           │
└─────────────────────────────────────────────────────────────────────────────┘

CRITICAL FINDINGS:
  • Subdomain Takeovers: $takeover_count
  • CORS Misconfigurations: $cors_count
  • Sensitive Files Exposed: $sensitive_count

SECURITY POSTURE:
  • WAF/CDN Protected Hosts: $waf_count

EOF

    # Add detailed findings if they exist
    if [[ $takeover_count -gt 0 ]]; then
        echo "SUBDOMAIN TAKEOVER VULNERABILITIES:" >> "$report_file"
        echo "-----------------------------------" >> "$report_file"
        cat "$OUTPUT_DIR/02-hosts/potential_takeovers.txt" 2>/dev/null >> "$report_file"
        echo "" >> "$report_file"
    fi
    
    if [[ $cors_count -gt 0 ]]; then
        echo "CORS MISCONFIGURATIONS:" >> "$report_file"
        echo "-----------------------" >> "$report_file"
        cat "$OUTPUT_DIR/02-hosts/cors_misconfig.txt" 2>/dev/null >> "$report_file"
        echo "" >> "$report_file"
    fi
    
    if [[ -f "$OUTPUT_DIR/02-hosts/security_headers_report.txt" ]]; then
        echo "SECURITY HEADERS ANALYSIS:" >> "$report_file"
        echo "--------------------------" >> "$report_file"
        head -100 "$OUTPUT_DIR/02-hosts/security_headers_report.txt" >> "$report_file"
        echo "" >> "$report_file"
    fi
    
    cat >> "$report_file" << EOF
═══════════════════════════════════════════════════════════════════════════════
                         END OF SECURITY ASSESSMENT
═══════════════════════════════════════════════════════════════════════════════
EOF

    log "SUCCESS" "Security assessment report: $report_file"
}

#═══════════════════════════════════════════════════════════════════════════════
# PRIORITY SCORING
#═══════════════════════════════════════════════════════════════════════════════

calculate_priority_score() {
    local host="$1"
    local status="$2"
    local title="$3"
    local tech="$4"
    local server="$5"
    
    local score=50  # Base score
    
    # Subdomain keyword analysis
    [[ "$host" =~ (auth|login|sso|oauth) ]] && score=$((score + WEIGHT_AUTH))
    [[ "$host" =~ (api|rest|v1|v2|v3) ]] && score=$((score + WEIGHT_API))
    [[ "$host" =~ (admin|panel|dashboard|manage|cms) ]] && score=$((score + WEIGHT_ADMIN))
    [[ "$host" =~ (payment|checkout|pay|billing|invoice) ]] && score=$((score + WEIGHT_PAYMENT))
    [[ "$host" =~ (internal|staging|dev|test|uat|qa|demo|sandbox) ]] && score=$((score + WEIGHT_INTERNAL))
    [[ "$host" =~ graphql ]] && score=$((score + 35))
    [[ "$host" =~ (mail|webmail|smtp|imap) ]] && score=$((score + 25))
    [[ "$host" =~ (git|gitlab|github|bitbucket|svn) ]] && score=$((score + 40))
    [[ "$host" =~ (jenkins|ci|cd|build|deploy) ]] && score=$((score + 35))
    [[ "$host" =~ (jira|confluence|wiki|docs) ]] && score=$((score + 20))
    [[ "$host" =~ (elastic|kibana|grafana|prometheus) ]] && score=$((score + 30))
    [[ "$host" =~ (mongo|mysql|postgres|redis|db) ]] && score=$((score + 35))
    [[ "$host" =~ (vpn|remote|rdp|ssh) ]] && score=$((score + 30))
    [[ "$host" =~ (backup|bak|old|archive) ]] && score=$((score + 25))
    [[ "$host" =~ (upload|file|media|cdn|static|assets) ]] && score=$((score + 15))
    
    # Status code intelligence
    [[ "$status" == "403" ]] && score=$((score + 30))
    [[ "$status" == "401" ]] && score=$((score + 35))
    [[ "$status" == "200" ]] && score=$((score + 20))
    [[ "$status" == "500" ]] && score=$((score + 15))
    [[ "$status" == "502" ]] && score=$((score + 10))
    [[ "$status" == "503" ]] && score=$((score + 10))
    
    # Title analysis (case insensitive)
    local title_lower=$(echo "$title" | tr '[:upper:]' '[:lower:]')
    [[ "$title_lower" =~ (login|signin|sign.in|log.in) ]] && score=$((score + 30))
    [[ "$title_lower" =~ (dashboard|admin|control.panel) ]] && score=$((score + 35))
    [[ "$title_lower" =~ (swagger|api.doc|graphql) ]] && score=$((score + 30))
    [[ "$title_lower" =~ (jenkins|gitlab|jira) ]] && score=$((score + 25))
    [[ "$title_lower" =~ (404|not.found|error|forbidden) ]] && score=$((score - 20))
    [[ "$title_lower" =~ (coming.soon|under.construction|maintenance) ]] && score=$((score - 15))
    
    # Technology detection
    local tech_lower=$(echo "$tech" | tr '[:upper:]' '[:lower:]')
    [[ "$tech_lower" =~ (laravel|symfony|django|rails|spring) ]] && score=$((score + 25))
    [[ "$tech_lower" =~ (react|vue|angular|next|nuxt) ]] && score=$((score + 15))
    [[ "$tech_lower" =~ wordpress ]] && score=$((score + 10))
    [[ "$tech_lower" =~ graphql ]] && score=$((score + 30))
    [[ "$tech_lower" =~ (express|fastapi|flask|gin) ]] && score=$((score + 20))
    [[ "$tech_lower" =~ (tomcat|jboss|weblogic) ]] && score=$((score + 25))
    
    # Server/CDN analysis
    local server_lower=$(echo "$server" | tr '[:upper:]' '[:lower:]')
    [[ "$server_lower" =~ cloudflare ]] && score=$((score - 10))
    [[ "$server_lower" =~ akamai ]] && score=$((score - 10))
    [[ "$server_lower" =~ (apache|nginx) ]] && score=$((score + 10))
    
    # Subdomain depth (deeper = potentially less tested)
    local depth=$(echo "$host" | grep -o "\." | wc -l)
    [[ $depth -ge 3 ]] && score=$((score + 10))
    [[ $depth -ge 4 ]] && score=$((score + 5))
    
    # Cap score at 100
    [[ $score -gt 100 ]] && score=100
    [[ $score -lt 0 ]] && score=0
    
    echo "$score"
}

sort_by_priority() {
    log "INFO" "🎯 ${BOLD}Calculating priority scores for all hosts...${RESET}"
    
    local input_file="$OUTPUT_DIR/02-hosts/httpx_output.txt"
    local output_file="$OUTPUT_DIR/02-hosts/hosts_by_priority.txt"
    
    if [[ ! -f "$input_file" ]] || [[ ! -s "$input_file" ]]; then
        log "WARN" "No hosts to prioritize"
        return
    fi
    
    > "$output_file.tmp"
    
    while IFS= read -r line; do
        # Skip empty lines
        [[ -z "$line" ]] && continue
        
        # Parse JSON fields (handle different httpx versions)
        local url=$(echo "$line" | jq -r '.url // .input // empty' 2>/dev/null)
        local status=$(echo "$line" | jq -r '.status_code // .status // 0' 2>/dev/null)
        local title=$(echo "$line" | jq -r '.title // ""' 2>/dev/null)
        # httpx uses different field names for tech in different versions
        local tech=$(echo "$line" | jq -r '(.tech // .technologies // []) | if type == "array" then join(",") else . end' 2>/dev/null)
        local server=$(echo "$line" | jq -r '.webserver // .server // ""' 2>/dev/null)
        
        if [[ -n "$url" ]] && [[ "$url" != "null" ]]; then
            local host=$(echo "$url" | sed -E 's|^https?://||' | cut -d'/' -f1)
            local score=$(calculate_priority_score "$host" "$status" "$title" "$tech" "$server")
            echo "$url|$score|$tech|$status|$title|$server" >> "$output_file.tmp"
        fi
    done < "$input_file"
    
    # Check if we have any results
    if [[ ! -s "$output_file.tmp" ]]; then
        log "WARN" "No valid hosts found to prioritize"
        rm -f "$output_file.tmp"
        return
    fi
    
    # Sort by score (descending)
    sort -t'|' -k2 -rn "$output_file.tmp" > "$output_file"
    rm -f "$output_file.tmp"
    
    local total=$(wc -l < "$output_file" 2>/dev/null || echo 0)
    log "SUCCESS" "Sorted ${BOLD}$total${RESET} hosts by priority"
}

display_scan_queue() {
    local priority_file="$OUTPUT_DIR/02-hosts/hosts_by_priority.txt"
    
    if [[ ! -f "$priority_file" ]]; then
        return
    fi
    
    echo ""
    echo -e "${PURPLE}┌─────────────────────────────────────────────────────────────────────────────┐${RESET}"
    echo -e "${PURPLE}│${RESET} ${BOLD}🎯 SCAN QUEUE (Top 10 by Priority)${RESET}                                        ${PURPLE}│${RESET}"
    echo -e "${PURPLE}└─────────────────────────────────────────────────────────────────────────────┘${RESET}"
    echo ""
    
    local count=0
    while IFS='|' read -r url score tech status title server; do
        ((count++))
        [[ $count -gt 10 ]] && break
        
        local priority_color="$GREEN"
        local priority_emoji="🟢"
        [[ $score -ge 80 ]] && priority_color="$RED" && priority_emoji="🔴"
        [[ $score -ge 60 && $score -lt 80 ]] && priority_color="$YELLOW" && priority_emoji="🟡"
        
        printf "  ${BOLD}%2d.${RESET} ${priority_emoji} ${priority_color}[%3d]${RESET} ${BOLD}%-45s${RESET} ${DIM}%s${RESET}\n" \
            "$count" "$score" "$url" "$tech"
    done < "$priority_file"
    
    local total=$(wc -l < "$priority_file" 2>/dev/null || echo 0)
    [[ $total -gt 10 ]] && echo -e "  ${DIM}... and $((total - 10)) more hosts${RESET}"
    
    echo ""
}

#═══════════════════════════════════════════════════════════════════════════════
# WORDLIST SELECTION - TECH-BASED
#═══════════════════════════════════════════════════════════════════════════════

select_wordlist() {
    local host="$1"
    local tech="$2"
    local wordlists=()
    
    # Custom wordlist takes precedence
    if [[ -n "$CUSTOM_WORDLIST" ]] && [[ -f "$CUSTOM_WORDLIST" ]]; then
        echo "$CUSTOM_WORDLIST"
        return
    fi
    
    # Use smart wordlist selection if tech is known
    if [[ -n "$tech" ]] && [[ "$tech" != "unknown" ]] && [[ "$tech" != "null" ]]; then
        local smart_wordlist=$(select_smart_wordlist "$host" "$tech")
        if [[ -f "$smart_wordlist" ]]; then
            echo "$smart_wordlist"
            return
        fi
    fi
    
    local tech_lower=$(echo "$tech" | tr '[:upper:]' '[:lower:]')
    local host_lower=$(echo "$host" | tr '[:upper:]' '[:lower:]')
    
    # === API DETECTION ===
    if [[ "$host_lower" =~ (api|rest|v1|v2|v3|graphql) ]] || \
       [[ "$tech_lower" =~ (express|fastapi|flask|django|rest|json|swagger) ]]; then
        [[ -f "$WORDLIST_API" ]] && wordlists+=("$WORDLIST_API")
        # Also check for graphql
        if [[ "$host_lower" =~ graphql ]] || [[ "$tech_lower" =~ graphql ]]; then
            [[ -f "$WORDLIST_GRAPHQL" ]] && wordlists+=("$WORDLIST_GRAPHQL")
        fi
    fi
    
    # === CMS DETECTION ===
    if [[ "$tech_lower" =~ wordpress ]] || [[ "$host_lower" =~ (wp|blog|wordpress) ]]; then
        [[ -f "$WORDLIST_WORDPRESS" ]] && wordlists+=("$WORDLIST_WORDPRESS")
    fi
    
    if [[ "$tech_lower" =~ laravel ]] || [[ "$tech_lower" =~ php ]]; then
        [[ -f "$WORDLIST_LARAVEL" ]] && wordlists+=("$WORDLIST_LARAVEL")
    fi
    
    if [[ "$tech_lower" =~ (drupal|joomla|magento) ]]; then
        # Add CMS-specific lists if available
        [[ -f "$SECLISTS_PATH/Discovery/Web-Content/CMS/drupal.txt" ]] && \
            [[ "$tech_lower" =~ drupal ]] && wordlists+=("$SECLISTS_PATH/Discovery/Web-Content/CMS/drupal.txt")
    fi
    
    # === ADMIN PANEL DETECTION ===
    if [[ "$host_lower" =~ (admin|panel|dashboard|manage|cms|backend|console) ]]; then
        [[ -f "$WORDLIST_ADMIN" ]] && wordlists+=("$WORDLIST_ADMIN")
    fi
    
    # === JAVA/SPRING DETECTION ===
    if [[ "$tech_lower" =~ (java|spring|tomcat|jboss|weblogic|struts) ]]; then
        [[ -f "$SECLISTS_PATH/Discovery/Web-Content/spring-boot.txt" ]] && \
            wordlists+=("$SECLISTS_PATH/Discovery/Web-Content/spring-boot.txt")
    fi
    
    # === .NET DETECTION ===
    if [[ "$tech_lower" =~ (asp|\.net|iis|aspx) ]]; then
        [[ -f "$SECLISTS_PATH/Discovery/Web-Content/IIS.fuzz.txt" ]] && \
            wordlists+=("$SECLISTS_PATH/Discovery/Web-Content/IIS.fuzz.txt")
    fi
    
    # === NODEJS DETECTION ===
    if [[ "$tech_lower" =~ (node|express|next\.js|nuxt) ]]; then
        [[ -f "$SECLISTS_PATH/Discovery/Web-Content/nodejs.txt" ]] && \
            wordlists+=("$SECLISTS_PATH/Discovery/Web-Content/nodejs.txt")
    fi
    
    # === BACKUP/SENSITIVE FILES ===
    if [[ "$SCOPE_TYPE" == "single" ]] || [[ "$SCAN_MODE" == "deep" ]]; then
        [[ -f "$SECLISTS_PATH/Discovery/Web-Content/common-and-french.txt" ]] && \
            wordlists+=("$SECLISTS_PATH/Discovery/Web-Content/common-and-french.txt")
    fi
    
    # === DEFAULT WORDLIST BASED ON MODE ===
    if [[ ${#wordlists[@]} -eq 0 ]]; then
        case $SCAN_MODE in
            fast)
                wordlists+=("$WORDLIST_COMMON")
                ;;
            balanced)
                [[ -f "$WORDLIST_MEDIUM" ]] && wordlists+=("$WORDLIST_MEDIUM") || wordlists+=("$WORDLIST_COMMON")
                ;;
            deep)
                [[ -f "$WORDLIST_BIG" ]] && wordlists+=("$WORDLIST_BIG")
                [[ -f "$WORDLIST_RAFT_LARGE" ]] && wordlists+=("$WORDLIST_RAFT_LARGE")
                ;;
        esac
    else
        # Always add common wordlist as base
        wordlists+=("$WORDLIST_COMMON")
    fi
    
    # Find first valid wordlist
    for wl in "${wordlists[@]}"; do
        if [[ -f "$wl" ]]; then
            echo "$wl"
            return
        fi
    done
    
    # Ultimate fallback
    echo "$WORDLIST_COMMON"
}

# Get multiple wordlists for deep scanning
get_all_wordlists_for_tech() {
    local host="$1"
    local tech="$2"
    local wordlists=()
    
    local tech_lower=$(echo "$tech" | tr '[:upper:]' '[:lower:]')
    local host_lower=$(echo "$host" | tr '[:upper:]' '[:lower:]')
    
    # Always start with common
    [[ -f "$WORDLIST_COMMON" ]] && wordlists+=("$WORDLIST_COMMON")
    
    # Add tech-specific
    if [[ "$host_lower" =~ (api|rest) ]] || [[ "$tech_lower" =~ (api|rest|json) ]]; then
        [[ -f "$WORDLIST_API" ]] && wordlists+=("$WORDLIST_API")
    fi
    
    if [[ "$tech_lower" =~ wordpress ]]; then
        [[ -f "$WORDLIST_WORDPRESS" ]] && wordlists+=("$WORDLIST_WORDPRESS")
    fi
    
    if [[ "$tech_lower" =~ (laravel|php) ]]; then
        [[ -f "$WORDLIST_LARAVEL" ]] && wordlists+=("$WORDLIST_LARAVEL")
    fi
    
    if [[ "$host_lower" =~ admin ]]; then
        [[ -f "$WORDLIST_ADMIN" ]] && wordlists+=("$WORDLIST_ADMIN")
    fi
    
    # Return unique wordlists
    printf '%s\n' "${wordlists[@]}" | sort -u
}

#═══════════════════════════════════════════════════════════════════════════════
# DIRECTORY SCANNING
#═══════════════════════════════════════════════════════════════════════════════

scan_host() {
    local url="$1"
    local tech="$2"
    local scanner="${3:-auto}"  # Can be: auto, feroxbuster, ffuf, curl
    local host=$(echo "$url" | sed -E 's|^https?://||' | cut -d'/' -f1 | tr -d '/')
    
    # Sanitize hostname for filename
    local safe_host=$(echo "$host" | tr '/:' '_')
    
    local wordlist=$(select_wordlist "$host" "$tech")
    local output_file="$OUTPUT_DIR/03-directories/by_host/${safe_host}.txt"
    local raw_file="$OUTPUT_DIR/03-directories/raw/ferox_${safe_host}.txt"
    
    # Check if wordlist exists
    if [[ ! -f "$wordlist" ]]; then
        log "WARN" "Wordlist not found: $wordlist"
        if [[ -f "$WORDLIST_COMMON" ]]; then
            wordlist="$WORDLIST_COMMON"
        else
            log "ERROR" "❌ No wordlist available for $host"
            return 1
        fi
    fi
    
    local wordlist_name=$(basename "$wordlist")
    local wordlist_lines=$(wc -l < "$wordlist" 2>/dev/null || echo "?")
    
    # Auto-select scanner based on availability
    if [[ "$scanner" == "auto" ]]; then
        if [[ -n "$FFUF" ]]; then
            scanner="ffuf"
        elif [[ -n "$FEROXBUSTER" ]]; then
            scanner="feroxbuster"
        else
            scanner="curl"
        fi
    fi
    
    # Use selected scanner
    case "$scanner" in
        ffuf)
            if [[ -n "$FFUF" ]]; then
                scan_host_ffuf "$url" "$tech"
                return $?
            else
                scanner="feroxbuster"
            fi
            ;;&
        feroxbuster)
            if [[ -z "$FEROXBUSTER" ]]; then
                log "WARN" "⚠️  Feroxbuster not found, using curl (slower)"
                scan_host_curl "$url" "$wordlist" "$output_file"
                return $?
            fi
            ;;
        curl)
            scan_host_curl "$url" "$wordlist" "$output_file"
            return $?
            ;;
    esac
    
    echo -e "  ${CYAN}🎯 Target:${RESET}    ${BOLD}$url${RESET}"
    echo -e "  ${CYAN}📚 Wordlist:${RESET}  $wordlist_name ${DIM}($wordlist_lines entries)${RESET}"
    [[ -n "$tech" ]] && [[ "$tech" != "null" ]] && echo -e "  ${CYAN}🔧 Tech:${RESET}      $tech"
    echo -e "  ${CYAN}🚀 Scanner:${RESET}   feroxbuster"
    
    # Clear previous results
    > "$output_file"
    > "$raw_file"
    
    # Create a timeout for feroxbuster (prevent hanging)
    local ferox_timeout=300  # 5 minutes max per host
    
    # Run feroxbuster - capture output properly
    echo -e "  ${DIM}Scanning...${RESET}"
    
    timeout "$ferox_timeout" $FEROXBUSTER \
        -u "$url" \
        -w "$wordlist" \
        -o "$raw_file" \
        -t "$FEROX_THREADS" \
        -d "$FEROX_DEPTH" \
        --timeout "$FEROX_TIMEOUT" \
        --status-codes "$FEROX_STATUS_CODES" \
        --no-state \
        --insecure \
        --no-recursion \
        2>&1 | tee -a "$OUTPUT_DIR/03-directories/raw/ferox_log.txt" | \
        grep -E "^[0-9]{3}" | head -20 | while read -r line; do
            echo -e "    ${DIM}$line${RESET}"
        done
    
    local exit_code=${PIPESTATUS[0]}
    
    # Check if timed out
    if [[ $exit_code -eq 124 ]]; then
        echo -e "  ${WARN}⏱️  Timed out after ${ferox_timeout}s"
    fi
    
    # Process results - feroxbuster output format varies
    if [[ -f "$raw_file" ]] && [[ -s "$raw_file" ]]; then
        # Try different parsing methods for feroxbuster output
        # Format 1: STATUS  METHOD  LINES  WORDS  CHARS  URL
        # Format 2: Just URLs with status
        grep -oE 'https?://[^ ]+' "$raw_file" 2>/dev/null | while read -r found_url; do
            # Get status for this URL from the same line
            local status=$(grep -F "$found_url" "$raw_file" | head -1 | grep -oE '^[0-9]{3}' || echo "200")
            echo "$found_url [$status]"
        done | sort -u > "$output_file"
        
        # Also try extracting from structured output
        grep -E "^[0-9]{3}" "$raw_file" 2>/dev/null | \
            awk '{for(i=1;i<=NF;i++) if($i ~ /^https?:/) print $i " [" $1 "]"}' | \
            sort -u >> "$output_file"
        
        # Deduplicate
        sort -u -o "$output_file" "$output_file"
        
        # Check for high-value findings
        check_high_value_findings "$raw_file" "$host"
        
        local found=$(wc -l < "$output_file" 2>/dev/null || echo 0)
        
        if [[ $found -gt 0 ]]; then
            echo -e "  ${SUCCESS} ${GREEN}${BOLD}Found $found endpoints${RESET}"
            
            # Show top findings
            echo -e "  ${DIM}────────────────────────────────────${RESET}"
            head -5 "$output_file" | while read -r line; do
                local status=$(echo "$line" | grep -oE '\[[0-9]+\]' | tr -d '[]')
                local endpoint=$(echo "$line" | sed 's/ \[.*\]//')
                
                local color="$GREEN"
                [[ "$status" == "403" ]] && color="$YELLOW"
                [[ "$status" == "401" ]] && color="$RED"
                [[ "$status" == "500" ]] && color="$PURPLE"
                
                echo -e "    ${color}[$status]${RESET} ${DIM}$endpoint${RESET}"
            done
            [[ $found -gt 5 ]] && echo -e "    ${DIM}... and $((found - 5)) more${RESET}"
        else
            echo -e "  ${DIM}No new endpoints found${RESET}"
        fi
    else
        echo -e "  ${DIM}No results (target may be blocking)${RESET}"
    fi
    
    return 0
}

scan_host_curl() {
    local url="$1"
    local wordlist="$2"
    local output_file="$3"
    
    > "$output_file"
    
    local total=$(wc -l < "$wordlist" 2>/dev/null || echo 0)
    local current=0
    local found=0
    
    echo -e "  ${DIM}Using curl (this may take a while)...${RESET}"
    
    while IFS= read -r path; do
        [[ -z "$path" ]] && continue
        [[ "$path" == "#"* ]] && continue
        
        ((current++))
        
        # Progress every 50 requests
        if [[ $((current % 50)) -eq 0 ]]; then
            printf "\r  ${DIM}Progress: %d/%d paths tested, %d found${RESET}    " "$current" "$total" "$found"
        fi
        
        local test_url="${url%/}/${path#/}"
        local response=$(curl -s -o /dev/null -w "%{http_code}" \
            --connect-timeout 3 \
            --max-time 5 \
            -k \
            -L \
            "$test_url" 2>/dev/null)
        
        # Check if status code is interesting
        if [[ "$response" =~ ^(200|204|301|302|307|401|403|405|500)$ ]]; then
            echo "$test_url [$response]" >> "$output_file"
            ((found++))
            
            # Show finding immediately for important status codes
            if [[ "$response" == "200" ]] || [[ "$response" == "401" ]] || [[ "$response" == "403" ]]; then
                printf "\r  ${GREEN}[$response]${RESET} %s\n" "$test_url"
            fi
            
            # Check high value patterns
            for pattern in "${HIGH_VALUE_PATTERNS[@]}"; do
                if [[ "$path" == *"$pattern"* ]]; then
                    alert_finding "$test_url" "$response" "$pattern"
                fi
            done
        fi
        
    done < "$wordlist"
    
    printf "\r                                                                    \r"
    echo -e "  ${SUCCESS} ${GREEN}Found $found endpoints${RESET}"
}

# Fast fuzzing with ffuf
scan_host_ffuf() {
    local url="$1"
    local tech="$2"
    local host=$(echo "$url" | sed -E 's|^https?://||' | cut -d'/' -f1 | tr -d '/')
    local safe_host=$(echo "$host" | tr '/:' '_')
    
    local wordlist=$(select_wordlist "$host" "$tech")
    local output_file="$OUTPUT_DIR/03-directories/by_host/${safe_host}.txt"
    local json_file="$OUTPUT_DIR/03-directories/raw/ffuf_${safe_host}.json"
    
    if [[ ! -f "$wordlist" ]]; then
        log "WARN" "Wordlist not found: $wordlist"
        if [[ -f "$WORDLIST_COMMON" ]]; then
            wordlist="$WORDLIST_COMMON"
        else
            log "ERROR" "No wordlist available"
            return 1
        fi
    fi
    
    local wordlist_name=$(basename "$wordlist")
    local wordlist_lines=$(wc -l < "$wordlist" 2>/dev/null || echo "?")
    
    echo -e "  ${CYAN}🎯 Target:${RESET}    ${BOLD}$url${RESET}"
    echo -e "  ${CYAN}📚 Wordlist:${RESET}  $wordlist_name ${DIM}($wordlist_lines entries)${RESET}"
    echo -e "  ${CYAN}🚀 Scanner:${RESET}   ffuf (fast)"
    
    > "$output_file"
    
    echo -e "  ${DIM}Scanning...${RESET}"
    
    # Build ffuf command
    local ffuf_cmd="$FFUF -u '${url}/FUZZ' -w '$wordlist' -mc 200,204,301,302,307,401,403,405,500 -ac -t $FEROX_THREADS -timeout 10 -o '$json_file' -of json"
    
    # Add proxy if configured
    case "$CONNECTION_METHOD" in
        tor)   ffuf_cmd="$ffuf_cmd -x '$TOR_SOCKS_PROXY'" ;;
        proxy) 
            local proxy=$(get_next_proxy)
            [[ -n "$proxy" ]] && ffuf_cmd="$ffuf_cmd -x '$proxy'"
            ;;
    esac
    
    # Add user agent
    local ua=$(get_random_user_agent)
    ffuf_cmd="$ffuf_cmd -H 'User-Agent: $ua'"
    
    # Execute
    timeout 300 eval "$ffuf_cmd" 2>/dev/null
    
    local exit_code=$?
    
    # Parse JSON results
    if [[ -f "$json_file" ]] && [[ -s "$json_file" ]]; then
        # Extract results from ffuf JSON
        if command -v jq &>/dev/null; then
            jq -r '.results[] | "\(.url) [\(.status)]"' "$json_file" 2>/dev/null | sort -u > "$output_file"
        else
            grep -oE '"url":"[^"]+","status":[0-9]+' "$json_file" | \
                sed 's/"url":"//;s/","status":/ [/;s/$/]/' | sort -u > "$output_file"
        fi
        
        local found=$(wc -l < "$output_file" 2>/dev/null || echo 0)
        
        if [[ $found -gt 0 ]]; then
            echo -e "  ${SUCCESS} ${GREEN}${BOLD}Found $found endpoints${RESET}"
            
            # Show top findings
            echo -e "  ${DIM}────────────────────────────────────${RESET}"
            head -5 "$output_file" | while read -r line; do
                local status=$(echo "$line" | grep -oE '\[[0-9]+\]' | tr -d '[]')
                local endpoint=$(echo "$line" | sed 's/ \[.*\]//')
                
                local color="$GREEN"
                [[ "$status" == "403" ]] && color="$YELLOW"
                [[ "$status" == "401" ]] && color="$RED"
                [[ "$status" == "500" ]] && color="$PURPLE"
                
                echo -e "    ${color}[$status]${RESET} ${DIM}$endpoint${RESET}"
            done
            [[ $found -gt 5 ]] && echo -e "    ${DIM}... and $((found - 5)) more${RESET}"
        else
            echo -e "  ${DIM}No endpoints found${RESET}"
        fi
    else
        echo -e "  ${DIM}No results (target may be blocking)${RESET}"
    fi
    
    return 0
}

check_high_value_findings() {
    local results_file="$1"
    local host="$2"
    
    if [[ ! -f "$results_file" ]] || [[ ! -s "$results_file" ]]; then
        return
    fi
    
    for pattern in "${HIGH_VALUE_PATTERNS[@]}"; do
        local matches=$(grep -i "$pattern" "$results_file" 2>/dev/null)
        if [[ -n "$matches" ]]; then
            while IFS= read -r match; do
                # Feroxbuster format: STATUS METHOD LINES WORDS CHARS URL
                # or sometimes: STATUS URL
                local status=$(echo "$match" | awk '{print $1}')
                local url=$(echo "$match" | awk '{print $NF}')  # Last field is URL
                
                # Skip if not a valid finding
                [[ -z "$url" ]] && continue
                [[ "$url" == "$status" ]] && continue
                
                alert_finding "$url" "$status" "$pattern"
            done <<< "$matches"
        fi
    done
}

alert_finding() {
    local url="$1"
    local status="$2"
    local pattern="$3"
    
    ((INTERESTING_FINDINGS++))
    
    # Determine severity
    local severity="MEDIUM"
    local color="$GREEN"
    
    if [[ "$pattern" =~ (\.git|\.env|\.aws|phpinfo|debug|config|backup|swagger|graphql) ]]; then
        severity="CRITICAL"
        color="$RED"
    elif [[ "$pattern" =~ (admin|api|upload|console) ]]; then
        severity="HIGH"
        color="$YELLOW"
    fi
    
    log "$severity" "$url [$status] ← ${pattern}"
    
    # Save to findings file
    echo "[$severity] $url [$status] $pattern" >> "$OUTPUT_DIR/03-directories/interesting_findings.txt"
}

aggregate_endpoints() {
    log "INFO" "📊 ${BOLD}Aggregating all endpoints...${RESET}"
    
    local all_endpoints="$OUTPUT_DIR/03-directories/all_endpoints.txt"
    
    # Initialize file
    > "$all_endpoints"
    
    # Combine all by_host files
    if ls "$OUTPUT_DIR/03-directories/by_host/"*.txt 1>/dev/null 2>&1; then
        cat "$OUTPUT_DIR/03-directories/by_host/"*.txt 2>/dev/null | \
            grep -v "^$" | \
            sort -u >> "$all_endpoints"
    fi
    
    # Also add from raw feroxbuster output (backup)
    if ls "$OUTPUT_DIR/03-directories/raw/"ferox_*.txt 1>/dev/null 2>&1; then
        for raw_file in "$OUTPUT_DIR/03-directories/raw/"ferox_*.txt; do
            grep -oE 'https?://[^ ]+' "$raw_file" 2>/dev/null
        done | sort -u >> "$all_endpoints"
    fi
    
    # Deduplicate
    sort -u -o "$all_endpoints" "$all_endpoints" 2>/dev/null
    
    TOTAL_ENDPOINTS=$(wc -l < "$all_endpoints" 2>/dev/null || echo 0)
    
    # Organize by status code
    mkdir -p "$OUTPUT_DIR/03-directories/by_status"
    for code in 200 204 301 302 307 401 403 405 500; do
        grep "\[$code\]" "$all_endpoints" 2>/dev/null > "$OUTPUT_DIR/03-directories/by_status/${code}.txt" || true
    done
    
    log "SUCCESS" "Aggregated ${BOLD}$TOTAL_ENDPOINTS${RESET} total endpoints"
    
    # Show breakdown by status
    if [[ $TOTAL_ENDPOINTS -gt 0 ]]; then
        echo -e "  ${DIM}────────────────────────────────────${RESET}"
        for code in 200 403 401 301 302 500; do
            local count=$(wc -l < "$OUTPUT_DIR/03-directories/by_status/${code}.txt" 2>/dev/null || echo 0)
            if [[ $count -gt 0 ]]; then
                local color="$GREEN"
                [[ "$code" == "403" ]] && color="$YELLOW"
                [[ "$code" == "401" ]] && color="$RED"
                [[ "$code" == "500" ]] && color="$PURPLE"
                echo -e "    ${color}[$code]${RESET} $count endpoints"
            fi
        done
    fi
}

#═══════════════════════════════════════════════════════════════════════════════
# WAYBACK MACHINE
#═══════════════════════════════════════════════════════════════════════════════

fetch_wayback_urls() {
    if [[ "$ENABLE_WAYBACK" != true ]]; then
        return
    fi
    
    log "INFO" "⏰ ${BOLD}Fetching historical URLs from Wayback Machine...${RESET}"
    
    local output_file="$OUTPUT_DIR/07-wayback/historical_urls.txt"
    local unique_file="$OUTPUT_DIR/07-wayback/unique_endpoints.txt"
    
    > "$output_file"
    
    # Use waybackurls if available
    if [[ -n "$WAYBACKURLS" ]]; then
        echo "$TARGET" | $WAYBACKURLS 2>/dev/null >> "$output_file"
    fi
    
    # Use gau if available
    if [[ -n "$GAU" ]]; then
        echo "$TARGET" | $GAU --threads 5 2>/dev/null >> "$output_file"
    fi
    
    # Fallback to web.archive.org API
    if [[ ! -s "$output_file" ]]; then
        curl -s "https://web.archive.org/cdx/search/cdx?url=*.$TARGET/*&output=text&fl=original&collapse=urlkey" 2>/dev/null >> "$output_file"
    fi
    
    # Deduplicate and extract unique paths
    cat "$output_file" 2>/dev/null | \
        sed -E 's|^https?://[^/]+||' | \
        sort -u > "$unique_file"
    
    local count=$(wc -l < "$output_file" 2>/dev/null || echo 0)
    local unique=$(wc -l < "$unique_file" 2>/dev/null || echo 0)
    
    log "SUCCESS" "Wayback URLs: $count total, $unique unique paths"
}

#═══════════════════════════════════════════════════════════════════════════════
#
#  ██╗███████╗     █████╗ ███╗   ██╗ █████╗ ██╗  ██╗   ██╗███████╗██╗███████╗
#  ██║██╔════╝    ██╔══██╗████╗  ██║██╔══██╗██║  ╚██╗ ██╔╝██╔════╝██║██╔════╝
#  ██║███████╗    ███████║██╔██╗ ██║███████║██║   ╚████╔╝ ███████╗██║███████╗
#  ██║╚════██║    ██╔══██║██║╚██╗██║██╔══██║██║    ╚██╔╝  ╚════██║██║╚════██║
#  ██║███████║    ██║  ██║██║ ╚████║██║  ██║███████╗██║   ███████║██║███████║
#  ╚═╝╚══════╝    ╚═╝  ╚═╝╚═╝  ╚═══╝╚═╝  ╚═╝╚══════╝╚═╝   ╚══════╝╚═╝╚══════╝
#
#  ELITE JAVASCRIPT INTELLIGENCE ENGINE v3.0
#
#  FEATURES:
#  • Smart curl with redirect following & cookie handling
#  • Host-by-host crawling with progress display
#  • Multi-pattern JS extraction (6 patterns)
#  • Download verification (reject HTML error pages)
#  • 70+ secret detection patterns
#  • Hidden path discovery
#  • Endpoint extraction
#  • Config leak detection
#
#  TEAM INTEGRATION:
#  • Uses subdomains from Phase 1
#  • Uses live hosts from Phase 3
#  • Feeds endpoints to Content Discovery
#  • Feeds secrets to Final Report
#
#═══════════════════════════════════════════════════════════════════════════════

run_js_analysis() {
    echo ""
    echo -e "${PURPLE}╔══════════════════════════════════════════════════════════════════════════════╗${RESET}"
    echo -e "${PURPLE}║${RESET}                                                                              ${PURPLE}║${RESET}"
    echo -e "${PURPLE}║${RESET}   ${BOLD}ELITE JAVASCRIPT INTELLIGENCE ENGINE v3.0${RESET}                                ${PURPLE}║${RESET}"
    echo -e "${PURPLE}║${RESET}                                                                              ${PURPLE}║${RESET}"
    echo -e "${PURPLE}╠══════════════════════════════════════════════════════════════════════════════╣${RESET}"
    echo -e "${PURPLE}║${RESET}   • Smart crawling with redirect following                                   ${PURPLE}║${RESET}"
    echo -e "${PURPLE}║${RESET}   • Host-by-host processing with live progress                               ${PURPLE}║${RESET}"
    echo -e "${PURPLE}║${RESET}   • 70+ secret patterns + entropy analysis                                   ${PURPLE}║${RESET}"
    echo -e "${PURPLE}║${RESET}   • Hidden paths, endpoints, config leaks                                    ${PURPLE}║${RESET}"
    echo -e "${PURPLE}╚══════════════════════════════════════════════════════════════════════════════╝${RESET}"
    echo ""
    
    # ═══════════════════════════════════════════════════════════════════════════
    # SETUP OUTPUT DIRECTORIES
    # ═══════════════════════════════════════════════════════════════════════════
    
    local js_dir="$OUTPUT_DIR/04-javascript"
    mkdir -p "$js_dir"/{downloaded,secrets,endpoints}
    
    # Initialize output files
    > "$js_dir/all_js_urls.txt"
    > "$js_dir/secrets/all_secrets.txt"
    > "$js_dir/secrets/hidden_paths.txt"
    > "$js_dir/secrets/config_leaks.txt"
    > "$js_dir/endpoints/all_endpoints.txt"
    
    # ═══════════════════════════════════════════════════════════════════════════
    # GATHER HOSTS FROM PREVIOUS PHASES (TEAM INTEGRATION)
    # ═══════════════════════════════════════════════════════════════════════════
    
    echo -e "  ${CYAN}Gathering hosts from previous phases...${RESET}"
    
    local all_hosts="/tmp/js_all_hosts_$$.txt"
    > "$all_hosts"
    
    # Source 1: Live hosts from HTTP validation
    if [[ -f "$OUTPUT_DIR/02-hosts/live_hosts.txt" ]] && [[ -s "$OUTPUT_DIR/02-hosts/live_hosts.txt" ]]; then
        cat "$OUTPUT_DIR/02-hosts/live_hosts.txt" >> "$all_hosts"
        local c1=$(wc -l < "$OUTPUT_DIR/02-hosts/live_hosts.txt")
        echo -e "    ${GREEN}✓${RESET} Live hosts: ${BOLD}$c1${RESET}"
    fi
    
    # Source 2: Prioritized hosts
    if [[ -f "$OUTPUT_DIR/02-hosts/hosts_by_priority.txt" ]] && [[ -s "$OUTPUT_DIR/02-hosts/hosts_by_priority.txt" ]]; then
        cut -d'|' -f1 "$OUTPUT_DIR/02-hosts/hosts_by_priority.txt" >> "$all_hosts"
        local c2=$(wc -l < "$OUTPUT_DIR/02-hosts/hosts_by_priority.txt")
        echo -e "    ${GREEN}✓${RESET} Priority hosts: ${BOLD}$c2${RESET}"
    fi
    
    # Source 3: HTTPX output
    if [[ -f "$OUTPUT_DIR/02-hosts/httpx_output.txt" ]] && [[ -s "$OUTPUT_DIR/02-hosts/httpx_output.txt" ]]; then
        grep -oE 'https?://[^[:space:]]+' "$OUTPUT_DIR/02-hosts/httpx_output.txt" >> "$all_hosts"
    fi
    
    # Source 4: If no hosts found, try subdomains directly
    if [[ ! -s "$all_hosts" ]]; then
        if [[ -f "$OUTPUT_DIR/01-subdomains/subdomains_validated.txt" ]]; then
            while read -r sub; do
                [[ -n "$sub" ]] && echo "https://$sub" >> "$all_hosts"
            done < "$OUTPUT_DIR/01-subdomains/subdomains_validated.txt"
            local c3=$(wc -l < "$OUTPUT_DIR/01-subdomains/subdomains_validated.txt")
            echo -e "    ${GREEN}✓${RESET} Validated subdomains: ${BOLD}$c3${RESET}"
        fi
    fi
    
    # Source 5: Fallback to main target
    if [[ ! -s "$all_hosts" ]]; then
        echo "https://$TARGET" >> "$all_hosts"
        echo "http://$TARGET" >> "$all_hosts"
        echo -e "    ${YELLOW}⚠${RESET}  Using main target only"
    fi
    
    # Clean and deduplicate
    sort -u "$all_hosts" | grep -E '^https?://' > "${all_hosts}.clean"
    mv "${all_hosts}.clean" "$all_hosts"
    
    local total_hosts=$(wc -l < "$all_hosts")
    
    echo ""
    echo -e "  ${CYAN}Total unique hosts available:${RESET} ${BOLD}$total_hosts${RESET}"
    echo ""
    
    # ═══════════════════════════════════════════════════════════════════════════
    # USER CHOICE: How many hosts to crawl?
    # ═══════════════════════════════════════════════════════════════════════════
    
    echo -e "${YELLOW}┌─────────────────────────────────────────────────────────────────────────────┐${RESET}"
    echo -e "${YELLOW}│${RESET} ${BOLD}JavaScript Crawling Scope${RESET}                                                  ${YELLOW}│${RESET}"
    echo -e "${YELLOW}├─────────────────────────────────────────────────────────────────────────────┤${RESET}"
    echo -e "${YELLOW}│${RESET}                                                                             ${YELLOW}│${RESET}"
    echo -e "${YELLOW}│${RESET}   ${GREEN}1)${RESET} Main domain only      - Just $TARGET                     ${YELLOW}│${RESET}"
    echo -e "${YELLOW}│${RESET}   ${CYAN}2)${RESET} Top 10 hosts          - Quick scan (~3-5 min)                        ${YELLOW}│${RESET}"
    echo -e "${YELLOW}│${RESET}   ${YELLOW}3)${RESET} Top 30 hosts          - Balanced (~10-15 min)                       ${YELLOW}│${RESET}"
    echo -e "${YELLOW}│${RESET}   ${RED}4)${RESET} ALL $total_hosts hosts         - Full coverage (longer)                      ${YELLOW}│${RESET}"
    echo -e "${YELLOW}│${RESET}   ${DIM}5)${RESET} Skip JS analysis                                                      ${YELLOW}│${RESET}"
    echo -e "${YELLOW}│${RESET}                                                                             ${YELLOW}│${RESET}"
    echo -e "${YELLOW}└─────────────────────────────────────────────────────────────────────────────┘${RESET}"
    echo ""
    read -p "  Select [1-5] (default: 2): " js_choice
    [[ -z "$js_choice" ]] && js_choice="2"
    
    local max_hosts=10
    case "$js_choice" in
        1)
            # Main domain only
            echo "https://$TARGET" > "$all_hosts"
            max_hosts=1
            echo -e "  ${GREEN}→${RESET} Scanning main domain only"
            ;;
        2)
            max_hosts=10
            echo -e "  ${CYAN}→${RESET} Scanning top 10 hosts"
            ;;
        3)
            max_hosts=30
            echo -e "  ${YELLOW}→${RESET} Scanning top 30 hosts"
            ;;
        4)
            max_hosts=$total_hosts
            echo -e "  ${RED}→${RESET} Scanning ALL $total_hosts hosts"
            ;;
        5)
            echo -e "  ${DIM}Skipping JS analysis${RESET}"
            rm -f "$all_hosts"
            return
            ;;
    esac
    
    # Limit hosts if needed
    if [[ $total_hosts -gt $max_hosts ]]; then
        head -n "$max_hosts" "$all_hosts" > "${all_hosts}.limited"
        mv "${all_hosts}.limited" "$all_hosts"
    fi
    
    local hosts_to_scan=$(wc -l < "$all_hosts")
    
    echo ""
    echo -e "  ${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RESET}"
    echo -e "  ${BOLD}Starting JS crawl: $hosts_to_scan hosts${RESET}"
    echo -e "  ${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RESET}"
    echo ""
    
    enable_phase_skip "JavaScript Analysis"
    
    # ═══════════════════════════════════════════════════════════════════════════
    # HOST-BY-HOST CRAWLING
    # ═══════════════════════════════════════════════════════════════════════════
    
    local start_time=$(date +%s)
    local processed=0
    local total_js_files=0
    local total_secrets=0
    local total_endpoints=0
    local total_hidden=0
    local successful_hosts=0
    
    while read -r host_url || [[ -n "$host_url" ]]; do
        [[ -z "$host_url" ]] && continue
        [[ ! "$host_url" =~ ^https?:// ]] && continue
        
        should_skip_phase && break
        
        ((processed++))
        
        # Extract domain for display
        local host_domain=$(echo "$host_url" | sed -E 's|https?://||' | cut -d'/' -f1 | cut -d':' -f1)
        
        # Progress display
        printf "  ${DIM}[%d/%d]${RESET} ${BOLD}%-50s${RESET}" "$processed" "$hosts_to_scan" "$host_domain"
        
        # Create host directory
        local safe_name=$(echo "$host_domain" | tr '.:' '__')
        local host_dir="$js_dir/downloaded/$safe_name"
        mkdir -p "$host_dir"
        
        # CRAWL THIS HOST
        local js_found=0
        local secrets_found=0
        local endpoints_found=0
        local hidden_found=0
        
        js_crawl_single_host "$host_url" "$host_dir" "$js_dir" js_found secrets_found endpoints_found hidden_found
        
        # Display results
        if [[ $js_found -gt 0 ]]; then
            printf "\r  ${DIM}[%d/%d]${RESET} ${BOLD}%-40s${RESET} ${GREEN}JS:%-3d${RESET}" "$processed" "$hosts_to_scan" "$host_domain" "$js_found"
            [[ $secrets_found -gt 0 ]] && printf " ${RED}Secrets:%-2d${RESET}" "$secrets_found"
            [[ $endpoints_found -gt 0 ]] && printf " ${CYAN}EP:%-3d${RESET}" "$endpoints_found"
            echo ""
            
            ((total_js_files += js_found))
            ((total_secrets += secrets_found))
            ((total_endpoints += endpoints_found))
            ((total_hidden += hidden_found))
            ((successful_hosts++))
        else
            printf "\r  ${DIM}[%d/%d]${RESET} ${DIM}%-40s No JS found${RESET}\n" "$processed" "$hosts_to_scan" "$host_domain"
        fi
        
    done < "$all_hosts"
    
    disable_phase_skip
    rm -f "$all_hosts"
    
    # Deduplicate output files
    for f in "$js_dir/secrets/all_secrets.txt" "$js_dir/secrets/hidden_paths.txt" "$js_dir/endpoints/all_endpoints.txt"; do
        [[ -f "$f" ]] && sort -u -o "$f" "$f"
    done
    
    # Final counts
    local final_endpoints=$(wc -l < "$js_dir/endpoints/all_endpoints.txt" 2>/dev/null || echo 0)
    local final_hidden=$(wc -l < "$js_dir/secrets/hidden_paths.txt" 2>/dev/null || echo 0)
    local final_secrets=$(grep -c "^\[" "$js_dir/secrets/all_secrets.txt" 2>/dev/null || echo 0)
    
    # Update globals
    JS_FILES=$total_js_files
    SECRETS_FOUND=$final_secrets
    
    local duration=$(($(date +%s) - start_time))
    local mins=$((duration / 60))
    local secs=$((duration % 60))
    
    # ═══════════════════════════════════════════════════════════════════════════
    # FINAL REPORT
    # ═══════════════════════════════════════════════════════════════════════════
    
    echo ""
    echo -e "${GREEN}╔══════════════════════════════════════════════════════════════════════════════╗${RESET}"
    echo -e "${GREEN}║${RESET}   ${BOLD}JAVASCRIPT ANALYSIS COMPLETE${RESET}                                              ${GREEN}║${RESET}"
    echo -e "${GREEN}╠══════════════════════════════════════════════════════════════════════════════╣${RESET}"
    printf "${GREEN}║${RESET}   Hosts crawled:          %-50d ${GREEN}║${RESET}\n" "$processed"
    printf "${GREEN}║${RESET}   Hosts with JS:          %-50d ${GREEN}║${RESET}\n" "$successful_hosts"
    printf "${GREEN}║${RESET}   JS files downloaded:    %-50d ${GREEN}║${RESET}\n" "$total_js_files"
    echo -e "${GREEN}╠══════════════════════════════════════════════════════════════════════════════╣${RESET}"
    
    if [[ $final_secrets -gt 0 ]]; then
        printf "${GREEN}║${RESET}   ${RED}🔐 SECRETS FOUND:        %-50d${RESET} ${GREEN}║${RESET}\n" "$final_secrets"
    fi
    
    printf "${GREEN}║${RESET}   📍 Endpoints found:     %-50d ${GREEN}║${RESET}\n" "$final_endpoints"
    
    if [[ $final_hidden -gt 0 ]]; then
        printf "${GREEN}║${RESET}   ${YELLOW}🔍 Hidden paths:         %-50d${RESET} ${GREEN}║${RESET}\n" "$final_hidden"
    fi
    
    echo -e "${GREEN}╠══════════════════════════════════════════════════════════════════════════════╣${RESET}"
    printf "${GREEN}║${RESET}   Duration:               %-50s ${GREEN}║${RESET}\n" "${mins}m ${secs}s"
    echo -e "${GREEN}╚══════════════════════════════════════════════════════════════════════════════╝${RESET}"
    
    # Show secrets if found
    if [[ $final_secrets -gt 0 ]]; then
        echo ""
        echo -e "  ${RED}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RESET}"
        echo -e "  ${RED}⚠️  SECRETS DISCOVERED:${RESET}"
        echo -e "  ${RED}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RESET}"
        
        # Show CRITICAL first
        grep "^\[CRITICAL\]" "$js_dir/secrets/all_secrets.txt" 2>/dev/null | head -5 | while read -r line; do
            echo -e "    ${RED}✗${RESET} $line"
        done
        
        # Then HIGH
        grep "^\[HIGH\]" "$js_dir/secrets/all_secrets.txt" 2>/dev/null | head -3 | while read -r line; do
            echo -e "    ${YELLOW}!${RESET} $line"
        done
        
        echo ""
        echo -e "  ${DIM}Full secrets: $js_dir/secrets/all_secrets.txt${RESET}"
    fi
    
    # Show hidden paths if found
    if [[ $final_hidden -gt 5 ]]; then
        echo ""
        echo -e "  ${YELLOW}Hidden paths found (sample):${RESET}"
        head -5 "$js_dir/secrets/hidden_paths.txt" | while read -r path; do
            echo -e "    ${CYAN}→${RESET} $path"
        done
        echo -e "  ${DIM}Full list: $js_dir/secrets/hidden_paths.txt${RESET}"
    fi
    
    echo ""
}

# ══════════════════════════════════════════════════════════════════════════════
# CRAWL SINGLE HOST - Downloads and analyzes all JS from one host
# ══════════════════════════════════════════════════════════════════════════════

js_crawl_single_host() {
    local base_url="$1"
    local host_dir="$2"
    local js_dir="$3"
    local -n _js_count=$4
    local -n _secrets_count=$5
    local -n _endpoints_count=$6
    local -n _hidden_count=$7
    
    _js_count=0
    _secrets_count=0
    _endpoints_count=0
    _hidden_count=0
    
    local base_domain=$(echo "$base_url" | grep -oE 'https?://[^/]+')
    
    # Temp files for this host
    local js_urls="/tmp/js_urls_$$.txt"
    local cookie_jar="/tmp/cookies_$$.txt"
    > "$js_urls"
    > "$cookie_jar"
    
    # ═══════════════════════════════════════════════════════════════════════════
    # STEP 1: Fetch main page with smart curl
    # ═══════════════════════════════════════════════════════════════════════════
    
    local html=$(curl -sSkL \
        --max-time 20 \
        --connect-timeout 10 \
        --max-redirs 5 \
        -b "$cookie_jar" \
        -c "$cookie_jar" \
        -H "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36" \
        -H "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8" \
        -H "Accept-Language: en-US,en;q=0.9" \
        -H "Connection: keep-alive" \
        "$base_url" 2>/dev/null)
    
    if [[ -z "$html" ]] || [[ ${#html} -lt 100 ]]; then
        rm -f "$js_urls" "$cookie_jar"
        return
    fi
    
    # Save HTML for reference
    echo "$html" > "$host_dir/index.html"
    
    # ═══════════════════════════════════════════════════════════════════════════
    # STEP 2: Extract JS URLs using multiple patterns
    # ═══════════════════════════════════════════════════════════════════════════
    
    # Pattern 1: <script src="...">
    echo "$html" | grep -oiE '<script[^>]+src=["\047][^"\047]+["\047]' | \
        grep -oiE 'src=["\047][^"\047]+["\047]' | \
        sed "s/src=[\"']//gi; s/[\"']$//g" >> "$js_urls"
    
    # Pattern 2: <script src=...> (without quotes)
    echo "$html" | grep -oiE '<script[^>]+src=[^[:space:]>]+' | \
        sed 's/.*src=//gi' | tr -d '"'"'" >> "$js_urls"
    
    # Pattern 3: import() statements
    echo "$html" | grep -oE 'import\(["\047][^"\047]+["\047]\)' | \
        grep -oE '["\047][^"\047]+["\047]' | tr -d '"\047' >> "$js_urls"
    
    # Pattern 4: Webpack chunks in inline script
    echo "$html" | grep -oE '"[^"]*chunk[^"]*\.js"' | tr -d '"' >> "$js_urls"
    echo "$html" | grep -oE "'[^']*chunk[^']*\.js'" | tr -d "'" >> "$js_urls"
    
    # Pattern 5: Next.js / React patterns
    echo "$html" | grep -oE '"/_next/static/[^"]+\.js"' | tr -d '"' >> "$js_urls"
    echo "$html" | grep -oE '"/static/js/[^"]+\.js"' | tr -d '"' >> "$js_urls"
    
    # Pattern 6: Any .js reference in JSON-like structures
    echo "$html" | grep -oE '"[^"]+\.js"' | tr -d '"' | grep -E '^/|^http' >> "$js_urls"
    
    # ═══════════════════════════════════════════════════════════════════════════
    # STEP 3: Resolve relative URLs and filter
    # ═══════════════════════════════════════════════════════════════════════════
    
    local resolved_urls="/tmp/resolved_$$.txt"
    > "$resolved_urls"
    
    sort -u "$js_urls" | while read -r url; do
        [[ -z "$url" ]] && continue
        [[ "$url" =~ ^data: ]] && continue
        [[ "$url" =~ ^blob: ]] && continue
        [[ "$url" =~ ^# ]] && continue
        
        local final_url=""
        
        # Already absolute
        if [[ "$url" =~ ^https?:// ]]; then
            final_url="$url"
        # Protocol-relative //
        elif [[ "$url" =~ ^// ]]; then
            final_url="https:$url"
        # Absolute path /
        elif [[ "$url" =~ ^/ ]]; then
            final_url="${base_domain}${url}"
        # Relative path
        else
            final_url="${base_domain}/${url}"
        fi
        
        # Filter out common CDN libraries (low value for secrets)
        if [[ "$final_url" =~ (googleapis\.com|google-analytics|googletagmanager|gstatic\.com) ]]; then
            continue
        fi
        if [[ "$final_url" =~ (facebook\.net|fbcdn\.net|twitter\.com|twimg\.com) ]]; then
            continue
        fi
        if [[ "$final_url" =~ (cdn\.jsdelivr|unpkg\.com|cdnjs\.cloudflare) ]]; then
            continue
        fi
        if [[ "$final_url" =~ (jquery\.min\.js|bootstrap\.min\.js|angular\.min\.js) ]]; then
            continue
        fi
        if [[ "$final_url" =~ (react\.production\.min|vue\.min\.js|lodash\.min) ]]; then
            continue
        fi
        
        echo "$final_url" >> "$resolved_urls"
    done
    
    # ═══════════════════════════════════════════════════════════════════════════
    # STEP 4: Also check common JS paths that might not be in HTML
    # ═══════════════════════════════════════════════════════════════════════════
    
    local common_paths=(
        "/app.js" "/main.js" "/bundle.js" "/config.js" "/settings.js"
        "/js/app.js" "/js/main.js" "/js/bundle.js"
        "/static/js/main.js" "/static/js/app.js" "/static/js/bundle.js"
        "/assets/js/app.js" "/assets/js/main.js"
        "/dist/bundle.js" "/dist/app.js"
        "/build/bundle.js"
        "/env.js" "/environment.js" "/runtime.js"
    )
    
    for path in "${common_paths[@]}"; do
        local check_url="${base_domain}${path}"
        # Quick HEAD request
        local status=$(curl -sSkI -o /dev/null -w "%{http_code}" \
            --max-time 5 \
            -H "User-Agent: Mozilla/5.0" \
            "$check_url" 2>/dev/null)
        
        if [[ "$status" == "200" ]]; then
            echo "$check_url" >> "$resolved_urls"
        fi
    done
    
    # Deduplicate
    sort -u -o "$resolved_urls" "$resolved_urls"
    
    local js_count=$(wc -l < "$resolved_urls" 2>/dev/null || echo 0)
    
    if [[ $js_count -eq 0 ]]; then
        rm -f "$js_urls" "$cookie_jar" "$resolved_urls"
        return
    fi
    
    # ═══════════════════════════════════════════════════════════════════════════
    # STEP 5: Download each JS file
    # ═══════════════════════════════════════════════════════════════════════════
    
    while read -r js_url; do
        [[ -z "$js_url" ]] && continue
        
        # Generate filename from hash
        local filename=$(echo "$js_url" | md5sum | cut -c1-16).js
        local filepath="$host_dir/$filename"
        
        # Download with smart curl
        local http_code=$(curl -sSkL \
            --max-time 15 \
            --connect-timeout 8 \
            --max-redirs 3 \
            -b "$cookie_jar" \
            -H "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36" \
            -H "Accept: application/javascript, text/javascript, */*" \
            -H "Referer: $base_url" \
            -o "$filepath" \
            -w "%{http_code}" \
            "$js_url" 2>/dev/null)
        
        # Verify download succeeded
        if [[ "$http_code" != "200" ]] || [[ ! -f "$filepath" ]] || [[ ! -s "$filepath" ]]; then
            rm -f "$filepath" 2>/dev/null
            continue
        fi
        
        # Verify it's actually JavaScript (not HTML error page)
        local first_line=$(head -c 200 "$filepath" 2>/dev/null)
        
        if [[ "$first_line" =~ ^\<\!DOCTYPE ]] || \
           [[ "$first_line" =~ ^\<html ]] || \
           [[ "$first_line" =~ ^\<\!-- ]] || \
           [[ "$first_line" =~ ^\<\?xml ]]; then
            rm -f "$filepath"
            continue
        fi
        
        # SUCCESS - Valid JS file downloaded
        ((_js_count++))
        
        # Record mapping
        echo "$js_url -> $filename" >> "$host_dir/url_mapping.txt"
        echo "$js_url" >> "$js_dir/all_js_urls.txt"
        
        # ═══════════════════════════════════════════════════════════════════════
        # STEP 6: Analyze this JS file
        # ═══════════════════════════════════════════════════════════════════════
        
        local file_secrets=0
        local file_endpoints=0
        local file_hidden=0
        
        js_elite_analyze "$filepath" "$js_url" "$js_dir" file_secrets file_endpoints file_hidden
        
        ((_secrets_count += file_secrets))
        ((_endpoints_count += file_endpoints))
        ((_hidden_count += file_hidden))
        
    done < "$resolved_urls"
    
    # Cleanup
    rm -f "$js_urls" "$cookie_jar" "$resolved_urls"
}

# ══════════════════════════════════════════════════════════════════════════════
#  JS ANALYZER 
# ══════════════════════════════════════════════════════════════════════════════

js_elite_analyze() {
    local js_file="$1"
    local source_url="$2"
    local js_dir="$3"
    local -n __secrets=$4
    local -n __endpoints=$5
    local -n __hidden=$6
    
    __secrets=0
    __endpoints=0
    __hidden=0
    
    local content=$(cat "$js_file" 2>/dev/null)
    [[ -z "$content" ]] && return
    
    local file_size=${#content}
    [[ $file_size -lt 50 ]] && return
    [[ $file_size -gt 15000000 ]] && return  # Skip files > 15MB
    
    local secrets_file="$js_dir/secrets/all_secrets.txt"
    local endpoints_file="$js_dir/endpoints/all_endpoints.txt"
    local hidden_file="$js_dir/secrets/hidden_paths.txt"
    local config_file="$js_dir/secrets/config_leaks.txt"
    
    # ═══════════════════════════════════════════════════════════════════════════
    # SECRET DETECTION 
    # ═══════════════════════════════════════════════════════════════════════════
    
    # --- AWS ---
    if [[ "$content" =~ AKIA[0-9A-Z]{16} ]]; then
        local key=$(echo "$content" | grep -oE 'AKIA[0-9A-Z]{16}' | head -1)
        echo "[CRITICAL] AWS Access Key: $key" >> "$secrets_file"
        echo "  URL: $source_url" >> "$secrets_file"
        ((__secrets++))
    fi
    
    if [[ "$content" =~ ASIA[0-9A-Z]{16} ]]; then
        local key=$(echo "$content" | grep -oE 'ASIA[0-9A-Z]{16}' | head -1)
        echo "[CRITICAL] AWS Temp Key: $key" >> "$secrets_file"
        echo "  URL: $source_url" >> "$secrets_file"
        ((__secrets++))
    fi
    
    # --- Google ---
    if [[ "$content" =~ AIza[0-9A-Za-z_-]{35} ]]; then
        local key=$(echo "$content" | grep -oE 'AIza[0-9A-Za-z_-]{35}' | head -1)
        echo "[HIGH] Google API Key: $key" >> "$secrets_file"
        echo "  URL: $source_url" >> "$secrets_file"
        ((__secrets++))
    fi
    
    # --- GitHub ---
    if echo "$content" | grep -qE 'gh[pousr]_[0-9a-zA-Z]{36}'; then
        local token=$(echo "$content" | grep -oE 'gh[pousr]_[0-9a-zA-Z]{36}' | head -1)
        echo "[CRITICAL] GitHub Token: ${token:0:12}..." >> "$secrets_file"
        echo "  URL: $source_url" >> "$secrets_file"
        ((__secrets++))
    fi
    
    # --- GitLab ---
    if echo "$content" | grep -qE 'glpat-[0-9a-zA-Z_-]{20,}'; then
        echo "[CRITICAL] GitLab PAT found" >> "$secrets_file"
        echo "  URL: $source_url" >> "$secrets_file"
        ((__secrets++))
    fi
    
    # --- Stripe ---
    if echo "$content" | grep -qE 'sk_live_[0-9a-zA-Z]{24,}'; then
        local key=$(echo "$content" | grep -oE 'sk_live_[0-9a-zA-Z]{24,}' | head -1)
        echo "[CRITICAL] Stripe Secret: ${key:0:15}..." >> "$secrets_file"
        echo "  URL: $source_url" >> "$secrets_file"
        ((__secrets++))
    fi
    
    if echo "$content" | grep -qE 'pk_live_[0-9a-zA-Z]{24,}'; then
        local key=$(echo "$content" | grep -oE 'pk_live_[0-9a-zA-Z]{24,}' | head -1)
        echo "[MEDIUM] Stripe Public: ${key:0:15}..." >> "$secrets_file"
        echo "  URL: $source_url" >> "$secrets_file"
        ((__secrets++))
    fi
    
    # --- Slack ---
    if echo "$content" | grep -qE 'xox[baprs]-[0-9a-zA-Z-]{10,}'; then
        local token=$(echo "$content" | grep -oE 'xox[baprs]-[0-9a-zA-Z-]{10,}' | head -1)
        echo "[CRITICAL] Slack Token: ${token:0:12}..." >> "$secrets_file"
        echo "  URL: $source_url" >> "$secrets_file"
        ((__secrets++))
    fi
    
    if echo "$content" | grep -qE 'hooks\.slack\.com/services/T[A-Z0-9]+/B[A-Z0-9]+'; then
        echo "[HIGH] Slack Webhook found" >> "$secrets_file"
        echo "  URL: $source_url" >> "$secrets_file"
        ((__secrets++))
    fi
    
    # --- Discord ---
    if echo "$content" | grep -qE 'discord(app)?\.com/api/webhooks/[0-9]+'; then
        echo "[HIGH] Discord Webhook found" >> "$secrets_file"
        echo "  URL: $source_url" >> "$secrets_file"
        ((__secrets++))
    fi
    
    # --- Telegram ---
    if echo "$content" | grep -qE '[0-9]{8,10}:AA[0-9A-Za-z_-]{33}'; then
        echo "[CRITICAL] Telegram Bot Token found" >> "$secrets_file"
        echo "  URL: $source_url" >> "$secrets_file"
        ((__secrets++))
    fi
    
    # --- Twilio ---
    if echo "$content" | grep -qE 'SK[0-9a-fA-F]{32}'; then
        echo "[HIGH] Twilio API Key found" >> "$secrets_file"
        echo "  URL: $source_url" >> "$secrets_file"
        ((__secrets++))
    fi
    
    # --- SendGrid ---
    if echo "$content" | grep -qE 'SG\.[a-zA-Z0-9_-]{22}\.[a-zA-Z0-9_-]{43}'; then
        echo "[CRITICAL] SendGrid API Key found" >> "$secrets_file"
        echo "  URL: $source_url" >> "$secrets_file"
        ((__secrets++))
    fi
    
    # --- Mailgun ---
    if echo "$content" | grep -qE 'key-[0-9a-zA-Z]{32}'; then
        echo "[HIGH] Mailgun API Key found" >> "$secrets_file"
        echo "  URL: $source_url" >> "$secrets_file"
        ((__secrets++))
    fi
    
    # --- JWT ---
    if echo "$content" | grep -qE 'eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{5,}'; then
        echo "[HIGH] JWT Token found" >> "$secrets_file"
        echo "  URL: $source_url" >> "$secrets_file"
        ((__secrets++))
    fi
    
    # --- Private Keys ---
    if echo "$content" | grep -q "BEGIN.*PRIVATE KEY"; then
        echo "[CRITICAL] Private Key found" >> "$secrets_file"
        echo "  URL: $source_url" >> "$secrets_file"
        ((__secrets++))
    fi
    
    # --- Database URLs ---
    if echo "$content" | grep -qE 'mongodb(\+srv)?://[^"'"'"'\s]+'; then
        local url=$(echo "$content" | grep -oE 'mongodb(\+srv)?://[^"'"'"'\s]+' | head -1)
        echo "[CRITICAL] MongoDB URL: ${url:0:35}..." >> "$secrets_file"
        echo "  URL: $source_url" >> "$secrets_file"
        ((__secrets++))
    fi
    
    if echo "$content" | grep -qE 'postgres(ql)?://[^"'"'"'\s]+'; then
        local url=$(echo "$content" | grep -oE 'postgres(ql)?://[^"'"'"'\s]+' | head -1)
        echo "[CRITICAL] PostgreSQL URL: ${url:0:35}..." >> "$secrets_file"
        echo "  URL: $source_url" >> "$secrets_file"
        ((__secrets++))
    fi
    
    if echo "$content" | grep -qE 'mysql://[^"'"'"'\s]+'; then
        local url=$(echo "$content" | grep -oE 'mysql://[^"'"'"'\s]+' | head -1)
        echo "[CRITICAL] MySQL URL: ${url:0:35}..." >> "$secrets_file"
        echo "  URL: $source_url" >> "$secrets_file"
        ((__secrets++))
    fi
    
    if echo "$content" | grep -qE 'redis://[^"'"'"'\s]+'; then
        local url=$(echo "$content" | grep -oE 'redis://[^"'"'"'\s]+' | head -1)
        echo "[HIGH] Redis URL: ${url:0:35}..." >> "$secrets_file"
        echo "  URL: $source_url" >> "$secrets_file"
        ((__secrets++))
    fi
    
    # --- Firebase ---
    if echo "$content" | grep -qE '[a-z0-9-]+\.firebaseio\.com'; then
        local fb=$(echo "$content" | grep -oE '[a-z0-9-]+\.firebaseio\.com' | head -1)
        echo "[HIGH] Firebase DB: $fb" >> "$secrets_file"
        echo "  URL: $source_url" >> "$secrets_file"
        ((__secrets++))
    fi
    
    # --- Supabase ---
    if echo "$content" | grep -qE '[a-z]+\.supabase\.co'; then
        local sb=$(echo "$content" | grep -oE '[a-z]+\.supabase\.co' | head -1)
        echo "[MEDIUM] Supabase: $sb" >> "$secrets_file"
        echo "  URL: $source_url" >> "$secrets_file"
        ((__secrets++))
    fi
    
    # --- NPM ---
    if echo "$content" | grep -qE 'npm_[a-zA-Z0-9]{36}'; then
        echo "[CRITICAL] NPM Token found" >> "$secrets_file"
        echo "  URL: $source_url" >> "$secrets_file"
        ((__secrets++))
    fi
    
    # --- Square ---
    if echo "$content" | grep -qE 'sq0[a-z]{3}-[0-9A-Za-z_-]{22,}'; then
        echo "[CRITICAL] Square Token found" >> "$secrets_file"
        echo "  URL: $source_url" >> "$secrets_file"
        ((__secrets++))
    fi
    
    # --- PayPal ---
    if echo "$content" | grep -qiE 'paypal.*client.*(id|secret).*[A-Za-z0-9_-]{20,}'; then
        echo "[HIGH] PayPal Credentials found" >> "$secrets_file"
        echo "  URL: $source_url" >> "$secrets_file"
        ((__secrets++))
    fi
    
    # --- Azure ---
    if echo "$content" | grep -qE 'DefaultEndpointsProtocol=https;AccountName='; then
        echo "[CRITICAL] Azure Connection String found" >> "$secrets_file"
        echo "  URL: $source_url" >> "$secrets_file"
        ((__secrets++))
    fi
    
    # --- Heroku ---
    if echo "$content" | grep -qiE 'heroku.*api.*[0-9a-f]{8}-[0-9a-f]{4}'; then
        echo "[HIGH] Heroku API Key found" >> "$secrets_file"
        echo "  URL: $source_url" >> "$secrets_file"
        ((__secrets++))
    fi
    
    # --- Generic API Keys ---
    if echo "$content" | grep -qiE '(api_key|apikey|api-key)["\047\s:=]+["\047][a-zA-Z0-9_-]{20,}["\047]'; then
        local match=$(echo "$content" | grep -oiE '(api_key|apikey|api-key)["\047\s:=]+["\047][a-zA-Z0-9_-]{20,}["\047]' | head -1)
        if [[ ! "$match" =~ (YOUR_|REPLACE_|EXAMPLE|xxx|TODO) ]]; then
            echo "[MEDIUM] API Key pattern: ${match:0:40}..." >> "$secrets_file"
            echo "  URL: $source_url" >> "$secrets_file"
            ((__secrets++))
        fi
    fi
    
    # --- Generic Secrets ---
    if echo "$content" | grep -qiE '(secret_key|secretkey|secret)["\047\s:=]+["\047][a-zA-Z0-9_-]{20,}["\047]'; then
        local match=$(echo "$content" | grep -oiE '(secret_key|secretkey|secret)["\047\s:=]+["\047][a-zA-Z0-9_-]{20,}["\047]' | head -1)
        if [[ ! "$match" =~ (YOUR_|REPLACE_|EXAMPLE|xxx|TODO|process\.env) ]]; then
            echo "[HIGH] Secret pattern: ${match:0:40}..." >> "$secrets_file"
            echo "  URL: $source_url" >> "$secrets_file"
            ((__secrets++))
        fi
    fi
    
    # --- Internal IPs ---
    local internal_ips=$(echo "$content" | grep -oE '(10\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}|192\.168\.[0-9]{1,3}\.[0-9]{1,3}|172\.(1[6-9]|2[0-9]|3[01])\.[0-9]{1,3}\.[0-9]{1,3})' | sort -u | head -3)
    if [[ -n "$internal_ips" ]]; then
        echo "[LOW] Internal IPs: $(echo $internal_ips | tr '\n' ' ')" >> "$config_file"
        echo "  URL: $source_url" >> "$config_file"
    fi
    
    # --- S3 Buckets ---
    if echo "$content" | grep -qE '[a-z0-9.-]+\.s3[.-][a-z0-9-]*\.amazonaws\.com'; then
        local bucket=$(echo "$content" | grep -oE '[a-z0-9.-]+\.s3[.-][a-z0-9-]*\.amazonaws\.com' | head -1)
        echo "[HIGH] S3 Bucket: $bucket" >> "$secrets_file"
        echo "  URL: $source_url" >> "$secrets_file"
        ((__secrets++))
    fi
    
    # ═══════════════════════════════════════════════════════════════════════════
    # ENDPOINT EXTRACTION
    # ═══════════════════════════════════════════════════════════════════════════
    
    # API endpoints
    echo "$content" | grep -oE '["\047](/api/[a-zA-Z0-9/_.-]+)["\047]' | tr -d '"\047' >> "$endpoints_file"
    echo "$content" | grep -oE '["\047](/v[0-9]+/[a-zA-Z0-9/_.-]+)["\047]' | tr -d '"\047' >> "$endpoints_file"
    echo "$content" | grep -oE '["\047](/rest/[a-zA-Z0-9/_.-]+)["\047]' | tr -d '"\047' >> "$endpoints_file"
    echo "$content" | grep -oE '["\047](/graphql)["\047]' | tr -d '"\047' >> "$endpoints_file"
    
    # Full URL endpoints
    echo "$content" | grep -oE 'https?://[a-zA-Z0-9.-]+/[a-zA-Z0-9/._?=-]*' | \
        grep -vE '\.(js|css|png|jpg|gif|svg|ico|woff)' >> "$endpoints_file"
    
    __endpoints=$(echo "$content" | grep -cE '["\047](/api/|/v[0-9]+/|/rest/)' || echo 0)
    
    # ═══════════════════════════════════════════════════════════════════════════
    # HIDDEN PATH DETECTION
    # ═══════════════════════════════════════════════════════════════════════════
    
    local hidden_patterns="/admin|/administrator|/manage|/dashboard|/console|/internal|/private|/debug|/test|/dev|/staging|/backup|/config|/setup|/install|/phpmyadmin|/wp-admin|/jenkins|/gitlab|/swagger|/api-docs|/graphiql|/actuator|/health|/metrics|/.git|/.env|/.htaccess"
    
    local found_hidden=$(echo "$content" | grep -oiE "[\"'][^\"']*(${hidden_patterns})[^\"']*[\"']" | tr -d '"\047' | sort -u)
    if [[ -n "$found_hidden" ]]; then
        echo "$found_hidden" | while read -r path; do
            echo "$path | $source_url" >> "$hidden_file"
            ((__hidden++))
        done
    fi
}

# Backward compatibility wrapper
extract_js_files() {
    run_js_analysis
}

#═══════════════════════════════════════════════════════════════════════════════
# PARAMETER DISCOVERY
#═══════════════════════════════════════════════════════════════════════════════

run_arjun() {
    if [[ "$ENABLE_PARAM_DISCOVERY" != true ]]; then
        return
    fi
    
    if [[ -z "$ARJUN" ]]; then
        log "WARN" "Arjun not installed, skipping parameter discovery"
        return
    fi
    
    local live_file="$OUTPUT_DIR/02-hosts/hosts_by_priority.txt"
    
    if [[ ! -f "$live_file" ]] || [[ ! -s "$live_file" ]]; then
        log "WARN" "No live hosts for parameter discovery"
        return
    fi
    
    local total=$(wc -l < "$live_file")
    
    echo ""
    echo -e "${YELLOW}┌─────────────────────────────────────────────────────────────────────────────┐${RESET}"
    echo -e "${YELLOW}│${RESET} 🔍 ${BOLD}PARAMETER DISCOVERY (Arjun)${RESET}"
    echo -e "${YELLOW}│${RESET}    Discover hidden GET/POST parameters on $total hosts"
    echo -e "${YELLOW}│${RESET}    ${DIM}This can take 1-2 minutes per host${RESET}"
    echo -e "${YELLOW}└─────────────────────────────────────────────────────────────────────────────┘${RESET}"
    echo ""
    read -p "  Do you want to run Arjun parameter discovery? [y/N]: " -n 1 -r
    echo ""
    
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        log "INFO" "⏭️  Skipping parameter discovery (user choice)"
        return
    fi
    
    # Create directories
    mkdir -p "$OUTPUT_DIR/05-parameters/arjun_results"
    
    local params_file="$OUTPUT_DIR/05-parameters/all_parameters.txt"
    
    # Initialize params file
    > "$params_file"
    
    local count=0
    local found_params=0
    
    echo ""
    echo -e "  ${DIM}Discovering hidden parameters on $total hosts...${RESET}"
    echo ""
    
    while IFS='|' read -r url score tech status title server; do
        [[ -z "$url" ]] && continue
        ((count++))
        
        local host=$(echo "$url" | sed -E 's|^https?://||' | cut -d'/' -f1)
        local safe_host=$(echo "$host" | tr '/:' '_')
        local output="$OUTPUT_DIR/05-parameters/arjun_results/${safe_host}.json"
        
        printf "  ${DIM}[%d/%d]${RESET} %s " "$count" "$total" "$host"
        
        # Run Arjun with timeout
        if timeout 120 $ARJUN -u "$url" -oJ "$output" -q 2>/dev/null; then
            # Extract parameters from JSON
            if [[ -f "$output" ]] && [[ -s "$output" ]]; then
                local params=$(jq -r 'to_entries[] | .value.params[]?' "$output" 2>/dev/null | sort -u)
                if [[ -n "$params" ]]; then
                    local param_count=$(echo "$params" | wc -l)
                    echo -e "${GREEN}✓ $param_count params${RESET}"
                    echo "$params" >> "$params_file"
                    ((found_params += param_count))
                else
                    echo -e "${DIM}no params${RESET}"
                fi
            else
                echo -e "${DIM}no params${RESET}"
            fi
        else
            echo -e "${YELLOW}timeout${RESET}"
        fi
        
    done < "$live_file"
    
    # Deduplicate
    if [[ -f "$params_file" ]]; then
        sort -u -o "$params_file" "$params_file" 2>/dev/null
        PARAMS_DISCOVERED=$(wc -l < "$params_file" 2>/dev/null || echo 0)
    else
        PARAMS_DISCOVERED=0
    fi
    
    echo ""
    log "SUCCESS" "Discovered ${BOLD}$PARAMS_DISCOVERED${RESET} unique parameters"
    
    # Show some discovered params
    if [[ $PARAMS_DISCOVERED -gt 0 ]]; then
        echo -e "  ${DIM}Sample parameters:${RESET}"
        head -10 "$params_file" | while read -r param; do
            echo -e "    ${CYAN}$param${RESET}"
        done
        [[ $PARAMS_DISCOVERED -gt 10 ]] && echo -e "    ${DIM}... and $((PARAMS_DISCOVERED - 10)) more${RESET}"
    fi
}

#═══════════════════════════════════════════════════════════════════════════════
# NUCLEI SCANNING
#═══════════════════════════════════════════════════════════════════════════════

run_nuclei() {
    if [[ "$ENABLE_NUCLEI" != true ]]; then
        return
    fi
    
    if [[ -z "$NUCLEI" ]]; then
        log "WARN" "Nuclei not installed, skipping vulnerability scanning"
        return
    fi
    
    log "INFO" "Running Nuclei vulnerability scanner..."
    
    local targets_file="$OUTPUT_DIR/01-subdomains/subdomains_live.txt"
    local output_file="$OUTPUT_DIR/09-raw/nuclei_results.txt"
    
    # Prepend https:// to hosts
    sed 's/^/https:\/\//' "$targets_file" > "$TEMP_DIR/nuclei_targets.txt"
    
    $NUCLEI -l "$TEMP_DIR/nuclei_targets.txt" \
        -severity low,medium,high,critical \
        -silent \
        -o "$output_file" 2>/dev/null
    
    local vulns=$(wc -l < "$output_file" 2>/dev/null || echo 0)
    
    if [[ $vulns -gt 0 ]]; then
        log "CRITICAL" "Nuclei found $vulns potential vulnerabilities!"
    else
        log "SUCCESS" "Nuclei scan completed (no vulnerabilities found)"
    fi
}

#═══════════════════════════════════════════════════════════════════════════════
# REPORT GENERATION
#═══════════════════════════════════════════════════════════════════════════════

generate_summary() {
    log "INFO" "📊 ${BOLD}Generating summary report...${RESET}"
    
    local report_file="$OUTPUT_DIR/08-reports/SUMMARY.txt"
    local end_time=$(date +%s)
    local duration=$((end_time - START_TIME))
    local duration_str=$(elapsed_time)
    
    cat > "$report_file" << EOF
═══════════════════════════════════════════════════════════════════════════════
🎯 RECONNAISSANCE REPORT: $TARGET
═══════════════════════════════════════════════════════════════════════════════
⏱️  Duration: $duration_str
📅 Completed: $(timestamp)
🎯 Scope: $(echo "$SCOPE_TYPE" | sed 's/wildcard/Wildcard (*.'$TARGET')/;s/single/Single Domain ('$TARGET')/')
📊 Scan Mode: $SCAN_MODE

┌─────────────────────────────────────────────────────────────────────────────┐
│ 📊 STATISTICS                                                               │
└─────────────────────────────────────────────────────────────────────────────┘
• Subdomains discovered: $TOTAL_SUBDOMAINS
• Live hosts: $LIVE_HOSTS
• Dead hosts: $DEAD_HOSTS
• Total endpoints found: $TOTAL_ENDPOINTS
• Interesting findings: $INTERESTING_FINDINGS
• JavaScript files: $JS_FILES
• Parameters discovered: $PARAMS_DISCOVERED

EOF

    # Add high priority targets
    echo "┌─────────────────────────────────────────────────────────────────────────────┐" >> "$report_file"
    echo "│ 🔴 HIGH PRIORITY TARGETS (TEST THESE FIRST)                                │" >> "$report_file"
    echo "└─────────────────────────────────────────────────────────────────────────────┘" >> "$report_file"
    echo "" >> "$report_file"
    
    local count=0
    while IFS='|' read -r url score tech status title server; do
        ((count++))
        [[ $count -gt 10 ]] && break
        
        echo "$url [Priority: $score/100]" >> "$report_file"
        echo "├─ Tech: ${tech:-unknown}" >> "$report_file"
        echo "├─ Status: $status" >> "$report_file"
        
        # Get findings for this host
        local host=$(echo "$url" | sed -E 's|^https?://||' | cut -d'/' -f1)
        local findings=$(grep "$host" "$OUTPUT_DIR/03-directories/interesting_findings.txt" 2>/dev/null | head -5)
        
        if [[ -n "$findings" ]]; then
            echo "├─ Findings:" >> "$report_file"
            echo "$findings" | while read -r finding; do
                echo "│  ├─ $finding" >> "$report_file"
            done
        fi
        
        echo "" >> "$report_file"
    done < "$OUTPUT_DIR/02-hosts/hosts_by_priority.txt"
    
    # Add interesting findings section
    echo "" >> "$report_file"
    echo "┌─────────────────────────────────────────────────────────────────────────────┐" >> "$report_file"
    echo "│ ⚠️  INTERESTING FINDINGS                                                    │" >> "$report_file"
    echo "└─────────────────────────────────────────────────────────────────────────────┘" >> "$report_file"
    echo "" >> "$report_file"
    
    if [[ -f "$OUTPUT_DIR/03-directories/interesting_findings.txt" ]]; then
        echo "🔴 CRITICAL:" >> "$report_file"
        grep "^\[CRITICAL\]" "$OUTPUT_DIR/03-directories/interesting_findings.txt" 2>/dev/null | \
            sed 's/^\[CRITICAL\]/✓/' >> "$report_file"
        
        echo "" >> "$report_file"
        echo "🟡 HIGH:" >> "$report_file"
        grep "^\[HIGH\]" "$OUTPUT_DIR/03-directories/interesting_findings.txt" 2>/dev/null | \
            sed 's/^\[HIGH\]/✓/' >> "$report_file"
        
        echo "" >> "$report_file"
        echo "🟢 MEDIUM:" >> "$report_file"
        grep "^\[MEDIUM\]" "$OUTPUT_DIR/03-directories/interesting_findings.txt" 2>/dev/null | \
            sed 's/^\[MEDIUM\]/✓/' >> "$report_file"
    fi
    
    # Add technology breakdown
    echo "" >> "$report_file"
    echo "┌─────────────────────────────────────────────────────────────────────────────┐" >> "$report_file"
    echo "│ 📈 TECHNOLOGY BREAKDOWN                                                     │" >> "$report_file"
    echo "└─────────────────────────────────────────────────────────────────────────────┘" >> "$report_file"
    echo "" >> "$report_file"
    
    if [[ -f "$OUTPUT_DIR/06-technologies/tech_stack.json" ]]; then
        jq -r 'to_entries | .[] | "• \(.key): \(.value) hosts"' "$OUTPUT_DIR/06-technologies/tech_stack.json" 2>/dev/null >> "$report_file"
    fi
    
    # Add security findings
    echo "" >> "$report_file"
    echo "┌─────────────────────────────────────────────────────────────────────────────┐" >> "$report_file"
    echo "│ 🔥 SECURITY FINDINGS                                                        │" >> "$report_file"
    echo "└─────────────────────────────────────────────────────────────────────────────┘" >> "$report_file"
    echo "" >> "$report_file"
    
    # Subdomain takeovers
    if [[ -f "$OUTPUT_DIR/02-hosts/potential_takeovers.txt" ]] && [[ -s "$OUTPUT_DIR/02-hosts/potential_takeovers.txt" ]]; then
        echo "🚨 POTENTIAL SUBDOMAIN TAKEOVERS:" >> "$report_file"
        cat "$OUTPUT_DIR/02-hosts/potential_takeovers.txt" | while IFS='|' read -r domain cname pattern likely; do
            echo "  • $domain -> $cname" >> "$report_file"
        done
        echo "" >> "$report_file"
    fi
    
    # CORS misconfigurations
    if [[ -f "$OUTPUT_DIR/02-hosts/cors_misconfig.txt" ]] && [[ -s "$OUTPUT_DIR/02-hosts/cors_misconfig.txt" ]]; then
        echo "🌐 CORS MISCONFIGURATIONS:" >> "$report_file"
        cat "$OUTPUT_DIR/02-hosts/cors_misconfig.txt" | while IFS='|' read -r host origin type severity; do
            echo "  • [$severity] $host - $type" >> "$report_file"
        done
        echo "" >> "$report_file"
    fi
    
    # Sensitive files
    if [[ -f "$OUTPUT_DIR/02-hosts/sensitive_files.txt" ]] && [[ -s "$OUTPUT_DIR/02-hosts/sensitive_files.txt" ]]; then
        echo "🔓 SENSITIVE FILES EXPOSED:" >> "$report_file"
        cat "$OUTPUT_DIR/02-hosts/sensitive_files.txt" >> "$report_file"
        echo "" >> "$report_file"
    fi
    
    # Missing security headers
    if [[ -f "$OUTPUT_DIR/02-hosts/missing_headers.txt" ]] && [[ -s "$OUTPUT_DIR/02-hosts/missing_headers.txt" ]]; then
        echo "🛡️ MISSING SECURITY HEADERS:" >> "$report_file"
        cat "$OUTPUT_DIR/02-hosts/missing_headers.txt" | while IFS='|' read -r host headers; do
            echo "  • $host: $headers" >> "$report_file"
        done
        echo "" >> "$report_file"
    fi
    
    # WAF Detection
    if [[ -f "$OUTPUT_DIR/02-hosts/waf_detected.txt" ]] && [[ -s "$OUTPUT_DIR/02-hosts/waf_detected.txt" ]]; then
        echo "🛡️ WAF/CDN DETECTED:" >> "$report_file"
        cat "$OUTPUT_DIR/02-hosts/waf_detected.txt" | while IFS='|' read -r host waf; do
            echo "  • $host: $waf" >> "$report_file"
        done
        echo "" >> "$report_file"
    fi
    
    # Cloud buckets
    if [[ -f "$OUTPUT_DIR/02-hosts/cloud_buckets.txt" ]] && [[ -s "$OUTPUT_DIR/02-hosts/cloud_buckets.txt" ]]; then
        echo "☁️ CLOUD STORAGE FINDINGS:" >> "$report_file"
        cat "$OUTPUT_DIR/02-hosts/cloud_buckets.txt" >> "$report_file"
        echo "" >> "$report_file"
    fi
    
    # Add file locations
    cat >> "$report_file" << EOF

═══════════════════════════════════════════════════════════════════════════════
📁 Full results: $OUTPUT_DIR/
🎯 High Priority Targets: $OUTPUT_DIR/08-reports/HIGH_PRIORITY_TARGETS.txt
═══════════════════════════════════════════════════════════════════════════════
⏱️  Next step: Review high-priority targets and begin manual testing
═══════════════════════════════════════════════════════════════════════════════
EOF

    log "SUCCESS" "Summary report generated: $report_file"
}

create_priority_list() {
    log "INFO" "Creating high priority targets list..."
    
    local priority_file="$OUTPUT_DIR/08-reports/HIGH_PRIORITY_TARGETS.txt"
    
    echo "# High Priority Targets for Manual Testing" > "$priority_file"
    echo "# Generated: $(timestamp)" >> "$priority_file"
    echo "# Target: $TARGET" >> "$priority_file"
    echo "" >> "$priority_file"
    
    # Get top 20 priority hosts
    head -20 "$OUTPUT_DIR/02-hosts/hosts_by_priority.txt" | \
        while IFS='|' read -r url score tech status title server; do
            echo "$url" >> "$priority_file"
        done
    
    log "SUCCESS" "Priority list created: $priority_file"
}

generate_html_report() {
    if [[ "$GENERATE_HTML_REPORT" != true ]]; then
        return
    fi
    
    log "INFO" "🌐 ${BOLD}Generating HTML report...${RESET}"
    
    local html_file="$OUTPUT_DIR/08-reports/full_report.html"
    local duration_str=$(elapsed_time)
    
    cat > "$html_file" << 'HTMLHEAD'
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Recon Report</title>
    <style>
        :root {
            --bg-primary: #1a1a2e;
            --bg-secondary: #16213e;
            --bg-card: #0f3460;
            --text-primary: #eee;
            --text-secondary: #aaa;
            --accent-red: #e94560;
            --accent-yellow: #f39c12;
            --accent-green: #27ae60;
            --accent-blue: #3498db;
        }
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: var(--bg-primary);
            color: var(--text-primary);
            line-height: 1.6;
            padding: 20px;
        }
        .container { max-width: 1400px; margin: 0 auto; }
        .header {
            background: linear-gradient(135deg, var(--bg-secondary), var(--bg-card));
            padding: 30px;
            border-radius: 10px;
            margin-bottom: 20px;
            text-align: center;
        }
        .header h1 { font-size: 2.5em; margin-bottom: 10px; }
        .header .meta { color: var(--text-secondary); }
        .stats-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 15px;
            margin-bottom: 20px;
        }
        .stat-card {
            background: var(--bg-secondary);
            padding: 20px;
            border-radius: 8px;
            text-align: center;
        }
        .stat-card .number {
            font-size: 2.5em;
            font-weight: bold;
            color: var(--accent-blue);
        }
        .stat-card.critical .number { color: var(--accent-red); }
        .stat-card.warning .number { color: var(--accent-yellow); }
        .stat-card.success .number { color: var(--accent-green); }
        .stat-card .label { color: var(--text-secondary); margin-top: 5px; }
        .section {
            background: var(--bg-secondary);
            border-radius: 10px;
            padding: 20px;
            margin-bottom: 20px;
        }
        .section h2 {
            border-bottom: 2px solid var(--bg-card);
            padding-bottom: 10px;
            margin-bottom: 15px;
        }
        .target-item {
            background: var(--bg-card);
            padding: 15px;
            border-radius: 8px;
            margin-bottom: 10px;
        }
        .target-item .url {
            font-family: monospace;
            color: var(--accent-blue);
            word-break: break-all;
        }
        .target-item .score {
            display: inline-block;
            padding: 3px 10px;
            border-radius: 15px;
            font-weight: bold;
            margin-left: 10px;
        }
        .score-high { background: var(--accent-red); }
        .score-medium { background: var(--accent-yellow); color: #333; }
        .score-low { background: var(--accent-green); }
        .finding {
            padding: 10px;
            margin: 5px 0;
            border-left: 4px solid var(--accent-blue);
            background: rgba(0,0,0,0.2);
        }
        .finding.critical { border-color: var(--accent-red); }
        .finding.high { border-color: var(--accent-yellow); }
        .finding.medium { border-color: var(--accent-green); }
        table {
            width: 100%;
            border-collapse: collapse;
        }
        th, td {
            padding: 10px;
            text-align: left;
            border-bottom: 1px solid var(--bg-card);
        }
        th { background: var(--bg-card); }
        .tech-badge {
            display: inline-block;
            padding: 3px 8px;
            border-radius: 4px;
            background: var(--bg-card);
            margin: 2px;
            font-size: 0.85em;
        }
        .filter-bar {
            margin-bottom: 15px;
            display: flex;
            gap: 10px;
            flex-wrap: wrap;
        }
        .filter-btn {
            padding: 8px 15px;
            border: none;
            border-radius: 5px;
            background: var(--bg-card);
            color: var(--text-primary);
            cursor: pointer;
            transition: background 0.3s;
        }
        .filter-btn:hover, .filter-btn.active {
            background: var(--accent-blue);
        }
        .search-box {
            padding: 10px;
            border: none;
            border-radius: 5px;
            background: var(--bg-card);
            color: var(--text-primary);
            width: 300px;
        }
    </style>
</head>
<body>
    <div class="container">
HTMLHEAD

    # Add dynamic content
    cat >> "$html_file" << EOF
        <div class="header">
            <h1>🎯 Recon Report</h1>
            <p class="meta">Target: <strong>$TARGET</strong> | Duration: $duration_str | Completed: $(timestamp)</p>
        </div>
        
        <div class="stats-grid">
            <div class="stat-card">
                <div class="number">$TOTAL_SUBDOMAINS</div>
                <div class="label">Subdomains</div>
            </div>
            <div class="stat-card success">
                <div class="number">$LIVE_HOSTS</div>
                <div class="label">Live Hosts</div>
            </div>
            <div class="stat-card">
                <div class="number">$TOTAL_ENDPOINTS</div>
                <div class="label">Endpoints</div>
            </div>
            <div class="stat-card critical">
                <div class="number">$INTERESTING_FINDINGS</div>
                <div class="label">Interesting Findings</div>
            </div>
            <div class="stat-card warning">
                <div class="number">$JS_FILES</div>
                <div class="label">JS Files</div>
            </div>
            <div class="stat-card">
                <div class="number">$PARAMS_DISCOVERED</div>
                <div class="label">Parameters</div>
            </div>
        </div>
        
        <div class="section">
            <h2>🔴 High Priority Targets</h2>
            <div class="filter-bar">
                <input type="text" class="search-box" placeholder="Search targets..." id="searchBox">
            </div>
            <div id="targets">
EOF

    # Add priority targets
    local count=0
    while IFS='|' read -r url score tech status title server; do
        ((count++))
        [[ $count -gt 50 ]] && break
        
        local score_class="score-low"
        [[ $score -ge 80 ]] && score_class="score-high"
        [[ $score -ge 60 && $score -lt 80 ]] && score_class="score-medium"
        
        cat >> "$html_file" << EOF
                <div class="target-item">
                    <span class="url">$url</span>
                    <span class="score $score_class">$score/100</span>
                    <div style="margin-top: 10px; color: var(--text-secondary);">
                        Status: $status | Tech: <span class="tech-badge">${tech:-unknown}</span>
                    </div>
                </div>
EOF
    done < "$OUTPUT_DIR/02-hosts/hosts_by_priority.txt" 2>/dev/null

    cat >> "$html_file" << 'EOF'
            </div>
        </div>
        
        <div class="section">
            <h2>⚠️ Interesting Findings</h2>
            <div id="findings">
EOF

    # Add findings
    if [[ -f "$OUTPUT_DIR/03-directories/interesting_findings.txt" ]]; then
        while IFS= read -r finding; do
            local severity_class="medium"
            [[ "$finding" =~ ^\[CRITICAL\] ]] && severity_class="critical"
            [[ "$finding" =~ ^\[HIGH\] ]] && severity_class="high"
            
            cat >> "$html_file" << EOF
                <div class="finding $severity_class">$finding</div>
EOF
        done < "$OUTPUT_DIR/03-directories/interesting_findings.txt"
    fi

    cat >> "$html_file" << 'EOF'
            </div>
        </div>
    </div>
    
    <script>
        // Simple search functionality
        document.getElementById('searchBox').addEventListener('input', function(e) {
            const query = e.target.value.toLowerCase();
            document.querySelectorAll('.target-item').forEach(item => {
                const text = item.textContent.toLowerCase();
                item.style.display = text.includes(query) ? 'block' : 'none';
            });
        });
    </script>
</body>
</html>
EOF

    log "SUCCESS" "HTML report generated: $html_file"
}

display_final_summary() {
    echo ""
    echo -e "${PURPLE}═══════════════════════════════════════════════════════════════════════════════${RESET}"
    echo -e "${PURPLE}${BOLD}                        🎯 RECONNAISSANCE COMPLETE 🎯                         ${RESET}"
    echo -e "${PURPLE}═══════════════════════════════════════════════════════════════════════════════${RESET}"
    echo ""
    echo -e "  ${BOLD}🌐 Target:${RESET}              $TARGET"
    echo -e "  ${BOLD}⏱️  Duration:${RESET}            $(elapsed_time)"
    echo -e "  ${BOLD}📋 Scope:${RESET}               $SCOPE_TYPE"
    echo ""
    echo -e "  ${GREEN}${BOLD}━━━ 📊 Statistics ━━━${RESET}"
    echo -e "  🔍 Subdomains:          ${BOLD}$TOTAL_SUBDOMAINS${RESET}"
    echo -e "  ✅ Live Hosts:          ${GREEN}${BOLD}$LIVE_HOSTS${RESET}"
    echo -e "  ❌ Dead Hosts:          ${DIM}$DEAD_HOSTS${RESET}"
    echo -e "  📁 Endpoints:           ${BOLD}$TOTAL_ENDPOINTS${RESET}"
    echo -e "  🔥 Interesting:         ${YELLOW}${BOLD}$INTERESTING_FINDINGS${RESET}"
    echo -e "  📜 JS Files:            ${BOLD}$JS_FILES${RESET}"
    echo -e "  🔧 Parameters:          ${BOLD}$PARAMS_DISCOVERED${RESET}"
    echo ""
    
    # Show security findings summary
    echo -e "  ${RED}${BOLD}━━━ 🔥 Security Issues Found ━━━${RESET}"
    
    local takeovers=$(wc -l < "$OUTPUT_DIR/02-hosts/potential_takeovers.txt" 2>/dev/null || echo 0)
    local cors=$(wc -l < "$OUTPUT_DIR/02-hosts/cors_misconfig.txt" 2>/dev/null || echo 0)
    local sensitive=$(wc -l < "$OUTPUT_DIR/02-hosts/sensitive_files.txt" 2>/dev/null || echo 0)
    local waf=$(wc -l < "$OUTPUT_DIR/02-hosts/waf_detected.txt" 2>/dev/null || echo 0)
    local buckets=$(wc -l < "$OUTPUT_DIR/02-hosts/cloud_buckets.txt" 2>/dev/null || echo 0)
    local headers=$(wc -l < "$OUTPUT_DIR/02-hosts/missing_headers.txt" 2>/dev/null || echo 0)
    
    [[ $takeovers -gt 0 ]] && echo -e "  ${RED}🚨 Subdomain Takeovers: ${BOLD}$takeovers${RESET}"
    [[ $cors -gt 0 ]] && echo -e "  ${RED}🌐 CORS Misconfigs:     ${BOLD}$cors${RESET}"
    [[ $sensitive -gt 0 ]] && echo -e "  ${RED}🔓 Sensitive Files:     ${BOLD}$sensitive${RESET}"
    [[ $buckets -gt 0 ]] && echo -e "  ${YELLOW}☁️  Cloud Buckets:       ${BOLD}$buckets${RESET}"
    [[ $headers -gt 0 ]] && echo -e "  ${YELLOW}🛡️  Missing Headers:     ${BOLD}$headers${RESET}"
    [[ $waf -gt 0 ]] && echo -e "  ${CYAN}🛡️  WAF Detected:        ${BOLD}$waf${RESET}"
    
    if [[ $takeovers -eq 0 ]] && [[ $cors -eq 0 ]] && [[ $sensitive -eq 0 ]]; then
        echo -e "  ${GREEN}✓ No critical issues automatically detected${RESET}"
    fi
    
    echo ""
    echo -e "  ${GREEN}${BOLD}━━━ 📂 Output Files ━━━${RESET}"
    echo -e "  📁 Results:          ${UNDERLINE}$OUTPUT_DIR/${RESET}"
    echo -e "  📊 Summary:          ${UNDERLINE}$OUTPUT_DIR/08-reports/SUMMARY.txt${RESET}"
    echo -e "  🎯 Priority List:    ${UNDERLINE}$OUTPUT_DIR/08-reports/HIGH_PRIORITY_TARGETS.txt${RESET}"
    [[ "$GENERATE_HTML_REPORT" == true ]] && \
        echo -e "  🌐 HTML Report:      ${UNDERLINE}$OUTPUT_DIR/08-reports/full_report.html${RESET}"
    echo ""
    echo -e "${PURPLE}═══════════════════════════════════════════════════════════════════════════════${RESET}"
    echo -e "  ${BOLD}⚡ Next Step:${RESET} Review high-priority targets and begin manual testing"
    echo -e "${PURPLE}═══════════════════════════════════════════════════════════════════════════════${RESET}"
    echo ""
}

#═══════════════════════════════════════════════════════════════════════════════
# ARGUMENT PARSING
#═══════════════════════════════════════════════════════════════════════════════

show_help() {
    echo ""
    echo -e "${PURPLE}${BOLD}  ██╗  ██╗   ██╗ ██████╗ ██╗  ██╗██╗  ██╗ █████╗ ${RESET}"
    echo -e "${PURPLE}${BOLD}  ██║  ╚██╗ ██╔╝██╔═████╗██║ ██╔╝██║  ██║██╔══██╗${RESET}"
    echo -e "${PURPLE}${BOLD}  ██║   ╚████╔╝ ██║██╔██║█████╔╝ ███████║███████║${RESET}"
    echo -e "${PURPLE}${BOLD}  ██║    ╚██╔╝  ████╔╝██║██╔═██╗ ██╔══██║██╔══██║${RESET}"
    echo -e "${PURPLE}${BOLD}  ███████╗██║   ╚██████╔╝██║  ██╗██║  ██║██║  ██║${RESET}"
    echo -e "${PURPLE}${BOLD}  ╚══════╝╚═╝    ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═╝${RESET}"
    echo ""
    echo -e "${CYAN}${BOLD}  ⚡ Bug Bounty Reconnaissance Framework${RESET}"
    echo ""
    echo -e "${BOLD}📖 USAGE:${RESET}"
    echo -e "  ./recon.sh ${GREEN}<domain>${RESET} [options]"
    echo -e "  ./recon.sh ${GREEN}--install-deps${RESET}     Install all dependencies"
    echo ""
    echo -e "${BOLD}🔧 INSTALLATION:${RESET}"
    echo -e "  ${GREEN}--install-deps${RESET}          ${YELLOW}Auto-install all tools${RESET} (Go, Rust, SecLists, etc.)"
    echo ""
    echo -e "${BOLD}🔐 OPSEC OPTIONS:${RESET}"
    echo -e "  ${GREEN}--tor${RESET}                   Use Tor network (maximum anonymity)"
    echo -e "  ${GREEN}--proxy ${CYAN}<file>${RESET}         Use proxy chain from file"
    echo -e "  ${GREEN}--direct${RESET}                Direct connection (no anonymity)"
    echo -e "  ${GREEN}--stealth ${CYAN}<1-5>${RESET}        Stealth level: 1=fast, 5=paranoid"
    echo ""
    echo -e "${BOLD}🎛️  OPTIONS:${RESET}"
    echo -e "  ${GREEN}-h, --help${RESET}              Show this help message"
    echo -e "  ${GREEN}-m, --mode ${CYAN}<mode>${RESET}       Scan mode: ${YELLOW}fast${RESET}, ${GREEN}balanced${RESET}, ${RED}deep${RESET}"
    echo -e "  ${GREEN}-o, --output ${CYAN}<dir>${RESET}      Output directory (default: ./recon_results)"
    echo -e "  ${GREEN}-t, --threads ${CYAN}<num>${RESET}     Threads per scan (default: 50)"
    echo -e "  ${GREEN}--no-subdomain${RESET}          Skip subdomain enumeration"
    echo -e "  ${GREEN}--no-wayback${RESET}            Skip Wayback Machine"
    echo -e "  ${GREEN}--no-js${RESET}                 Skip JavaScript analysis"
    echo -e "  ${GREEN}--no-params${RESET}             Skip parameter discovery"
    echo -e "  ${GREEN}--nuclei${RESET}                Enable nuclei scanning"
    echo -e "  ${GREEN}--single${RESET}                Treat as single domain (not wildcard)"
    echo -e "  ${GREEN}--wordlist ${CYAN}<file>${RESET}       Use custom wordlist"
    echo -e "  ${GREEN}--max-time ${CYAN}<minutes>${RESET}    Maximum runtime"
    echo -e "  ${GREEN}-v, --verbose${RESET}           Verbose output"
    echo -e "  ${GREEN}-q, --quiet${RESET}             Minimal output"
    echo ""
    echo -e "${BOLD}📝 EXAMPLES:${RESET}"
    echo -e "  ${DIM}./recon.sh --install-deps${RESET}                        # First time setup"
    echo -e "  ${DIM}./recon.sh example.com${RESET}                           # Interactive mode"
    echo -e "  ${DIM}./recon.sh example.com --tor --stealth 3${RESET}         # Tor + cautious"
    echo -e "  ${DIM}./recon.sh example.com --proxy proxies.txt${RESET}       # Use proxy chain"
    echo -e "  ${DIM}./recon.sh example.com --direct --stealth 1${RESET}      # Fast direct scan"
    echo -e "  ${DIM}./recon.sh example.com --mode deep --nuclei${RESET}      # Deep + vuln scan"
    echo ""
    echo -e "${BOLD}🔐 STEALTH LEVELS:${RESET}"
    echo -e "  ${YELLOW}1 (fast)${RESET}      ⚡ 0.1-0.5s delay, 120 req/min"
    echo -e "  ${GREEN}2 (balanced)${RESET}  🎯 0.5-2.0s delay, 60 req/min ${DIM}(default)${RESET}"
    echo -e "  ${CYAN}3 (cautious)${RESET}  🛡️  1.0-3.0s delay, 30 req/min"
    echo -e "  ${BLUE}4 (slow)${RESET}      🐢 2.0-5.0s delay, 15 req/min"
    echo -e "  ${PURPLE}5 (paranoid)${RESET}  🔒 5.0-10s delay, 6 req/min"
    echo ""
    echo -e "${BOLD}🎚️  SCAN MODES:${RESET}"
    echo -e "  ${YELLOW}fast${RESET}       ⚡ Quick scan with common wordlist (~5 min)"
    echo -e "  ${GREEN}balanced${RESET}   🎯 Standard scan with medium wordlist (~15 min)"
    echo -e "  ${RED}deep${RESET}       🔥 Thorough scan with large wordlist (~60 min)"
    echo ""
    echo -e "${BOLD}🖥️  SUPPORTED SYSTEMS:${RESET}"
    echo -e "  ${GREEN}•${RESET} Debian/Ubuntu/Kali/Parrot (apt)"
    echo -e "  ${GREEN}•${RESET} Fedora/RHEL/CentOS (dnf/yum)"
    echo -e "  ${GREEN}•${RESET} Arch/Manjaro (pacman)"
    echo -e "  ${GREEN}•${RESET} Alpine (apk)"
    echo -e "  ${GREEN}•${RESET} macOS (brew)"
    echo ""
    exit 0
}

parse_arguments() {
    if [[ $# -eq 0 ]]; then
        show_help
    fi
    
    while [[ $# -gt 0 ]]; do
        case $1 in
            -h|--help)
                show_help
                ;;
            --install-deps|--install)
                # Run dependency check and installation only
                detect_os
                display_system_info
                echo ""
                echo -e "${PURPLE}═══════════════════════════════════════════════════════════════════════════════${RESET}"
                echo -e "${PURPLE}${BOLD}                    🔧 INSTALL ALL DEPENDENCIES                               ${RESET}"
                echo -e "${PURPLE}═══════════════════════════════════════════════════════════════════════════════${RESET}"
                echo ""
                
                # Install system packages
                if [[ -n "$PKG_UPDATE" ]]; then
                    echo -e "  ${CYAN}Updating package lists...${RESET}"
                    eval "$PKG_UPDATE" &>/dev/null
                fi
                
                # Install required system tools
                echo -e "  ${BOLD}Installing system tools...${RESET}"
                for tool in curl jq git nmap masscan dig; do
                    if ! command -v "$tool" &>/dev/null; then
                        install_tool "$tool"
                    else
                        echo -e "  ${GREEN}✓${RESET} $tool already installed"
                    fi
                done
                
                # Install Go if not present
                if ! command -v go &>/dev/null; then
                    echo -e "  ${YELLOW}Installing Go (required for most tools)...${RESET}"
                    install_tool "golang"
                    source ~/.bashrc 2>/dev/null || source ~/.profile 2>/dev/null
                    export PATH="$PATH:/usr/local/go/bin:$HOME/go/bin"
                else
                    echo -e "  ${GREEN}✓${RESET} Go already installed ($(go version | awk '{print $3}'))"
                fi
                
                # Install Rust/Cargo if not present
                if ! command -v cargo &>/dev/null; then
                    echo -e "  ${YELLOW}Installing Rust/Cargo (for feroxbuster)...${RESET}"
                    install_tool "rust"
                    source "$HOME/.cargo/env" 2>/dev/null
                else
                    echo -e "  ${GREEN}✓${RESET} Cargo already installed"
                fi
                
                # Install pip if not present
                if ! command -v pip3 &>/dev/null && ! command -v pip &>/dev/null; then
                    echo -e "  ${YELLOW}Installing pip...${RESET}"
                    install_tool "pip"
                else
                    echo -e "  ${GREEN}✓${RESET} pip already installed"
                fi
                
                echo ""
                echo -e "  ${BOLD}${CYAN}═══ GO-BASED TOOLS ═══${RESET}"
                echo ""
                
                # Core Go tools
                local go_tools=(
                    "github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"
                    "github.com/projectdiscovery/httpx/cmd/httpx@latest"
                    "github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"
                    "github.com/projectdiscovery/dnsx/cmd/dnsx@latest"
                    "github.com/projectdiscovery/shuffledns/cmd/shuffledns@latest"
                    "github.com/tomnomnom/assetfinder@latest"
                    "github.com/tomnomnom/waybackurls@latest"
                    "github.com/tomnomnom/httprobe@latest"
                    "github.com/lc/gau/v2/cmd/gau@latest"
                    "github.com/ffuf/ffuf/v2@latest"
                    "github.com/OJ/gobuster/v3@latest"
                    "github.com/sensepost/gowitness@latest"
                    "github.com/d3mondev/puredns/v2@latest"
                    "github.com/owasp-amass/amass/v4/...@master"
                    "github.com/LukaSikworkerp/subzy@latest"
                    "github.com/haccer/subjack@latest"
                    "github.com/michenriksen/aquatone@latest"
                    "github.com/hakluke/hakrawler@latest"
                    "github.com/jaeles-project/gospider@latest"
                )
                
                for pkg in "${go_tools[@]}"; do
                    local tool_name=$(basename "$pkg" | cut -d'@' -f1)
                    if ! command -v "$tool_name" &>/dev/null; then
                        echo -e "  ${YELLOW}Installing${RESET} $tool_name..."
                        go install "$pkg" 2>/dev/null && \
                            echo -e "  ${GREEN}✓${RESET} $tool_name installed" || \
                            echo -e "  ${RED}✗${RESET} $tool_name failed"
                    else
                        echo -e "  ${GREEN}✓${RESET} $tool_name already installed"
                    fi
                done
                
                # ════════════════════════════════════════════════════════════════════
                # CRITICAL: Install massdns (required by puredns)
                # ════════════════════════════════════════════════════════════════════
                echo ""
                echo -e "  ${BOLD}${CYAN}═══ MASSDNS (CRITICAL FOR RECURSIVE DISCOVERY) ═══${RESET}"
                echo ""
                
                if ! command -v massdns &>/dev/null; then
                    echo -e "  ${YELLOW}Installing massdns (required by puredns)...${RESET}"
                    
                    # Try package manager first
                    if [[ "$OS_TYPE" == "linux" ]]; then
                        if command -v apt &>/dev/null; then
                            sudo apt install -y massdns 2>/dev/null && \
                                echo -e "  ${GREEN}✓${RESET} massdns installed via apt" || {
                                # Build from source
                                echo -e "  ${DIM}Building massdns from source...${RESET}"
                                git clone https://github.com/blechschmidt/massdns.git /tmp/massdns 2>/dev/null
                                cd /tmp/massdns && make 2>/dev/null
                                sudo cp bin/massdns /usr/local/bin/ 2>/dev/null
                                cd - >/dev/null
                                rm -rf /tmp/massdns
                                command -v massdns &>/dev/null && \
                                    echo -e "  ${GREEN}✓${RESET} massdns built and installed" || \
                                    echo -e "  ${RED}✗${RESET} massdns installation failed"
                            }
                        elif command -v yum &>/dev/null; then
                            # Build from source for RHEL/CentOS
                            git clone https://github.com/blechschmidt/massdns.git /tmp/massdns 2>/dev/null
                            cd /tmp/massdns && make 2>/dev/null
                            sudo cp bin/massdns /usr/local/bin/ 2>/dev/null
                            cd - >/dev/null
                            rm -rf /tmp/massdns
                        fi
                    elif [[ "$OS_TYPE" == "macos" ]]; then
                        brew install massdns 2>/dev/null || {
                            git clone https://github.com/blechschmidt/massdns.git /tmp/massdns 2>/dev/null
                            cd /tmp/massdns && make 2>/dev/null
                            cp bin/massdns /usr/local/bin/ 2>/dev/null
                            cd - >/dev/null
                            rm -rf /tmp/massdns
                        }
                    fi
                else
                    echo -e "  ${GREEN}✓${RESET} massdns already installed"
                fi
                
                # ════════════════════════════════════════════════════════════════════
                # Python-based tools
                # ════════════════════════════════════════════════════════════════════
                echo ""
                echo -e "  ${BOLD}${CYAN}═══ PYTHON-BASED TOOLS ═══${RESET}"
                echo ""
                
                local pip_tools=("wafw00f" "arjun" "droopescan" "wpscan" "s3scanner")
                for tool in "${pip_tools[@]}"; do
                    if ! command -v "$tool" &>/dev/null; then
                        echo -e "  ${YELLOW}Installing${RESET} $tool..."
                        pip3 install "$tool" --break-system-packages 2>/dev/null && \
                            echo -e "  ${GREEN}✓${RESET} $tool installed" || \
                            echo -e "  ${RED}✗${RESET} $tool failed"
                    else
                        echo -e "  ${GREEN}✓${RESET} $tool already installed"
                    fi
                done
                
                # WhatWeb (special case - Ruby)
                if ! command -v whatweb &>/dev/null; then
                    echo -e "  ${YELLOW}Installing whatweb...${RESET}"
                    if [[ "$OS_TYPE" == "linux" ]]; then
                        sudo apt install -y whatweb 2>/dev/null || \
                            sudo gem install whatweb 2>/dev/null
                    elif [[ "$OS_TYPE" == "macos" ]]; then
                        brew install whatweb 2>/dev/null
                    fi
                else
                    echo -e "  ${GREEN}✓${RESET} whatweb already installed"
                fi
                
                # ════════════════════════════════════════════════════════════════════
                # Rust-based tools
                # ════════════════════════════════════════════════════════════════════
                echo ""
                echo -e "  ${BOLD}${CYAN}═══ RUST-BASED TOOLS ═══${RESET}"
                echo ""
                
                if ! command -v feroxbuster &>/dev/null; then
                    echo -e "  ${YELLOW}Installing feroxbuster...${RESET}"
                    cargo install feroxbuster 2>/dev/null && \
                        echo -e "  ${GREEN}✓${RESET} feroxbuster installed" || \
                        echo -e "  ${RED}✗${RESET} feroxbuster failed"
                else
                    echo -e "  ${GREEN}✓${RESET} feroxbuster already installed"
                fi
                
                if ! command -v rustscan &>/dev/null; then
                    echo -e "  ${YELLOW}Installing rustscan...${RESET}"
                    cargo install rustscan 2>/dev/null && \
                        echo -e "  ${GREEN}✓${RESET} rustscan installed" || \
                        echo -e "  ${RED}✗${RESET} rustscan failed"
                else
                    echo -e "  ${GREEN}✓${RESET} rustscan already installed"
                fi
                
                # ════════════════════════════════════════════════════════════════════
                # SecLists wordlists
                # ════════════════════════════════════════════════════════════════════
                echo ""
                echo -e "  ${BOLD}${CYAN}═══ WORDLISTS ═══${RESET}"
                echo ""
                
                if [[ ! -d "$SECLISTS_PATH" ]] || [[ ! -f "$SECLISTS_PATH/Discovery/Web-Content/common.txt" ]]; then
                    echo -e "  ${YELLOW}Installing SecLists (~400MB)...${RESET}"
                    install_tool "seclists"
                else
                    echo -e "  ${GREEN}✓${RESET} SecLists already installed"
                fi
                
                # DNS resolvers for puredns
                local resolvers_file="$HOME/.config/puredns/resolvers.txt"
                if [[ ! -f "$resolvers_file" ]]; then
                    echo -e "  ${YELLOW}Creating DNS resolvers list...${RESET}"
                    mkdir -p "$HOME/.config/puredns"
                    cat > "$resolvers_file" << 'RESOLVERS'
8.8.8.8
8.8.4.4
1.1.1.1
1.0.0.1
9.9.9.9
149.112.112.112
208.67.222.222
208.67.220.220
RESOLVERS
                    echo -e "  ${GREEN}✓${RESET} Resolvers created at $resolvers_file"
                else
                    echo -e "  ${GREEN}✓${RESET} DNS resolvers already configured"
                fi
                
                echo ""
                echo -e "${GREEN}═══════════════════════════════════════════════════════════════════════════════${RESET}"
                echo -e "${GREEN}${BOLD}                    ✅ INSTALLATION COMPLETE                                   ${RESET}"
                echo -e "${GREEN}═══════════════════════════════════════════════════════════════════════════════${RESET}"
                echo ""
                echo -e "  ${BOLD}Installed tools:${RESET}"
                echo -e "    • Subdomain: subfinder, assetfinder, amass, puredns"
                echo -e "    • DNS: dnsx, massdns"
                echo -e "    • HTTP: httpx, httprobe, gowitness"
                echo -e "    • Fuzzing: ffuf, gobuster, feroxbuster"
                echo -e "    • Scanning: nmap, masscan, rustscan, nuclei"
                echo -e "    • Analysis: whatweb, wafw00f, wpscan"
                echo ""
                echo -e "  You may need to restart your shell or run:"
                echo -e "    ${CYAN}source ~/.bashrc${RESET}  or  ${CYAN}export PATH=\$PATH:\$HOME/go/bin${RESET}"
                echo ""
                echo -e "  Then run: ${GREEN}./recon.sh <target>${RESET}"
                echo ""
                exit 0
                ;;
            -m|--mode)
                SCAN_MODE="$2"
                shift 2
                ;;
            -o|--output)
                OUTPUT_DIR="$2"
                shift 2
                ;;
            -t|--threads)
                FEROX_THREADS="$2"
                shift 2
                ;;
            --tor)
                CONNECTION_METHOD="tor"
                SKIP_OPSEC_PROMPT=true
                shift
                ;;
            --proxy)
                CONNECTION_METHOD="proxy"
                PROXY_FILE="$2"
                SKIP_OPSEC_PROMPT=true
                shift 2
                ;;
            --direct)
                CONNECTION_METHOD="direct"
                SKIP_OPSEC_PROMPT=true
                shift
                ;;
            --stealth)
                STEALTH_LEVEL="$2"
                if [[ ! "$STEALTH_LEVEL" =~ ^[1-5]$ ]]; then
                    log "ERROR" "Stealth level must be 1-5"
                    exit 1
                fi
                shift 2
                ;;
            -s)
                # Old stealth flag - set to level 3
                STEALTH_LEVEL=3
                shift
                ;;
            --no-subdomain)
                ENABLE_SUBDOMAIN_ENUM=false
                shift
                ;;
            --no-wayback)
                ENABLE_WAYBACK=false
                shift
                ;;
            --no-js)
                ENABLE_JS_ANALYSIS=false
                shift
                ;;
            --no-params)
                ENABLE_PARAM_DISCOVERY=false
                shift
                ;;
            --nuclei)
                ENABLE_NUCLEI=true
                shift
                ;;
            --single)
                SCOPE_TYPE_ARG="single"
                shift
                ;;
            --wordlist)
                CUSTOM_WORDLIST="$2"
                shift 2
                ;;
            --max-time)
                MAX_TIME="$2"
                shift 2
                ;;
            -v|--verbose)
                VERBOSE=true
                shift
                ;;
            -q|--quiet)
                QUIET_MODE=true
                shift
                ;;
            -*)
                log "ERROR" "Unknown option: $1"
                show_help
                ;;
            *)
                TARGET="$1"
                shift
                ;;
        esac
    done
    
    if [[ -z "$TARGET" ]]; then
        log "ERROR" "No target domain specified"
        show_help
    fi
}

#═══════════════════════════════════════════════════════════════════════════════
# CLEANUP & SIGNAL HANDLING
#═══════════════════════════════════════════════════════════════════════════════

cleanup() {
    local status=$?
    SCAN_RUNNING=false
    
    # Kill any background processes
    if [[ -f "$PIDS_FILE" ]]; then
        while read -r pid; do
            kill "$pid" 2>/dev/null
        done < "$PIDS_FILE"
    fi
    
    # Remove temp directory
    [[ -n "$TEMP_DIR" ]] && [[ -d "$TEMP_DIR" ]] && rm -rf "$TEMP_DIR"
    
    # Final message on interrupt
    if [[ $status -ne 0 ]] && [[ -n "$OUTPUT_DIR" ]]; then
        echo ""
        log "WARN" "Scan interrupted. Partial results saved to: $OUTPUT_DIR"
    fi

    return $status
}

# Global interrupt handler - used when NOT in phase skip mode
global_interrupt_handler() {
    # If we're in a phase skip section, let that handler deal with it
    if [[ -n "$PHASE_NAME" ]]; then
        return
    fi
    
    echo ""
    log "WARN" "Interrupt received. Saving partial results..."
    
    # Generate partial report
    if [[ -d "$OUTPUT_DIR" ]]; then
        generate_summary 2>/dev/null
        create_priority_list 2>/dev/null
    fi
    
    cleanup
    exit 130
}

# Enhanced cleanup with full temp/PID lifecycle management
enhanced_cleanup() {
    local status=$?
    # Kill all tracked background processes
    if [[ -f "$PIDS_FILE" ]]; then
        while read -r pid; do
            [[ -n "$pid" ]] && kill "$pid" 2>/dev/null
        done < "$PIDS_FILE"
    fi
    # Remove all tracked temp files
    for tmp_file in "${TMP_TRACK[@]}"; do
        [[ -e "$tmp_file" ]] && rm -rf "$tmp_file" 2>/dev/null
    done
    # Remove temp directory
    [[ -n "$TEMP_DIR" ]] && [[ -d "$TEMP_DIR" ]] && rm -rf "$TEMP_DIR"
    return $status
}

# Set up signal handlers - start with global handler
trap global_interrupt_handler SIGINT SIGTERM
trap enhanced_cleanup EXIT

#═══════════════════════════════════════════════════════════════════════════════
# MAIN EXECUTION
#═══════════════════════════════════════════════════════════════════════════════

main() {
    # ══════════════════════════════════════════════════════════════════════════════
    #                    RECON FRAMEWORK - ORGANIZED WORKFLOW
    # ══════════════════════════════════════════════════════════════════════════════
    #
    # LOGICAL PHASE ORDER:
    # ┌─────────────────────────────────────────────────────────────────────────────┐
    # │ PHASE 1: Subdomain Enumeration (passive + active bruteforce)               │
    # │ PHASE 2: DNS Validation (filter dead DNS entries)                          │
    # │ PHASE 3: HTTP Probing (find live web services)                             │
    # │ PHASE 4: Technology Detection (fingerprint tech stack)                     │
    # │ PHASE 5: Crawling & URL Discovery (gau, wayback, katana)                   │
    # │ PHASE 6: JavaScript Analysis (extract secrets, endpoints from JS)          │
    # │ PHASE 7: Port Scanning (discover open ports/services)                      │
    # │ PHASE 8: Content Discovery (directory/file bruteforce)                     │
    # │ PHASE 9: Security Testing (takeover, headers, CORS, WAF)                   │
    # │ PHASE 10: Vulnerability Scanning (nuclei)                                  │
    # │ PHASE 11: Screenshots (visual evidence)                                    │
    # │ PHASE 12: Reporting (generate reports)                                     │
    # └─────────────────────────────────────────────────────────────────────────────┘
    #
    # ══════════════════════════════════════════════════════════════════════════════
    
    # ══════════════════════════════════════════════════════════════════════════════
    # INITIALIZATION
    # ══════════════════════════════════════════════════════════════════════════════
    
    nuclear_cleanup
    START_TIME=$(date +%s)
    
    banner
    parse_arguments "$@"
    
    validate_target_display "$TARGET" "$SCOPE_TYPE" "$OUTPUT_DIR"
    
    echo -e "  ${DIM}Capturing real IP for OpSec violation detection...${RESET}"
    capture_real_ip
    
    # OpSec Configuration
    if [[ -z "$SKIP_OPSEC_PROMPT" ]]; then
        choose_connection_method
    else
        apply_stealth_settings
        case "$CONNECTION_METHOD" in
            tor) initialize_tor_connection || { log "ERROR" "Tor connection failed"; exit 1; } ;;
            proxy) initialize_proxy_connection || { log "ERROR" "Proxy connection failed"; exit 1; } ;;
            direct) initialize_direct_connection ;;
        esac
    fi
    
    check_dependencies
    validate_domain "$TARGET"
    setup_directories
    ask_scope_type
    save_scope
    
    # ══════════════════════════════════════════════════════════════════════════════
    # PHASE 1: SUBDOMAIN ENUMERATION
    # ══════════════════════════════════════════════════════════════════════════════
    
    if [[ "$SCOPE_TYPE" == "wildcard" ]] && [[ "$ENABLE_SUBDOMAIN_ENUM" == true ]]; then
        display_phase_opsec_banner "PHASE 1: SUBDOMAIN ENUMERATION"
        echo -e "${DIM}  Press Ctrl+C to skip this phase${RESET}"
        
        enable_phase_skip "Subdomain Enumeration"
        
        # 1a. Passive enumeration
        should_skip_phase || run_subfinder
        
        if ! should_skip_phase; then
            echo -e "${CYAN}  Running additional passive sources...${RESET}"
            run_assetfinder &
            local pid1=$!
            run_crtsh &
            local pid2=$!
            run_hackertarget &
            local pid3=$!
            wait $pid1 $pid2 $pid3 2>/dev/null
        fi
        
        should_skip_phase || run_amass_passive
        
        disable_phase_skip
        
        # Aggregate passive results
        aggregate_subdomains
        
        # 1b. Active bruteforce (only level 2, exclude existing)
        run_subdomain_bruteforce_smart
        
        echo ""
        echo -e "${GREEN}┌─────────────────────────────────────────────────────────────────────────────┐${RESET}"
        echo -e "${GREEN}│${RESET} PHASE 1 COMPLETE: ${BOLD}${GREEN}$TOTAL_SUBDOMAINS${RESET} subdomains found"
        echo -e "${GREEN}└─────────────────────────────────────────────────────────────────────────────┘${RESET}"
    else
        echo "$TARGET" > "$OUTPUT_DIR/01-subdomains/subdomains_all.txt"
        TOTAL_SUBDOMAINS=1
        log "INFO" "Single domain mode: $TARGET"
    fi
    
    # ══════════════════════════════════════════════════════════════════════════════
    # PHASE 2: DNS VALIDATION
    # ══════════════════════════════════════════════════════════════════════════════
    
    display_phase_opsec_banner "PHASE 2: DNS VALIDATION"
    dns_validate_subdomains
    
    # ══════════════════════════════════════════════════════════════════════════════
    # PHASE 3: HTTP PROBING
    # ══════════════════════════════════════════════════════════════════════════════
    
    display_phase_opsec_banner "PHASE 3: HTTP PROBING"
    log "INFO" "Finding live web services..."
    validate_hosts
    parse_httpx_output
    
    # ══════════════════════════════════════════════════════════════════════════════
    # PHASE 4: TECHNOLOGY DETECTION
    # ══════════════════════════════════════════════════════════════════════════════
    
    display_phase_opsec_banner "PHASE 4: TECHNOLOGY DETECTION"
    detect_technology
    run_wpscan
    
    # ══════════════════════════════════════════════════════════════════════════════
    # PHASE 4.5: TLS/SAN ENUMERATION (tlsx)
    # ══════════════════════════════════════════════════════════════════════════════
    
    display_phase_opsec_banner "PHASE 4.5: TLS/SAN ENUMERATION"
    run_tlsx_san_enum
    
    # ══════════════════════════════════════════════════════════════════════════════
    # PHASE 5: URL DISCOVERY (Multi-source: Crawling + Historical + Advanced)
    # ══════════════════════════════════════════════════════════════════════════════
    
    display_phase_opsec_banner "PHASE 5: URL DISCOVERY (Multi-source)"
    run_url_discovery
    run_katana_crawl
    run_gauplus_discovery
    
    # ══════════════════════════════════════════════════════════════════════════════
    # PHASE 6: JAVASCRIPT ANALYSIS + SECRETS EXTRACTION
    # ══════════════════════════════════════════════════════════════════════════════
    
    display_phase_opsec_banner "PHASE 6: JAVASCRIPT ANALYSIS & SECRETS"
    run_js_analysis
    run_secrets_extraction
    
    # ══════════════════════════════════════════════════════════════════════════════
    # PHASE 7: FAST PORT SCANNING (Naabu + Traditional)
    # ══════════════════════════════════════════════════════════════════════════════
    
    display_phase_opsec_banner "PHASE 7: PORT SCANNING (Naabu + Traditional)"
    run_naabu_scan
    run_port_scan
    
    # ══════════════════════════════════════════════════════════════════════════════
    # PHASE 8: CONTENT DISCOVERY (Directory Bruteforce)
    # ══════════════════════════════════════════════════════════════════════════════
    
    display_phase_opsec_banner "PHASE 8: CONTENT DISCOVERY"
    run_content_discovery
    
    # ══════════════════════════════════════════════════════════════════════════════
    # PHASE 9: SECURITY TESTING
    # ══════════════════════════════════════════════════════════════════════════════
    
    display_phase_opsec_banner "PHASE 9: SECURITY TESTING"
    run_intelligent_recon
    
    # ══════════════════════════════════════════════════════════════════════════════
    # PHASE 10: VULNERABILITY SCANNING
    # ══════════════════════════════════════════════════════════════════════════════
    
    if [[ "$ENABLE_NUCLEI" == true ]] || [[ -n "$NUCLEI" ]]; then
        display_phase_opsec_banner "PHASE 10: VULNERABILITY SCANNING"
        run_nuclei
    fi
    
    # ══════════════════════════════════════════════════════════════════════════════
    # PHASE 11: SCREENSHOTS
    # ══════════════════════════════════════════════════════════════════════════════
    
    display_phase_opsec_banner "PHASE 11: SCREENSHOTS"
    capture_screenshots
    
    # ══════════════════════════════════════════════════════════════════════════════
    # PHASE 12: REPORTING
    # ══════════════════════════════════════════════════════════════════════════════
    
    display_phase_opsec_banner "PHASE 12: FINAL REPORT"
    generate_final_report
    
    # ══════════════════════════════════════════════════════════════════════════════
    # SCAN COMPLETE
    # ══════════════════════════════════════════════════════════════════════════════
    
    local end_time=$(date +%s)
    local duration=$((end_time - START_TIME))
    local duration_min=$((duration / 60))
    local duration_sec=$((duration % 60))
    
    echo ""
    echo -e "${GREEN}╔══════════════════════════════════════════════════════════════════════════════╗${RESET}"
    echo -e "${GREEN}║${RESET}                        ${BOLD}SCAN COMPLETE${RESET}                                        ${GREEN}║${RESET}"
    echo -e "${GREEN}╠══════════════════════════════════════════════════════════════════════════════╣${RESET}"
    printf "${GREEN}║${RESET}  Target:              %-56s ${GREEN}║${RESET}\n" "$TARGET"
    printf "${GREEN}║${RESET}  Duration:            %-56s ${GREEN}║${RESET}\n" "${duration_min}m ${duration_sec}s"
    printf "${GREEN}║${RESET}  Output:              %-56s ${GREEN}║${RESET}\n" "$OUTPUT_DIR"
    echo -e "${GREEN}╠══════════════════════════════════════════════════════════════════════════════╣${RESET}"
    printf "${GREEN}║${RESET}  Subdomains:          %-56d ${GREEN}║${RESET}\n" "$TOTAL_SUBDOMAINS"
    printf "${GREEN}║${RESET}  Live Hosts:          %-56d ${GREEN}║${RESET}\n" "$LIVE_HOSTS"
    printf "${GREEN}║${RESET}  JS Files:            %-56d ${GREEN}║${RESET}\n" "$JS_FILES"
    
    if [[ ${SECRETS_FOUND:-0} -gt 0 ]]; then
        printf "${GREEN}║${RESET}  ${RED}Secrets Found:        %-56d${RESET} ${GREEN}║${RESET}\n" "$SECRETS_FOUND"
    fi
    
    echo -e "${GREEN}╚══════════════════════════════════════════════════════════════════════════════╝${RESET}"
    echo ""
    echo -e "  ${CYAN}Reports:${RESET}"
    echo -e "    → $OUTPUT_DIR/reports/"
    echo ""
}

# ══════════════════════════════════════════════════════════════════════════════
# URL DISCOVERY PHASE (Crawling + Historical URLs)
# ══════════════════════════════════════════════════════════════════════════════

run_url_discovery() {
    echo ""
    echo -e "${PURPLE}╔══════════════════════════════════════════════════════════════════════════════╗${RESET}"
    echo -e "${PURPLE}║${RESET}  ${BOLD}URL DISCOVERY${RESET}                                                              ${PURPLE}║${RESET}"
    echo -e "${PURPLE}╠══════════════════════════════════════════════════════════════════════════════╣${RESET}"
    echo -e "${PURPLE}║${RESET}  Crawling live hosts + historical URL sources (gau, waybackurls)            ${PURPLE}║${RESET}"
    echo -e "${PURPLE}╚══════════════════════════════════════════════════════════════════════════════╝${RESET}"
    echo ""
    
    local live_file="$OUTPUT_DIR/02-hosts/live_hosts.txt"
    [[ ! -f "$live_file" ]] && live_file="$OUTPUT_DIR/02-hosts/hosts_by_priority.txt"
    
    if [[ ! -f "$live_file" ]] || [[ ! -s "$live_file" ]]; then
        log "WARN" "No live hosts for URL discovery"
        return
    fi
    
    local url_dir="$OUTPUT_DIR/05-urls"
    mkdir -p "$url_dir"
    
    local all_urls="$url_dir/all_urls.txt"
    > "$all_urls"
    
    echo -e "  ${CYAN}Options:${RESET}"
    echo -e "    ${GREEN}1)${RESET} Quick   - gau only (~2 min)"
    echo -e "    ${YELLOW}2)${RESET} Normal  - gau + waybackurls (~5 min)"
    echo -e "    ${RED}3)${RESET} Deep    - All sources + active crawling (~15 min)"
    echo -e "    ${DIM}4)${RESET} Skip"
    echo ""
    read -p "  Select [1-4] (default: 2): " url_choice
    [[ -z "$url_choice" ]] && url_choice="2"
    
    [[ "$url_choice" == "4" ]] && { log "INFO" "Skipping URL discovery"; return; }
    
    enable_phase_skip "URL Discovery"
    
    local start_time=$(date +%s)
    
    # Get domains from live hosts
    local domains_file="/tmp/url_domains_$$.txt"
    cut -d'|' -f1 "$live_file" 2>/dev/null | sed -E 's|https?://||' | cut -d'/' -f1 | sort -u > "$domains_file"
    
    local domain_count=$(wc -l < "$domains_file")
    echo -e "  ${CYAN}Domains to scan:${RESET} ${BOLD}$domain_count${RESET}"
    echo ""
    
    # GAU - GetAllUrls
    if [[ -n "$GAU" ]] && ! should_skip_phase; then
        echo -e "  ${DIM}Running gau...${RESET}"
        local gau_out="$url_dir/gau.txt"
        
        cat "$domains_file" | $GAU --threads 5 --timeout 30 2>/dev/null > "$gau_out" &
        local pid=$!
        
        while kill -0 $pid 2>/dev/null; do
            local count=$(wc -l < "$gau_out" 2>/dev/null || echo 0)
            printf "\r  ${DIM}gau: %d URLs found${RESET}     " "$count"
            sleep 2
        done
        wait $pid
        
        local gau_count=$(wc -l < "$gau_out" 2>/dev/null || echo 0)
        printf "\r  ${GREEN}✓${RESET} gau: %d URLs                    \n" "$gau_count"
        cat "$gau_out" >> "$all_urls"
    fi
    
    # Waybackurls
    if [[ -n "$WAYBACKURLS" ]] && [[ "$url_choice" != "1" ]] && ! should_skip_phase; then
        echo -e "  ${DIM}Running waybackurls...${RESET}"
        local wb_out="$url_dir/waybackurls.txt"
        
        cat "$domains_file" | $WAYBACKURLS 2>/dev/null > "$wb_out" &
        local pid=$!
        
        while kill -0 $pid 2>/dev/null; do
            local count=$(wc -l < "$wb_out" 2>/dev/null || echo 0)
            printf "\r  ${DIM}waybackurls: %d URLs found${RESET}     " "$count"
            sleep 2
        done
        wait $pid
        
        local wb_count=$(wc -l < "$wb_out" 2>/dev/null || echo 0)
        printf "\r  ${GREEN}✓${RESET} waybackurls: %d URLs              \n" "$wb_count"
        cat "$wb_out" >> "$all_urls"
    fi
    
    # Katana (active crawling) - only for deep mode
    if [[ -n "$KATANA" ]] && [[ "$url_choice" == "3" ]] && ! should_skip_phase; then
        echo -e "  ${DIM}Running katana crawler...${RESET}"
        local katana_out="$url_dir/katana.txt"
        
        cut -d'|' -f1 "$live_file" 2>/dev/null | head -20 | \
            $KATANA -silent -d 2 -jc -timeout 10 2>/dev/null > "$katana_out" &
        local pid=$!
        
        while kill -0 $pid 2>/dev/null; do
            local count=$(wc -l < "$katana_out" 2>/dev/null || echo 0)
            printf "\r  ${DIM}katana: %d URLs found${RESET}     " "$count"
            sleep 2
        done
        wait $pid
        
        local katana_count=$(wc -l < "$katana_out" 2>/dev/null || echo 0)
        printf "\r  ${GREEN}✓${RESET} katana: %d URLs                  \n" "$katana_count"
        cat "$katana_out" >> "$all_urls"
    fi
    
    disable_phase_skip
    
    # Deduplicate and categorize
    sort -u -o "$all_urls" "$all_urls"
    local total_urls=$(wc -l < "$all_urls")
    
    # Categorize URLs
    grep -iE '\.js(\?|$)' "$all_urls" > "$url_dir/js_files.txt" 2>/dev/null
    grep -iE '\.json(\?|$)' "$all_urls" > "$url_dir/json_files.txt" 2>/dev/null
    grep -iE '\.(php|asp|aspx|jsp)' "$all_urls" > "$url_dir/dynamic.txt" 2>/dev/null
    grep -iE '\?.*=' "$all_urls" > "$url_dir/with_params.txt" 2>/dev/null
    grep -iE '\.(zip|tar|gz|bak|backup|sql|db)' "$all_urls" > "$url_dir/interesting.txt" 2>/dev/null
    
    local js_count=$(wc -l < "$url_dir/js_files.txt" 2>/dev/null || echo 0)
    local params_count=$(wc -l < "$url_dir/with_params.txt" 2>/dev/null || echo 0)
    
    rm -f "$domains_file"
    
    local duration=$(($(date +%s) - start_time))
    
    echo ""
    echo -e "${GREEN}╔══════════════════════════════════════════════════════════════════════════════╗${RESET}"
    echo -e "${GREEN}║${RESET}  ${BOLD}URL DISCOVERY COMPLETE${RESET}                                                    ${GREEN}║${RESET}"
    echo -e "${GREEN}╠══════════════════════════════════════════════════════════════════════════════╣${RESET}"
    printf "${GREEN}║${RESET}  Total URLs:          %-55d ${GREEN}║${RESET}\n" "$total_urls"
    printf "${GREEN}║${RESET}  JS Files:            %-55d ${GREEN}║${RESET}\n" "$js_count"
    printf "${GREEN}║${RESET}  URLs with params:    %-55d ${GREEN}║${RESET}\n" "$params_count"
    printf "${GREEN}║${RESET}  Time:                %-55s ${GREEN}║${RESET}\n" "${duration}s"
    echo -e "${GREEN}╚══════════════════════════════════════════════════════════════════════════════╝${RESET}"
}

# ══════════════════════════════════════════════════════════════════════════════
# CONTENT DISCOVERY (Directory Bruteforce)
# ══════════════════════════════════════════════════════════════════════════════

run_content_discovery() {
    echo ""
    echo -e "${PURPLE}╔══════════════════════════════════════════════════════════════════════════════╗${RESET}"
    echo -e "${PURPLE}║${RESET}  ${BOLD}CONTENT DISCOVERY${RESET}                                                          ${PURPLE}║${RESET}"
    echo -e "${PURPLE}╠══════════════════════════════════════════════════════════════════════════════╣${RESET}"
    echo -e "${PURPLE}║${RESET}  Directory and file bruteforcing on live hosts                               ${PURPLE}║${RESET}"
    echo -e "${PURPLE}╚══════════════════════════════════════════════════════════════════════════════╝${RESET}"
    echo ""
    
    local live_file="$OUTPUT_DIR/02-hosts/hosts_by_priority.txt"
    [[ ! -f "$live_file" ]] && live_file="$OUTPUT_DIR/02-hosts/live_hosts.txt"
    
    if [[ ! -f "$live_file" ]] || [[ ! -s "$live_file" ]]; then
        log "WARN" "No live hosts for content discovery"
        return
    fi
    
    local total_hosts=$(wc -l < "$live_file")
    
    echo -e "  ${CYAN}Live hosts:${RESET} ${BOLD}$total_hosts${RESET}"
    echo ""
    echo -e "  ${CYAN}Options:${RESET}"
    echo -e "    ${GREEN}1)${RESET} Quick      - Top 5 hosts, small wordlist (~5 min)"
    echo -e "    ${YELLOW}2)${RESET} Normal     - Top 15 hosts, medium wordlist (~15 min)"
    echo -e "    ${RED}3)${RESET} Deep       - All hosts, large wordlist (~30+ min)"
    echo -e "    ${DIM}4)${RESET} Skip"
    echo ""
    read -p "  Select [1-4] (default: 1): " content_choice
    [[ -z "$content_choice" ]] && content_choice="1"
    
    [[ "$content_choice" == "4" ]] && { log "INFO" "Skipping content discovery"; return; }
    
    local max_hosts=5
    local wordlist_size="small"
    case "$content_choice" in
        1) max_hosts=5; wordlist_size="small" ;;
        2) max_hosts=15; wordlist_size="medium" ;;
        3) max_hosts=100; wordlist_size="large" ;;
    esac
    
    # Select wordlist
    local wordlist=""
    case "$wordlist_size" in
        small) 
            wordlist="$SECLISTS_PATH/Discovery/Web-Content/common.txt"
            [[ ! -f "$wordlist" ]] && wordlist="/usr/share/wordlists/dirb/common.txt"
            ;;
        medium)
            wordlist="$SECLISTS_PATH/Discovery/Web-Content/directory-list-2.3-small.txt"
            [[ ! -f "$wordlist" ]] && wordlist="$SECLISTS_PATH/Discovery/Web-Content/common.txt"
            ;;
        large)
            wordlist="$SECLISTS_PATH/Discovery/Web-Content/directory-list-2.3-medium.txt"
            [[ ! -f "$wordlist" ]] && wordlist="$SECLISTS_PATH/Discovery/Web-Content/directory-list-2.3-small.txt"
            ;;
    esac
    
    if [[ ! -f "$wordlist" ]]; then
        log "WARN" "No wordlist found. Install SecLists."
        return
    fi
    
    enable_phase_skip "Content Discovery"
    
    local content_dir="$OUTPUT_DIR/03-directories"
    mkdir -p "$content_dir"
    
    local all_findings="$content_dir/all_findings.txt"
    > "$all_findings"
    
    local processed=0
    local start_time=$(date +%s)
    
    echo ""
    
    while IFS='|' read -r url rest || [[ -n "$url" ]]; do
        [[ -z "$url" ]] && continue
        [[ ! "$url" =~ ^https?:// ]] && continue
        
        ((processed++))
        [[ $processed -gt $max_hosts ]] && break
        should_skip_phase && break
        
        local domain=$(echo "$url" | sed -E 's|https?://||' | cut -d'/' -f1)
        
        echo -e "  ${DIM}[$processed/$max_hosts]${RESET} ${BOLD}$domain${RESET}"
        
        local output_file="$content_dir/${domain//[^a-zA-Z0-9]/_}.txt"
        
        if [[ -n "$FFUF" ]]; then
            $FFUF -u "${url}/FUZZ" -w "$wordlist" -mc 200,201,204,301,302,307,401,403 \
                -t 50 -timeout 10 -s 2>/dev/null | tee -a "$all_findings" > "$output_file" &
            local pid=$!
            
            while kill -0 $pid 2>/dev/null; do
                local count=$(wc -l < "$output_file" 2>/dev/null || echo 0)
                printf "\r    ${DIM}Found: %d${RESET}     " "$count"
                sleep 2
            done
            wait $pid
            
        elif [[ -n "$GOBUSTER" ]]; then
            $GOBUSTER dir -u "$url" -w "$wordlist" -t 50 -q --no-error 2>/dev/null | \
                tee -a "$all_findings" > "$output_file" &
            local pid=$!
            
            while kill -0 $pid 2>/dev/null; do
                sleep 2
            done
            wait $pid
        fi
        
        local found=$(wc -l < "$output_file" 2>/dev/null || echo 0)
        printf "\r    ${GREEN}✓${RESET} Found: %d paths              \n" "$found"
        
    done < "$live_file"
    
    disable_phase_skip
    
    local total_found=$(wc -l < "$all_findings" 2>/dev/null || echo 0)
    local duration=$(($(date +%s) - start_time))
    
    echo ""
    echo -e "${GREEN}╔══════════════════════════════════════════════════════════════════════════════╗${RESET}"
    echo -e "${GREEN}║${RESET}  ${BOLD}CONTENT DISCOVERY COMPLETE${RESET}                                                ${GREEN}║${RESET}"
    echo -e "${GREEN}╠══════════════════════════════════════════════════════════════════════════════╣${RESET}"
    printf "${GREEN}║${RESET}  Hosts scanned:       %-55d ${GREEN}║${RESET}\n" "$processed"
    printf "${GREEN}║${RESET}  Total findings:      %-55d ${GREEN}║${RESET}\n" "$total_found"
    printf "${GREEN}║${RESET}  Time:                %-55s ${GREEN}║${RESET}\n" "${duration}s"
    echo -e "${GREEN}╚══════════════════════════════════════════════════════════════════════════════╝${RESET}"
}

# ══════════════════════════════════════════════════════════════════════════════
# FINAL REPORT GENERATION
# ══════════════════════════════════════════════════════════════════════════════

generate_final_report() {
    echo ""
    log "INFO" "Generating final reports..."
    
    local report_dir="$OUTPUT_DIR/reports"
    mkdir -p "$report_dir"
    
    # Markdown Report
    local md_report="$report_dir/report.md"
    cat > "$md_report" << EOF
# Recon Report: $TARGET

**Date:** $(date '+%Y-%m-%d %H:%M:%S')
**Duration:** $(($(date +%s) - START_TIME)) seconds

## Summary

| Metric | Count |
|--------|-------|
| Subdomains | $TOTAL_SUBDOMAINS |
| Live Hosts | $LIVE_HOSTS |
| JS Files | $JS_FILES |
| Secrets Found | ${SECRETS_FOUND:-0} |

## Subdomains

\`\`\`
$(head -50 "$OUTPUT_DIR/01-subdomains/subdomains_all.txt" 2>/dev/null)
\`\`\`

## Live Hosts

\`\`\`
$(cut -d'|' -f1 "$OUTPUT_DIR/02-hosts/hosts_by_priority.txt" 2>/dev/null | head -30)
\`\`\`

EOF

    if [[ -s "$OUTPUT_DIR/04-javascript/secrets/all_secrets.txt" ]]; then
        cat >> "$md_report" << EOF
## Secrets Found

\`\`\`
$(cat "$OUTPUT_DIR/04-javascript/secrets/all_secrets.txt")
\`\`\`

EOF
    fi
    
    cat >> "$md_report" << EOF

## Output Files

- Subdomains: \`$OUTPUT_DIR/01-subdomains/\`
- Live Hosts: \`$OUTPUT_DIR/02-hosts/\`
- Directories: \`$OUTPUT_DIR/03-directories/\`
- JavaScript: \`$OUTPUT_DIR/04-javascript/\`
- URLs: \`$OUTPUT_DIR/05-urls/\`

---
*Generated by ly0kha Recon Framework v$VERSION*
EOF

    echo -e "  ${GREEN}✓${RESET} Markdown report: $md_report"
    
    # Generate security assessment if exists
    [[ -f "$OUTPUT_DIR/06-security/assessment.txt" ]] && \
        echo -e "  ${GREEN}✓${RESET} Security assessment: $OUTPUT_DIR/06-security/assessment.txt"
}
main "$@"

