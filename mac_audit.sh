#!/bin/zsh
set -u

# =============================================================================
# macOS Security Audit Script v2.0
# =============================================================================
# Comprehensive read-only security audit for macOS systems.
# Generates timestamped report with security posture analysis.
#
# Usage:
#   sudo zsh macos_audit_enhanced.sh [--quick] [--output /path/to/report.txt]
#
# Requirements:
#   - Run with sudo for complete access
#   - Grant Terminal "Full Disk Access" in System Settings
#     (Privacy & Security -> Full Disk Access)
#
# Output: Desktop/macos_audit_[hostname]_[timestamp].txt
# =============================================================================

# --- Configuration ---
NOW="$(date '+%Y-%m-%d_%H-%M-%S')"
HOST="$(scutil --get ComputerName 2>/dev/null || hostname | sed 's/.local$//')"
DEFAULT_OUT="$HOME/Desktop/macos_audit_${HOST}_${NOW}.txt"
OUT="${OUT:-$DEFAULT_OUT}"
QUICK_MODE=false

# Color codes for terminal output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# --- Argument Parsing ---
while [[ $# -gt 0 ]]; do
  case $1 in
    --quick)
      QUICK_MODE=true
      shift
      ;;
    --output)
      OUT="$2"
      shift 2
      ;;
    --help|-h)
      echo "Usage: sudo zsh $0 [--quick] [--output /path/to/report.txt]"
      echo ""
      echo "Options:"
      echo "  --quick      Skip lengthy operations (logs, detailed signing checks)"
      echo "  --output     Specify custom output path"
      echo "  --help       Show this help message"
      exit 0
      ;;
    *)
      echo "Unknown option: $1"
      echo "Use --help for usage information"
      exit 1
      ;;
  esac
done

# --- Helper Functions ---
is_root() { [[ "$(id -u)" -eq 0 ]]; }

print_color() {
  # Terminal only, not in file
  echo -e "${1}${2}${NC}" >&2
}

header() {
  local bar="================================================================"
  echo ""
  echo "$bar"
  echo "  $1"
  echo "$bar"
  echo ""
}

subheader() {
  echo ""
  echo "--- $1 ---"
  echo ""
}

cmd() {
  local title="$1"
  shift
  subheader "$title"
  echo "\$ $*"
  echo ""
  "$@" 2>&1 || echo "[Command failed or returned non-zero: $*]"
  echo ""
}

exists() { command -v "$1" >/dev/null 2>&1; }

note() {
  echo "[NOTE] $1"
  echo ""
}

warn() {
  echo "[WARNING] $1"
  echo ""
}

check_mark() {
  # $1 = condition (0=good, 1=bad)
  # $2 = good message
  # $3 = bad message
  if [[ $1 -eq 0 ]]; then
    echo "✓ $2"
  else
    echo "✗ $3"
  fi
}

# --- Privilege Check ---
check_privileges() {
  if ! is_root; then
    warn "Not running as root. Some sections may be incomplete."
    warn "Re-run with: sudo zsh $0"
  fi
  
  # Check for Full Disk Access (try to read a protected file)
  if ! sqlite3 "/Library/Application Support/com.apple.TCC/TCC.db" "SELECT 1 FROM access LIMIT 1" &>/dev/null; then
    warn "Terminal does not have Full Disk Access."
    warn "Grant it in: System Settings -> Privacy & Security -> Full Disk Access"
    warn "Some TCC database queries will fail."
  fi
}

# --- Report Sections ---

write_intro() {
  header "macOS Security Audit Report"
  
  cat <<EOF
Report File:     $OUT
Generated:       $(date)
Hostname:        $HOST
User:            $(whoami) (UID $(id -u))
Running as Root: $(is_root && echo "YES" || echo "NO")
Quick Mode:      $QUICK_MODE

System Information:
$(sw_vers 2>/dev/null | sed 's/^/  /')

Hardware:
$(system_profiler SPHardwareDataType 2>/dev/null | grep -E 'Model|Processor|Memory|Serial' | sed 's/^/  /')

This audit collects:
  • Security posture (SIP, Gatekeeper, Firewall, FileVault, XProtect)
  • User accounts and administrative access
  • Persistence mechanisms (LaunchAgents/Daemons, Login Items, Profiles)
  • Application signing and notarization status
  • Privacy permissions (TCC database)
  • Network connections and running processes
  • System extensions and kernel extensions
  • Browser extension hints
  • Security-relevant logs

EOF
  
  check_privileges
}

collect_security_posture() {
  header "1. SECURITY POSTURE"
  
  # SIP Status
  subheader "System Integrity Protection (SIP)"
  local sip_status=$(csrutil status 2>&1)
  echo "$sip_status"
  echo ""
  if echo "$sip_status" | grep -q "enabled"; then
    check_mark 0 "SIP is enabled (good)"
  else
    check_mark 1 "SIP is disabled (security risk)"
  fi
  echo ""
  
  # Gatekeeper
  subheader "Gatekeeper Status"
  local gk_status=$(spctl --status 2>&1)
  echo "$gk_status"
  echo ""
  if echo "$gk_status" | grep -q "enabled"; then
    check_mark 0 "Gatekeeper is enabled (good)"
  else
    check_mark 1 "Gatekeeper is disabled (security risk)"
  fi
  echo ""
  
  # XProtect & MRT Versions
  subheader "XProtect & Malware Removal Tool (MRT) Versions"
  for pkg in com.apple.pkg.XProtectPlistConfigData com.apple.pkg.XProtectPayloads com.apple.pkg.MRT; do
    echo "Package: $pkg"
    pkgutil --pkg-info "$pkg" 2>/dev/null | grep -E 'version|install-time' | sed 's/^/  /' || echo "  Not installed or not found"
    echo ""
  done
  
  # FileVault
  if exists fdesetup; then
    subheader "FileVault Status"
    local fv_status=$(fdesetup status 2>&1)
    echo "$fv_status"
    echo ""
    if echo "$fv_status" | grep -q "On"; then
      check_mark 0 "FileVault is enabled (good)"
    else
      check_mark 1 "FileVault is disabled (encryption risk)"
    fi
    echo ""
  fi
  
  # Firewall
  if exists /usr/libexec/ApplicationFirewall/socketfilterfw; then
    subheader "Application Firewall"
    echo "Global State:"
    /usr/libexec/ApplicationFirewall/socketfilterfw --getglobalstate 2>&1
    echo ""
    echo "Stealth Mode:"
    /usr/libexec/ApplicationFirewall/socketfilterfw --getstealthmode 2>&1
    echo ""
    echo "Logging Mode:"
    /usr/libexec/ApplicationFirewall/socketfilterfw --getloggingmode 2>&1
    echo ""
    echo "Allowed Applications:"
    /usr/libexec/ApplicationFirewall/socketfilterfw --listapps 2>&1 | head -50
    echo ""
  fi
  
  # Automatic Updates
  cmd "Automatic Software Updates Configuration" softwareupdate --schedule
  
  # Secure Boot / T2 Status (on supported hardware)
  if exists nvram; then
    subheader "Secure Boot Policy (for T2/Apple Silicon)"
    nvram -p | grep -i "secure" || echo "No secure boot variables found (may not be supported)"
    echo ""
  fi
}

collect_users_and_admins() {
  header "2. USER ACCOUNTS & ADMINISTRATIVE ACCESS"
  
  subheader "Local User Accounts (non-system)"
  dscl . list /Users | grep -v "^_" | while read user; do
    echo "User: $user"
    dscl . read /Users/$user RealName UniqueID PrimaryGroupID UserShell 2>/dev/null | sed 's/^/  /'
    echo ""
  done
  
  subheader "Administrator Group Members"
  dscl . read /Groups/admin GroupMembership 2>/dev/null
  echo ""
  
  subheader "Currently Logged In Users"
  who
  echo ""
  w
  echo ""
  
  subheader "Recent Logins (last)"
  last -20 2>/dev/null || echo "last command failed"
  echo ""
  
  subheader "Failed Login Attempts (if available)"
  if [[ -f /var/log/system.log ]]; then
    grep -i "authentication failure\|failed login" /var/log/system.log 2>/dev/null | tail -20 || echo "No failed logins in system.log"
  else
    echo "system.log not accessible"
  fi
  echo ""
  
  # Sudo usage
  subheader "Recent Sudo Usage"
  if [[ -f /var/log/sudo.log ]]; then
    tail -50 /var/log/sudo.log 2>/dev/null || echo "Cannot read sudo.log"
  else
    echo "sudo.log not found or not accessible"
  fi
  echo ""
}

collect_login_items() {
  header "3. LOGIN ITEMS & BACKGROUND ITEMS"
  
  if exists osascript; then
    subheader "Legacy Login Items (per-user, via osascript)"
    echo "Login Item Names:"
    osascript -e 'tell application "System Events" to get the name of every login item' 2>&1
    echo ""
    echo "Login Item Details:"
    osascript -e 'tell application "System Events" to get the properties of every login item' 2>&1
    echo ""
  fi
  
  # Modern Background Items are harder to enumerate programmatically
  # User can check System Settings -> General -> Login Items
  note "For modern Background Items, check: System Settings -> General -> Login Items"
  
  # Service Management Login Items (SMLoginItem)
  if exists sfltool; then
    subheader "Service Management Login Items"
    sfltool dumpbtm 2>/dev/null || echo "sfltool not available or insufficient permissions"
    echo ""
  fi
}

list_launchd_dir() {
  local dir="$1"
  local detail="${2:-full}"
  
  if [[ ! -d "$dir" ]]; then
    echo "Directory not found: $dir"
    echo ""
    return
  fi
  
  subheader "LaunchD Directory: $dir"
  echo "\$ ls -la $dir"
  ls -la "$dir" 2>&1 || true
  echo ""
  
  if [[ "$detail" == "full" ]] && exists plutil; then
    echo "Plist Summaries:"
    for f in "$dir"/*.plist(N); do
      [[ -f "$f" ]] || continue
      echo ""
      echo "━━━ $(basename "$f") ━━━"
      
      # Extract key fields
      local label=$(plutil -extract Label raw "$f" 2>/dev/null || echo "N/A")
      local program=$(plutil -extract Program raw "$f" 2>/dev/null || echo "N/A")
      local runatload=$(plutil -extract RunAtLoad raw "$f" 2>/dev/null || echo "N/A")
      local keepalive=$(plutil -extract KeepAlive raw "$f" 2>/dev/null || echo "N/A")
      
      echo "Label:      $label"
      echo "Program:    $program"
      echo "RunAtLoad:  $runatload"
      echo "KeepAlive:  $keepalive"
      
      # Show ProgramArguments if present
      if plutil -extract ProgramArguments raw "$f" &>/dev/null; then
        echo "ProgramArguments:"
        plutil -extract ProgramArguments xml1 -o - "$f" 2>/dev/null | grep -A1 "<string>" | grep -v "^--$" | sed 's/<[^>]*>//g' | sed 's/^/  /'
      fi
      
      # Flag suspicious patterns
      if plutil -p "$f" 2>/dev/null | grep -qi -E "curl|wget|base64|/tmp/|/var/tmp/|\.sh|python|perl|ruby"; then
        echo "⚠️  SUSPICIOUS: Contains potentially risky commands (curl/wget/base64/scripting)"
      fi
    done
    echo ""
  fi
}

collect_persistence() {
  header "4. PERSISTENCE MECHANISMS (LaunchD, Cron, Periodic)"
  
  list_launchd_dir "$HOME/Library/LaunchAgents" full
  list_launchd_dir "/Library/LaunchAgents" full
  list_launchd_dir "/Library/LaunchDaemons" full
  list_launchd_dir "/System/Library/LaunchAgents" summary
  list_launchd_dir "/System/Library/LaunchDaemons" summary
  
  # Currently loaded launch jobs
  subheader "Currently Loaded LaunchD Jobs"
  launchctl list | head -100
  echo ""
  note "Full list may be very long. Showing first 100."
  
  # Cron
  subheader "User Crontab"
  crontab -l 2>/dev/null || echo "No user crontab or insufficient permissions"
  echo ""
  
  if is_root; then
    subheader "System Crontabs"
    for f in /etc/crontab /var/at/tabs/*; do
      if [[ -f "$f" ]]; then
        echo "File: $f"
        cat "$f" 2>/dev/null | head -20
        echo ""
      fi
    done
  fi
  
  # Periodic
  cmd "Periodic Scripts" sh -c 'find /etc/periodic -type f 2>/dev/null'
}

collect_profiles_and_mdm() {
  header "5. CONFIGURATION PROFILES & MDM"
  
  if ! exists profiles; then
    warn "profiles command not found (unexpected on modern macOS)"
    return
  fi
  
  cmd "Profile Status & MDM Enrollment" profiles status
  cmd "Installed Configuration Profiles" profiles list -verbose
  
  note "Check for unexpected profiles. MDM profiles control device policy."
  note "Malicious profiles can enforce proxy settings, install root CAs, etc."
}

collect_system_extensions() {
  header "6. SYSTEM EXTENSIONS & KERNEL EXTENSIONS"
  
  cmd "System Extensions" systemextensionsctl list
  
  if exists kextstat; then
    subheader "Loaded Kernel Extensions"
    kextstat | head -50
    echo ""
    note "Full kext list may be very long. Showing first 50."
  fi
  
  subheader "Installed Kernel Extensions"
  if [[ -d /Library/Extensions ]]; then
    ls -la /Library/Extensions/*.kext 2>/dev/null | head -30
    echo ""
  fi
  if [[ -d /System/Library/Extensions ]]; then
    echo "System kexts (partial list):"
    ls /System/Library/Extensions/*.kext 2>/dev/null | head -20
    echo ""
  fi
}

collect_apps_and_signing() {
  header "7. APPLICATIONS & CODE SIGNING"
  
  subheader "Recently Installed Packages (via receipts)"
  ls -lt /var/db/receipts/*.bom 2>/dev/null | head -30 || echo "No receipts found"
  echo ""
  
  # Quarantine check
  subheader "Quarantine Attributes on Downloads"
  if [[ -d "$HOME/Downloads" ]]; then
    echo "Files with com.apple.quarantine xattr in ~/Downloads:"
    find "$HOME/Downloads" -maxdepth 1 -type f -exec sh -c 'xattr -l "$1" 2>/dev/null | grep -q "com.apple.quarantine" && echo "$1"' _ {} \; | head -20
    echo ""
  fi
  
  # App signing verification
  if ! $QUICK_MODE && exists codesign && exists spctl; then
    subheader "Application Signing Verification"
    
    for appdir in "/Applications" "$HOME/Applications"; do
      [[ -d "$appdir" ]] || continue
      
      echo ""
      echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
      echo "Checking applications in: $appdir"
      echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
      
      for app in "$appdir"/*.app(N); do
        [[ -d "$app" ]] || continue
        
        echo ""
        echo "--- $(basename "$app") ---"
        
        # Gatekeeper assessment
        local spctl_result=$(spctl -a -vv "$app" 2>&1)
        echo "$spctl_result"
        
        if echo "$spctl_result" | grep -q "accepted"; then
          echo "✓ Gatekeeper: Accepted"
        else
          echo "✗ Gatekeeper: REJECTED or unsigned"
        fi
        
        # Code signing details
        local codesign_result=$(codesign -dv --verbose=4 "$app" 2>&1)
        echo ""
        echo "Code Signing Details:"
        echo "$codesign_result" | head -15
        
        # Flag unsigned or ad-hoc signed
        if echo "$codesign_result" | grep -q "Signature=adhoc"; then
          echo "⚠️  Ad-hoc signed (not from App Store or identified developer)"
        fi
      done
    done
  else
    note "Skipping detailed app signing checks (use without --quick for full scan)"
  fi
}

collect_tcc_permissions() {
  header "8. PRIVACY PERMISSIONS (TCC Database)"
  
  note "Requires Terminal to have Full Disk Access"
  note "Key services: kTCCServiceScreenCapture, kTCCServiceAccessibility,"
  note "              kTCCServiceSystemPolicyAllFiles, kTCCServiceListenEvent"
  
  if ! exists sqlite3; then
    warn "sqlite3 not found, cannot query TCC databases"
    return
  fi
  
  # User TCC
  local user_tcc="$HOME/Library/Application Support/com.apple.TCC/TCC.db"
  subheader "User TCC Database: $user_tcc"
  
  if [[ -f "$user_tcc" ]]; then
    echo "Recent permissions (last 100):"
    sqlite3 "$user_tcc" "
      SELECT 
        service, 
        client, 
        auth_value,
        auth_reason,
        datetime(last_modified, 'unixepoch') as last_modified
      FROM access 
      ORDER BY last_modified DESC 
      LIMIT 100;
    " 2>&1 || echo "Failed to query user TCC database"
    echo ""
    
    echo "High-risk permissions granted:"
    sqlite3 "$user_tcc" "
      SELECT service, client, auth_value 
      FROM access 
      WHERE service IN (
        'kTCCServiceScreenCapture',
        'kTCCServiceAccessibility', 
        'kTCCServiceSystemPolicyAllFiles',
        'kTCCServiceListenEvent',
        'kTCCServicePostEvent'
      ) AND auth_value = 2;
    " 2>&1 || echo "Query failed"
    echo ""
  else
    echo "User TCC database not found"
    echo ""
  fi
  
  # System TCC
  local sys_tcc="/Library/Application Support/com.apple.TCC/TCC.db"
  subheader "System TCC Database: $sys_tcc"
  
  if [[ -f "$sys_tcc" ]]; then
    echo "Recent permissions (last 100):"
    sqlite3 "$sys_tcc" "
      SELECT 
        service, 
        client, 
        auth_value,
        auth_reason,
        datetime(last_modified, 'unixepoch') as last_modified
      FROM access 
      ORDER BY last_modified DESC 
      LIMIT 100;
    " 2>&1 || echo "Failed to query system TCC database (may need root + FDA)"
    echo ""
    
    echo "High-risk permissions granted:"
    sqlite3 "$sys_tcc" "
      SELECT service, client, auth_value 
      FROM access 
      WHERE service IN (
        'kTCCServiceScreenCapture',
        'kTCCServiceAccessibility',
        'kTCCServiceSystemPolicyAllFiles',
        'kTCCServiceListenEvent',
        'kTCCServicePostEvent'
      ) AND auth_value = 2;
    " 2>&1 || echo "Query failed"
    echo ""
  else
    echo "System TCC database not found or not accessible"
    echo ""
  fi
}

collect_network_and_processes() {
  header "9. NETWORK CONNECTIONS & RUNNING PROCESSES"
  
  subheader "Top Processes by CPU"
  ps -axo pid,ppid,user,%cpu,%mem,start,time,command | head -1
  ps -axo pid,ppid,user,%cpu,%mem,start,time,command | sort -k4 -nr | head -30
  echo ""
  
  subheader "Top Processes by Memory"
  ps -axo pid,ppid,user,%cpu,%mem,start,time,command | head -1
  ps -axo pid,ppid,user,%cpu,%mem,start,time,command | sort -k5 -nr | head -30
  echo ""
  
  if exists lsof; then
    subheader "Active Network Connections (lsof -i)"
    lsof -i -n -P 2>/dev/null | head -200 || echo "lsof failed or insufficient permissions"
    echo ""
  fi
  
  if exists netstat; then
    subheader "Listening Ports"
    netstat -anv | grep LISTEN | head -100
    echo ""
  fi
  
  if exists scutil; then
    cmd "DNS Configuration" scutil --dns
  fi
  
  # Hosts file
  subheader "Hosts File (/etc/hosts)"
  cat /etc/hosts 2>/dev/null | grep -v "^#" | grep -v "^$"
  echo ""
}

collect_browser_extensions() {
  header "10. BROWSER EXTENSIONS & SETTINGS"
  
  subheader "Safari Extensions"
  if [[ -f "$HOME/Library/Safari/Extensions/Extensions.plist" ]]; then
    plutil -p "$HOME/Library/Safari/Extensions/Extensions.plist" 2>/dev/null || echo "Cannot read Extensions.plist"
  else
    echo "No Safari extensions plist found"
  fi
  echo ""
  
  subheader "Chromium-Based Browser Extension Directories"
  for browser_path in \
    "$HOME/Library/Application Support/Google/Chrome" \
    "$HOME/Library/Application Support/Chromium" \
    "$HOME/Library/Application Support/BraveSoftware/Brave-Browser" \
    "$HOME/Library/Application Support/Microsoft Edge" \
    "$HOME/Library/Application Support/Vivaldi"
  do
    if [[ -d "$browser_path" ]]; then
      echo ""
      echo "Browser: $(basename "$(dirname "$browser_path")")/$(basename "$browser_path")"
      echo "Extension directories:"
      find "$browser_path" -maxdepth 4 -type d -name "Extensions" 2>/dev/null | while read ext_dir; do
        echo "  $ext_dir"
        # List extension IDs
        ls -1 "$ext_dir" 2>/dev/null | grep -v "Temp" | sed 's/^/    /'
      done
    fi
  done
  echo ""
  
  note "For detailed extension analysis, inspect manifest.json in each extension folder"
}

collect_logs() {
  header "11. SECURITY-RELEVANT LOGS"
  
  if ! exists log; then
    warn "log command not found (unusual on modern macOS)"
    return
  fi
  
  if $QUICK_MODE; then
    note "Skipping log collection in quick mode"
    return
  fi
  
  note "Log collection can be slow. Limiting to last 7 days."
  
  cmd "Gatekeeper Assessment Events (last 7 days)" \
    log show --style syslog --predicate 'subsystem == "com.apple.security.assessment"' --last 7d
  
  cmd "XProtect Events (last 7 days)" \
    log show --style syslog --predicate 'eventMessage CONTAINS[c] "XProtect" OR eventMessage CONTAINS[c] "MRT"' --last 7d
  
  cmd "TCC Permission Events (last 7 days)" \
    log show --style syslog --predicate 'eventMessage CONTAINS[c] "TCC"' --last 7d
  
  cmd "Authentication Events (last 7 days)" \
    log show --style syslog --predicate 'process == "authd" OR process == "SecurityAgent"' --last 7d
}

generate_summary() {
  header "12. AUDIT SUMMARY & RECOMMENDATIONS"
  
  cat <<'EOF'
HIGH-VALUE SECURITY INDICATORS:

🔴 Critical Issues to Investigate:
  • SIP or Gatekeeper disabled
  • FileVault encryption disabled
  • Unknown apps with dangerous TCC permissions:
    - Screen Recording (kTCCServiceScreenCapture)
    - Accessibility (kTCCServiceAccessibility)
    - Full Disk Access (kTCCServiceSystemPolicyAllFiles)
    - Input Monitoring (kTCCServiceListenEvent)
  • Unsigned or ad-hoc signed applications
  • Unknown Configuration Profiles (especially MDM)
  • Suspicious LaunchAgents/Daemons with:
    - curl/wget + shell scripts
    - Base64 encoded blobs
    - Unusual paths (/tmp/, hidden directories)
    - KeepAlive + RunAtLoad for persistence

🟡 Medium Priority:
  • Firewall disabled or not in stealth mode
  • Unexpected network connections from unknown processes
  • Unknown system extensions or kernel extensions
  • Browser extensions from untrusted sources
  • Failed login attempts from unusual sources

🟢 Best Practices:
  • Enable and maintain FileVault encryption
  • Keep SIP and Gatekeeper enabled
  • Enable Application Firewall with stealth mode
  • Enable automatic security updates
  • Regularly review TCC permissions
  • Audit LaunchAgents/Daemons quarterly
  • Remove unnecessary Login Items
  • Keep macOS and applications updated

NEXT STEPS:
  1. Review this report for red flags mentioned above
  2. Create a baseline of expected LaunchAgents, TCC permissions, and apps
  3. Run this audit monthly and diff against baseline
  4. Remove unnecessary permissions and persistence items
  5. For enterprise: Consider MDM solution for policy enforcement

TOOLS FOR DEEPER ANALYSIS:
  • KnockKnock (Objective-See) - Persistent process scanner
  • BlockBlock (Objective-See) - Persistence monitor
  • LuLu (Objective-See) - Firewall with process monitoring
  • ReiKey (Objective-See) - Keylogger detection
  • OverSight (Objective-See) - Camera/microphone monitor

EOF
}

# --- Main Execution ---
main() {
  print_color "$CYAN" "Starting macOS Security Audit..."
  print_color "$CYAN" "Output: $OUT"
  echo ""
  
  {
    write_intro
    collect_security_posture
    collect_users_and_admins
    collect_login_items
    collect_persistence
    collect_profiles_and_mdm
    collect_system_extensions
    collect_apps_and_signing
    collect_tcc_permissions
    collect_network_and_processes
    collect_browser_extensions
    
    if ! $QUICK_MODE; then
      collect_logs
    fi
    
    generate_summary
    
    echo ""
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo "AUDIT COMPLETE"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo "Report saved to: $OUT"
    echo "Generated: $(date)"
    echo ""
    
  } | tee "$OUT"
  
  print_color "$GREEN" "✓ Audit complete! Report saved to:"
  print_color "$YELLOW" "  $OUT"
  echo ""
  print_color "$CYAN" "Review the report for security issues and compare against your baseline."
}

# Run the audit
main
