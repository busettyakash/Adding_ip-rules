#!/bin/bash
set -e

# ---------------------------
# Check dependencies
# ---------------------------
if ! command -v az &> /dev/null; then
  echo "❌ Required dependency 'az' is not installed."
  exit 1
fi

# ---------------------------
# Default log directory
# ---------------------------
LOG_DIR="${HOME}/firewall_logs"
mkdir -p "$LOG_DIR"

# ---------------------------
# Functions
# ---------------------------
validate_ip_cidr() {
  local ip_cidr="$1"
  if [[ ! "$ip_cidr" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}(/([0-9]|[1-2][0-9]|3[0-2]))?$ ]]; then
    echo "❌ Invalid IP. Use 192.168.1.1 or 192.168.1.0/24."
    return 1
  fi
  IFS='/' read -r ip cidr <<< "$ip_cidr"
  IFS='.' read -r -a octets <<< "$ip"
  for octet in "${octets[@]}"; do
    if [[ $octet -lt 0 || $octet -gt 255 ]]; then
      echo "❌ Octets must be 0-255."
      return 1
    fi
  done
  [[ -z "$cidr" ]] && cidr=32
  [[ $cidr -lt 0 || $cidr -gt 32 ]] && { echo "❌ CIDR must be /0-32."; return 1; }
  echo "$ip_cidr"
}

sanitize_ip_cidr() {
  local ip_cidr="$1"
  ip_cidr=$(echo "$ip_cidr" | tr -d ' ;')
  [[ ! "$ip_cidr" =~ / ]] && ip_cidr="${ip_cidr}/32"
  validate_ip_cidr "$ip_cidr"
}

print_usage() {
  echo "Usage: $0 --env <dev|qa|prod> --rg <resource-group> --server <server-name> --ip <IP-address> --dev <developer-name>"
  exit 1
}

# ---------------------------
# Parse named arguments
# ---------------------------
while [[ $# -gt 0 ]]; do
  case "$1" in
    --env) ENV="$2"; shift 2 ;;
    --rg) RESOURCE_GROUP="$2"; shift 2 ;;
    --server) SERVER_NAME="$2"; shift 2 ;;
    --ip) USER_IP="$2"; shift 2 ;;
    --dev) DEVELOPER_NAME="$2"; shift 2 ;;
    *) echo "Unknown option $1"; print_usage ;;
  esac
done

# ---------------------------
# Validate required arguments
# ---------------------------
if [ -z "$ENV" ] || [ -z "$RESOURCE_GROUP" ] || [ -z "$SERVER_NAME" ] || [ -z "$USER_IP" ] || [ -z "$DEVELOPER_NAME" ]; then
  echo "❌ Missing required arguments."
  print_usage
fi

# ---------------------------
# Determine monthly log file
# ---------------------------
DAY=$(date +%d)
MONTH=$(date +%Y-%m)
if [ "$DAY" -ge 20 ]; then
  LOG_FILE="$LOG_DIR/${ENV}_firewall_${MONTH}-20.log"
else
  LOG_FILE="$LOG_DIR/${ENV}_firewall_${MONTH}.log"
fi
mkdir -p "$(dirname "$LOG_FILE")"
touch "$LOG_FILE"

# ---------------------------
# Sanitize IP
# ---------------------------
VALIDATED_IP=$(sanitize_ip_cidr "$USER_IP") || { echo "❌ IP validation failed"; exit 1; }
IFS='/' read -r START_IP CIDR <<< "$VALIDATED_IP"
END_IP="$START_IP"

# ---------------------------
# Check existing firewall rules
# ---------------------------
EXISTING_RULES=$(az sql server firewall-rule list \
  --resource-group "$RESOURCE_GROUP" \
  --server "$SERVER_NAME" \
  --query "[].{name:name, start:startIpAddress, end:endIpAddress}" -o tsv)

DUPLICATE=$(echo "$EXISTING_RULES" | awk -v start="$START_IP" -v end="$END_IP" '$2==start && $3==end {print $1}')
if [ -n "$DUPLICATE" ]; then
  echo "⚠️ IP '$VALIDATED_IP' already exists as rule '$DUPLICATE'. Skipping."
  exit 0
fi

# ---------------------------
# Add firewall rule with ENV prefix
# ---------------------------
RULE_NAME="DevOpsAccess_${ENV}_$(date +%Y%m%d_%H%M%S)"
echo "📝 Adding firewall rule '$RULE_NAME' for IP '$VALIDATED_IP'..."
az sql server firewall-rule create \
  --resource-group "$RESOURCE_GROUP" \
  --server "$SERVER_NAME" \
  --name "$RULE_NAME" \
  --start-ip-address "$START_IP" \
  --end-ip-address "$END_IP"

echo "✅ Added IP '$VALIDATED_IP' to server '$SERVER_NAME'"

# ---------------------------
# Append to log file
# ---------------------------
echo "$(date '+%Y-%m-%d %H:%M:%S') | $SERVER_NAME | $VALIDATED_IP | $RULE_NAME | $DEVELOPER_NAME" >> "$LOG_FILE"
echo "🗒️ Logged IP to file: $LOG_FILE"

# ---------------------------
# Display current monthly log for this environment
# ---------------------------
echo "📂 Current IPs in $LOG_FILE for environment '$ENV':"
if [ -s "$LOG_FILE" ]; then
  cat "$LOG_FILE"
else
  echo "- No IPs added yet for this month."
fi

# ---------------------------
# Show current firewall rules
# ---------------------------
az sql server firewall-rule list \
  --resource-group "$RESOURCE_GROUP" \
  --server "$SERVER_NAME" \
  --output table
