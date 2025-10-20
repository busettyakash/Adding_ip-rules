#!/bin/bash

set -e

# Check for required dependency
if ! command -v az &> /dev/null; then
  echo "❌ Required dependency 'az' is not installed."
  exit 1
fi

# Directory for storing logs
LOG_DIR="${HOME}/firewall_logs"
mkdir -p "$LOG_DIR"

# Validate IP with optional CIDR
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
  return 0
}

sanitize_ip_cidr() {
  local ip_cidr="$1"
  ip_cidr=$(echo "$ip_cidr" | tr -d ' ;')
  [[ ! "$ip_cidr" =~ / ]] && ip_cidr="${ip_cidr}/32"
  validate_ip_cidr "$ip_cidr"
}

# Main logic
main() {
  local ENV="$1"              # dev, qa, prod
  local RESOURCE_GROUP="$2"
  local SERVER_NAME="$3"
  local USER_IP="$4"

  if [ -z "$ENV" ] || [ -z "$RESOURCE_GROUP" ] || [ -z "$SERVER_NAME" ] || [ -z "$USER_IP" ]; then
    echo "❌ Missing arguments: ENV RESOURCE_GROUP SERVER_NAME USER_IP"
    exit 1
  fi

  # Determine monthly log file
  DAY=$(date +%d)
  MONTH=$(date +%Y-%m)
  if [ "$DAY" -ge 20 ]; then
    LOG_FILE="$LOG_DIR/${ENV}_firewall_${MONTH}-20.log"
  else
    LOG_FILE="$LOG_DIR/${ENV}_firewall_${MONTH}.log"
  fi
  touch "$LOG_FILE"

  # Sanitize IP
  VALIDATED_IP=$(sanitize_ip_cidr "$USER_IP") || { echo "❌ IP validation failed"; exit 1; }
  IFS='/' read -r START_IP CIDR <<< "$VALIDATED_IP"
  END_IP="$START_IP"

  # Check existing firewall rules
  EXISTING_RULES=$(az sql server firewall-rule list \
    --resource-group "$RESOURCE_GROUP" \
    --server "$SERVER_NAME" \
    --query "[].{name:name, start:startIpAddress, end:endIpAddress}" -o tsv)
  
  DUPLICATE=$(echo "$EXISTING_RULES" | awk -v start="$START_IP" -v end="$END_IP" '$2==start && $3==end {print $1}')
  if [ -n "$DUPLICATE" ]; then
    echo "⚠️ IP '$VALIDATED_IP' already exists as rule '$DUPLICATE'. Skipping."
    exit 0
  fi

  # Create new firewall rule
  RULE_NAME="DevOpsAccess_$(date +%Y%m%d_%H%M%S)"
  echo "📝 Adding firewall rule for IP '$VALIDATED_IP'..."
  az sql server firewall-rule create \
    --resource-group "$RESOURCE_GROUP" \
    --server "$SERVER_NAME" \
    --name "$RULE_NAME" \
    --start-ip-address "$START_IP" \
    --end-ip-address "$END_IP"

  echo "✅ Added IP '$VALIDATED_IP' to server '$SERVER_NAME'"

  # Append to env log file
  echo "$(date '+%Y-%m-%d %H:%M:%S') | $SERVER_NAME | $VALIDATED_IP | $RULE_NAME" >> "$LOG_FILE"
  echo "🗒️ Logged IP to file: $LOG_FILE"

  # Display current firewall rules
  az sql server firewall-rule list \
    --resource-group "$RESOURCE_GROUP" \
    --server "$SERVER_NAME" \
    --output table
}

main "$@"
