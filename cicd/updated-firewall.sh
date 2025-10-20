#!/bin/bash

set -e

# -----------------------------
# CHECK DEPENDENCY
# -----------------------------
if ! command -v az &> /dev/null; then
  echo "❌ Required dependency 'az' is not installed. Please install it first."
  exit 1
fi

# -----------------------------
# FUNCTION: Validate IP with optional CIDR
# -----------------------------
validate_ip_cidr() {
  local ip_cidr="$1"

  if [[ ! "$ip_cidr" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}(/([0-9]|[1-2][0-9]|3[0-2]))?$ ]]; then
    echo "❌ Invalid IP address format. Use a valid IP with optional CIDR (e.g., 192.168.1.1 or 192.168.1.0/24)."
    exit 1
  fi

  IFS='/' read -r ip cidr <<< "$ip_cidr"
  IFS='.' read -r -a octets <<< "$ip"
  for octet in "${octets[@]}"; do
    if [[ $octet -lt 0 || $octet -gt 255 ]]; then
      echo "❌ Invalid IP address. Octets must be 0-255."
      exit 1
    fi
  done

  if [[ -z "$cidr" ]]; then
    cidr=32
  fi

  if [[ $cidr -lt 0 || $cidr -gt 32 ]]; then
    echo "❌ Invalid CIDR. Must be /0 to /32."
    exit 1
  fi

  echo "$ip/$cidr"
}

# -----------------------------
# FUNCTION: Sanitize IP input
# -----------------------------
sanitize_ip_cidr() {
  local ip_cidr="$1"
  ip_cidr=$(echo "$ip_cidr" | tr -d ' ;')
  if [[ ! "$ip_cidr" =~ / ]]; then
    ip_cidr="${ip_cidr}/32"
  fi
  validate_ip_cidr "$ip_cidr"
}

# -----------------------------
# MAIN SCRIPT
# -----------------------------
main() {
  local RESOURCE_GROUP="$1"
  local SERVER_NAME="$2"
  local DEVELOPER_NAME="$3"
  local USER_IP="$4"

  # Require all 4 arguments
  if [ -z "$RESOURCE_GROUP" ] || [ -z "$SERVER_NAME" ] || [ -z "$DEVELOPER_NAME" ] || [ -z "$USER_IP" ]; then
    echo "❌ Missing required arguments: RESOURCE_GROUP, SERVER_NAME, DEVELOPER_NAME, USER_IP"
    exit 1
  fi

  # Sanitize and validate IP
  VALIDATED_IP=$(sanitize_ip_cidr "$USER_IP")
  IFS='/' read -r START_IP CIDR <<< "$VALIDATED_IP"

  # Use start IP as end IP for simplicity
  END_IP="$START_IP"

  # -----------------------------
  # CHECK FOR DUPLICATES (Warning only)
  # -----------------------------
  EXISTING_IPS=$(az sql server firewall-rule list \
    --resource-group "$RESOURCE_GROUP" \
    --server "$SERVER_NAME" \
    --query "[].startIpAddress" -o tsv)

  for EXISTING_IP in $EXISTING_IPS; do
    if [[ "$START_IP" == "$EXISTING_IP" ]]; then
      echo "⚠️ Warning: IP '$START_IP' is already whitelisted. Skipping addition..."
      exit 0  # Exit gracefully for duplicate
    fi
  done

  # -----------------------------
  # ADD FIREWALL RULE
  # -----------------------------
  RULE_NAME="${DEVELOPER_NAME}_Access_$(date +%Y%m%d_%H%M%S)"

  echo "📝 Adding firewall rule for IP '$VALIDATED_IP'..."
  az sql server firewall-rule create \
    --resource-group "$RESOURCE_GROUP" \
    --server "$SERVER_NAME" \
    --name "$RULE_NAME" \
    --start-ip-address "$START_IP" \
    --end-ip-address "$END_IP"

  echo "✅ Successfully added IP '$VALIDATED_IP' to server '$SERVER_NAME'"

  # Display current firewall rules
  echo "📍 Current firewall rules:"
  az sql server firewall-rule list \
    --resource-group "$RESOURCE_GROUP" \
    --server "$SERVER_NAME" \
    --output table
}

# -----------------------------
# CALL MAIN
# -----------------------------
main "$@"
