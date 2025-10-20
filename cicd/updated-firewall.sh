#!/bin/bash

set -e

# Check for required dependency
if ! command -v az &> /dev/null; then
  echo "❌ Required dependency 'az' is not installed. Please install it first."
  exit 1
fi

# Function to validate IP address with CIDR notation
validate_ip_cidr() {
  local ip_cidr="$1"
  
  if [[ ! "$ip_cidr" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}(/([0-9]|[1-2][0-9]|3[0-2]))?$ ]]; then
    echo "❌ Invalid IP address format. Use a valid IP with optional CIDR (e.g., 192.168.1.1 or 192.168.1.0/24)."
    return 1
  fi
  
  IFS='/' read -r ip cidr <<< "$ip_cidr"
  IFS='.' read -r -a octets <<< "$ip"
  for octet in "${octets[@]}"; do
    if [[ $octet -lt 0 || $octet -gt 255 ]]; then
      echo "❌ Invalid IP address. Octets must be 0-255."
      return 1
    fi
  done

  if [[ -z "$cidr" ]]; then
    cidr=32
  fi

  if [[ $cidr -lt 0 || $cidr -gt 32 ]]; then
    echo "❌ Invalid CIDR. Must be /0 to /32."
    return 1
  fi

  echo "$ip_cidr"
  return 0
}

# Sanitize and validate IP input
sanitize_ip_cidr() {
  local ip_cidr="$1"
  ip_cidr=$(echo "$ip_cidr" | tr -d ' ;')
  if [[ ! "$ip_cidr" =~ / ]]; then
    ip_cidr="${ip_cidr}/32"
  fi
  validate_ip_cidr "$ip_cidr"
}

# Main script logic
main() {
  # Required arguments
  local RESOURCE_GROUP="$1"
  local DEVELOPER_NAME="$2"
  local USER_IP="$3"

  shift 3

  if [ -z "$RESOURCE_GROUP" ] || [ -z "$DEVELOPER_NAME" ] || [ -z "$USER_IP" ]; then
    echo "❌ Missing arguments: RESOURCE_GROUP, DEVELOPER_NAME, USER_IP"
    exit 1
  fi

  # Sanitize and validate IP
  VALIDATED_IP=$(sanitize_ip_cidr "$USER_IP")
  if [ $? -ne 0 ]; then
    echo "❌ IP validation failed"
    exit 1
  fi

  IFS='/' read -r START_IP cidr <<< "$VALIDATED_IP"
  if [[ "$cidr" == "32" ]]; then
    END_IP="$START_IP"
  else
    # For simplicity, using start IP as end IP for CIDR ranges
    END_IP="$START_IP"
  fi

  # Check for duplicates
  EXISTING_IPS=$(az sql server firewall-rule list \
    --resource-group "$RESOURCE_GROUP" \
    --server "$SERVER_NAME" \
    --query "[].{start:startIpAddress,end:endIpAddress}" -o tsv)

  while read -r s e; do
    if [[ "$START_IP" == "$s" ]] && [[ "$END_IP" == "$e" ]]; then
      echo "⚠️ IP '$VALIDATED_IP' already exists in firewall rules. Skipping..."
      exit 0
    fi
  done <<< "$EXISTING_IPS"

  # Generate unique rule name
  RULE_NAME="${DEVELOPER_NAME}_Access_$(date +%Y%m%d_%H%M%S)"

  # Add firewall rule
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

# Call main with arguments
main "$@"
