#!/bin/bash

set -e

# -----------------------------
# CONFIGURATION
# -----------------------------
LOG_DIR="$HOME/firewall_logs"
mkdir -p "$LOG_DIR"

STORAGE_ACCOUNT="gvkplatformstorage"
CONTAINER_NAME="ip-adding"
# Optional: export AZURE_STORAGE_CONNECTION_STRING="..."

# -----------------------------
# FUNCTION: Get Monthly Log File
# -----------------------------
get_log_filename() {
  today_day=$(date +%d)
  if [ "$today_day" -ge 20 ]; then
    start_date=$(date +%Y-%m-20 | xargs date +%d-%m-%Y -d)
    end_date=$(date -d "20 next month -1 day" +%d-%m-%Y)
  else
    start_date=$(date -d "20 last month" +%d-%m-%Y)
    end_date=$(date -d "19 this month" +%d-%m-%Y)
  fi
  echo "${start_date}_to_${end_date}.log"
}

# -----------------------------
# MODE: Upload Only
# -----------------------------
if [ "$1" == "upload-only" ]; then
    echo "📤 Uploading monthly log files to Azure Blob Storage..."
    for env_file in "$LOG_DIR"/*_$(date +'%d-%m-%Y')*.log; do
        [ -f "$env_file" ] || continue
        echo "Uploading $env_file ..."
        az storage blob upload \
          --account-name "$STORAGE_ACCOUNT" \
          --container-name "$CONTAINER_NAME" \
          --file "$env_file" \
          --name "$(basename "$env_file")" \
          --overwrite
        echo "✅ Uploaded $(basename "$env_file")"
    done
    exit 0
fi

# -----------------------------
# NORMAL MODE: Add Firewall IP
# -----------------------------
if ! command -v az &> /dev/null; then
  echo "❌ Required dependency 'az' is not installed."
  exit 1
fi

validate_ip_cidr() {
  local ip_cidr="$1"
  if [[ ! "$ip_cidr" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}(/([0-9]|[1-2][0-9]|3[0-2]))?$ ]]; then
    echo "❌ Invalid IP format"; return 1
  fi
  IFS='/' read -r ip cidr <<< "$ip_cidr"
  IFS='.' read -r -a octets <<< "$ip"
  for octet in "${octets[@]}"; do
    if [[ $octet -lt 0 || $octet -gt 255 ]]; then echo "❌ Invalid IP octet"; return 1; fi
  done
  [[ -z "$cidr" ]] && cidr=32
  [[ $cidr -lt 0 || $cidr -gt 32 ]] && { echo "❌ Invalid CIDR"; return 1; }
  echo "$ip_cidr"
}

sanitize_ip_cidr() {
  local ip_cidr=$(echo "$1" | tr -d ' ;')
  [[ "$ip_cidr" =~ / ]] || ip_cidr="${ip_cidr}/32"
  validate_ip_cidr "$ip_cidr"
}

log_action() {
  local ip="$1" local developer="$2" local env="$3" local status="$4" local rule_name="$5"

  MONTHLY_FILE="$LOG_DIR/${env}_$(get_log_filename)"
  mkdir -p "$(dirname "$MONTHLY_FILE")"
  [ ! -f "$MONTHLY_FILE" ] && echo "IP,Developer,Environment,Status,RuleName" >> "$MONTHLY_FILE"
  echo "$ip,$developer,$env,$status,$rule_name" >> "$MONTHLY_FILE"
}

main() {
  local RESOURCE_GROUP="$1" local SERVER_NAME="$2" local USER_IP="$3" local DEVELOPER="$4" local ENVIRONMENT="$5"

  if [ -z "$RESOURCE_GROUP" ] || [ -z "$SERVER_NAME" ] || [ -z "$USER_IP" ] || [ -z "$DEVELOPER" ] || [ -z "$ENVIRONMENT" ]; then
    echo "❌ Missing arguments"; exit 1
  fi

  VALIDATED_IP=$(sanitize_ip_cidr "$USER_IP") || { log_action "$USER_IP" "$DEVELOPER" "$ENVIRONMENT" "Failed" "N/A"; exit 1; }

  IFS='/' read -r start_ip cidr <<< "$VALIDATED_IP"
  END_IP="$start_ip"
  RULE_NAME="DevOpsAccess_${start_ip//./-}"

  EXISTING_RULE=$(az sql server firewall-rule list \
    --resource-group "$RESOURCE_GROUP" \
    --server "$SERVER_NAME" \
    --query "[?startIpAddress=='$start_ip' && endIpAddress=='$END_IP'].name" \
    -o tsv)

  if [ -n "$EXISTING_RULE" ]; then
    echo "⚠ IP $start_ip already exists in rule $EXISTING_RULE"
    log_action "$VALIDATED_IP" "$DEVELOPER" "$ENVIRONMENT" "AlreadyExists" "$EXISTING_RULE"
    exit 0
  fi

  echo "📝 Adding firewall rule for IP '$VALIDATED_IP'..."
  az sql server firewall-rule create \
    --resource-group "$RESOURCE_GROUP" \
    --server "$SERVER_NAME" \
    --name "$RULE_NAME" \
    --start-ip-address "$start_ip" \
    --end-ip-address "$END_IP"

  echo "✅ Added IP '$VALIDATED_IP' to server '$SERVER_NAME'"
  log_action "$VALIDATED_IP" "$DEVELOPER" "$ENVIRONMENT" "Success" "$RULE_NAME"

  echo "📍 Current firewall rules:"
  az sql server firewall-rule list --resource-group "$RESOURCE_GROUP" --server "$SERVER_NAME" --output table
}

main "$@"
