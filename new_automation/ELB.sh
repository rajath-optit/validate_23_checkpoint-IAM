#!/bin/bash

# Set strict error handling
set -euo pipefail

# Global variables
readonly SCRIPT_NAME=$(basename "$0")
readonly TIMESTAMP=$(date +%Y%m%d_%H%M%S)
readonly LOG_FILE="/var/log/elb-compliance-${TIMESTAMP}.log"
readonly REPORT_FILE="/var/log/elb-compliance-report-${TIMESTAMP}.csv"
readonly MAX_RETRIES=3
readonly REQUIRED_COMMANDS="aws jq date csvkit"

# Color codes for output
readonly RED='\033[0;31m'
readonly GREEN='\033[0;32m'
readonly YELLOW='\033[1;33m'
readonly NC='\033[0m' # No Color

# Statistics tracking
declare -A CONTROL_STATUS
declare -A CHANGES_MADE
declare -i TOTAL_RESOURCES=0
declare -i COMPLIANT_RESOURCES=0
declare -i UPDATED_RESOURCES=0
declare -i ERRORS=0

# Initialize report file
initialize_report() {
    echo "Resource ARN,Control,Initial Status,Action Taken,Final Status,Changes Made" > "$REPORT_FILE"
}

# Enhanced logging functions
log() {
    echo -e "[$(date +'%Y-%m-%d %H:%M:%S')] [INFO] $*" | tee -a "$LOG_FILE"
}

warn() {
    echo -e "[$(date +'%Y-%m-%d %H:%M:%S')] [${YELLOW}WARN${NC}] $*" | tee -a "$LOG_FILE"
}

error() {
    echo -e "[$(date +'%Y-%m-%d %H:%M:%S')] [${RED}ERROR${NC}] $*" | tee -a "$LOG_FILE"
    ((ERRORS++))
}

success() {
    echo -e "[$(date +'%Y-%m-%d %H:%M:%S')] [${GREEN}SUCCESS${NC}] $*" | tee -a "$LOG_FILE"
}

# Function to validate ARN
validate_arn() {
    local arn="$1"
    if [[ ! "$arn" =~ ^arn:aws:elasticloadbalancing:[a-z0-9-]+:[0-9]+:loadbalancer/ ]]; then
        error "Invalid ELB ARN format: $arn"
        return 1
    fi
    return 0
}

# Enhanced retry function with status tracking
retry_command() {
    local cmd="$1"
    local resource="$2"
    local control="$3"
    local attempt=1

    while ((attempt <= MAX_RETRIES)); do
        if eval "$cmd"; then
            success "Command succeeded for $control on $resource (attempt $attempt)"
            CHANGES_MADE["$resource:$control"]="Success on attempt $attempt"
            return 0
        fi
        
        warn "Attempt $attempt failed for $control on $resource, retrying..."
        sleep $((2 ** attempt))
        ((attempt++))
    done

    error "Command failed after $MAX_RETRIES attempts for $control on $resource"
    CHANGES_MADE["$resource:$control"]="Failed after $MAX_RETRIES attempts"
    return 1
}

# Check and enforce single control
check_control() {
    local resource="$1"
    local control="$2"
    local initial_status
    local final_status
    
    case "$control" in
        "desync_mitigation")
            initial_status=$(aws elbv2 describe-load-balancer-attributes \
                --load-balancer-arn "$resource" \
                --query "Attributes[?Key=='routing.http.desync_mitigation_mode'].Value" \
                --output text)
            
            if [[ "$initial_status" != "defensive" && "$initial_status" != "strictest" ]]; then
                warn "Fixing desync mitigation mode for $resource"
                if retry_command "aws elbv2 modify-load-balancer-attributes \
                    --load-balancer-arn $resource \
                    --attributes Key=routing.http.desync_mitigation_mode,Value=defensive" "$resource" "$control"; then
                    final_status="compliant"
                else
                    final_status="failed"
                fi
            else
                final_status="already_compliant"
            fi
            ;;
            
        "deletion_protection")
            initial_status=$(aws elbv2 describe-load-balancer-attributes \
                --load-balancer-arn "$resource" \
                --query "Attributes[?Key=='deletion_protection.enabled'].Value" \
                --output text)
            
            if [[ "$initial_status" != "true" ]]; then
                warn "Enabling deletion protection for $resource"
                if retry_command "aws elbv2 modify-load-balancer-attributes \
                    --load-balancer-arn $resource \
                    --attributes Key=deletion_protection.enabled,Value=true" "$resource" "$control"; then
                    final_status="compliant"
                else
                    final_status="failed"
                fi
            else
                final_status="already_compliant"
            fi
            ;;
                "outbound_rule")
            initial_status=$(aws elbv2 describe-listeners \
                --load-balancer-arn "$resource" \
                --query "Listeners[?Protocol=='HTTP'].DefaultActions[].Type" \
                --output text)
            
            if [[ -z "$initial_status" ]]; then
                warn "Configuring outbound rule for $resource"
                if retry_command "aws elbv2 create-listener \
                    --load-balancer-arn $resource \
                    --protocol HTTPS \
                    --port 443 \
                    --default-actions Type=allow" "$resource" "$control"; then
                    final_status="compliant"
                else
                    final_status="failed"
                fi
            else
                final_status="already_compliant"
            fi
            ;;
        
        "registered_instance")
            initial_status=$(aws elbv2 describe-target-groups \
                --load-balancer-arn "$resource" \
                --query "TargetGroups[0].TargetHealthDescriptions[].Target.Id" \
                --output text)
            
            if [[ -z "$initial_status" ]]; then
                warn "Adding registered instance for $resource"
                if retry_command "aws elbv2 register-targets \
                    --target-group-arn <your-target-group-arn> \
                    --targets Id=<instance-id>" "$resource" "$control"; then
                    final_status="compliant"
                else
                    final_status="failed"
                fi
            else
                final_status="already_compliant"
            fi
            ;;
        
        "secure_ssl_cipher")
            initial_status=$(aws elbv2 describe-listeners \
                --load-balancer-arn "$resource" \
                --query "Listeners[].SslPolicy" \
                --output text)
            
            if [[ "$initial_status" != "ELBSecurityPolicy-2016-08" ]]; then
                warn "Setting SSL cipher to secure policy for $resource"
                if retry_command "aws elbv2 modify-listener \
                    --load-balancer-arn $resource \
                    --port 443 \
                    --ssl-policy ELBSecurityPolicy-2016-08" "$resource" "$control"; then
                    final_status="compliant"
                else
                    final_status="failed"
                fi
            else
                final_status="already_compliant"
            fi
            ;;
        
        "ssl_https_listeners")
            initial_status=$(aws elbv2 describe-listeners \
                --load-balancer-arn "$resource" \
                --query "Listeners[].Protocol" \
                --output text)
            
            if [[ "$initial_status" != *"HTTPS"* && "$initial_status" != *"SSL"* ]]; then
                warn "Configuring SSL or HTTPS listener for $resource"
                if retry_command "aws elbv2 create-listener \
                    --load-balancer-arn $resource \
                    --protocol HTTPS \
                    --port 443 \
                    --default-actions Type=forward,TargetGroupArn=<your-target-group-arn>" "$resource" "$control"; then
                    final_status="compliant"
                else
                    final_status="failed"
                fi
            else
                final_status="already_compliant"
            fi
            ;;
        
        "availability_zones")
            initial_status=$(aws elbv2 describe-load-balancers \
                --load-balancer-arn "$resource" \
                --query "LoadBalancers[0].AvailabilityZones" \
                --output text)
            
            if [[ -z "$initial_status" ]]; then
                warn "Spanning multiple availability zones for $resource"
                if retry_command "aws elbv2 modify-load-balancer-attributes \
                    --load-balancer-arn $resource \
                    --attributes Key=load_balancing.cross_zone.enabled,Value=true" "$resource" "$control"; then
                    final_status="compliant"
                else
                    final_status="failed"
                fi
            else
                final_status="already_compliant"
            fi
            ;;
        
        "logging_enabled")
            initial_status=$(aws elbv2 describe-load-balancer-attributes \
                --load-balancer-arn "$resource" \
                --query "Attributes[?Key=='access_logs.s3.enabled'].Value" \
                --output text)
            
            if [[ "$initial_status" != "true" ]]; then
                warn "Enabling logging for $resource"
                if retry_command "aws elbv2 modify-load-balancer-attributes \
                    --load-balancer-arn $resource \
                    --attributes Key=access_logs.s3.enabled,Value=true,Key=access_logs.s3.bucket,Value=<your-log-bucket>" "$resource" "$control"; then
                    final_status="compliant"
                else
                    final_status="failed"
                fi
            else
                final_status="already_compliant"
            fi
            ;;
        
        "listeners_enabled")
            initial_status=$(aws elbv2 describe-listeners \
                --load-balancer-arn "$resource" \
                --query "Listeners[].ListenerArn" \
                --output text)
            
            if [[ -z "$initial_status" ]]; then
                warn "Enabling listener for $resource"
                if retry_command "aws elbv2 create-listener \
                    --load-balancer-arn $resource \
                    --protocol HTTPS \
                    --port 443 \
                    --default-actions Type=forward,TargetGroupArn=<your-target-group-arn>" "$resource" "$control"; then
                    final_status="compliant"
                else
                    final_status="failed"
                fi
            else
                final_status="already_compliant"
            fi
            ;;
        
        "cert_expiry_30_days")
            initial_status=$(aws elbv2 describe-listeners \
                --load-balancer-arn "$resource" \
                --query "Listeners[?Protocol=='HTTPS'].SslCertificate.CertificateArn" \
                --output text)
            
            expiry_date=$(aws acm describe-certificate \
                --certificate-arn "$initial_status" \
                --query "Certificate.NotAfter" \
                --output text)
            
            if [[ "$(date -d "$expiry_date" +%s)" -lt "$(date -d "+30 days" +%s)" ]]; then
                warn "Updating expiring certificate for $resource"
                if retry_command "aws acm renew-certificate --certificate-arn $initial_status" "$resource" "$control"; then
                    final_status="compliant"
                else
                    final_status="failed"
                fi
            else
                final_status="already_compliant"
            fi
            ;;
        
        "tls_security_policy")
            initial_status=$(aws elbv2 describe-listeners \
                --load-balancer-arn "$resource" \
                --query "Listeners[].SslPolicy" \
                --output text)
            
            if [[ "$initial_status" != "ELBSecurityPolicy-2016-08" ]]; then
                warn "Setting TLS security policy for $resource"
                if retry_command "aws elbv2 modify-listener \
                    --load-balancer-arn $resource \
                    --port 443 \
                    --ssl-policy ELBSecurityPolicy-2016-08" "$resource" "$control"; then
                    final_status="compliant"
                else
                    final_status="failed"
                fi
            else
                final_status="already_compliant"
            fi
            ;;
        
        "inbound_rule")
            initial_status=$(aws ec2 describe-security-groups \
                --group-ids $(aws elbv2 describe-load-balancers \
                    --load-balancer-arn "$resource" \
                    --query "LoadBalancers[0].SecurityGroups[0]" \
                    --output text) \
                --query "SecurityGroups[].IpPermissions" \
                --output text)
            
            if [[ -z "$initial_status" ]]; then
                warn "Adding inbound rule for $resource"
                if retry_command "aws ec2 authorize-security-group-ingress \
                    --group-id <security-group-id> \
                    --protocol tcp --port 80 --cidr 0.0.0.0/0" "$resource" "$control"; then
                    final_status="compliant"
                else
                    final_status="failed"
                fi
            else
                final_status="already_compliant"
            fi
            ;;
        
        "connection_draining")
            initial_status=$(aws elbv2 describe-load-balancer-attributes \
                --load-balancer-arn "$resource" \
                --query "Attributes[?Key=='connection_draining.enabled'].Value" \
                --output text)
            
            if [[ "$initial_status" != "true" ]]; then
                warn "Enabling connection draining for $resource"
                if retry_command "aws elbv2 modify-load-balancer-attributes \
                    --load-balancer-arn $resource \
                    --attributes Key=connection_draining.enabled,Value=true" "$resource" "$control"; then
                    final_status="compliant"
                else
                    final_status="failed"
                fi
            else
                final_status="already_compliant"
            fi
            ;;
        
        "cert_expiry_7_days")
            initial_status=$(aws elbv2 describe-listeners \
                --load-balancer-arn "$resource" \
                --query "Listeners[?Protocol=='HTTPS'].SslCertificate.CertificateArn" \
                --output text)
            
            expiry_date=$(aws acm describe-certificate \
                --certificate-arn "$initial_status" \
                --query "Certificate.NotAfter" \
                --output text)
            
            if [[ "$(date -d "$expiry_date" +%s)" -lt "$(date -d "+7 days" +%s)" ]]; then
                warn "Updating certificate expiring in 7 days for $resource"
                if retry_command "aws acm renew-certificate --certificate-arn $initial_status" "$resource" "$control"; then
                    final_status="compliant"
                else
                    final_status="failed"
                fi
            else
                final_status="already_compliant"
            fi
            ;;
        
        "ssl_tls_protocol_version")
            initial_status=$(aws elbv2 describe-listeners \
                --load-balancer-arn "$resource" \
                --query "Listeners[].SslPolicy" \
                --output text)
            
            if [[ "$initial_status" != "ELBSecurityPolicy-2016-08" ]]; then
                warn "Configuring SSL/TLS protocol version for $resource"
                if retry_command "aws elbv2 modify-listener \
                    --load-balancer-arn $resource \
                    --port 443 \
                    --ssl-policy ELBSecurityPolicy-2016-08" "$resource" "$control"; then
                    final_status="compliant"
                else
                    final_status="failed"
                fi
            else
                final_status="already_compliant"
            fi
            ;;
        
        "public_access")
            initial_status=$(aws elbv2 describe-load-balancers \
                --load-balancer-arn "$resource" \
                --query "LoadBalancers[0].Scheme" \
                --output text)
            
            if [[ "$initial_status" == "internet-facing" ]]; then
                warn "Prohibiting public access for $resource"
                if retry_command "aws elbv2 modify-load-balancer-attributes \
                    --load-balancer-arn $resource \
                    --attributes Key=access_logs.s3.enabled,Value=false" "$resource" "$control"; then
                    final_status="compliant"
                else
                    final_status="failed"
                fi
            else
                final_status="already_compliant"
            fi
            ;;
        
        "ssl_certificates")
            initial_status=$(aws elbv2 describe-listeners \
                --load-balancer-arn "$resource" \
                --query "Listeners[].SslCertificate.CertificateArn" \
                --output text)
            
            if [[ -z "$initial_status" ]]; then
                warn "Configuring SSL certificates for $resource"
                if retry_command "aws elbv2 modify-listener \
                    --load-balancer-arn $resource \
                    --port 443 \
                    --ssl-certificate-arn <your-ssl-cert-arn>" "$resource" "$control"; then
                    final_status="compliant"
                else
                    final_status="failed"
                fi
            else
                final_status="already_compliant"
            fi
            ;;
    esac

    # Record status in report
    echo "$resource,$control,$initial_status,${CHANGES_MADE[$resource:$control]:-None},$final_status,${CHANGES_MADE[$resource:$control]:-None}" >> "$REPORT_FILE"
    
    # Update statistics
    if [[ "$final_status" == "compliant" ]]; then
        ((UPDATED_RESOURCES++))
    elif [[ "$final_status" == "already_compliant" ]]; then
        ((COMPLIANT_RESOURCES++))
    fi
}

# Process CSV file
process_csv() {
    local csv_file="$1"
    
    if [[ ! -f "$csv_file" ]]; then
        error "CSV file not found: $csv_file"
        exit 1
    }

    # Read CSV file and process each resource
    while IFS=, read -r resource; do
        if ! validate_arn "$resource"; then
            continue
        fi

        ((TOTAL_RESOURCES++))
        log "Processing resource: $resource"

        # List of controls to check
        local controls=(
            "desync_mitigation"
            "deletion_protection"
            "waf_enabled"
            "http_to_https"
            "ssl_policy"
            # Add more controls here...
        )

        for control in "${controls[@]}"; do
            check_control "$resource" "$control"
        done
    done < <(tail -n +2 "$csv_file") # Skip header row
}

# Generate detailed summary
generate_summary() {
    log "\nCompliance Check Summary:"
    log "========================="
    log "Total resources processed: $TOTAL_RESOURCES"
    log "Already compliant: $COMPLIANT_RESOURCES"
    log "Successfully updated: $UPDATED_RESOURCES"
    log "Errors encountered: $ERRORS"
    
    log "\nDetailed Control Status:"
    log "======================="
    for control in "${!CONTROL_STATUS[@]}"; do
        log "$control: ${CONTROL_STATUS[$control]}"
    done
    
    log "\nReport generated: $REPORT_FILE"
}

# Main function
main() {
    if [[ $# -ne 1 ]]; then
        error "Usage: $SCRIPT_NAME <csv_file>"
        exit 1
    }

    local csv_file="$1"
    
    log "Starting ELB compliance check with input file: $csv_file"
    initialize_report
    process_csv "$csv_file"
    generate_summary

    if ((ERRORS > 0)); then
        error "Script completed with errors. Check $LOG_FILE for details."
        exit 1
    fi

    success "Script completed successfully."
}

# Execute main function
main "$@"
