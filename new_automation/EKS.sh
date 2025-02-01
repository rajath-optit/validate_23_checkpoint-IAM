#!/bin/bash

set -euo pipefail

# Script configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PYTHON_SCRIPT="eks_compliance_check.py"
REQUIREMENTS_FILE="requirements.txt"
LOG_DIR="logs"
REPORTS_DIR="reports"
INPUT_FILE="input_clusters.csv"
VENV_DIR=".venv"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Logging function
log() {
    local level=$1
    shift
    local message=$*
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    echo -e "${timestamp} - ${level}: ${message}"
}

# Error handling function
handle_error() {
    local exit_code=$?
    log "ERROR" "An error occurred on line $1"
    if [ -n "${2:-}" ]; then
        log "ERROR" "Additional context: $2"
    fi
    exit $exit_code
}

# Set up error handling
trap 'handle_error ${LINENO}' ERR

# Check if Python 3 is installed
check_python() {
    if ! command -v python3 &> /dev/null; then
        log "ERROR" "Python 3 is not installed. Please install Python 3 and try again."
        exit 1
    fi
    log "INFO" "Found Python 3: $(python3 --version)"
}

# Create virtual environment
setup_venv() {
    if [ ! -d "$VENV_DIR" ]; then
        log "INFO" "Creating virtual environment..."
        python3 -m venv "$VENV_DIR"
    fi
    source "$VENV_DIR/bin/activate"
    log "INFO" "Virtual environment activated"
}

# Install required packages
install_requirements() {
    if [ ! -f "$REQUIREMENTS_FILE" ]; then
        log "INFO" "Creating requirements.txt..."
        cat > "$REQUIREMENTS_FILE" << EOF
boto3>=1.26.0
botocore>=1.29.0
EOF
    fi
    
    log "INFO" "Installing required packages..."
    pip install -r "$REQUIREMENTS_FILE"
}

# Create necessary directories
create_directories() {
    for dir in "$LOG_DIR" "$REPORTS_DIR"; do
        if [ ! -d "$dir" ]; then
            mkdir -p "$dir"
            log "INFO" "Created directory: $dir"
        fi
    done
}

# Check AWS credentials
check_aws_credentials() {
    log "INFO" "Checking AWS credentials..."
    if ! aws sts get-caller-identity &> /dev/null; then
        log "ERROR" "AWS credentials not configured. Please configure AWS credentials and try again."
        exit 1
    fi
    log "INFO" "AWS credentials validated successfully"
}

# Create Python script
create_python_script() {
    if [ ! -f "$PYTHON_SCRIPT" ]; then
        log "INFO" "Creating Python script..."
        cat > "$PYTHON_SCRIPT" << 'EOF'
# Python script content from the previous code goes here
EOF
        # Copy the entire Python script content here
        log "INFO" "Created Python script: $PYTHON_SCRIPT"
    fi
}

# Check input file
check_input_file() {
    if [ ! -f "$INPUT_FILE" ]; then
        log "ERROR" "Input file '$INPUT_FILE' not found. Please create the input file with cluster ARNs."
        cat > "$INPUT_FILE" << EOF
Resource_ARN
arn:aws:eks:region:account:cluster/cluster-name
EOF
        log "INFO" "Created sample input file: $INPUT_FILE"
        exit 1
    fi
}

# Run compliance check
run_compliance_check() {
    local timestamp=$(date '+%Y%m%d_%H%M%S')
    local log_file="${LOG_DIR}/compliance_check_${timestamp}.log"
    local report_file="${REPORTS_DIR}/compliance_report_${timestamp}.csv"

    log "INFO" "Starting compliance check..."
    log "INFO" "Log file: $log_file"
    log "INFO" "Report file: $report_file"

    python3 "$PYTHON_SCRIPT" \
        --input "$INPUT_FILE" \
        --output "$report_file" \
        2>&1 | tee -a "$log_file"

    if [ ${PIPESTATUS[0]} -eq 0 ]; then
        log "INFO" "Compliance check completed successfully"
        log "INFO" "Report generated: $report_file"
    else
        log "ERROR" "Compliance check failed. Check logs for details: $log_file"
        exit 1
    fi
}

# Main execution
main() {
    log "INFO" "Starting EKS Compliance Checker..."
    
    # Run all setup and check functions
    check_python
    setup_venv
    install_requirements
    create_directories
    check_aws_credentials
    create_python_script
    check_input_file
    
    # Run the compliance check
    run_compliance_check
    
    # Deactivate virtual environment
    deactivate
    
    log "INFO" "EKS Compliance Checker completed successfully"
}

# Run main function
main "$@"
