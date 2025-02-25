# List available controls
./eks-remediation.sh --list-controls

# Check a specific cluster against all controls
./eks-remediation.sh --cluster production-cluster

# Apply a specific control to all clusters
./eks-remediation.sh "EKS clusters should have control plane audit logging enabled"

# Process findings from a CSV file
./eks-remediation.sh --csv findings.csv "EKS clusters endpoint should restrict public access"
