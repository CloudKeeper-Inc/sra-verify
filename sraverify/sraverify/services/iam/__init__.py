"""
IAM security checks.
"""
from sraverify.services.iam.checks.sra_iam_01 import SRA_IAM_01

# Register checks
CHECKS = {
    "SRA-IAM-01": SRA_IAM_01,
}
