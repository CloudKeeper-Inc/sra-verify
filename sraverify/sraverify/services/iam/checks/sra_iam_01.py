"""
Check for IAM users in an AWS account (SRA-IAM-01).
"""
from typing import Any, Dict, List, Set

from sraverify.services.iam.base import IAMCheck


class SRA_IAM_01(IAMCheck):
    """Detect the presence of IAM users in an AWS account.

    AWS Security Reference Architecture (SRA) guidance directs customers to
    use federated identity through AWS IAM Identity Center and to assume IAM
    roles rather than provision long-lived IAM users. Any IAM user in an
    account is a deviation worth reporting as a HIGH severity finding.
    """

    def __init__(self):
        """Initialize the IAM user detection check."""
        super().__init__()
        self.check_id = "SRA-IAM-01"
        self.check_name = "Account contains no IAM users."
        self.description = (
            "This check verifies that the AWS account contains no IAM users. "
            "AWS Security Reference Architecture (SRA) guidance recommends "
            "federated identity through AWS IAM Identity Center and assuming "
            "IAM roles over provisioning IAM users with long-lived credentials. "
            "Long-lived credentials associated with an IAM user increase the "
            "risk of credential exposure, complicate credential rotation, and "
            "contribute to identity sprawl. Replace each IAM user with "
            "federated access through IAM Identity Center or an IAM role."
        )
        self.severity = "HIGH"
        self.check_logic = (
            "Call the IAM ListUsers API against the global endpoint "
            "(us-east-1) and paginate until all users are retrieved. "
            "One FAIL finding is created for each IAM user returned by the "
            "API call. If no IAM users are returned, one PASS finding is "
            "created for the account. If the API call fails, one ERROR "
            "finding is created and no PASS or FAIL findings are produced."
        )

    def execute(self) -> List[Dict[str, Any]]:
        """
        Execute the check.

        Returns:
            List of findings for the account.
        """
        self._validate_metadata()
        region = self.GLOBAL_REGION  # "us-east-1"

        response = self.list_users()

        # Error path: a single ERROR finding, no PASS or FAIL findings.
        if "Error" in response:
            message = response["Error"].get("Message") or ""
            actual_value = message[:1000] if message else "Unknown error"
            self.findings.append(self.create_finding(
                status="ERROR",
                region=region,
                resource_id=self.account_id,
                actual_value=actual_value,
                remediation=(
                    "Verify the execution role has the iam:ListUsers "
                    "permission attached."
                ),
            ))
            return self.findings

        # Deduplicate users by ARN, preserving first occurrence.
        users = response.get("Users", [])
        seen_arns: Set[str] = set()
        distinct_users: List[Dict[str, Any]] = []
        for user in users:
            arn = user.get("Arn")
            if arn and arn not in seen_arns:
                seen_arns.add(arn)
                distinct_users.append(user)

        # PASS path: zero IAM users found in the account.
        if not distinct_users:
            self.findings.append(self.create_finding(
                status="PASS",
                region=region,
                resource_id=self.account_id,
                actual_value="0 IAM users found in the account.",
                remediation="No remediation needed.",
            ))
            return self.findings

        # FAIL path: one finding per distinct IAM user ARN.
        remediation = (
            "Replace the IAM user with federated access through AWS IAM "
            "Identity Center or assume an IAM role with temporary "
            "credentials, then delete the IAM user after migration is "
            "complete."
        )
        for user in distinct_users:
            self.findings.append(self.create_finding(
                status="FAIL",
                region=region,
                resource_id=user["Arn"],
                actual_value=(
                    f"IAM user '{user.get('UserName', '')}' exists in the "
                    "account."
                ),
                remediation=remediation,
            ))

        return self.findings
