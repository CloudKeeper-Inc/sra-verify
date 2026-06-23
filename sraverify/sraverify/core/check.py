"""
Base class for security checks.
"""
from typing import List, Optional, Dict, Any
import boto3
from botocore.exceptions import ClientError
from sraverify.core.logging import logger

# Status used when a check cannot be evaluated because the required AWS
# Organizations / delegated-administrator context is not available in this
# account or deployment (e.g. multi-account scanning without an org setup).
# This is distinct from FAIL: it means "not assessable here", not "misconfigured".
INSUFFICIENT_DATA = "INSUFFICIENT_DATA"


class SecurityCheck:
    """Base class for all security checks."""

    # Class-level cache for account information shared across all instances
    _account_info_cache = {}

    # Tri-state org-access availability shared across all instances.
    #   None  -> not yet determined (probe will run on first use)
    #   True  -> account can read AWS Organizations data (management or delegated admin)
    #   False -> no Organizations/delegated-admin access (multi-account-without-org setup)
    # Can be set explicitly via set_org_access() to honor CLI overrides.
    _org_access_available = None

    def __init__(self, account_type="application", service=None, resource_type=None):
        """
        Initialize security check.
        
        Args:
            account_type: Type of account (application, audit, log-archive, management)
            service: AWS service name
            resource_type: AWS resource type for findings
        """
        self.account_type = account_type
        self.service = service
        self.resource_type = resource_type
        self.check_id = None
        self.check_name = None
        self.description = None
        self.rationale = None
        self.remediation = None
        self.severity = "Unknown"
        self.check_logic = None
        self.findings = []
        self.regions = []
        self.session = None
        self._clients = {}
        self.account_info = None  # Will hold {'account_id': str, 'account_name': str}
        
    def initialize(self, session: boto3.Session, regions: Optional[List[str]] = None):
        """
        Initialize check with AWS session and optional regions.
        
        Args:
            session: AWS session to use for the check
            regions: List of AWS regions to check. If not provided, enabled regions will be detected.
        """
        logger.debug(f"Initializing {self.__class__.__name__} check")
        self.session = session
        # All account types need regions, so we'll get them regardless of account type
        self.regions = regions if regions else self._get_enabled_regions()
        logger.debug(f"Check will run in regions: {', '.join(self.regions)}")
        
        # Get account info once during initialization
        self.account_info = self._get_account_info()
        logger.debug(f"Check initialized for account: {self.account_info['account_name']} ({self.account_info['account_id']})")
        
        self._setup_clients()

    def _get_enabled_regions(self) -> List[str]:
        """
        Get all enabled regions in the AWS account.
        
        Returns:
            List of enabled region names
        """
        try:
            logger.debug("Getting enabled AWS regions")
            session = boto3.Session()
            ec2_client = session.client('ec2', region_name='us-east-1')
            response = ec2_client.describe_regions(AllRegions=False)
            regions = [region['RegionName'] for region in response['Regions']]
            logger.debug(f"Found {len(regions)} enabled regions")
            return regions
        except Exception as e:
            logger.error(f"Failed to get enabled regions: {str(e)}")
            raise Exception(f"Failed to get enabled regions: {str(e)}")
    
    def _setup_clients(self):
        """
        Set up clients for each region. Must be implemented by subclasses.
        """
        raise NotImplementedError("Subclasses must implement _setup_clients method")
    
    def get_client(self, region: str) -> Optional[Any]:
        """
        Get client for a specific region.
        
        Args:
            region: AWS region name
            
        Returns:
            Client for the region or None if not available
        """
        return self._clients.get(region)
    
    def create_finding(self, status: str, region: str, resource_id: str, 
                      actual_value: str, remediation: str, 
                      checked_value: Optional[str] = None) -> Dict[str, Any]:
        """
        Create a standardized finding.
        
        Args:
            status: Check status (PASS/FAIL/ERROR)
            region: AWS region
            resource_id: Resource identifier
            actual_value: Actual value found
            remediation: Remediation steps
            checked_value: Value that was checked (defaults to service name + " Configuration")
            
        Returns:
            Finding dictionary
            
        Note: account_id and account_name are automatically populated from initialization.
        """
        if checked_value is None:
            checked_value = f"{self.service} Configuration"
            
        return {
            "CheckId": self.check_id,
            "Status": status,
            "Region": region,
            "Severity": self.severity,
            "Title": f"{self.check_id} {self.check_name}",
            "Description": self.description,
            "ResourceId": resource_id,
            "ResourceType": self.resource_type,
            "AccountId": self.account_id,
            "AccountName": self.account_name,
            "CheckedValue": checked_value,
            "ActualValue": actual_value,
            "Remediation": remediation,
            "Service": self.service,
            "CheckLogic": self.check_logic,
            "AccountType": self.account_type
        }
    
    @property
    def requires_org_access(self) -> bool:
        """
        Whether this check depends on AWS Organizations / delegated-administrator
        access to produce a meaningful result.

        Every non-application check (management, audit, log-archive) presupposes
        either Organizations API access or that the scanning account is a service
        delegated administrator. Application checks are evaluated standalone within
        a single account and never require org access.
        """
        return self.account_type != "application"

    def create_insufficient_data_finding(self, region: str,
                                         resource_id: Optional[str] = None,
                                         reason: Optional[str] = None,
                                         remediation: Optional[str] = None
                                         ) -> Dict[str, Any]:
        """
        Create a standardized INSUFFICIENT_DATA finding.

        Used when a check cannot be evaluated because the required AWS
        Organizations / delegated-administrator context is unavailable.

        Args:
            region: AWS region (or "global" for non-regional checks)
            resource_id: Optional resource identifier
            reason: Human-readable reason (defaults to a standard message)
            remediation: Optional remediation/explanation

        Returns:
            Finding dictionary with status INSUFFICIENT_DATA
        """
        if reason is None:
            reason = ("Check requires AWS Organizations / delegated administrator "
                      "access, which is not available in this account or deployment.")
        if remediation is None:
            remediation = ("This check evaluates an organization-level or delegated-"
                           "administrator control. Run it from the AWS Organizations "
                           "management account or the relevant service's delegated "
                           "administrator account. In a multi-account scan without an "
                           "organization setup, this control cannot be assessed.")
        return self.create_finding(
            status=INSUFFICIENT_DATA,
            region=region,
            resource_id=resource_id,
            actual_value=reason,
            remediation=remediation,
            checked_value=f"{self.service} organization/delegated-admin configuration"
        )

    def build_insufficient_data_findings(self) -> List[Dict[str, Any]]:
        """
        Build the INSUFFICIENT_DATA finding(s) for this check without calling any
        AWS APIs. Emits a single finding per check (region "global") to keep the
        report clean rather than one identical row per region.

        Returns:
            List containing a single INSUFFICIENT_DATA finding
        """
        finding = self.create_insufficient_data_finding(region="global")
        self.findings.append(finding)
        return [finding]

    @classmethod
    def set_org_access(cls, available: Optional[bool]) -> None:
        """
        Explicitly set whether Organizations/delegated-admin access is available,
        overriding auto-detection. Pass None to reset and allow auto-detection.
        """
        cls._org_access_available = available

    @classmethod
    def detect_org_access(cls, session: boto3.Session) -> bool:
        """
        Determine (once, cached) whether the current credentials can read AWS
        Organizations data. Uses a lightweight organizations:ListAccounts probe.

        - Succeeds  -> management account or Organizations delegated administrator.
        - AccessDenied / failure -> no org/delegated-admin access.

        The result is cached at the class level so the probe runs only once per
        process. If set_org_access() was already called, that value is honored.

        Args:
            session: AWS session to probe with

        Returns:
            True if Organizations data is readable, False otherwise
        """
        if cls._org_access_available is not None:
            return cls._org_access_available

        try:
            logger.debug("Probing AWS Organizations access (organizations:ListAccounts)")
            org_client = session.client("organizations")
            org_client.list_accounts(MaxResults=1)
            cls._org_access_available = True
            logger.debug("Organizations access available")
        except ClientError as e:
            error_code = e.response.get("Error", {}).get("Code", "")
            logger.debug(f"Organizations access not available ({error_code}); "
                         "org/delegated-admin checks will report INSUFFICIENT_DATA")
            cls._org_access_available = False
        except Exception as e:
            logger.debug(f"Organizations access probe failed ({e}); assuming no org access")
            cls._org_access_available = False

        return cls._org_access_available

    def execute(self) -> List[Dict[str, Any]]:
        """
        Execute the check. Must be implemented by subclasses.

        Returns:
            List of findings
        """
        raise NotImplementedError("Subclasses must implement execute method")
    
    def get_findings(self) -> List[Dict[str, Any]]:
        """
        Get findings from the check.
        
        Returns:
            List of findings
        """
        return self.findings

    def _get_account_info(self) -> Dict[str, str]:
        """
        Get account ID and name from AWS Account API with caching.
        
        Returns:
            Dictionary with 'account_id' and 'account_name' keys
        """
        # Get account ID from STS first (reliable, high rate limits)
        try:
            sts_client = self.session.client("sts")
            response = sts_client.get_caller_identity()
            account_id = response["Account"]
        except Exception as e:
            logger.error(f"Failed to get account ID from STS: {str(e)}")
            raise Exception(f"Failed to get account ID: {str(e)}")
        
        # Check class-level cache
        if account_id in SecurityCheck._account_info_cache:
            logger.debug(f"Using cached account information for {account_id}")
            return SecurityCheck._account_info_cache[account_id]
        
        # Try to get account name from Account API (low rate limits)
        try:
            logger.debug("Getting AWS account name from Account API")
            account_client = self.session.client("account")
            response = account_client.get_account_information()
            account_name = response['AccountName']
            logger.debug(f"Retrieved account name: {account_name}")
        except Exception as e:
            logger.warning(f"Failed to get account name from Account API: {str(e)}")
            account_name = ""  # Blank account name when Account API fails
        
        # Create and cache account info
        account_info = {
            'account_id': account_id,
            'account_name': account_name
        }
        SecurityCheck._account_info_cache[account_id] = account_info
        logger.debug(f"Cached account information for {account_id}")
        
        return account_info

    @property
    def account_id(self) -> str:
        """Get current account ID."""
        return self.account_info['account_id'] if self.account_info else None
    
    @property 
    def account_name(self) -> str:
        """Get current account name."""
        return self.account_info['account_name'] if self.account_info else None

    def get_management_accountId(self, session: boto3.Session) -> str:
        """
        Get AWS management account ID from the session.

        Args:
            session: AWS session

        Returns:
            AWS management account ID
        """
        try:
            logger.debug("Getting AWS management account ID")
            org_client = session.client("organizations")
            response = org_client.describe_organization()
            management_account_id = response["Organization"]["MasterAccountId"]
            logger.debug(f"Management account ID: {management_account_id}")
            return management_account_id
        except Exception as e:
            logger.error(f"Failed to get AWS management account ID: {str(e)}")
            raise Exception(f"Failed to get AWS management account ID: {str(e)}")
