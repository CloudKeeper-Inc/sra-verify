"""
Base class for AWS IAM security checks.
"""
from typing import Any, Dict, Optional

from sraverify.core.check import SecurityCheck
from sraverify.core.logging import logger
from sraverify.services.iam.client import IAM_Client


class IAMCheck(SecurityCheck):
    """Base class for all AWS IAM security checks.

    IAM is a global AWS service, so a single :class:`IAM_Client` pinned to
    ``us-east-1`` is constructed per instance and findings always carry
    ``Region = "us-east-1"``. Shared class-level caches keyed by
    ``account_id`` avoid duplicate ``ListUsers`` API calls when multiple IAM
    checks run in the same SRA Verify invocation.
    """

    # Class-level cache shared across all instances, keyed by account_id.
    # Both success and error responses are cached so that repeated failures
    # do not cascade into additional API calls within the same run.
    _users_cache: Dict[str, Dict[str, Any]] = {}

    # IAM is a global service; all API calls target this endpoint and every
    # finding produced by an IAM check reports this region.
    GLOBAL_REGION: str = "us-east-1"

    def __init__(self):
        """Initialize the IAM base check with SRA-standard metadata."""
        super().__init__(
            account_type="application",
            service="IAM",
            resource_type="AWS::IAM::User",
        )
        self._iam_client: Optional[IAM_Client] = None

    def _setup_clients(self):
        """Set up the IAM client (global service, no per-region clients)."""
        # IAM is a global service: one client pinned to us-east-1 is enough.
        self._iam_client = IAM_Client(self.session)
        # Clear the inherited per-region clients dict since IAM does not use it
        # (mirrors the pattern used by OrganizationsCheck).
        self._clients.clear()

    def get_iam_client(self) -> IAM_Client:
        """
        Get the IAM client.

        Returns:
            The :class:`IAM_Client` instance constructed in :meth:`_setup_clients`.
        """
        return self._iam_client

    def list_users(self) -> Dict[str, Any]:
        """
        List IAM users for the current account with caching.

        Looks up ``self.account_id`` in the class-level ``_users_cache`` first
        and returns the cached response on hit. On miss, delegates to
        :meth:`IAM_Client.list_users`, caches the response (success or error),
        and returns it.

        Returns:
            Dictionary with a ``Users`` key (success) or an ``Error`` key
            (failure), matching the shape returned by :class:`IAM_Client`.
        """
        cache_key = self.account_id
        if cache_key in IAMCheck._users_cache:
            logger.debug("IAM: Using cached list_users response")
            return IAMCheck._users_cache[cache_key]

        logger.debug("IAM: Fetching list_users response")
        response = self._iam_client.list_users()

        # Cache both success and error responses so repeated failures don't
        # cascade into additional API calls within the same run.
        IAMCheck._users_cache[cache_key] = response
        logger.debug("IAM: Cached list_users response")

        return response

    def _validate_metadata(self):
        """
        Validate that required metadata attributes are populated.

        Raises:
            ValueError: If ``check_name``, ``description``, or ``check_logic``
                is ``None`` or an empty string. The error message identifies
                the missing attribute and the offending subclass.
        """
        for attr_name in ("check_name", "description", "check_logic"):
            value = getattr(self, attr_name, None)
            if value is None or value == "":
                raise ValueError(
                    f"{attr_name} is missing or empty on {self.__class__.__name__}"
                )
