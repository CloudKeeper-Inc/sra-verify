"""
IAM client for interacting with AWS IAM service.
"""
from typing import Any, Dict, Optional

import boto3
from botocore.exceptions import (
    ClientError,
    ConnectTimeoutError,
    EndpointConnectionError,
    ReadTimeoutError,
)

from sraverify.core.logging import logger


class IAM_Client:
    """Client for interacting with AWS IAM service.

    IAM is a global AWS service, so the underlying boto3 client is always
    pinned to ``us-east-1`` regardless of the session's configured region.
    """

    def __init__(self, session: Optional[boto3.Session] = None):
        """
        Initialize IAM client.

        Args:
            session: AWS session to use (if None, a new session will be created)
        """
        self.session = session or boto3.Session()
        # IAM is a global service, always use us-east-1
        self.client = self.session.client('iam', region_name='us-east-1')

    def list_users(self) -> Dict[str, Any]:
        """
        List all IAM users in the account with pagination support.

        Returns:
            Dictionary with ``Users`` key containing the list of IAM users
            accumulated across every response page, or an ``Error`` key with
            ``Code``/``Message`` fields if the API call failed. Exceptions are
            never re-raised; failures are always returned as a structured dict.
        """
        try:
            users = []
            paginator = self.client.get_paginator('list_users')
            for page in paginator.paginate():
                users.extend(page.get('Users', []))
            return {"Users": users}
        except ClientError as e:
            error_code = e.response.get('Error', {}).get('Code', '')
            error_message = e.response.get('Error', {}).get('Message', str(e))
            logger.warning(f"Error listing IAM users: {error_message}")
            return {
                "Error": {
                    "Code": error_code,
                    "Message": error_message
                }
            }
        except (EndpointConnectionError, ReadTimeoutError, ConnectTimeoutError) as e:
            logger.warning(f"Network error listing IAM users: {e}")
            return {
                "Error": {
                    "Code": e.__class__.__name__,
                    "Message": str(e)
                }
            }
        except Exception as e:
            logger.warning(f"Unexpected error listing IAM users: {e}")
            return {
                "Error": {
                    "Code": "UnknownError",
                    "Message": str(e)
                }
            }
