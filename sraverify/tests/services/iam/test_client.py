"""Unit tests for IAM_Client wrapper."""
import pytest
from unittest.mock import MagicMock, patch
from botocore.exceptions import ClientError

from sraverify.services.iam.client import IAM_Client


@pytest.fixture
def mock_session():
    """Create a mock boto3 session with a mock IAM client."""
    session = MagicMock()
    return session


class TestIAMClientListUsers:
    """Tests for IAM_Client.list_users method."""

    def test_single_page_success(self, mock_session):
        """Returns {"Users": [...]} for a single-page response. (Req 1.6)"""
        mock_client = MagicMock()
        mock_session.client.return_value = mock_client

        users = [
            {"Arn": "arn:aws:iam::123456789012:user/alice", "UserName": "alice"},
            {"Arn": "arn:aws:iam::123456789012:user/bob", "UserName": "bob"},
        ]
        mock_paginator = MagicMock()
        mock_paginator.paginate.return_value = [{"Users": users}]
        mock_client.get_paginator.return_value = mock_paginator

        client = IAM_Client(session=mock_session)
        result = client.list_users()

        assert "Users" in result
        assert result["Users"] == users
        assert len(result["Users"]) == 2
        mock_client.get_paginator.assert_called_once_with("list_users")

    def test_multi_page_pagination(self, mock_session):
        """Paginator iterates all pages; result contains union. (Req 1.7)"""
        mock_client = MagicMock()
        mock_session.client.return_value = mock_client

        page1_users = [
            {"Arn": "arn:aws:iam::123456789012:user/alice", "UserName": "alice"},
        ]
        page2_users = [
            {"Arn": "arn:aws:iam::123456789012:user/bob", "UserName": "bob"},
        ]
        page3_users = [
            {"Arn": "arn:aws:iam::123456789012:user/carol", "UserName": "carol"},
        ]
        mock_paginator = MagicMock()
        mock_paginator.paginate.return_value = [
            {"Users": page1_users},
            {"Users": page2_users},
            {"Users": page3_users},
        ]
        mock_client.get_paginator.return_value = mock_paginator

        client = IAM_Client(session=mock_session)
        result = client.list_users()

        assert "Users" in result
        assert len(result["Users"]) == 3
        assert result["Users"] == page1_users + page2_users + page3_users

    def test_empty_page(self, mock_session):
        """Returns {"Users": []} when paginator yields no users. (Req 3.1)"""
        mock_client = MagicMock()
        mock_session.client.return_value = mock_client

        mock_paginator = MagicMock()
        mock_paginator.paginate.return_value = [{"Users": []}]
        mock_client.get_paginator.return_value = mock_paginator

        client = IAM_Client(session=mock_session)
        result = client.list_users()

        assert result == {"Users": []}

    def test_client_error_access_denied(self, mock_session):
        """ClientError mapped to {"Error": {"Code": "AccessDenied", ...}} without raising. (Req 4.1)"""
        mock_client = MagicMock()
        mock_session.client.return_value = mock_client

        error_response = {
            "Error": {
                "Code": "AccessDenied",
                "Message": "User is not authorized to perform iam:ListUsers",
            }
        }
        mock_paginator = MagicMock()
        mock_paginator.paginate.side_effect = ClientError(error_response, "ListUsers")
        mock_client.get_paginator.return_value = mock_paginator

        client = IAM_Client(session=mock_session)
        result = client.list_users()

        assert "Error" in result
        assert result["Error"]["Code"] == "AccessDenied"
        assert "not authorized" in result["Error"]["Message"]

    def test_client_error_throttling(self, mock_session):
        """Throttling ClientError mapped structurally. (Req 4.1)"""
        mock_client = MagicMock()
        mock_session.client.return_value = mock_client

        error_response = {
            "Error": {
                "Code": "Throttling",
                "Message": "Rate exceeded",
            }
        }
        mock_paginator = MagicMock()
        mock_paginator.paginate.side_effect = ClientError(error_response, "ListUsers")
        mock_client.get_paginator.return_value = mock_paginator

        client = IAM_Client(session=mock_session)
        result = client.list_users()

        assert "Error" in result
        assert result["Error"]["Code"] == "Throttling"
        assert result["Error"]["Message"] == "Rate exceeded"

    def test_unexpected_exception(self, mock_session):
        """Generic Exception mapped to {"Error": {"Code": "UnknownError", ...}}. (Req 4.1)"""
        mock_client = MagicMock()
        mock_session.client.return_value = mock_client

        mock_paginator = MagicMock()
        mock_paginator.paginate.side_effect = RuntimeError("Something unexpected happened")
        mock_client.get_paginator.return_value = mock_paginator

        client = IAM_Client(session=mock_session)
        result = client.list_users()

        assert "Error" in result
        assert result["Error"]["Code"] == "UnknownError"
        assert result["Error"]["Message"] == "Something unexpected happened"

    def test_region_pinned_us_east_1(self, mock_session):
        """Asserts session.client("iam", region_name="us-east-1") was called. (Req 1.6, 3.5)"""
        mock_client = MagicMock()
        mock_session.client.return_value = mock_client

        IAM_Client(session=mock_session)

        mock_session.client.assert_called_once_with("iam", region_name="us-east-1")
