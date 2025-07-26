from google.cloud import kms_v1
from google.cloud import secretmanager
from google.cloud.storage import Blob
from google.cloud import storage
from google.cloud.storage import Bucket
from google.api_core.exceptions import (
    GoogleAPIError,
    AlreadyExists,
    PermissionDenied,
    DeadlineExceeded,
)
import logging


"""
This module provides a class for managing Google Cloud Platform (GCP) Secrets.

"""
# Define the logger for the module
logger = logging.getLogger(__name__)


class GCPManager:
    def __init__(
        self,
        project_id: str,
        kms_keyring_name: str = None,
        kms_key_name: str = None,
        storage_bucket: str = None,
    ):
        # initialize attributes
        self.project_id = project_id
        self.kms_keyring_name = kms_keyring_name
        self.kms_key_name = kms_key_name
        self.storage_bucket = storage_bucket
        self.location = "global"

        # Initialize KMS client
        self.kms_client = kms_v1.KeyManagementServiceClient()

        # Initialize Secret Manager client
        self.secret_manager_client = secretmanager.SecretManagerServiceClient()

        # Initialize key-path to kms key.
        self.key_path = self.kms_client.crypto_key_path(
            self.project_id, self.location, self.kms_keyring_name, self.kms_key_name
        )

    def create_secret(self, secret_id: str, payload: bytes) -> None:
        """Creates a secret in Secret Manager."""

        # Build parent resource name.
        parent = f"projects/{self.project_id}"

        # Build parent request, initialize arguments and create secret.
        parent_request = {
            "parent": parent,
            "secret_id": secret_id,
            "secret": {"replication": {"automatic": {}}},
        }
        # Create secret.
        try:
            self.secret_manager_client.create_secret(request=parent_request)
            self.add_secret_version(secret_id, payload)

        # If secret already exists, add secret version.
        except AlreadyExists:
            self.add_secret_version(secret_id, payload)

        # If permission denied, print error message.
        except PermissionDenied as err:
            logger.error(f"Permission denied: {err}", exc_info=True)

        # If deadline exceeded, print error message.
        except DeadlineExceeded as err:
            logger.error(f"communication failure on server side: {err}", exc_info=True)

        # If any other error occurs, print error message.
        except Exception as err:
            logger.error(f"An error occurred: {err}", exc_info=True)

    def add_secret_version(self, secret_id: str, payload: bytes) -> None:
        """Add secret version to secrets manager."""

        # Build path to parent.
        parent = self.secret_manager_client.secret_path(self.project_id, secret_id)

        # Add secret version.
        request = {"parent": parent, "payload": {"data": payload}}
        try:
            self.secret_manager_client.add_secret_version(request=request)

        # If permission denied, print error message.
        except PermissionDenied as err:
            logger.error(f"Permission denied: {err}", exc_info=True)

        # If deadline exceeded, print error message.
        except DeadlineExceeded as err:
            logger.error(f"communication failure on server side: {err}", exc_info=True)

        # If any other error occurs, print error message.
        except Exception as err:
            logger.error(f"An error occurred: {err}", exc_info=True)

    def get_secret(self, secret_id: str, version_id="latest") -> bytes:
        # Get secret (private key or passphrase) from secrets manager.

        # Build the resource name of the secret version.
        name = f"projects/{self.project_id}/secrets/{secret_id}/versions/{version_id}"

        # Build Request.
        request = {"name": name}

        # Access the secret version.
        try:
            response = self.secret_manager_client.access_secret_version(request)

            # Get secret.
            payload = response.payload.data

            # return payload.
            return payload

        # If permission denied, print error message.
        except PermissionDenied as err:
            logger.error(f"Permission denied: {err}", exc_info=True)

        # If deadline exceeded, print error message.
        except DeadlineExceeded as err:
            logger.error(f"communication failure on server side: {err}", exc_info=True)

        # If any other error occurs, print error message.
        except Exception as err:
            logger.error(f"An error occurred: {err}", exc_info=True)

    def encrypt_secret(self, payload: bytes) -> bytes:
        """Encrypts a secret using Cloud KMS key."""

        # Encrypt payload
        request = {"name": self.key_path, "plaintext": payload}
        try:
            response = self.kms_client.encrypt(request=request)

            # Return encrypted secret.
            return response.ciphertext

        # If permission denied, print error message.
        except PermissionDenied as err:
            logger.error(f"Permission denied: {err}", exc_info=True)

        # If deadline exceeded, print error message.
        except DeadlineExceeded as err:
            logger.error(f"communication failure on server side: {err}", exc_info=True)

        # If any other error occurs, print error message.
        except Exception as err:
            logger.error(f"An error occurred: {err}", exc_info=True)

    def decrypt_secret(self, encrypted_payload: bytes) -> bytes:
        """Decrypts a secret using Cloud KMS key."""

        # Decrypt secret
        request = {"name": self.key_path, "ciphertext": encrypted_payload}

        try:
            response = self.kms_client.decrypt(request=request)

            # Return decrypted secret.
            return response.plaintext

        # If permission denied, print error message.
        except PermissionDenied as err:
            logger.error(f"Permission denied: {err}", exc_info=True)

        # If deadline exceeded, print error message.
        except DeadlineExceeded as err:
            logger.error(f"communication failure on server side: {err}", exc_info=True)

        # If any other error occurs, print error message.
        except Exception as err:
            logger.error(f"An error occurred: {err}", exc_info=True)

    def store_in_bucket(self, path: str, payload: bytes) -> None:
        """Stores a secret in a GCP bucket."""
        storage_client = storage.Client(project=self.project_id)
        storage_bucket = storage_client.get_bucket(self.storage_bucket)
        blob = Blob(path, storage_bucket)
        try:
            blob.upload_from_string(payload)
        except GoogleAPIError as err:
            logger.error(f"An error occurred with the API: {err}", exc_info=True)
