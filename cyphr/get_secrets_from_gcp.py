import os
import logging
from cyph3r.gcp import GCPManager


"""
Module to get secrets for the cyph3r project.

"""
# Define the logger for the module
logger = logging.getLogger(__name__)


def get_secret(id=None) -> str:
    """
    Get secret from secrets manager.

    Returns:
        str: Django secret key or PostgreSQL password.
    """
    try:
        # Get Project ID from environment variable.
        project_id = os.getenv("GCP_SECRET_PROJECT_ID")

        # Initialize GCPManager object.
        gcpm = GCPManager(project_id)

        # Get django secret key from secrets manager.
        if id == "django_secret":
            secret_id = os.getenv("DJANGO_SECRET_KEY_SECRET_ID")
            secret = gcpm.get_secret(secret_id).decode("utf-8")

        # Get PostgreSQL password from secrets manager.
        if id == "postgres_secret":
            secret_id = os.getenv("DJANGO_POSTGRES_PASSWORD_SECRET_ID")
            secret = gcpm.get_secret(secret_id).decode("utf-8")
        return secret
    except Exception as e:
        logger.error(f"Error getting secret: {e}")
        return None
