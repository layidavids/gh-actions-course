import time
from django.core.management.base import BaseCommand, CommandError
from django.conf import settings
import os
from django.utils._os import safe_join
from pathlib import Path
import shutil
import logging

# Define the logger for the module
logger = logging.getLogger(__name__)


class Command(BaseCommand):
    help = "Delete files and folders in /media older than an hour."

    def handle(self, *args, **kwargs):
        now = time.time()
        media_root = Path("/var/www/cyph3r/media")

        time_limit = 1 * 60 * 60  # 1 hour in seconds

        for f in os.listdir(media_root):
            path = safe_join(media_root, f)

            # Check last modification time of file or folder has not exceeded time limit
            if now - os.path.getmtime(path) > time_limit:
                try:
                    if os.path.isdir(path):
                        shutil.rmtree(path)
                        logger.info(f"Successfully deleted {path}")
                    else:
                        os.remove(path)
                    logger.info(f"Successfully deleted {path}")
                except Exception as e:
                    logger.error(
                        f"An error occurred deleting media files in {e}", exc_info=True
                    )
