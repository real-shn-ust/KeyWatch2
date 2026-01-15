# Import tasks to register them with Celery
import os

from celery import Celery

from .tasks_linux import scan_certificates_linux
from .tasks_windows import scan_certificates_windows

# Create the Celery app instance
celery = Celery(
    "tasks", broker=os.getenv("CELERY_BROKER_URL", "redis://localhost:6379/0")
)
