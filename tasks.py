import os

from celery import Celery

# Create the Celery app instance
celery = Celery(
    "tasks", broker=os.getenv("CELERY_BROKER_URL", "redis://localhost:6379/0")
)

# Import tasks to register them with Celery
from tasks.tasks_linux import scan_certificates_linux
from tasks.tasks_windows import scan_certificates_windows
