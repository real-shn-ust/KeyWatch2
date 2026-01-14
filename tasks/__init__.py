# Import tasks to register them with Celery
from .tasks_linux import scan_certificates_linux
from .tasks_windows import scan_certificates_windows
