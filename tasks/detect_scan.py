import concurrent.futures

import winrm
from celery import group, shared_task
from fabric import Connection
from paramiko.ssh_exception import AuthenticationException, NoValidConnectionsError
from requests.exceptions import ConnectionError
from winrm.exceptions import InvalidCredentialsError

try:
    from tasks.tasks_linux import scan_certificates_linux
    from tasks.tasks_windows import scan_certificates_windows
except ImportError:
    from .tasks_linux import scan_certificates_linux
    from .tasks_windows import scan_certificates_windows


def _check_linux(ip: str, username: str, password: str) -> str | None:
    # Throws AuthenticationException if the credentials are wrong
    # NoValidConnectionsError if the host is unreachable

    try:
        conn = Connection(
            host=ip,
            user=username,
            connect_kwargs={"password": password},
            connect_timeout=1,
        )
        result = conn.run("uname -s", hide=True)
    except (AuthenticationException, NoValidConnectionsError, TimeoutError):
        return None

    return "linux"


def _check_windows(ip: str, username: str, password: str) -> str | None:
    # Throws InvalidCredentialsError if the credentials are wrong
    # ConnectionError if the host is unreachable

    try:
        s = winrm.Session(
            ip, auth=(username, password), operation_timeout_sec=1, read_timeout_sec=2
        )
        r = s.run_cmd("ver")
    except (InvalidCredentialsError, ConnectionError):
        return None

    return "windows"


def _detect_os(
    ip: str,
    linux_username: str,
    linux_password: str,
    windows_username: str,
    windows_password: str,
) -> str | None:
    with concurrent.futures.ThreadPoolExecutor() as executor:
        futures = [
            executor.submit(_check_linux, ip, linux_username, linux_password),
            executor.submit(_check_windows, ip, windows_username, windows_password),
        ]

        for future in concurrent.futures.as_completed(futures):
            result = future.result()
            if result:
                return result

    return None


# @shared_task
def detect_and_scan(host: str, user: str, password: str):
    os = _detect_os(host, user, password, user, password)

    if os == "linux":
        return scan_certificates_linux.s(host, user, password)
    elif os == "windows":
        return scan_certificates_windows.s(host, user, password)
