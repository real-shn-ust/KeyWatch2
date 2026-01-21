from flask import Blueprint, jsonify, request

from tasks import celery, scan_certificates_linux, scan_certificates_windows

import ipaddress
import nmap
import concurrent.futures

import winrm
from fabric import Connection
from paramiko.ssh_exception import AuthenticationException, NoValidConnectionsError
from requests.exceptions import ConnectionError
from winrm.exceptions import InvalidCredentialsError


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


api = Blueprint("api", __name__)


@api.route("/scan", methods=["POST"])
def scan():
    data = request.get_json()
    host = data.get("host")
    user = data.get("user")
    password = data.get("password")

    if not host or not user or not password:
        return jsonify(
            {"error": "Missing required parameters: host, user, password"}
        ), 400

    # Determine hosts to scan
    hosts = []
    try:
        network = ipaddress.ip_network(host, strict=False)
        if network.num_addresses > 1:
            # It's a CIDR range, perform ping scan
            nm = nmap.PortScanner()
            nm.scan(hosts=host, arguments='-sn')  # Ping scan
            hosts = [ip for ip in nm.all_hosts() if nm[ip].state() == 'up']
        else:
            hosts = [str(network.network_address)]  # Single IP
    except ValueError:
        # Not a valid network, assume single host
        hosts = [host]

    if not hosts:
        return jsonify({"error": "No active hosts found in the specified range"}), 400

    task_ids = []
    for h in hosts:
        os_detected = _detect_os(h, user, password, user, password)
        if os_detected == "linux":
            task = scan_certificates_linux.delay(h, user, password)
            task_ids.append(task.id)
        elif os_detected == "windows":
            task = scan_certificates_windows.delay(h, user, password)
            task_ids.append(task.id)
        # else: skip host

    if not task_ids:
        return jsonify({"error": "No valid hosts found or OS detection failed"}), 400

    return jsonify({"task_ids": task_ids}), 202


@api.route("/status/<task_id>", methods=["GET"])
def task_status(task_id):
    task = celery.AsyncResult(task_id)
    if task.state == "PENDING":
        response = {"state": task.state, "status": "Task is pending..."}
    elif task.state == "PROGRESS":
        response = {"state": task.state, "status": task.info.get("status", "")}
    elif task.state == "SUCCESS":
        response = {"state": task.state, "result": task.result}
    else:
        response = {"state": task.state, "status": str(task.info)}
    return jsonify(response)
