from flask import Blueprint, jsonify, request

from tasks import scan_certificates_linux, scan_certificates_windows, celery

api = Blueprint("api", __name__)


@api.route("/scan", methods=["POST"])
def scan():
    data = request.get_json()
    host = data.get("host")
    user = data.get("user")
    password = data.get("password")
    os_type = data.get("os")

    if not host or not user or not password or not os_type:
        return jsonify(
            {"error": "Missing required parameters: host, user, password, os"}
        ), 400

    if os_type not in ["linux", "windows"]:
        return jsonify(
            {"error": "Invalid os parameter. Must be 'linux' or 'windows'"}
        ), 400

    if os_type == "linux":
        task = scan_certificates_linux.delay(host, user, password)
    else:  # windows
        task = scan_certificates_windows.delay(host, user, password)

    return jsonify({"task_id": task.id}), 202


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
