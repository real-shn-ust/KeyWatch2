from flask import Blueprint, jsonify, request

from tasks import scan_certificates

api = Blueprint("api", __name__)


@api.route("/scan", methods=["GET"])
def scan():
    host = request.args.get("host")
    user = request.args.get("user")
    password = request.args.get("password")

    if not host or not user or not password:
        return jsonify(
            {"error": "Missing required parameters: host, user, password"}
        ), 400

    task = scan_certificates.delay(host, user, password)
    return jsonify({"task_id": task.id}), 202


@api.route("/status/<task_id>", methods=["GET"])
def task_status(task_id):
    task = scan_certificates.AsyncResult(task_id)
    if task.state == "PENDING":
        response = {"state": task.state, "status": "Task is pending..."}
    elif task.state == "PROGRESS":
        response = {"state": task.state, "status": task.info.get("status", "")}
    elif task.state == "SUCCESS":
        response = {"state": task.state, "result": task.result}
    else:
        response = {"state": task.state, "status": str(task.info)}
    return jsonify(response)
