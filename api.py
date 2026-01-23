import concurrent.futures
import ipaddress

import nmap
from celery import group
from celery.result import GroupResult
from flask import Blueprint, jsonify, request

from tasks import celery, detect_and_scan

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

    hosts = []
    try:
        network = ipaddress.ip_network(host, strict=False)
        if network.num_addresses > 1:
            nm = nmap.PortScanner()
            nm.scan(hosts=host, arguments="-sn -T5")
            hosts = [ip for ip in nm.all_hosts() if nm[ip].state() == "up"]
        else:
            hosts = [str(network.network_address)]
    except ValueError:
        hosts = [host]

    if not hosts:
        return jsonify({"error": "No active hosts found in the specified range"}), 400

    jobs = group(detect_and_scan.s(host, user, password) for host in hosts)

    res = jobs()
    res.save()

    return {"job_id": res.id}, 200


@api.route("/status/<task_id>", methods=["GET"])
def task_status(task_id):
    # task = celery.AsyncResult(task_id)
    # if task.state == "PENDING":
    #     response = {"state": task.state, "status": "Task is pending..."}
    # elif task.state == "PROGRESS":
    #     response = {"state": task.state, "status": task.info.get("status", "")}
    # elif task.state == "SUCCESS":
    #     response = {"state": task.state, "result": task.result}
    # else:
    #     response = {"state": task.state, "status": str(task.info)}
    # return jsonify(response)
    res = GroupResult.restore(task_id)
    return {
        "ready": res.ready() if res else False,
        "successful": res.successful() if res else False,
        "value": res.get() if (res and res.ready() and res.successful()) else None,
    }, 200
