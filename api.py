import concurrent.futures
import ipaddress

import nmap
from celery import chain, group
from celery.result import GroupResult
from flask import Blueprint, jsonify, request
from flask_jwt_extended import create_access_token, jwt_required
from werkzeug.security import check_password_hash

from . import mongo
from .tasks import celery, detect_and_scan

api = Blueprint("api", __name__)

USERS = {
    "admin": "scrypt:32768:8:1$UdmG9NOUXhHcl2jP$757ea452d404b5a84f13c835f01c49cda6023790c74e3ff5a7502a285a40b17685a24924bea785fc15b5078053ec316b2b49b6d76728d26ee05ad9608e099c95",
    "test": "test",
}


@api.post("/login")
def login():
    data = request.get_json()
    username = data.get("username", "")
    password = data.get("password", "")

    hpass = USERS.get(username)

    if password != USERS.get(username):
        return {"error": "invalid username or password"}, 401

    # if (not check_password_hash(password, hpass)):
    #     return {"error": "invalid username or password"}, 401

    access_token = create_access_token(identity=username)
    return jsonify(access_token=access_token)


@api.route("/scan", methods=["POST"])
@jwt_required()
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

    jobs = group(
        task for host in hosts if (task := detect_and_scan(host, user, password))
    )

    res = jobs()
    res.save()

    return {"job_id": res.id}, 200


@api.route("/status/<task_id>", methods=["GET"])
@jwt_required()
def task_status(task_id):
    res = GroupResult.restore(task_id)
    return {
        "ready": res.ready() if res else False,
        "successful": res.successful() if res else False,
        "value": res.get() if (res and res.ready() and res.successful()) else None,
    }, 200


@api.get("/certificates")
@jwt_required()
def certificates():
    page = int(request.args.get("page", 1))
    page_size = int(request.args.get("page_size", 10))

    if page < 1 or page_size < 1:
        return {"error": "Invalid pagination parameters"}, 400

    skip = (page - 1) * page_size

    documents = mongo.documents(skip=skip, page_size=page_size)
    for doc in documents:
        doc["_id"] = str(doc["_id"])

    return {
        "page": page,
        "page_size": page_size,
        "count": len(documents),
        "certificates": documents,
    }, 200


@api.get("/certificates/<id>")
@jwt_required()
def certificate(id):
    document = mongo.get(id)

    if document:
        return document, 200

    return {"error": "Document doesn't exists"}, 404
