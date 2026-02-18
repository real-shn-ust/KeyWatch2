from datetime import UTC, datetime

from flask import Blueprint, jsonify, request
from flask_jwt_extended import jwt_required

from . import mongo, utils

certificate_bp = Blueprint("certificate_bp", __name__, url_prefix="/certificates")


@certificate_bp.get("/hosts")
# @jwt_required()
def certificates():
    return jsonify(mongo.unique_hosts()), 200
    # page = int(request.args.get("page", 1))
    # page_size = int(request.args.get("page_size", 10))

    # if page < 1 or page_size < 1:
    #     return {"error": "Invalid pagination parameters"}, 400

    # skip = (page - 1) * page_size

    # documents = mongo.documents(skip=skip, page_size=page_size)
    # for doc in documents:
    #     doc["_id"] = str(doc["_id"])

    # return {
    #     "page": page,
    #     "page_size": page_size,
    #     "count": len(documents),
    #     "certificates": documents,
    # }, 200


@certificate_bp.get("/hosts/<host>")
def certificates_per_host(host):
    res = mongo.certificates_per_host(host)
    for doc in res:
        doc["_id"] = str(doc["_id"])
    return jsonify(res)
    # return jsonify(mongo.certificates_per_host(host))


# @certificate_bp.get("/<id>")
# # @jwt_required()
# def certificate(id):
#     document = mongo.get(id)

#     if document:
#         return document, 200

#     return {"error": "Document doesn't exists"}, 404


@certificate_bp.get("/expiry-counts")
# @jwt_required()
def expiry_counts():
    tw = utils.time_windows()
    pipeline = utils.base_pipeline() + [
        {
            "$group": {
                "_id": None,
                "expired": {
                    "$sum": {
                        "$cond": [
                            {"$lt": ["$not_valid_after", tw["now"]]},
                            1,
                            0,
                        ]
                    }
                },
                "expiring_in_3_days": {
                    "$sum": {
                        "$cond": [
                            {
                                "$and": [
                                    {"$gte": ["$not_valid_after", tw["now"]]},
                                    {"$lt": ["$not_valid_after", tw["in_3_days"]]},
                                ]
                            },
                            1,
                            0,
                        ]
                    }
                },
                "expiring_in_7_days": {
                    "$sum": {
                        "$cond": [
                            {
                                "$and": [
                                    {"$gte": ["$not_valid_after", tw["now"]]},
                                    {"$lt": ["$not_valid_after", tw["in_7_days"]]},
                                ]
                            },
                            1,
                            0,
                        ]
                    }
                },
                "expiring_in_1_month": {
                    "$sum": {
                        "$cond": [
                            {
                                "$and": [
                                    {"$gte": ["$not_valid_after", tw["now"]]},
                                    {"$lt": ["$not_valid_after", tw["in_1_month"]]},
                                ]
                            },
                            1,
                            0,
                        ]
                    }
                },
                "expiring_in_3_months": {
                    "$sum": {
                        "$cond": [
                            {
                                "$and": [
                                    {"$gte": ["$not_valid_after", tw["now"]]},
                                    {"$lt": ["$not_valid_after", tw["in_3_months"]]},
                                ]
                            },
                            1,
                            0,
                        ]
                    }
                },
            }
        }
    ]

    res = mongo.aggregate(pipeline)
    return jsonify(list(res))


@certificate_bp.get("/expired")
# @jwt_required()
def expired_certs():
    tw = utils.time_windows()
    pipeline = utils.certs_by_expiry(datetime.min.replace(tzinfo=UTC), tw["now"])
    return jsonify(list(mongo.aggregate(pipeline)))


@certificate_bp.get("/expiry-3-days")
# @jwt_required()
def expiry_3_days():
    tw = utils.time_windows()
    pipeline = utils.certs_by_expiry(tw["now"], tw["in_3_days"])
    return jsonify(list(mongo.aggregate(pipeline)))


@certificate_bp.get("/expiry-7-days")
# @jwt_required()
def expiry_7_days():
    tw = utils.time_windows()
    pipeline = utils.certs_by_expiry(tw["now"], tw["in_7_days"])
    return jsonify(list(mongo.aggregate(pipeline)))


@certificate_bp.get("/expiry-1-month")
# @jwt_required()
def expiry_1_month():
    tw = utils.time_windows()
    pipeline = utils.certs_by_expiry(tw["now"], tw["in_1_month"])
    return jsonify(list(mongo.aggregate(pipeline)))


@certificate_bp.get("/expiry-3-months")
# @jwt_required()
def expiry_3_months():
    tw = utils.time_windows()
    pipeline = utils.certs_by_expiry(tw["now"], tw["in_3_months"])
    return jsonify(list(mongo.aggregate(pipeline)))


@certificate_bp.get("/top-issuers")
# @jwt_required()
def top_issuers():
    pipeline = utils.base_pipeline() + [
        {"$group": {"_id": "$issuer", "count": {"$sum": 1}}},
        {"$sort": {"count": -1}},
        {"$limit": 10},
    ]

    return jsonify(list(mongo.aggregate(pipeline)))
