from datetime import UTC, datetime

from bson import ObjectId
from pymongo import MongoClient

HOST = "mongo"
PORT = 27017
DB = "CertDB"
COLLECTION = "certificates"

client = MongoClient(f"mongodb://{HOST}:{PORT}/{DB}")
collection = client[DB][COLLECTION]


def insert(document):
    document["timestamp"] = datetime.now(UTC)
    res = collection.insert_one(document)

    return res.inserted_id


def documents(skip=0, page_size=10):
    cur = (
        collection.find({}, {"host": 1, "timestamp": 1})
        .sort("timestamp", -1)
        .skip(skip)
        .limit(page_size)
    )
    return list(cur)


def get(id):
    return collection.find_one({"_id": ObjectId(id)}, {"_id": 0})
