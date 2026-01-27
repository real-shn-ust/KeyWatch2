from pymongo import MongoClient


def insert(document, host="mongo", port=27017, db="CertDB", collection="certificates"):
    client = MongoClient(f"mongodb://{host}:{port}/{db}")
    _collection = client[db][collection]
    res = _collection.insert_one(document)

    return res.inserted_id
