from pymongo import MongoClient

client = MongoClient("mongodb://localhost:27017/")
modelo1 = client["modelo1"]
modelo2 = client["modelo2"]

vulnerabilities_collection = modelo1["vulnerabilities"]
