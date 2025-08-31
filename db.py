from pymongo import MongoClient

try:
    # conecta e define o database "db"
    client = MongoClient("mongodb://localhost:27017/")
    db = client["db"]

    # collections dentro de "db"
    modelo1 = db["modelo1"]
    modelo2 = db["modelo2"]
    vulnerabilities_collection = db["vulnerability"]

    # testando conexão
    client.admin.command("ping")
    print("Conexão com o MongoDB foi bem-sucedida!")

except Exception as e:
    print(f"Falha ao conectar ao MongoDB: {e}")
