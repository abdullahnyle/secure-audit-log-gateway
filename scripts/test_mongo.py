"""Quick smoke test for MongoDB connection. Delete after Day 1."""
import asyncio
from motor.motor_asyncio import AsyncIOMotorClient


async def main():
    # Connect to local MongoDB (default port 27017)
    client = AsyncIOMotorClient("mongodb://localhost:27017")
    db = client["audit_log_test"]
    collection = db["smoke_test"]

    # Insert a document
    result = await collection.insert_one({"msg": "hello from python", "ok": True})
    print(f"Inserted doc with _id: {result.inserted_id}")

    # Read it back
    doc = await collection.find_one({"_id": result.inserted_id})
    print(f"Read back: {doc}")

    # Clean up so we don't leave junk behind
    await collection.delete_one({"_id": result.inserted_id})
    print("Cleaned up test doc.")

    # Server info confirms which version we're hitting
    info = await client.server_info()
    print(f"MongoDB version: {info['version']}")

    client.close()


if __name__ == "__main__":
    asyncio.run(main())
