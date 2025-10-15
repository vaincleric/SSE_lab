import os
from app import generate_token

if not os.environ.get("APP_JWT_SECRET"):
    raise RuntimeError("APP_JWT_SECRET must be set before running this script")

print("ENCRYPT_TOKEN=", generate_token("dev1", ["encrypt"], expires_in_seconds=3600))
print("DECRYPT_TOKEN=", generate_token("dev1", ["decrypt"], expires_in_seconds=3600))
print("ADMIN_TOKEN=", generate_token("admin1", ["admin"], expires_in_seconds=3600))
