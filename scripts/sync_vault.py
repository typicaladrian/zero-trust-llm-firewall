import urllib.request
import json

def sync_clients():
    url = "http://127.0.0.1:8000/v1/vault/sync"
    
    # The known client and law firm names to lock into the cryptographic vault
    payload = {
        "names": [
            "Medica",
            "Hogan & Hartson",
            "Hogan & Hartson L.L.P.",
            "Vapotherm"
        ]
    }
    
    data = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(
        url,
        data=data,
        headers={"Content-Type": "application/json"},
        method="POST"
    )
    
    print("🔐 Syncing sensitive entities to Cryptographic Vault...")
    try:
        with urllib.request.urlopen(req) as response:
            res = json.loads(response.read().decode("utf-8"))
            print("✅ Status:", res.get("status"))
            print("💬 Message:", res.get("message"))
            print(f"📊 Active Hashes in Ephemeral RAM: {res.get('total_active_hashes')}")
    except Exception as e:
        print(f"❌ Failed to sync vault: {e}")

if __name__ == "__main__":
    sync_clients()