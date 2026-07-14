import requests
import json

PROXY_URL = "http://127.0.0.1:8000/v1/chat/completions" # loopback url

# simulate employee pasting data
payload = {
    "prompt": "Review this contract for John Doe. His SSN is 000-11-2222. Should we settle?"
}

print("Sending request to Local Privacy Proxy...")
response = requests.post(PROXY_URL, json=payload)

print(f"\nStatus Code: {response.status_code}")
print("Response from Proxy:")
print(json.dumps(response.json(), indent=2))