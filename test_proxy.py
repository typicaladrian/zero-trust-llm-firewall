import urllib.request
import json

def test_proxy(model_name="gpt-4o"):
    url = "http://127.0.0.1:8000/v1/chat/completions"
    
    # Construct the payload mimicking Open WebUI
    payload = {
        "model": model_name,
        "messages": [
            {
                "role": "user",
                "content": "Please write a 2-sentence draft email to John Doe thanking him for his time at Acme Corp in New York."
            }
        ]
    }
    
    # Convert payload to bytes
    data = json.dumps(payload).encode("utf-8")
    
    # Create the request object with required headers
    req = urllib.request.Request(
        url, 
        data=data, 
        headers={"Content-Type": "application/json"},
        method="POST"
    )
    
    print(f"Sending payload to {url} using model '{model_name}'...")
    print("Waiting for response...\n")
    
    try:
        # Execute the request
        with urllib.request.urlopen(req) as response:
            response_body = response.read().decode("utf-8")
            response_json = json.loads(response_body)
            
            print("--- FULL JSON RESPONSE ---")
            print(json.dumps(response_json, indent=2))
            
            # Extract the actual assistant message for quick reading
            assistant_msg = response_json.get("choices", [{}])[0].get("message", {}).get("content", "")
            print("\n--- ASSISTANT MESSAGE EXTRACT ---")
            print(assistant_msg)
            
    except urllib.error.URLError as e:
        print(f"Failed to connect or receive valid response: {e}")
        if hasattr(e, 'read'):
            print(e.read().decode("utf-8"))

if __name__ == "__main__":
    # Test the live OpenAI route
    test_proxy(model_name="gpt-4o")
    
    # You can also test your local auditor bypass by uncommenting the line below:
    # test_proxy(model_name="elm-tech-auditor")