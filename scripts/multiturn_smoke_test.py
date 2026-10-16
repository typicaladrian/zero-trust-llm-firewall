import urllib.request
import json

def test_multiturn_chat(model_name="gpt-4o"):
    url = "http://127.0.0.1:8000/v1/chat/completions"
    
    # Simulating a multi-turn conversation array sent by Open WebUI
    payload = {
        "model": model_name,
        "messages": [
            {
                "role": "system",
                "content": (
                    "You are a helpful AI assistant. You will receive text containing redacted "
                    "placeholders in the format [ENTITY_TYPE_ID] (e.g., [PERSON_1], [EMAIL_ADDRESS_1]). "
                    "You MUST use these exact placeholders in your responses whenever referring to "
                    "those entities. Do not invent fake names, emails, or data to fill them in."
                )
            },
            {
                "role": "user",
                "content": "Hello, my name is Jane Smith and my email address is jane.smith@example.com."
            },
            {
                "role": "assistant",
                "content": "Hello Jane Smith! I have noted your email address as jane.smith@example.com. How can I help you today?"
            },
            {
                "role": "user",
                "content": "Could you draft a brief out-of-office response for Jane Smith directing urgent inquiries to jane.smith@example.com?"
            }
        ]
    }
    
    data = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(
        url, 
        data=data, 
        headers={"Content-Type": "application/json"},
        method="POST"
    )
    
    print("\n⚙️ EXECUTING TEST CASE: Multi-Turn Stateful Context")
    print("Waiting for cloud response...\n")
    
    try:
        with urllib.request.urlopen(req) as response:
            response_body = response.read().decode("utf-8")
            response_json = json.loads(response_body)
            
            assistant_msg = response_json.get("choices", [{}])[0].get("message", {}).get("content", "")
            print("--- DEANONYMIZED FINAL ASSISTANT RESPONSE ---")
            print(assistant_msg)
            print("-" * 60)
            
    except urllib.error.URLError as e:
        print(f"❌ Failed to connect or receive valid response: {e}")
        if hasattr(e, 'read'):
            print(e.read().decode("utf-8"))

if __name__ == "__main__":
    test_multiturn_chat()