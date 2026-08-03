# import urllib.request
# import json
# import time

# def run_test_case(name, prompt, model_name="gpt-4o"):
#     url = "http://127.0.0.1:8000/v1/chat/completions"
    
#     payload = {
#         "model": model_name,
#         "messages": [
#             {
#                 "role": "user",
#                 "content": prompt
#             }
#         ]
#     }
    
#     data = json.dumps(payload).encode("utf-8")
#     req = urllib.request.Request(
#         url, 
#         data=data, 
#         headers={"Content-Type": "application/json"},
#         method="POST"
#     )
    
#     print(f"\n{'='*60}")
#     print(f"⚙️ EXECUTING TEST CASE: {name}")
#     print(f"Prompt: {prompt}")
#     print(f"{'='*60}")
#     print("Waiting for cloud response...\n")
    
#     try:
#         with urllib.request.urlopen(req) as response:
#             response_body = response.read().decode("utf-8")
#             response_json = json.loads(response_body)
            
#             assistant_msg = response_json.get("choices", [{}])[0].get("message", {}).get("content", "")
#             print("--- DEANONYMIZED ASSISTANT MESSAGE ---")
#             print(assistant_msg)
#             print("-" * 60)
            
#     except urllib.error.URLError as e:
#         print(f"❌ Failed to connect or receive valid response: {e}")
#         if hasattr(e, 'read'):
#             print(e.read().decode("utf-8"))

# if __name__ == "__main__":
#     # Define our suite of zero-trust test cases
#     test_suite = [
#         {
#             "name": "Standard Business (Original)",
#             "prompt": "Please write a 2-sentence draft email to John Doe thanking him for his time at Acme Corp in New York."
#         },
#         {
#             "name": "Medical Practice (HIPAA Simulation)",
#             "prompt": "Draft a short, professional medical referral letter for our patient, Robert Chen, who was recently diagnosed with chronic hypertension. Please address the letter to his specialist and mention his date of birth is 05/14/1975."
#         },
#         {
#             "name": "Law Firm (Legal Notice Simulation)",
#             "prompt": "Please write a 2-sentence formal legal notice to Alice Smith at 123 Legal Way confirming that her retainer fee for Apex Corp has been processed using her Credit Card Number 4000-1234-5678-9010."
#         }
#     ]
    
#     # Execute each test sequentially
#     for case in test_suite:
#         run_test_case(case["name"], case["prompt"])
#         time.sleep(2)  # Brief pause between network requests

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