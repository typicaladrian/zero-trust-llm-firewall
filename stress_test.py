import urllib.request
import json
import time

def run_stress_test():
    url = "http://127.0.0.1:8000/v1/chat/completions"
    
    # The four high-stress scenarios designed to test Regex + GLiNER2
    scenarios = [
        {
            "name": "Scenario 1: Personal Injury Litigation",
            "prompt": "Please write a brief deposition summary for the plaintiff, David Chen, in the matter of Chen v. Elm Tech Solutions LLC, Docket No. BER-L-1234-26. Mr. Chen (DOB: 08/22/1980, Medical Record Number: MRN-998877) was recently diagnosed with chronic severe hypertension and was prescribed Lisinopril 20mg. His primary contact number is 201-555-0199. Ensure the summary is empathetic but formal."
        },
        {
            "name": "Scenario 2: Corporate Tax Audit",
            "prompt": "Draft a formal audit response letter to the IRS on behalf of our client, Sarah Jenkins. Her personal SSN is 111-22-3333 and her business Tax Identification Number is 99-8877665. She currently banks with Capital One (Bank Account Number: 9876543210). Please instruct the auditor to send all future correspondence to her directly at s.jenkins@taxadvisors.com."
        },
        {
            "name": "Scenario 3: Real Estate / M&A Retainer",
            "prompt": "We are processing the legal retainer for the acquisition of Horizon Dynamics. Please generate a 2-sentence payment confirmation for CEO Marcus Vance. His billing address is 45 Main Street, Hackensack, NJ 07601. The $10,000 fee was successfully charged to his primary business Visa, Credit Card Number 4000-1234-5678-9010."
        },
        {
            "name": "Scenario 4: The Messy Paste",
            "prompt": "messy notes from client call - plaintiff name is Alice Smith. defendant is local corp. address: 100 Corporate Drive, Paramus, NJ 07652. she said her driver's license number is NJ-D12345678 and passport number is P88776655. user wants us to file the docket tomorrow. can you clean this up into a professional email we can send to the system admin?"
        }
    ]

    print(f"{'='*60}")
    print("STARTING ZERO-TRUST PROXY STRESS TEST")
    print(f"{'='*60}\n")
    
    for i, case in enumerate(scenarios, 1):
        # Using the local auditor model to test scrubbing without incurring API costs
        payload = {
            "model": "elm-tech-auditor",
            "messages": [
                {
                    "role": "user",
                    "content": case["prompt"]
                }
            ]
        }
        
        data = json.dumps(payload).encode("utf-8")
        
        # Injecting the Open WebUI headers to simulate a legitimate authenticated request
        headers = {
            "Content-Type": "application/json",
            "x-openwebui-user-email": "auditor@local.host",
            "x-openwebui-user-name": "auditor",
            "x-openwebui-user-id": "stress-test-uuid"
        }
        
        req = urllib.request.Request(url, data=data, headers=headers, method="POST")
        
        print(f"--- {case['name']} ---")
        
        start_time = time.time()
        
        try:
            with urllib.request.urlopen(req) as response:
                response_body = response.read().decode("utf-8")
                response_json = json.loads(response_body)
                
                round_trip_latency = round((time.time() - start_time) * 1000, 2)
                assistant_msg = response_json.get("choices", [{}])[0].get("message", {}).get("content", "")
                
                print(f"Round Trip Network Latency: {round_trip_latency}ms")
                print("\n▼ ELM-TECH-AUDITOR REPORT ▼")
                print(f"{assistant_msg}")
                print(f"{'-'*60}\n")
                
        except urllib.error.URLError as e:
            print(f"Status: FAILED")
            print(f"Error Details: {e}")
            if hasattr(e, 'read'):
                print(e.read().decode("utf-8"))
            print("\n")
        
        # A brief 1-second pause to prevent overwhelming the local CPU
        time.sleep(1)
        
    print(f"{'='*60}")
    print("STRESS TEST COMPLETE")
    print(f"{'='*60}")

if __name__ == "__main__":
    run_stress_test()