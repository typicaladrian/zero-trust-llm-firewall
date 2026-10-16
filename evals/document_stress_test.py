import urllib.request
import json
import time
import os
from pathlib import Path

EVALS_DIR = Path(__file__).resolve().parent

def run_document_load_test(file_path):
    url = "http://127.0.0.1:8000/v1/chat/completions"
    
    # 1. Load the massive document
    if not os.path.exists(file_path):
        print(f"❌ Error: Could not find {file_path}")
        return
        
    with open(file_path, "r", encoding="utf-8") as f:
        document_text = f.read()
        
    word_count = len(document_text.split())
    print(f"{'='*60}")
    print(f"🚀 INITIATING HEAVY LOAD TEST")
    print(f"Document Size: {word_count:,} words")
    print(f"{'='*60}\n")
    
    # 2. Build the prompt
    prompt = f"Please read the following contract and extract the top 3 liabilities:\n\n{document_text}"
    
    payload = {
        "model": "elm-tech-auditor", 
        "messages": [{"role": "user", "content": prompt}]
    }
    
    headers = {
        "Content-Type": "application/json",
        "x-openwebui-user-email": "partner@local.host"
    }
    
    req = urllib.request.Request(url, data=json.dumps(payload).encode("utf-8"), headers=headers, method="POST")
    
    print("Scrubbing document locally... (This will take a few moments)")
    start_time = time.time()
    
    # 3. Fire the payload
    try:
        with urllib.request.urlopen(req) as response:
            round_trip_time = round(time.time() - start_time, 2)
            response_json = json.loads(response.read().decode("utf-8"))
            
            print(f"\n✅ SUCCESS: Document Processed")
            print(f"⏱️ Total Redaction Time: {round_trip_time} seconds")
            
            # Extract the full redacted text
            assistant_msg = response_json.get("choices", [{}])[0].get("message", {}).get("content", "")
            
            # Write the fully redacted document to a new text file for manual auditing
            os.makedirs(EVALS_DIR / "output", exist_ok=True)
            output_filename = EVALS_DIR / "output" / "redacted_audit_report.txt"
            with open(output_filename, "w", encoding="utf-8") as out_file:
                out_file.write(assistant_msg)
                
            print(f"📄 Full redacted document saved to: {output_filename}")
            
    except Exception as e:
        print(f"❌ Failed to process document: {e}")

if __name__ == "__main__":
    run_document_load_test(EVALS_DIR / "fixtures" / "massive_contract.txt")