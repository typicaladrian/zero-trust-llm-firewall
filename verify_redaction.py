import re
import os

def run_audit():
    file_path = "redacted_audit_report.txt"
    
    if not os.path.exists(file_path):
        print(f"❌ Error: {file_path} not found. Run the stress test first.")
        return

    with open(file_path, "r", encoding="utf-8") as f:
        text = f.read()

    print(f"{'='*60}")
    print("🕵️  REDACTION AUDIT RESULTS")
    print(f"{'='*60}\n")

    # 1. The Regression Check (Testing the STOPWORDS fix)
    # Using \b to match exact word boundaries so we don't count "bANDwidth"
    and_count = len(re.findall(r'\band\b', text, re.IGNORECASE))
    inc_count = len(re.findall(r'\binc\b', text, re.IGNORECASE))
    print("--- 1. STOPWORD REGRESSION CHECK ---")
    print(f"Occurrences of 'and': {and_count}  <-- (Should be in the hundreds)")
    print(f"Occurrences of 'Inc': {inc_count}   <-- (Should be > 0)")
    print("")

    # 2. The Negative Check (Hunting for known sensitive data)
    sensitive_targets = [
        "Vapotherm", "Medica", "Joseph Army", "Luciano", "Fecondini", 
        "Giubertoni", "Stevensville", "Zempolich", "Hogan & Hartson"
    ]
    
    print("--- 2. NEGATIVE LEAK CHECK ---")
    total_leaks = 0
    for target in sensitive_targets:
        # THE FIX: Added \b to enforce exact word boundary matches
        pattern = r'\b' + re.escape(target) + r'\b'
        matches = len(re.findall(pattern, text, re.IGNORECASE))
        if matches > 0:
            print(f"⚠️ LEAK DETECTED: '{target}' found {matches} times!")
            total_leaks += matches
            
    if total_leaks == 0:
        print("✅ PASS: Zero known sensitive entities leaked through.")
    print("")

    # 3. The Positive Check (Counting synthetic placeholders)
    orgs = len(re.findall(r'\[ORGANIZATION_\d+\]', text))
    people = len(re.findall(r'\[PERSON_\d+\]', text))
    addresses = len(re.findall(r'\[ADDRESS_\d+\]', text))
    
    print("--- 3. SYNTHETIC TOKEN INJECTION ---")
    print(f"Organizations Protected: {orgs} replacements")
    print(f"People Protected: {people} replacements")
    print(f"Addresses Protected: {addresses} replacements")
    print(f"\n{'='*60}")

if __name__ == "__main__":
    run_audit()