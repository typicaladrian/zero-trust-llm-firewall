import json
import re
import os
import time
import sys
from pathlib import Path

EVALS_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(EVALS_DIR.parent))  # make main.py importable from any working directory

from main import EntityVault, STOPWORDS

FIXTURES_DIR = EVALS_DIR / "fixtures" / "cuad"
OUTPUT_DIR = EVALS_DIR / "output"

def run_benchmark(contract_text: str, ground_truth_json_path: str, output_txt_path: str):
    # 1. Load the Ground Truth entities
    with open(ground_truth_json_path, 'r', encoding="utf-8") as f:
        ground_truth = json.load(f)
    
    sensitive_entities = ground_truth.get("entities", [])
    
    # 2. Run your local Zero-Trust Engine with execution timing
    vault = EntityVault()
    
    start_time = time.perf_counter()
    scrubbed_text = vault.anonymize_text(contract_text)
    elapsed_time = time.perf_counter() - start_time

    # QA SANITY CHECK: Fail immediately if engine outputs empty text
    if not scrubbed_text or len(scrubbed_text.strip()) == 0:
        print(f"\n❌ CRITICAL PIPELINE FAILURE: Redacted text is EMPTY.")
        return

    if len(scrubbed_text) < len(contract_text) * 0.5:
        print(f"\n⚠️ WARNING: Excessive truncation detected ({len(scrubbed_text)} chars vs {len(contract_text)} input chars).")
    
    # 3. Save the Redacted Output for Manual Review
    with open(output_txt_path, "w", encoding="utf-8") as f:
        f.write(scrubbed_text)
    
    # 4. Calculate Recall (The Leak Check)
    leaks = []
    
    def is_just_stopwords(text_chunk):
        """Helper to check if a partial leak is just harmless boilerplate"""
        tokens = re.findall(r'\b\w+\b', text_chunk.lower())
        return len(tokens) > 0 and all(t in STOPWORDS for t in tokens)

    for entity in sensitive_entities:
        words = entity.split()
        
        # 1. Check for exact match first
        exact_pattern = r'\b' + re.escape(entity) + r'\b'
        if re.search(exact_pattern, scrubbed_text, re.IGNORECASE):
            leaks.append(entity)
            continue
            
        # 2. Check for partial leaks (if entity is multi-word)
        if len(words) >= 2:
            first_chunk = " ".join(words[:2])
            last_chunk = " ".join(words[-2:])
            
            # Filter out chunks that are entirely stopwords (e.g., "COM INC")
            if len(first_chunk) > 4 and not is_just_stopwords(first_chunk) and re.search(r'\b' + re.escape(first_chunk) + r'\b', scrubbed_text, re.IGNORECASE):
                leaks.append(f"{entity} (Partial Leak: '{first_chunk}')")
            elif len(last_chunk) > 4 and not is_just_stopwords(last_chunk) and re.search(r'\b' + re.escape(last_chunk) + r'\b', scrubbed_text, re.IGNORECASE):
                leaks.append(f"{entity} (Partial Leak: '{last_chunk}')")
            
    total_entities = len(sensitive_entities)
    missed_entities = len(leaks)
    caught_entities = total_entities - missed_entities
    
    recall_percentage = (caught_entities / total_entities) * 100 if total_entities > 0 else 100
    
    print(f"{'='*60}")
    print(f"📊 REDACTION BENCHMARK RESULTS")
    print(f"{'='*60}")
    print(f"Document Size: {len(contract_text):,} characters ({len(contract_text.split()):,} words)")
    print(f"⏱️ Anonymization Latency: {elapsed_time:.2f}s ({elapsed_time * 1000:.2f} ms)")
    print(f"Total Entities to Catch: {total_entities}")
    print(f"Entities Successfully Scrubbed: {caught_entities}")
    print(f"Entities Leaked: {missed_entities}")
    print(f"RECALL SCORE: {recall_percentage:.2f}%")
    
    if leaks:
        print("\n🚨 CRITICAL LEAKS DETECTED:")
        for leak in leaks:
            print(f" - {leak}")
    else:
        print("\n✅ PERFECT RUN: Zero Leaks Detected.")
        
    print(f"\n📄 Redacted text saved for review at: {output_txt_path}")
    
    print(f"\n{'='*60}")
    print(f"🔎 PRECISION AUDIT: WHAT THE ENGINE REDACTED")
    print(f"{'='*60}")
    
    redacted_strings = list(vault.entity_map.keys())
    
    if not redacted_strings:
        print("No entities were redacted.")
    else:
        for string in redacted_strings:
            print(f" [REDACTED] -> {string}")

if __name__ == "__main__":
    OUTPUT_DIR.mkdir(exist_ok=True)
    test_suite = [
        {
            "name": "CUAD Contract #1 (I-Escrow)",
            "text_path": FIXTURES_DIR / "cuad_contract_1.txt",
            "json_path": FIXTURES_DIR / "cuad_1_ground_truth.json",
            "out_path": OUTPUT_DIR / "cuad_1_redacted.txt"
        },
        {
            "name": "CUAD Contract #2 (Services Agreement)",
            "text_path": FIXTURES_DIR / "cuad_contract_2.txt",
            "json_path": FIXTURES_DIR / "cuad_2_ground_truth.json",
            "out_path": OUTPUT_DIR / "cuad_2_redacted.txt"
        },
        {
            "name": "CUAD Contract #3 (Strategic Alliance)",
            "text_path": FIXTURES_DIR / "cuad_contract_3.txt",
            "json_path": FIXTURES_DIR / "cuad_3_ground_truth.json",
            "out_path": OUTPUT_DIR / "cuad_3_redacted.txt"
        },
        {
            "name": "CUAD Contract #4 (AFSALA...)",
            "text_path": FIXTURES_DIR / "cuad_contract_4.txt",
            "json_path": FIXTURES_DIR / "cuad_4_ground_truth.json",
            "out_path": OUTPUT_DIR / "cuad_4_redacted.txt"
        },
        {
            "name": "CUAD Contract #5 (AzulSa_...)",
            "text_path": FIXTURES_DIR / "cuad_contract_5.txt",
            "json_path": FIXTURES_DIR / "cuad_5_ground_truth.json",
            "out_path": OUTPUT_DIR / "cuad_5_redacted.txt"
        }
    ]
    
    for test in test_suite:
        print(f"\n\n{'*'*60}")
        print(f"🚀 RUNNING BENCHMARK: {test['name']}")
        print(f"{'*'*60}")
        
        try:
            with open(test["text_path"], "r", encoding="utf-8") as f:
                contract_text = f.read()
                
            run_benchmark(contract_text, test["json_path"], test["out_path"])
            
        except FileNotFoundError as e:
            print(f"❌ Error: Could not find file {e.filename}. Ensure it is in the test_textfiles folder.")