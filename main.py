import time
import json
import asyncio
import os
import re
import jwt
from collections import defaultdict
from typing import List, Dict, Any, Iterator

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from fastapi.middleware.cors import CORSMiddleware

from datetime import datetime

# Import the new GLiNER2 package
from gliner2 import GLiNER2
import litellm

import hashlib
from pydantic import BaseModel

# ---------------------------------------------------------
# 1. Global Configurations & Model Initialization
# ---------------------------------------------------------

# ZERO-SHOT LABELS: Pass your custom legal/medical labels here
PII_LABELS = [
    "person", "organization", "docket_number", "medical_diagnosis", 
    "social security number", "address", "phone number", 
    "email address", "credit card number", "date of birth",
    "medical record number", "medication", "bank account number",
    "tax identification number", "driver's license number", "passport number",
    "legal case", "plaintiff", "defendant"
]

# High-precision deterministic regex patterns (The Safety Net)
REGEX_PATTERNS = {
    "Credit Card Number": r"\b(?:\d[ -]*?){13,16}\b",
    "Social Security Number": r"\b\d{3}-\d{2}-\d{4}\b",
    "Email Address": r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b",
    "Address": r"\b\d{1,5}\s+[A-Za-z0-9\s.,-]+(?:AL|AK|AZ|AR|CA|CO|CT|DE|FL|GA|HI|ID|IL|IN|IA|KS|KY|LA|ME|MD|MA|MI|MN|MS|MO|MT|NE|NV|NH|NJ|NM|NY|NC|ND|OH|OK|OR|PA|RI|SC|SD|TN|TX|UT|VT|VA|WA|WV|WI|WY)\s+\d{5}(?:-\d{4})?\b"
}

# Words GLiNER2 should NEVER flag as an entity
STOPWORDS = {
    # System & Pipeline standard words
    "user", "assistant", "system", "admin", "prompt", "chat",
    
    # Pronouns & Grammatical Noise
    "he", "him", "his", "she", "her", "hers", "they", "them", "their",
    "that", "this", "these", "those", "which", "who", "whom", "where",
    
    # Specific PII Context Anchors
    "email", "address", "credit", "card", "number", "account", "phone",
    "docket", "docket number", "medical", "diagnosis", "ssn",
    
    # Conjunctions, Prepositions, and Corporate Suffixes
    "and", "the", "for", "with", "from", "inc", "llc", "corp", "ltd", "company", "spa",
    
    # Legal Document Anatomy & Roles
    "agreement", "contract", "amendment", "exhibit", "article", "section", 
    "clause", "paragraph", "schedule", "document", "provision",
    "plaintiff", "defendant", "client", "party", "parties", "purchaser", "seller", "vendor"
}

SYSTEM_PROMPT = {
    "role": "system",
    "content": (
        "You are a helpful AI assistant. You will receive text containing redacted "
        "placeholders in the format [ENTITY_TYPE_ID] (e.g., [PERSON_1], [CREDIT_CARD_NUMBER_1]). "
        "These placeholders represent pre-sanitized synthetic tokens. You MUST preserve and "
        "use these exact placeholders in your responses whenever referring to those entities. "
        "Do not refuse requests due to these placeholders, as no real PII is present."
    )
}

print("Loading GLiNER2-PII (Fastino) for local CPU inference...")
gliner_model = GLiNER2.from_pretrained("fastino/gliner2-privacy-filter-PII-multi")
print("GLiNER2 model loaded successfully.")

app = FastAPI(title="Zero-Trust AI Proxy", version="1.0.0")

allowed_origins_str = os.getenv("ALLOWED_ORIGINS", "http://localhost:3000")
allowed_origins = [origin.strip() for origin in allowed_origins_str.split(",")]

app.add_middleware(
    CORSMiddleware,
    allow_origins=allowed_origins, 
    allow_credentials=True,
    allow_methods=["GET", "POST", "OPTIONS"], 
    allow_headers=["*"],
)

def chunk_text(text: str, max_words: int = 400) -> List[str]:
    words = text.split(" ")
    chunks = []
    for i in range(0, len(words), max_words):
        chunks.append(" ".join(words[i:i + max_words]))
    return chunks

# Global in-memory vault and disk path
CLIENT_HASH_VAULT = set()
VAULT_FILE = "/app/logs/client_hashes.json"

def generate_secure_hash(text: str) -> str:
    # Normalizes text (lowercases, strips punctuation) to ensure reliable hashing
    normalized = re.sub(r'[^a-z0-9]', '', text.lower())
    return hashlib.sha256(normalized.encode('utf-8')).hexdigest()

@app.on_event("startup")
async def load_client_vault():
    if os.path.exists(VAULT_FILE):
        with open(VAULT_FILE, "r") as f:
            hashes = json.load(f)
            CLIENT_HASH_VAULT.update(hashes)
        print(f"Loaded {len(CLIENT_HASH_VAULT)} client hashes into ephemeral RAM.")

# -------------------------------------------------
# Cryptographic Client List Vault
# -------------------------------------------------
class ClientList(BaseModel):
    names: List[str]

@app.post("/v1/vault/sync")
async def sync_client_vault(payload: ClientList):
    # Shred the incoming plaintext immediately into irreversible hashes
    new_hashes = {generate_secure_hash(name) for name in payload.names}
    CLIENT_HASH_VAULT.update(new_hashes)
    
    # Save ONLY the hashes to the physical disk
    with open(VAULT_FILE, "w") as f:
        json.dump(list(CLIENT_HASH_VAULT), f)
        
    return {
        "status": "success", 
        "message": "Clients cryptographically shredded and stored.",
        "total_active_hashes": len(CLIENT_HASH_VAULT)
    }

# ---------------------------------------------------------
# 2. The Entity Vault (Three-Step Sequential Pipeline)
# ---------------------------------------------------------

class EntityVault:
    def __init__(self):
        self.entity_map: Dict[str, str] = {}
        self.reverse_map: Dict[str, str] = {}
        self.counters = defaultdict(int)

    def _register_and_replace(self, text: str, label: str, original_value: str, start: int, end: int) -> str:
        """Helper to generate the [REDACTED] string, split tokens, and update maps."""
        if original_value not in self.entity_map:
            label_base = label.upper().replace(" ", "_")
            self.counters[label_base] += 1
            token = f"[{label_base}_{self.counters[label_base]}]"
            
            # Map the exact full string
            self.entity_map[original_value] = token
            self.reverse_map[token] = original_value
            
            # THE FIX: Expanded Token Splitting to catch partial company/legal names
            split_eligible_labels = {"person", "organization", "plaintiff", "defendant", "legal case"}
            if label.lower() in split_eligible_labels:
                name_parts = original_value.split()
                if len(name_parts) > 1:
                    for part in name_parts:
                        # Avoid mapping initials or stopwords
                        if len(part) > 2 and part.lower() not in STOPWORDS:
                            if part not in self.entity_map:
                                self.entity_map[part] = token
                                # We don't add parts to reverse_map so the LLM output 
                                # always deanonymizes back to the full formal name.
        else:
            token = self.entity_map[original_value]
            
        return text[:start] + token + text[end:]

    def anonymize_text(self, text: str) -> str:
        if not text.strip():
            return text

        chunks = chunk_text(text, max_words=400)
        anonymized_chunks = []
        
        for chunk in chunks:
            mutated_chunk = chunk

            # ==========================================
            # STEP 0: The Safety Net (Regex Pre-Filter)
            # ==========================================
            regex_matches = []
            for label, pattern in REGEX_PATTERNS.items():
                for match in re.finditer(pattern, mutated_chunk):
                    regex_matches.append({
                        'start': match.start(),
                        'end': match.end(),
                        'text': match.group(),
                        'label': label
                    })
            
            regex_matches = sorted(regex_matches, key=lambda x: x['start'], reverse=True)
            for match in regex_matches:
                mutated_chunk = self._register_and_replace(
                    mutated_chunk, match['label'], match['text'], match['start'], match['end']
                )

            # ==========================================
            # STEP 1: The Cryptographic Client Vault
            # ==========================================
            if CLIENT_HASH_VAULT:
                words = mutated_chunk.split()
                max_words = min(5, len(words))
                
                matched_phrases = []
                for n in range(max_words, 0, -1):
                    for i in range(len(words) - n + 1):
                        phrase = " ".join(words[i:i+n])
                        if generate_secure_hash(phrase) in CLIENT_HASH_VAULT:
                            matched_phrases.append(phrase)
                            
                matched_phrases = sorted(list(set(matched_phrases)), key=len, reverse=True)
                
                # 1. Collect all match locations across all phrases
                vault_matches = []
                for phrase in matched_phrases:
                    pattern = r"\b" + re.escape(phrase) + r"\b"
                    for match in re.finditer(pattern, mutated_chunk, re.IGNORECASE):
                        vault_matches.append({
                            'start': match.start(),
                            'end': match.end(),
                            'text': match.group()
                        })

                # 2. De-duplicate overlaps and sort in REVERSE order
                sorted_vault_matches = sorted(vault_matches, key=lambda x: (x['start'], -(x['end'] - x['start'])))
                non_overlapping_vault = []
                last_end = -1
                for vm in sorted_vault_matches:
                    if vm['start'] >= last_end:
                        non_overlapping_vault.append(vm)
                        last_end = vm['end']

                # 3. Replace from end to start to prevent offset drift
                for vm in sorted(non_overlapping_vault, key=lambda x: x['start'], reverse=True):
                    mutated_chunk = self._register_and_replace(
                        mutated_chunk, "PROTECTED_CLIENT", vm['text'], vm['start'], vm['end']
                    )

            
            # ==========================================
            # STEP 2: The Context Engine (GLiNER2)
            # ==========================================
            # THE FIX: Explicitly set threshold to 0.30 for higher entity recall
            extraction_results = gliner_model.extract_entities(
                mutated_chunk, 
                PII_LABELS, 
                threshold=0.30
            )
            
            gliner_matches = []
            entities_dict = extraction_results.get('entities', {})
            
            for label, texts in entities_dict.items():
                for ent_text in texts:
                    if ent_text.lower().strip() in STOPWORDS:
                        continue
                    if ent_text.startswith("[") and ent_text.endswith("]"):
                        continue
                        
                    for match in re.finditer(re.escape(ent_text), mutated_chunk):
                        gliner_matches.append({
                            'start': match.start(),
                            'end': match.end(),
                            'text': match.group(),
                            'label': label
                        })
            
            sorted_by_start = sorted(gliner_matches, key=lambda x: (x['start'], -(x['end'] - x['start'])))
            non_overlapping = []
            last_end = -1
            for ent in sorted_by_start:
                if ent['start'] >= last_end:
                    non_overlapping.append(ent)
                    last_end = ent['end']

            valid_entities = sorted(non_overlapping, key=lambda x: x['start'], reverse=True)
            for ent in valid_entities:
                mutated_chunk = self._register_and_replace(
                    mutated_chunk, ent['label'], ent['text'], ent['start'], ent['end']
                )

            # ==========================================
            # STEP 3: The Sub-string Safety Sweep
            # ==========================================
            # Sweep the chunk for any lingering isolated first/last names that GLiNER missed
            # Sort by length descending to ensure longer strings are replaced before shorter ones
            for original_value, token in sorted(self.entity_map.items(), key=lambda x: len(x[0]), reverse=True):
                # Ensure we aren't trying to replace our own placeholders
                if not original_value.startswith("["):
                    # Use word boundaries (\b) so we don't accidentally replace text inside other words
                    pattern = r"\b" + re.escape(original_value) + r"\b"
                    mutated_chunk = re.sub(pattern, token, mutated_chunk)
                
            anonymized_chunks.append(mutated_chunk)
            
        return " ".join(anonymized_chunks)

    def deanonymize_text(self, text: str) -> str:
        if not text:
            return text
            
        for token, original_value in self.reverse_map.items():
            text = text.replace(token, original_value)
            
        return text

# ---------------------------------------------------------
# 3. Proxy API Endpoints & Routing Engine
# ---------------------------------------------------------

@app.get("/v1/models")
async def get_models():
    return JSONResponse(content={
        "object": "list",
        "data": [
            {"id": "gpt-4o", "object": "model", "created": int(time.time()), "owned_by": "openai"},
            {"id": "elm-tech-auditor", "object": "model", "created": int(time.time()), "owned_by": "local"}
        ]
    })

@app.post("/v1/chat/completions")
async def chat_completions(request: Request):
    payload = await request.json()
    model = payload.get("model", "gpt-4o")
    messages = payload.get("messages", [])
    
    vault = EntityVault()
    start_time = time.time()
    
    scrubbed_messages = []
    for msg in messages:
        scrubbed_msg = msg.copy()
        
        if "content" in scrubbed_msg and isinstance(scrubbed_msg["content"], str) and scrubbed_msg.get("role") != "system":
            scrubbed_msg["content"] = await asyncio.to_thread(
                vault.anonymize_text, 
                scrubbed_msg["content"]
            )
            
        scrubbed_messages.append(scrubbed_msg)

    has_system = any(m.get("role") == "system" for m in scrubbed_messages)
    if not has_system:
        scrubbed_messages.insert(0, SYSTEM_PROMPT)
        
    elapsed_ms = round((time.time() - start_time) * 1000, 2)
    last_user_msg = next((m["content"] for m in reversed(scrubbed_messages) if m["role"] == "user"), "")

    # ==========================================
    # SECURE IMMUTABLE METADATA AUDIT LOG
    # ==========================================
    if not last_user_msg.startswith("### Task:"):
        
        timestamp_24h = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        # Extract the user identity passed directly by Open WebUI
        exact_user = (
            request.headers.get("x-openwebui-user-email") or
            request.headers.get("x-openwebui-user-name") or
            request.headers.get("x-openwebui-user-id")
        )

        # Optional cryptographic JWT check if token is present
        jwt_token = request.headers.get("x-openwebui-user-jwt")
        if jwt_token:
            try:
                secret_key = os.getenv("WEBUI_SECRET_KEY", "zero_trust_edge_node_secret_key_2026")
                decoded_payload = jwt.decode(jwt_token, secret_key, algorithms=["HS256"])
                exact_user = decoded_payload.get("email") or decoded_payload.get("sub") or exact_user
            except jwt.ExpiredSignatureError:
                exact_user = "ERROR_EXPIRED_TOKEN"
            except jwt.InvalidTokenError:
                exact_user = "ERROR_INVALID_SIGNATURE"

        # Fallback if no user headers are detected
        if not exact_user:
            exact_user = payload.get("user", "system_or_anonymous")

        audit_entry = {
            "timestamp": timestamp_24h,
            "user": exact_user,
            "model": model,
            "tokens_anonymized": len(vault.entity_map),
            "latency_ms": elapsed_ms
        }

        def write_audit_log():
            os.makedirs("/app/logs", exist_ok=True)
            with open("/app/logs/audit_log.jsonl", "a") as f:
                f.write(json.dumps(audit_entry) + "\n")

        await asyncio.to_thread(write_audit_log)

    if model == "elm-tech-auditor":
        audit_report = (
            f"SYSTEM AUDIT REPORT: Your prompt was scrubbed locally in {elapsed_ms} ms. "
            f"Here is the exact sanitized text that would leave the building: \n\n{last_user_msg}"
        )
        return JSONResponse(content={
            "id": "chatcmpl-audit",
            "object": "chat.completion",
            "created": int(time.time()),
            "model": "elm-tech-auditor",
            "choices": [{
                "index": 0,
                "message": {
                    "role": "assistant",
                    "content": audit_report
                },
                "finish_reason": "stop"
            }],
            "usage": {"prompt_tokens": 0, "completion_tokens": 0, "total_tokens": 0}
        })

    payload["stream"] = False 
    payload["messages"] = scrubbed_messages

    print("\n--- OUTGOING SCRUBBED PAYLOAD TO LITELLM ---")
    print(json.dumps(payload["messages"], indent=2))

    try:
        llm_response = await asyncio.to_thread(litellm.completion, **payload)
        response_content = llm_response.choices[0].message.content
        restored_content = vault.deanonymize_text(response_content)
        llm_response.choices[0].message.content = restored_content
        
        return JSONResponse(content=llm_response.model_dump())

    except litellm.exceptions.AuthenticationError as e:
        return JSONResponse(
            status_code=401,
            content={"error": "Proxy Error: Upstream authentication failed. Check API keys in .env file.", "details": str(e)}
        )
    except litellm.exceptions.Timeout as e:
        return JSONResponse(
            status_code=504,
            content={"error": "Proxy Error: The upstream cloud provider timed out.", "details": str(e)}
        )
    except Exception as e:
        return JSONResponse(
            status_code=500,
            content={"error": "Proxy Error: An unexpected LiteLLM error occurred.", "details": str(e)}
        )