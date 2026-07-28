import time
import json
import asyncio
from collections import defaultdict
from typing import List, Dict, Any, Iterator

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from gliner import GLiNER
import litellm

# ---------------------------------------------------------
# 1. Global Configurations & Model Initialization
# ---------------------------------------------------------

# Targeted PII labels with tight semantic boundaries
PII_LABELS = [
    "Person", "Organization", "Social Security Number", 
    "Medical Condition", "Address", "Phone Number", 
    "Email Address", "Credit Card Number", "Date of Birth",
    "Medical Record Number", "Medication", "Bank Account Number",
    "Tax Identification Number", "Driver's License Number", "Passport Number"
]

# Initialize GLiNER globally with ONNX runtime for optimized CPU execution
print("Loading GLiNER multi-pii-v1 with ONNX runtime...")
gliner_model = GLiNER.from_pretrained("sassoftware/glitext-pii-base", load_onnx_model=True)
print("GLiNER model loaded successfully.")

app = FastAPI(title="Zero-Trust AI Proxy", version="1.0.0")

# ---------------------------------------------------------
# 2. Text Chunking Utility
# ---------------------------------------------------------

def chunk_text(text: str, max_words: int = 400) -> List[str]:
    """
    Splits text into chunks of roughly max_words by spaces (~400 words).
    """
    words = text.split(" ")
    chunks = []
    for i in range(0, len(words), max_words):
        chunks.append(" ".join(words[i:i + max_words]))
    return chunks

# ---------------------------------------------------------
# 3. The Entity Vault (Stateless Context Mapping)
# ---------------------------------------------------------

class EntityVault:
    def __init__(self):
        # Maps raw entity text to token (e.g., "John Smith" -> "[PERSON_1]")
        self.entity_map: Dict[str, str] = {}
        # Maps token back to raw text for deanonymization
        self.reverse_map: Dict[str, str] = {}
        # Keeps track of token increments per label
        self.counters = defaultdict(int)

    def anonymize_text(self, text: str) -> str:
        """
        Chunks text, runs GLiNER batch inference, and reverses in-place
        substitutions to preserve string index integrity.
        """
        if not text.strip():
            return text

        chunks = chunk_text(text, max_words=400)
        
        # 1. Execute CPU batch inference on the GLiNER model
        batch_predictions = gliner_model.batch_predict_entities(
            chunks, 
            PII_LABELS, 
            batch_size=8
        )

        anonymized_chunks = []
        
        # 2. Process each chunk alongside its predictions
        for chunk, entities in zip(chunks, batch_predictions):
            mutated_chunk = chunk
            
            # Sort in reverse order by starting index to prevent index shifting!
            sorted_entities = sorted(entities, key=lambda x: x['start'], reverse=True)
            
            for ent in sorted_entities:
                ent_text = ent['text']
                label_base = ent['label'].upper().replace(" ", "_")
                
                # Check for existing token chronologically, else create new
                if ent_text not in self.entity_map:
                    self.counters[label_base] += 1
                    token = f"[{label_base}_{self.counters[label_base]}]"
                    self.entity_map[ent_text] = token
                    self.reverse_map[token] = ent_text
                else:
                    token = self.entity_map[ent_text]
                
                # Inject token exactly at the sorted indices
                start, end = ent['start'], ent['end']
                mutated_chunk = mutated_chunk[:start] + token + mutated_chunk[end:]
                
            anonymized_chunks.append(mutated_chunk)
            
        return " ".join(anonymized_chunks)

    def deanonymize_text(self, text: str) -> str:
        """
        Takes the LLM's response containing tokens and swaps them back 
        to original entities.
        """
        if not text:
            return text
            
        for token, original_value in self.reverse_map.items():
            text = text.replace(token, original_value)
            
        return text

# ---------------------------------------------------------
# 4. Proxy API Endpoints & Routing Engine
# ---------------------------------------------------------

@app.post("/v1/chat/completions")
async def chat_completions(request: Request):
    """
    Intercepts the Open WebUI OpenAI-format payload, scrubs PII asynchronously,
    handles diagnostic routing, passes to LiteLLM, and returns deanonymized results.
    """
    payload = await request.json()
    model = payload.get("model", "gpt-4o")
    messages = payload.get("messages", [])
    
    # Fresh Vault strictly bound to this request pass
    vault = EntityVault()
    start_time = time.time()
    
    # 1. Scrub the outgoing payload asynchronously (Concurrency Guard)
    scrubbed_messages = []
    for msg in messages:
        scrubbed_msg = msg.copy()
        if "content" in scrubbed_msg and isinstance(scrubbed_msg["content"], str):
            # Offload heavy CPU batch inference to worker thread so FastAPI remains non-blocking
            scrubbed_msg["content"] = await asyncio.to_thread(
                vault.anonymize_text, 
                scrubbed_msg["content"]
            )
        scrubbed_messages.append(scrubbed_msg)
        
    elapsed_ms = round((time.time() - start_time) * 1000, 2)
    
    # Extract last user message for audit reporting
    last_user_msg = next((m["content"] for m in reversed(scrubbed_messages) if m["role"] == "user"), "")

    # 2. Feature: The Elm Tech Auditor (Diagnostic Bypass)
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

    # 3. Model Routing & Upstream Request via LiteLLM
    payload["stream"] = False 
    payload["messages"] = scrubbed_messages

    print("\n--- OUTGOING SCRUBBED PAYLOAD TO LITELLM ---")
    print(json.dumps(payload["messages"], indent=2))

    try:
        # Offload synchronous LiteLLM network execution to thread worker
        llm_response = await asyncio.to_thread(litellm.completion, **payload)
        
        # 4. Deanonymize incoming response
        response_content = llm_response.choices[0].message.content
        restored_content = vault.deanonymize_text(response_content)
        
        # Inject restored text back into the response object
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
            content={"error": f"Proxy Error: An unexpected LiteLLM error occurred.", "details": str(e)}
        )