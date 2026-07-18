import os
import re
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from dotenv import load_dotenv
from openai import AsyncOpenAI
from presidio_analyzer import AnalyzerEngine, PatternRecognizer, Pattern
from presidio_anonymizer import AnonymizerEngine
from presidio_anonymizer.entities import OperatorConfig

# load in environment variables
load_dotenv()

# initialize FastAPI
app = FastAPI(title="Zero-Trust AI Privacy Proxy (Presidio Edition)", version="1.0.0")

# connect to external LLM
external_client = AsyncOpenAI(api_key=os.getenv("OPENAI_API_KEY"))

# initialize Presidio
print("Initializing Microsoft Presidio Engines...")
analyzer = AnalyzerEngine()
anonymizer = AnonymizerEngine()

# Pattern Recognizers (the Presidio version of our old Regex pattern matching)
# Legal Entity Pattern
legal_pattern = Pattern(name="legal_case_pattern", regex=r"\b([A-Z][\w\.\-]+(?:\s+[A-Z][\w\.\-]+)*)(?=\s+v[s]?\.)", score=0.9)
legal_recognizer = PatternRecognizer(supported_entity="LEGAL_ENTITY", patterns=[legal_pattern])
analyzer.registry.add_recognizer(legal_recognizer)

# Obfuscated Numbers Pattern
obf_num_pattern = Pattern(name="obfuscated_number", regex=r"(?<!\d)(?:\d[\s\-.]*){6,14}\d(?!\d)", score=0.7)
obf_num_recognizer = PatternRecognizer(supported_entity="PHONE_NUMBER", patterns=[obf_num_pattern])
analyzer.registry.add_recognizer(obf_num_recognizer)

# Obfuscated Words Pattern
obf_word_pattern = Pattern(name="obfuscated_word", regex=r"\b(?:[a-zA-Z]\.[\s]*){3,}[a-zA-Z]\b", score=0.8)
obf_word_recognizer = PatternRecognizer(supported_entity="OBFUSCATED_WORD", patterns=[obf_word_pattern])
analyzer.registry.add_recognizer(obf_word_recognizer)

# Corporate Entities Pattern
corp_pattern = Pattern(name="corporation_pattern", regex=r"\b[A-Z][\w\-]+(?:\s+[A-Z][\w\-]+)*\s+(?:Inc\.|Corp\.|LLC|Industries|Company|Ltd\.?)\b", score=0.8)
corp_recognizer = PatternRecognizer(supported_entity="ORGANIZATION", patterns=[corp_pattern])
analyzer.registry.add_recognizer(corp_recognizer)

# Financial/Money Pattern
money_pattern = Pattern(name="money_pattern", regex=r"\$\d+(?:,\d{3})*(?:\.\d+)?(?:[kKmMbB])?", score=0.8)
money_recognizer = PatternRecognizer(supported_entity="FINANCIAL_AMOUNT", patterns=[money_pattern])
analyzer.registry.add_recognizer(money_recognizer)

# Account/Routing Numbers
account_pattern = Pattern(name="account_pattern", regex=r"(?i)\b(?:account|acct\.?|ending in)\s*(?:number\s*|no\.?\s*|#\s*)?\d{4,12}\b", score=0.9)
account_recognizer = PatternRecognizer(supported_entity="ACCOUNT_NUMBER", patterns=[account_pattern])
analyzer.registry.add_recognizer(account_recognizer)
# --------------------------------------------------------------

# force expected incoming data structure
class ProxyRequest(BaseModel):
    prompt: str
    model: str = "gpt-3.5-turbo"

@app.post("/v1/chat/completions")
async def intercept_and_route(request: ProxyRequest):
    print(f"--> Received prompt: {request.prompt}")
    
    # 1. Presidio Coordinate Analysis
    # We explicitly tell Presidio which entity types to look for, plus our custom ones.
    results = analyzer.analyze(
        text=request.prompt,
        entities=["PERSON", "PHONE_NUMBER", "EMAIL_ADDRESS", 
                  "US_SSN", "ORGANIZATION", "LOCATION", "LEGAL_ENTITY", 
                  "FINANCIAL_AMOUNT", "OBFUSCATED_WORD", "DATE_TIME", "ACCOUNT_NUMBER"],
        language="en",
        score_threshold=0.5
    )
    
    # 2. Ephemeral Vault Initialization (Collision-Proof)
    vault = {}
    masked_prompt = request.prompt
    token_counter = 1
    
    # NEW: Overlap Filter. Sorts by length to prioritize massive entities (like a full case name),
    # and drops any smaller entity that shares the same character space to prevent slicing corruption.
    filtered_results = []
    results_by_length = sorted(results, key=lambda x: (x.end - x.start), reverse=True)
    
    for res in results_by_length:
        # Check if coordinates intersect with any already accepted result
        is_overlap = any(max(res.start, acc.start) < min(res.end, acc.end) for acc in filtered_results)
        if not is_overlap:
            filtered_results.append(res)
            
    # Now that collisions are purged, sort remaining results in reverse order for safe slicing
    sorted_results = sorted(filtered_results, key=lambda x: x.start, reverse=True)
    
    # STEP 1: Coordinate Slicing (Must happen first to preserve index math)
    for res in sorted_results:
        original_text = request.prompt[res.start:res.end]
        
        existing_token = next((tok for tok, val in vault.items() if val == original_text), None)
        
        if existing_token:
            token = existing_token
        else:
            token = f"[SECURE_TOKEN_{token_counter}]"
            vault[token] = original_text
            token_counter += 1
            
        # Flawless coordinate slice replacement
        masked_prompt = masked_prompt[:res.start] + token + masked_prompt[res.end:]

    # STEP 2: Dynamic Alias Masking (Safe to run now that coordinate slicing is done)
    for res in sorted_results:
        if res.entity_type == "ORGANIZATION":
            alias = request.prompt[res.start:res.end].split()[0]
            if len(alias) > 3: # Prevent masking tiny words
                # Use regex word boundaries (\b) to prevent substring masking (e.g. masking "Sun" inside "Sunday")
                escaped_alias = re.escape(alias)
                pattern = rf"\b{escaped_alias}\b"
                
                if re.search(pattern, masked_prompt):
                    token = f"[SECURE_TOKEN_{token_counter}]"
                    masked_prompt = re.sub(pattern, token, masked_prompt)
                    vault[token] = alias
                    token_counter += 1
        
    if vault:
        print(f"--> Presidio Vault Created: {vault}")
        print(f"--> Masked Prompt Sent to OpenAI: {masked_prompt}")
    else:
        print("--> No sensitive data detected. Bypassing Vault.")

    # 3. External API Routing
    try:
        response = await external_client.chat.completions.create(
            model=request.model,
            messages=[
                {
                    "role": "system", 
                    "content": (
                        "You are an enterprise legal and medical AI assistant. The text you receive has been "
                        "automatically sanitized for privacy compliance using secure placeholders like [SECURE_TOKEN_1]. "
                        "These tokens represent standard, benign nouns, entities, or financial figures. Treat these "
                        "tokens as normal variables, process the request completely, and preserve the exact token "
                        "formatting in your response."
                    )
                },
                {"role": "user", "content": masked_prompt}
            ]
        )
        
        external_reply = response.choices[0].message.content
        print(f"--> Raw OpenAI Response: {external_reply}")
        
        # 4. Unmask the response
        unmasked_reply = external_reply
        # Sort tokens by length descending to prevent substring collisions (e.g., Token 10 vs Token 1)
        for token in sorted(vault.keys(), key=len, reverse=True):
            unmasked_reply = unmasked_reply.replace(token, vault[token])
            
        print(f"--> Final Unmasked Response Delivered: {unmasked_reply}")
        
        return {"response": unmasked_reply}
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("presidio_proxy:app", host="127.0.0.1", port=8000, reload=True)