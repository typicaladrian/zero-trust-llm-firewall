import os
import spacy
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from dotenv import load_dotenv
from openai import AsyncOpenAI

# loading local dependencies securely
load_dotenv()

# loading spaCy NLP model
print("Loading spaCy NLP model...")
nlp = spacy.load("en_core_web_sm")

# initializing the FastAPI interceptor
app = FastAPI(title="Zero-Trust AI Privacy Proxy", version="0.2.0")

# connect to external llm
external_client = AsyncOpenAI(api_key=os.getenv("OPENAI_API_KEY"))

# connect to local slm (ollama/phi-3), ensuring zero data leaves the machine
local_slm_client = AsyncOpenAI(
    base_url="http://localhost:11434/v1",
    api_key="ollama"
)

# force expected incoming data structure
class ProxyRequest(BaseModel):
    prompt: str
    model: str = "gpt-3.5-turbo" # using turbo for now for cheap developemnt

async def perform_deep_scan(text: str) -> set:    
    # Deep scan using Phi-3 via Ollama
    # We must override the conversational saftey guardrails that are normally up to instantly...
    # ...quit processing once PII/SPII is detected.
    system_prompt = (
        "You are a strict Zero-Trust Data Redaction Engine. Your sole purpose is to identify "
        "sensitive PII, names, Social Security Numbers, and confidential data in the user's text. "
        "Return ONLY a comma-separated list of the sensitive terms. Do not include any conversational "
        "text, apologies, or explanations. If no sensitive data is found, return the exact word: NONE."
    )

    detected_entities = set()

    try:
        slm_response = await local_slm_client.chat.completions.create(
            model="phi3",
            messages=[
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": text}
            ],
            temperature=0.0
        )

        slm_findings = slm_response.choices[0].message.content.strip()
        if slm_findings.upper() != "NONE":
            # clean and split the comma-separated list returned by Phi-3
            for item in slm_findings.split(","):
                cleaned_item = item.strip()
                if cleaned_item:
                    detected_entities.add(cleaned_item)
        
    except Exception as e:
        print(f"SLM Engine Error: {e}")
        # secure fail if slm fails
        raise HTTPException(status_code=500, detail="Local SLM inspection failed.")

    return detected_entities
    
@app.post("/v1/chat/completions")
async def intercept_and_route(request: ProxyRequest):
    print(f"--> Received prompt: {request.prompt}")

    detected_entities = set()

    # First, quick pass using spaCy
    doc = nlp(request.prompt)
    for ent in doc.ents:
        if ent.label_ in ["PERSON", "ORG", "GPE", "LOC", "DATE"]:
            detected_entities.add(ent.text)
    print(f"--> spaCy found: {detected_entities}")

    # Next, deep contextual scan using Phi-3
    phi3_findings = await perform_deep_scan(request.prompt)
    detected_entities.update(phi3_findings)
    
    print(f"--> Total entities found: {detected_entities}")

    # If sensitive information detected, fully block processing and communication with LLM.
    if detected_entities:
        print(f"FIREWALL TRIGGERED! Blocked: {detected_entities}")
        raise HTTPException(
            status_code=403, 
            detail=f"Zero-Trust Engine blocked request. PII detected: {list(detected_entities)}"
        )

    # If no sensitive info detected, allow traffic to LLM.
    try:
        response = await external_client.chat.completions.create(
            model=request.model,
            messages=[
                {"role": "system", "content": "You are a helpful assistant."},
                {"role": "user", "content": request.prompt}
            ]
        )
        return {"response": response.choices[0].message.content}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

if __name__ == "__main__":
    import uvicorn
    # run the server locally on port 5000
    uvicorn.run("main:app", host="127.0.0.1", port=8000, reload=True)