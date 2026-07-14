import os
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from dotenv import load_dotenv
from openai import AsyncOpenAI

# loading local dependencies securely
load_dotenv()

# initializing the FastAPI interceptor
app = FastAPI(title="Zero-Trust AI Privacy Proxy", version="0.1.0")

# initialize the async OpenAI client
client = AsyncOpenAI(api_key=os.getenv("OPENAI_API_KEY"))

# force expected incoming data structure
class ProxyRequest(BaseModel):
    prompt: str
    model: str = "gpt-3.5-turbo" # using turbo for now for cheap developemnt

@app.post("/v1/chat/completions")
async def intercept_and_route(request: ProxyRequest):
    """
    PHASE 1: Core Proxy Routing
    """
    try:
        # route the raw prompt to the external LLM
        response = await client.chat.completions.create(
            model=request.model,
            messages=[
                {"role": "system", "content": "You are a helpful assistant."},
                {"role": "user", "content": request.prompt}
            ]
        )

        # return the response to the local client
        return {"response": response.choices[0].message.content}
    
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
    
if __name__ == "__main__":
    import uvicorn
    # run the server locally on port 5000
    uvicorn.run("main:app", host="127.0.0.1", port=8000, reload=True)