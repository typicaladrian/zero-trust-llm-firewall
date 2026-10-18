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

from datetime import datetime, timedelta

# Import the new GLiNER2 package
from gliner2 import GLiNER2
import litellm

import hashlib
from pydantic import BaseModel

import resend

from io import BytesIO
from fastapi.responses import StreamingResponse
from reportlab.lib.pagesizes import letter
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, Image
from reportlab.graphics.shapes import Drawing, String
from reportlab.graphics.charts.barcharts import HorizontalBarChart
from reportlab.graphics.charts.textlabels import Label
from reportlab.lib.validators import Auto


import glob
import gzip
import shutil

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
    "legal case", "plaintiff", "defendant", "location", "city", "law firm"
]

# High-precision deterministic regex patterns (The Safety Net)
REGEX_PATTERNS = {
    "Credit Card Number": r"\b(?:\d[ -]*?){13,16}\b",
    "Social Security Number": r"\b\d{3}-\d{2}-\d{4}\b",
    "Email Address": r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b",
    "Address (US)": r"(?i)\b(?:P\.?O\.?\s+Box\s+\d+|[1-9]\d{0,5}|One|Two|Three|Four|Five|Six|Seven|Eight|Nine|Ten)\b(?:\s+[A-Za-z0-9#.,-]+){2,15}?\s+(?:AL|AK|AZ|AR|CA|CO|CT|DE|FL|GA|HI|ID|IL|IN|IA|KS|KY|LA|ME|MD|MA|MI|MN|MS|MO|MT|NE|NV|NH|NJ|NM|NY|NC|ND|OH|OK|OR|PA|RI|SC|SD|TN|TX|UT|VT|VA|WA|WV|WI|WY|Alabama|Alaska|Arizona|Arkansas|California|Colorado|Connecticut|Delaware|Florida|Georgia|Hawaii|Idaho|Illinois|Indiana|Iowa|Kansas|Kentucky|Louisiana|Maine|Maryland|Massachusetts|Michigan|Minnesota|Mississippi|Missouri|Montana|Nebraska|Nevada|New Hampshire|New Jersey|New Mexico|New York|North Carolina|North Dakota|Ohio|Oklahoma|Oregon|Pennsylvania|Rhode Island|South Carolina|South Dakota|Tennessee|Texas|Utah|Vermont|Virginia|Washington|West Virginia|Wisconsin|Wyoming|DC|D\.C\.|District of Columbia)(?:\b|(?<=\.))\s*,?\s*\d{4,5}(?:-\d{4})?(?:\s*,?\s*USA?)?\b",
    "Address (UK)": r"(?i)\b\d{1,5}(?:\s+[A-Za-z0-9.,]+){1,10}\s+[A-Z]{1,2}\d[A-Z\d]?\s*\d[A-Z]{2}\b",
    "Website / URL": r"(?i)\b(?:https?://|www\.)[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}(?:/[^\s]*)?\b",
    "Banking / SWIFT": r"(?i)(?:SWIFT|IBAN|BIC)[\s\w:]*?([A-Z0-9]{8,11})\b",
    
    # Lookarounds prevent the punctuation boundary trap on L.L.P., LLC, etc.
    "Law Firm / Corporation": r"(?i)(?<!\w)(?:[A-Z][a-zA-Z]+\s*[,&]?\s*){1,5}(?:L\.L\.P\.|LLP|L\.L\.C\.|LLC|P\.C\.|Inc\.|Corp\.)(?!\w)",
    
    # Lookarounds capture Esq. perfectly
    "Legal Counsel (Esq)": r"(?i)(?<!\w)(?:[A-Z][a-zA-Z\.]+\s*){1,4},\s*Esq\.(?!\w)"
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
    "docket", "medical", "diagnosis", "ssn", "date", "birth",
    
    # Conjunctions, Prepositions, and Corporate Suffixes
    "and", "the", "for", "with", "from", "inc", "llc", "corp", "ltd", "company", "spa", "com",
    
    # Legal Document Anatomy & Entities
    "agreement", "contract", "amendment", "exhibit", "article", "section", 
    "clause", "paragraph", "schedule", "document", "provision", "law", "state", "court",
    
    # Generic Legal Roles & Concepts
    "plaintiff", "defendant", "client", "party", "parties", "purchaser", "seller", "vendor",
    "buyer", "recipient", "cpa", "government", "agency", "indemnified", "indemnifying", 
    "venture", "joint", "employee", "employer", "escrow", "site", "co-branded",
    
    # Contract Boilerplate & Expanded Roles
    "provider", "subcontractor", "subcontractors", "contractor", "contractors",
    "customer", "representatives", "employees", "providers", "creditors",
    "non-breaching", "breaching", "military", "authority", "carriers", 
    "suppliers", "assigns", "successors", "affiliates", "agents", "directors", 
    "officers", "receiving", "authorized", "officer", "counsel", "disclosing", 
    "registrant", "insurance", "petition", "bankruptcy", "governmental", "competent", 
    "jurisdiction", "provider representatives", "third-party service providers",
    "stock", "main", "elements", "repair", "maintenance", "chief", "financial", 
    "air", "transport", "aviation", "services", "pool", "advanced", "core", "owner", "management",
    
    # Multi-Word Boilerplate Phrases
    "indemnified party", "indemnifying party", "government agency", 
    "joint venture", "co-branded site", "escrow law", "email address", 
    "employee- employer", "independent contractor", "third-party", 
    "service providers", "third party", "breaching party", "non-breaching party", 
    "military authority", "governmental authority", "unaffiliated suppliers", 
    "permitted assigns", "receiving party", "authorized officer", "disclosing party", 
    "insurance providers", "court of competent jurisdiction", "petition in bankruptcy",
    
    # Life Sciences, Clinical, & Regulatory (Concepts Only)
    "jsc", "mdacc", "ogc", "alliance", "sponsor", "investigator", "investigators", 
    "researchers", "consultants", "students", "patients", "patient", "subjects", 
    "subject", "clinical", "pre-clinical", "study", "protocol", "therapy", "therapies", 
    "drug", "drugs", "cancer", "cancers", "tumor", "tumors", "antigen", "antigens", 
    "myeloma", "sarcoma", "t-cell", "tcr", "tcrs", "spear", "melanoma", "lung", 
    "ovarian", "bladder", "breast", "gastric", "hematologic", "principal investigator", 
    "principal investigators", "regulatory authorities", "study drug", "study drugs", 
    "study subject", "study subjects", "study patient", "study patients", 
    "strategic alliance", "joint steering committee", "public official", 
    "political party", "public agency", "international organization",

    # Biotech & Life Sciences (Concepts Only)
    "breast cancers", "gastric cancers", "multiple myeloma", "synovial sarcoma", 
    "hematologic cancers", "melanoma", "esophageal", "peptides", "antigens", 
    "receptors", "t-cell", "t-cells", "tcr", "tcrs", "spear", "ind", 
    "biotechnology companies", "biotechnology",
    
    # Standard Federal Statutes & Public Law
    "physician payments sunshine act", "sunshine act", 
    "health insurance portability and accountability act", "hipaa",
    "private securities litigation reform act of 1995", 
    "arms export control act", "export administration act of 1979",
    
    # Extended Legal Concepts & Boilerplate
    "partnership", "faculty members", "trustees", "regents", 
    "transferring party", "joint research partners", "scientific committee", 
    "public domain", "public international organization"
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
# Persistent data directory (Docker volume in production; overridable for tests)
LOG_DIR = os.getenv("AUDIT_LOG_DIR", "/app/logs")
VAULT_FILE = os.path.join(LOG_DIR, "client_hashes.json")

def generate_secure_hash(text: str) -> str:
    # Normalizes text (lowercases, strips punctuation) to ensure reliable hashing
    normalized = re.sub(r'[^a-z0-9]', '', text.lower())
    return hashlib.sha256(normalized.encode('utf-8')).hexdigest()

async def log_lifecycle_manager():
    """Runs continuously in the background to compress old logs and prune >90 days."""
    while True:
        try:
            log_dir = LOG_DIR
            os.makedirs(log_dir, exist_ok=True)
            current_month = datetime.now().strftime("%Y_%m")
            
            # 1. Compress previous months' active JSONL files
            for filepath in glob.glob(f"{log_dir}/audit_*.jsonl"):
                filename = os.path.basename(filepath)
                # If the file doesn't match the current month, it's old. Zip it!
                if current_month not in filename: 
                    with open(filepath, 'rb') as f_in:
                        with gzip.open(f"{filepath}.gz", 'wb') as f_out:
                            shutil.copyfileobj(f_in, f_out)
                    os.remove(filepath) # Delete the uncompressed legacy file
                    
            # 2. Prune archives older than 90 days
            cutoff_time = time.time() - (90 * 86400) # 90 days in seconds
            for filepath in glob.glob(f"{log_dir}/audit_*.gz"):
                if os.path.getmtime(filepath) < cutoff_time:
                    os.remove(filepath)
                    
        except Exception as e:
            print(f"Log manager encountered an error: {e}")
            
        await asyncio.sleep(86400) # Go to sleep for 24 hours

async def send_monthly_audit_email(pdf_buffer: BytesIO, target_month: str):
    """Fires the PDF over HTTPS port 443 via the Resend API."""
    resend.api_key = os.environ.get("EMAIL_API_KEY")
    client_name = os.environ.get("CLIENT_ORG_NAME", "Enterprise Client")
    appliance_id = os.environ.get("APPLIANCE_ID", "ELM-NUC-UNKNOWN")
    operator_email = os.environ.get("OPERATOR_EMAIL")
    sender_email = os.environ.get("EMAIL_SENDER")

    if not resend.api_key or not operator_email or not sender_email:
        print("CRITICAL ERROR: Missing EMAIL_API_KEY, OPERATOR_EMAIL, or EMAIL_SENDER. Cannot send report.")
        return

    try:
        # Resend Python SDK requires the attachment content as a list of integers (bytes)
        pdf_bytes = list(pdf_buffer.getvalue())
        
        params = {
            "from": sender_email,
            "to": [operator_email],
            "subject": f"[{appliance_id}] Monthly Security Audit - {client_name}",
            "html": f"""
                <h2>Monthly Edge Gateway Audit</h2>
                <p><b>Client:</b> {client_name}</p>
                <p><b>Appliance ID:</b> {appliance_id}</p>
                <p><b>Audit Period:</b> {target_month}</p>
                <p>Attached is the automated zero-trust security audit and cost mitigation report for the previous month.</p>
                <br/>
                <p><i>- Elm Tech Solutions HaaS Automated Delivery</i></p>
            """,
            "attachments": [
                {
                    "filename": f"elm_tech_audit_{target_month}.pdf",
                    "content": pdf_bytes
                }
            ]
        }
        
        # Execute the HTTPS delivery in a background thread to prevent blocking the async loop
        response = await asyncio.to_thread(resend.Emails.send, params)
        print(f"Successfully dispatched {target_month} audit to operator. Resend ID: {response.get('id')}")
        
    except Exception as e:
        print(f"Failed to send email via Resend: {str(e)}")

async def automated_report_scheduler():
    """Wakes up on the 1st of the month at midnight EST, generates the PDF, and emails it."""
    while True:
        now = datetime.now()
        
        # Calculate exactly when the next 1st of the month at 00:00:00 occurs
        if now.month == 12:
            next_run = now.replace(year=now.year + 1, month=1, day=1, hour=0, minute=0, second=0, microsecond=0)
        else:
            next_run = now.replace(month=now.month + 1, day=1, hour=0, minute=0, second=0, microsecond=0)
            
        sleep_seconds = (next_run - now).total_seconds()
        print(f"Report Scheduler armed. Sleeping for {sleep_seconds} seconds until {next_run.strftime('%Y-%m-%d %H:%M:%S')} EST.")
        
        await asyncio.sleep(sleep_seconds)
        
        # It is now exactly midnight on the 1st.
        print("Midnight reached. Initiating automated reporting sequence...")
        
        try:
            # We need the report for the month that *just* finished
            last_month_date = datetime.now() - timedelta(days=1)
            target_month = last_month_date.strftime("%Y_%m")
            
            # 1. Fetch the raw JSON metrics
            report_response = await generate_audit_report(target_month)
            if report_response.status_code == 200:
                report_data = json.loads(report_response.body.decode('utf-8'))
                
                # 2. Render the PDF in volatile memory
                pdf_buffer = render_executive_pdf(report_data)
                
                # 3. Fire it off to you (the operator)
                await send_monthly_audit_email(pdf_buffer, target_month)
            else:
                print(f"Report generation failed for {target_month}. Status: {report_response.status_code}")
                
        except Exception as e:
            print(f"Fatal error in automated scheduler: {e}")

@app.on_event("startup")
async def startup_routines():
    # Trigger the background lifecycle manager when Uvicorn boots
    asyncio.create_task(log_lifecycle_manager())
    
    # Trigger the monthly PDF automated delivery scheduler
    asyncio.create_task(automated_report_scheduler())
    
    # Existing vault load logic
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
        
        # Dynamically build a strict token pattern based ONLY on our approved labels
        all_labels = PII_LABELS + list(REGEX_PATTERNS.keys())
        valid_bases = [lbl.upper().replace(" ", "_") for lbl in all_labels]
        self.internal_token_pattern = re.compile(
            r"(?:" + "|".join(re.escape(b) for b in valid_bases) + r")_\d+"
        )

    def _register_and_replace(self, text: str, label: str, original_value: str, start: int, end: int) -> str:
        """Helper to generate the [REDACTED] string, split tokens, and update maps."""
        if original_value not in self.entity_map:
            label_base = label.upper().replace(" ", "_")
            self.counters[label_base] += 1
            token = f"[{label_base}_{self.counters[label_base]}]"
            
            # Map the exact full string
            self.entity_map[original_value] = token
            self.reverse_map[token] = original_value
            
            # Smart Token Splitting for partial names
            split_eligible_labels = {"person", "organization", "plaintiff", "defendant", "legal case"}
            if label.lower() in split_eligible_labels:
                name_parts = original_value.split()
                if len(name_parts) > 1:
                    
                    # Branch the logic: Keep all parts for humans, but only the first word for Orgs
                    if label.lower() == "person":
                        parts_to_map = name_parts
                    else:
                        parts_to_map = [name_parts[0]] # Catch the short-name (e.g., "Ability" from "Ability LLC")

                    for part in parts_to_map:
                        # Clean trailing punctuation from the part before mapping
                        clean_part = re.sub(r'[^A-Za-z0-9]', '', part)
                        
                        # Increased length to > 3 to prevent 2-letter collisions
                        if len(clean_part) > 3 and clean_part.lower() not in STOPWORDS:
                            if clean_part not in self.entity_map:
                                self.entity_map[clean_part] = token
        else:
            token = self.entity_map[original_value]
            
        return text[:start] + token + text[end:]

    @staticmethod
    def _merge_overlapping_regex(matches: list, chunk: str) -> list:
        """Merge overlapping regex spans into their union so no matched character survives (#6).

        Unlike the vault and NER layers (leftmost wins), a partial overlap here would leak the
        dropped span's tail. Each merged span takes the label of its longest member, ties going
        to REGEX_PATTERNS order. Spans that only touch stay separate.
        """
        groups = []
        for m in sorted(matches, key=lambda x: (x['start'], x['order'])):
            if groups and m['start'] < groups[-1]['end']:
                groups[-1]['end'] = max(groups[-1]['end'], m['end'])
                groups[-1]['members'].append(m)
            else:
                groups.append({'start': m['start'], 'end': m['end'], 'members': [m]})

        return [{
            'start': g['start'],
            'end': g['end'],
            'text': chunk[g['start']:g['end']],
            'label': max(g['members'], key=lambda x: (x['end'] - x['start'], -x['order']))['label']
        } for g in groups]

    def anonymize_text(self, text: str) -> str:
        if not text.strip():
            return text

        # Pre-clean known OCR/SEC pagination noise before chunking
        text = re.sub(r'(?:\n\s*(?:th|page)\s*){2,}', '\n', text, flags=re.IGNORECASE)

        chunks = chunk_text(text, max_words=400)
        anonymized_chunks = []
        
        for chunk in chunks:
            mutated_chunk = chunk

            # ==========================================
            # STEP 0: The Safety Net (Regex Pre-Filter)
            # ==========================================
            regex_matches = []
            for order, (label, pattern) in enumerate(REGEX_PATTERNS.items()):
                for match in re.finditer(pattern, mutated_chunk):
                    regex_matches.append({
                        'start': match.start(),
                        'end': match.end(),
                        'label': label,
                        'order': order
                    })

            regex_matches = self._merge_overlapping_regex(regex_matches, mutated_chunk)
            for match in sorted(regex_matches, key=lambda x: x['start'], reverse=True):
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
            # Explicitly set threshold to 0.30 for higher entity recall
            extraction_results = gliner_model.extract_entities(
                mutated_chunk, 
                PII_LABELS, 
                threshold=0.30
            )
            
            gliner_matches = []
            entities_dict = extraction_results.get('entities', {})
            
            for label, texts in entities_dict.items():
                for ent_text in texts:
                    # 1. Ignore if the entity is an exact stopword OR entirely composed of stopwords
                    ent_lower = ent_text.lower().strip()
                    if ent_lower in STOPWORDS:
                        continue
                    
                    # 2. Split into words and check if ALL words are in the stopword list
                    tokens = re.findall(r'\b\w+\b', ent_lower)
                    if tokens and all(t in STOPWORDS for t in tokens):
                        continue

                    # 3. Ignore if it is already a token
                    if ent_text.startswith("[") and ent_text.endswith("]"):
                        continue

                    # 4. Ignore if it is purely punctuation or underscores
                    if not re.search(r'[A-Za-z0-9]', ent_text):
                        continue
                        
                    # 5. Strictly ignore ONLY our exact generated token structures
                    if self.internal_token_pattern.search(ent_text):
                        continue
                        
                    # Replace \b with negative lookarounds
                    pattern = r"(?i)(?<!\w)" + re.escape(ent_text) + r"(?!\w)"
                    for match in re.finditer(pattern, mutated_chunk):
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

            anonymized_chunks.append(mutated_chunk)
        
        # ==========================================
        # STEP 3: Unified Global Safety Sweep
        # ==========================================
        full_text = " ".join(anonymized_chunks)
        
        # Extract and sort all non-token keys by length descending
        keys_to_sweep = [k for k in self.entity_map.keys() if not k.startswith("[")]
        keys_to_sweep.sort(key=len, reverse=True)
        
        if keys_to_sweep:
            # Replace \b with negative lookarounds
            escaped_keys = [re.escape(k) for k in keys_to_sweep]
            combined_pattern = re.compile(r"(?<!\w)(" + "|".join(escaped_keys) + r")(?!\w)", flags=re.IGNORECASE)
            
            def global_safe_replace(match):
                matched_text = match.group()
                # Retrieve the mapped token using a case-insensitive lookup
                original_key = next((k for k in self.entity_map if k.lower() == matched_text.lower()), matched_text)
                token = self.entity_map.get(original_key, matched_text)
                
                # Case-Aware safety check
                if "ORGANIZATION" in token and matched_text.islower():
                    return matched_text
                return token
                
            full_text = combined_pattern.sub(global_safe_replace, full_text)
            
        return full_text

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
            {
                "id": "gpt-4o-mini",
                "object": "model",
                "created": int(time.time()),
                "owned_by": "openai"
            },
            {
                "id": "claude-opus-5",
                "object": "model",
                "created": int(time.time()),
                "owned_by": "anthropic"
            },
            {
                "id": "claude-haiku-4-5-20251001",
                "object": "model",
                "created": int(time.time()),
                "owned_by": "anthropic"
            },
            {
                "id": "elm-tech-auditor",
                "object": "model",
                "created": int(time.time()),
                "owned_by": "local"
            },
            {
                "id": "public-research-base", 
                "object": "model", 
                "created": int(time.time()), 
                "owned_by": "elm-tech"}
        ]
    })

@app.post("/v1/chat/completions")
async def chat_completions(request: Request):
    payload = await request.json()
    model = payload.get("model", "gpt-4o-mini")
    print(f"--> INCOMING REQUEST MODEL ID: '{model}'")  
    messages = payload.get("messages", [])
    
    # 1. NEW METRIC: Payload Volume (Calculate before scrubbing)
    payload_char_count = sum(len(m.get("content", "")) for m in messages if isinstance(m.get("content"), str))

    # --- NEW: Check for bypass and map to upstream LLM ---
    is_unredacted = (model == "public-research-base")
    if is_unredacted:
        payload["model"] = "gpt-4o-mini"

    vault = EntityVault()
    start_time = time.time()
    
    scrubbed_messages = []
    if is_unredacted:
        # Bypass redaction completely
        scrubbed_messages = messages
    else:
        # Standard Zero-Trust Scrubbing Pipeline
        for msg in messages:
            scrubbed_msg = msg.copy()
            
            if "content" in scrubbed_msg and isinstance(scrubbed_msg["content"], str) and scrubbed_msg.get("role") != "system":
                scrubbed_msg["content"] = await asyncio.to_thread(
                    vault.anonymize_text, 
                    scrubbed_msg["content"]
                )
                
            scrubbed_messages.append(scrubbed_msg)

    # Skip adding the system PII prompt if unredacted
    if not is_unredacted:
        has_system = any(m.get("role") == "system" for m in scrubbed_messages)
        if not has_system:
            scrubbed_messages.insert(0, SYSTEM_PROMPT)
        
    elapsed_ms = round((time.time() - start_time) * 1000, 2)
    last_user_msg = next((m["content"] for m in reversed(scrubbed_messages) if m["role"] == "user"), "")

    # 2. NEW METRIC: Granular Threat Categorization
    entity_breakdown = dict(vault.counters)

    # ==========================================
    # SECURE IMMUTABLE METADATA AUDIT LOG
    # ==========================================
    timestamp_24h = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    exact_user = (
        request.headers.get("x-openwebui-user-email") or
        request.headers.get("x-openwebui-user-name") or
        request.headers.get("x-openwebui-user-id")
    )

    jwt_token = request.headers.get("x-openwebui-user-jwt")
    secret_key = os.getenv("WEBUI_SECRET_KEY")
    if jwt_token and not secret_key:
        exact_user = "ERROR_NO_SECRET_CONFIGURED"
    elif jwt_token:
        try:
            decoded_payload = jwt.decode(jwt_token, secret_key, algorithms=["HS256"])
            exact_user = decoded_payload.get("email") or decoded_payload.get("sub") or exact_user
        except jwt.ExpiredSignatureError:
            exact_user = "ERROR_EXPIRED_TOKEN"
        except jwt.InvalidTokenError:
            exact_user = "ERROR_INVALID_SIGNATURE"

    if not exact_user:
        exact_user = payload.get("user", "system_or_anonymous")

    # Build the base entry, but defer writing it so we can append upstream token usage
    audit_entry = {
        "timestamp": timestamp_24h,
        "user": exact_user,
        "model": model,
        "tokens_anonymized": len(vault.entity_map),
        "entity_breakdown": entity_breakdown,
        "payload_char_count": payload_char_count,
        "latency_ms": elapsed_ms,
        "upstream_tokens": 0  # Default to 0, updated after LLM call
    }

    def write_audit_log():
        ignore_phrases = [
            "Generate a concise, 3-5 word title",
            "Suggest 3-5 relevant follow-up questions",
            "Generate 1-3 broad tags",
            "determine the necessity of generating search queries"
        ]
        
        is_background_task = any(phrase in last_user_msg for phrase in ignore_phrases)
        
        if not is_background_task:
            os.makedirs(LOG_DIR, exist_ok=True)
            current_month = datetime.now().strftime("%Y_%m")
            log_path = os.path.join(LOG_DIR, f"audit_{current_month}.jsonl")
            
            with open(log_path, "a") as f:
                f.write(json.dumps(audit_entry) + "\n")

    if model == "elm-tech-auditor":
        await asyncio.to_thread(write_audit_log) 
        
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

    payload["messages"] = scrubbed_messages

    print("\n--- OUTGOING SCRUBBED PAYLOAD TO LITELLM ---")
    print(json.dumps(payload["messages"], indent=2))

    try:
        # 1. Determine if the frontend originally requested a stream
        requested_stream = payload.get("stream", False)
        
        # 2. Force synchronous mode ONLY for the Zero-Trust redacted pipeline
        if not is_unredacted:
            payload["stream"] = False
            requested_stream = False

        if requested_stream:
            # --- THE UNREDACTED STREAMING ROUTE ---
            async def event_stream():
                try:
                    response = await litellm.acompletion(**payload)
                    async for chunk in response:
                        # MUST use exclude_unset=True to prevent injecting 'null' fields
                        # which crashes the Open WebUI frontend Javascript parser.
                        if hasattr(chunk, "model_dump_json"):
                            json_str = chunk.model_dump_json(exclude_unset=True)
                        elif hasattr(chunk, "json"):
                            json_str = chunk.json(exclude_unset=True)
                        else:
                            json_str = json.dumps(chunk)
                            
                        yield f"data: {json_str}\n\n"
                    yield "data: [DONE]\n\n"
                except Exception as e:
                    print(f"PROXY STREAM EXCEPTION: {e}")
                    yield f"data: {json.dumps({'error': str(e)})}\n\n"
            
            # Log the transaction (Note: Upstream token counting is bypassed for streams in this MVP)
            await asyncio.to_thread(write_audit_log)
            return StreamingResponse(event_stream(), media_type="text/event-stream")
            
        else:
            # --- THE ZERO-TRUST SYNCHRONOUS ROUTE ---
            llm_response = await asyncio.to_thread(litellm.completion, **payload)

            if hasattr(llm_response, "usage") and llm_response.usage:
                audit_entry["upstream_tokens"] = llm_response.usage.total_tokens
                
            await asyncio.to_thread(write_audit_log)
            
            response_content = llm_response.choices[0].message.content
            
            if not is_unredacted:
                response_content = vault.deanonymize_text(response_content)
                
            llm_response.choices[0].message.content = response_content
            
            return JSONResponse(content=llm_response.model_dump())

    except litellm.exceptions.AuthenticationError as e:
        return JSONResponse(status_code=401, content={"error": "Proxy Error: Upstream auth failed.", "details": str(e)})
    except litellm.exceptions.Timeout as e:
        return JSONResponse(status_code=504, content={"error": "Proxy Error: Upstream timeout.", "details": str(e)})
    except Exception as e:
        return JSONResponse(status_code=500, content={"error": "Proxy Error: Unexpected LiteLLM error.", "details": str(e)})

@app.get("/v1/audit/report")
async def generate_audit_report(month: str = None):
    if not month:
        month = datetime.now().strftime("%Y_%m")
        
    log_path = os.path.join(LOG_DIR, f"audit_{month}.jsonl")
    
    if not os.path.exists(log_path):
        return JSONResponse(status_code=404, content={"error": f"No audit logs found for {month}."})
        
    total_prompts = 0
    total_threats = 0
    total_latency = 0
    total_upstream_tokens = 0
    total_payload_volume = 0
    model_usage = defaultdict(int)
    aggregated_threats = defaultdict(int)
    transaction_ledger = []
    
    # ROI Trackers
    unique_users = set()
    total_actual_cost = 0.0
    total_unoptimized_cost = 0.0
    
    # Estimated blended cost per token (Input/Output average)
    PRICING = {
        "gpt-4o-mini": 0.0000004,               # ~$0.40 per 1M
        "claude-haiku-4-5-20251001": 0.0000007, # ~$0.70 per 1M
        "claude-opus-5": 0.000045,              # ~$45.00 per 1M
        "elm-tech-auditor": 0.0
    }
    FLAGSHIP_RATE = PRICING["claude-opus-5"]
    
    try:
        with open(log_path, "r") as f:
            for line in f:
                if not line.strip():
                    continue
                    
                entry = json.loads(line)
                total_prompts += 1
                total_threats += entry.get("tokens_anonymized", 0)
                total_latency += entry.get("latency_ms", 0)
                
                tokens = entry.get("upstream_tokens", 0)
                total_upstream_tokens += tokens
                total_payload_volume += entry.get("payload_char_count", 0)
                
                model = entry.get("model", "unknown")
                user = entry.get("user", "unknown")
                
                model_usage[model] += 1
                unique_users.add(user)
                
                # Calculate Financials
                total_actual_cost += (tokens * PRICING.get(model, PRICING["gpt-4o-mini"]))
                total_unoptimized_cost += (tokens * FLAGSHIP_RATE)
                
                breakdown = entry.get("entity_breakdown", {})
                for entity_type, count in breakdown.items():
                    aggregated_threats[entity_type] += count
                
                transaction_ledger.append({
                    "timestamp": entry.get("timestamp"),
                    "user": user,
                    "model": model,
                    "latency_ms": entry.get("latency_ms"),
                    "payload_size": entry.get("payload_char_count"),
                    "threats_intercepted": entry.get("tokens_anonymized"),
                    "entities": breakdown
                })
                    
    except Exception as e:
        return JSONResponse(status_code=500, content={"error": f"Failed to parse audit logs: {str(e)}"})
        
    avg_latency = round(total_latency / total_prompts, 2) if total_prompts > 0 else 0
    transaction_ledger.reverse()
    
    active_users = max(len(unique_users), 1)
    
    report = {
        "report_generated_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "executive_summary": {
            "total_prompts_processed": total_prompts,
            "total_threats_intercepted": total_threats,
            "average_latency_ms": avg_latency,
            "total_cloud_tokens_used": total_upstream_tokens,
            "total_characters_scanned": total_payload_volume
        },
        "roi_metrics": {
            "actual_api_cost": round(total_actual_cost, 2),
            "flagship_cost_avoided": round(total_unoptimized_cost - total_actual_cost, 2),
            "active_users": active_users,
            "cost_per_user": round(total_actual_cost / active_users, 2)
        },
        "model_utilization": dict(model_usage),
        "threat_categorization": dict(aggregated_threats),
        "transaction_ledger": transaction_ledger
    }
    
    return JSONResponse(content=report)

def create_threat_bar_chart(threat_data: dict) -> Drawing:
    """Generates a styled, enterprise-grade ReportLab Horizontal Bar Chart."""
    # Create the drawing canvas
    drawing = Drawing(width=450, height=200)
    
    # Extract and format the data
    labels = list(threat_data.keys())
    # ReportLab bar charts expect a list of lists for data series
    data = [list(threat_data.values())] 
    
    # Determine the max value for dynamic axis scaling
    max_value = max(data[0]) if data[0] else 10
    
    # Initialize the Horizontal Bar Chart
    bc = HorizontalBarChart()
    bc.x = 120  # Push chart right to make room for long category labels
    bc.y = 20
    bc.height = 160
    bc.width = 300
    bc.data = data
    
    # Apply Enterprise Styling
    # Configure the Bars
    bc.bars[0].fillColor = colors.HexColor("#2C3E50") # Elm Tech Navy
    bc.bars[0].strokeColor = colors.white
    bc.bars[0].strokeWidth = 0.5
    bc.barSpacing = 4
    
    # Configure the Value Axis (Bottom - The Numbers)
    bc.valueAxis.valueMin = 0
    bc.valueAxis.valueMax = max_value + (max_value * 0.2) # Add 20% padding to the right
    bc.valueAxis.valueStep = max(1, int(max_value / 5)) # Create clean grid steps
    bc.valueAxis.labels.fontSize = 9
    bc.valueAxis.labels.fontName = 'Helvetica'
    bc.valueAxis.labels.fillColor = colors.HexColor("#7F8C8D")
    bc.valueAxis.visibleGrid = 1
    bc.valueAxis.gridStrokeColor = colors.HexColor("#ECF0F1")
    bc.valueAxis.gridStrokeWidth = 0.5
    
    # Configure the Category Axis (Left - The Labels)
    bc.categoryAxis.labels.fontName = 'Helvetica-Bold'
    bc.categoryAxis.labels.fontSize = 9
    bc.categoryAxis.labels.fillColor = colors.HexColor("#34495E")
    bc.categoryAxis.categoryNames = labels
    bc.categoryAxis.tickLeft = 0 # Hide the tick marks for a cleaner look
    bc.categoryAxis.visibleGrid = 0
    
    # Add the chart to the drawing
    drawing.add(bc)
    
    return drawing

def render_executive_pdf(report_data: dict) -> BytesIO:
    """Uses PLATYPUS to render a branded, multi-page PDF document."""
    buffer = BytesIO()
    # Set up the document canvas
    doc = SimpleDocTemplate(buffer, pagesize=letter, rightMargin=40, leftMargin=40, topMargin=40, bottomMargin=40)
    elements = []
    styles = getSampleStyleSheet()

    # Custom Corporate Styles
    title_style = ParagraphStyle(
        'CorporateTitle', 
        parent=styles['Heading1'], 
        alignment=1, 
        textColor=colors.HexColor("#1A252C"),
        fontSize=18,
        spaceAfter=6
    )
    subtitle_style = ParagraphStyle(
        'CorporateSubtitle',
        parent=styles['Heading3'],
        alignment=1,
        textColor=colors.HexColor("#7F8C8D"),
        spaceAfter=20
    )
    
    # Header: Letterhead
    logo_path = "/app/logo.png"
    if os.path.exists(logo_path):
        # The width and height are in points (1 point = 1/72 inch). 
        # Adjust these numbers to perfectly scale your specific logo!
        logo = Image(logo_path, width=200, height=70) 
        logo.hAlign = 'CENTER'
        elements.append(logo)
        elements.append(Spacer(1, 10))
    else:
        # Fallback to text if the image is missing
        elements.append(Paragraph("<b>Elm Tech Solutions LLC</b>", title_style))
        
    elements.append(Paragraph("Zero-Trust Edge Gateway: Monthly Security Audit", subtitle_style))
    
    # Part 1: Executive Summary
    elements.append(Paragraph("Executive Summary", styles['Heading2']))
    exec_data = report_data.get("executive_summary", {})
    exec_text = (
        f"<b>Report Generated:</b> {report_data.get('report_generated_at', 'N/A')}<br/><br/>"
        f"<b>Total Prompts Processed:</b> {exec_data.get('total_prompts_processed', 0)}<br/>"
        f"<b>Total Threats Intercepted:</b> {exec_data.get('total_threats_intercepted', 0)}<br/>"
        f"<b>Average Processing Latency:</b> {exec_data.get('average_latency_ms', 0)} ms<br/>"
        f"<b>Total Cloud Tokens Billed:</b> {exec_data.get('total_cloud_tokens_used', 0)}<br/>"
        f"<b>Total Characters Scanned:</b> {exec_data.get('total_characters_scanned', 0)}"
    )
    elements.append(Paragraph(exec_text, styles['Normal']))
    elements.append(Spacer(1, 20))

    # Part 1.5: Enterprise Value & ROI
    elements.append(Spacer(1, 10))
    elements.append(Paragraph("Enterprise Value & ROI Mitigation", styles['Heading2']))
    
    roi = report_data.get("roi_metrics", {})
    roi_table_data = [
        ["Estimated Cloud API Expenditure:", f"${roi.get('actual_api_cost', 0):.2f}"],
        ["Active Network Associates:", str(roi.get('active_users', 0))],
        ["Average API Cost Per Associate:", f"${roi.get('cost_per_user', 0):.2f}/mo"],
        ["Flagship Premium Avoided (Edge Routing Savings):", f"${roi.get('flagship_cost_avoided', 0):.2f}"],
        ["Critical Data Breaches Averted (Entities Masked):", str(exec_data.get('total_threats_intercepted', 0))]
    ]
    
    t_roi = Table(roi_table_data, colWidths=[300, 100])
    t_roi.setStyle(TableStyle([
        ('FONTNAME', (0, 0), (0, -1), 'Helvetica-Bold'),
        ('TEXTCOLOR', (0, 0), (0, -1), colors.HexColor("#2C3E50")),
        ('ALIGN', (1, 0), (1, -1), 'RIGHT'),
        ('BACKGROUND', (0, 3), (1, 3), colors.HexColor("#E8F8F5")), # Subtle green highlight for savings
        ('TEXTCOLOR', (1, 3), (1, 3), colors.HexColor("#117A65")),  # Dark green text for savings
        ('BACKGROUND', (0, 4), (1, 4), colors.HexColor("#FDEDEC")), # Subtle red highlight for threats
        ('TEXTCOLOR', (1, 4), (1, 4), colors.HexColor("#C0392B")),  # Dark red text for threats
        ('GRID', (0, 0), (-1, -1), 0.25, colors.lightgrey),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 8),
        ('TOPPADDING', (0, 0), (-1, -1), 8),
    ]))
    elements.append(t_roi)
    elements.append(Spacer(1, 20))

    # Part 2: Threat Categorization
    elements.append(Paragraph("Threat Categorization Breakdown", styles['Heading2']))
    threat_data = report_data.get("threat_categorization", {})
    
    if threat_data:
        # 1. Add the Visual Bar Chart
        threat_chart = create_threat_bar_chart(threat_data) # <-- UPDATE THIS LINE
        elements.append(threat_chart)
        elements.append(Spacer(1, 20))
        
        # 2. Add the Raw Data Table
        threat_table_data = [["Compliance Entity Type", "Intercepted Count"]]
        for k, v in threat_data.items():
            threat_table_data.append([k, str(v)])
            
        t = Table(threat_table_data, colWidths=[250, 150])
        t.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor("#2C3E50")),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('BOTTOMPADDING', (0, 0), (-1, 0), 10),
            ('BACKGROUND', (0, 1), (-1, -1), colors.HexColor("#F8F9F9")),
            ('GRID', (0, 0), (-1, -1), 0.5, colors.grey),
        ]))
        elements.append(t)
    else:
        elements.append(Paragraph("No threats intercepted during this period.", styles['Normal']))
        
    elements.append(Spacer(1, 20))

    # Part 3: Itemized Ledger
    elements.append(Paragraph("Itemized Transaction Ledger", styles['Heading2']))
    ledger = report_data.get("transaction_ledger", [])
    if ledger:
        # Define table headers
        ledger_table_data = [["Timestamp", "Latency", "Payload", "Threats", "Model"]]
        for row in ledger[:50]: # Capping at 50 for the MVP to prevent massive files
            ledger_table_data.append([
                row.get("timestamp", "").split(" ")[0], # Just date for space
                f"{row.get('latency_ms', 0)} ms",
                str(row.get("payload_size", 0)),
                str(row.get("threats_intercepted", 0)),
                row.get("model", "")
            ])
            
        t2 = Table(ledger_table_data, colWidths=[80, 80, 80, 80, 100])
        t2.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor("#34495E")),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('GRID', (0, 0), (-1, -1), 0.25, colors.lightgrey),
            ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, colors.HexColor("#F2F4F4")])
        ]))
        elements.append(t2)
    else:
        elements.append(Paragraph("No transactions recorded.", styles['Normal']))

    doc.build(elements)
    buffer.seek(0)
    return buffer

@app.post("/v1/admin/force-audit-delivery")
async def force_audit_delivery(month: str = None):
    """QA Endpoint: Manually triggers report generation and email delivery."""
    # Default to the current month if none is provided
    if not month:
        month = datetime.now().strftime("%Y_%m")
        
    print(f"Manual override triggered for month: {month}")
    
    try:
        # 1. Fetch the data
        report_response = await generate_audit_report(month)
        if report_response.status_code != 200:
            return JSONResponse(
                status_code=500, 
                content={"error": f"Failed to fetch data for {month}."}
            )
            
        report_data = json.loads(report_response.body.decode('utf-8'))
        
        # 2. Render the PDF
        pdf_buffer = render_executive_pdf(report_data)
        
        # 3. Fire the email
        await send_monthly_audit_email(pdf_buffer, month)
        
        return JSONResponse(content={
            "status": "success", 
            "message": f"Audit for {month} rendered and dispatched to operator."
        })
        
    except Exception as e:
        return JSONResponse(status_code=500, content={"error": str(e)})

@app.get("/v1/audit/pdf")
async def generate_audit_pdf():
    # 1. Fetch the exact same JSON data from our existing logic
    # In a production app, we would extract the read loop to a shared helper function, 
    # but for this MVP, we can directly call the existing endpoint function.
    report_response = await generate_audit_report()
    
    if report_response.status_code != 200:
        return report_response # Pass through the 404/500 errors
        
    report_data = json.loads(report_response.body.decode('utf-8'))
    
    # 2. Render the PDF buffer
    pdf_buffer = render_executive_pdf(report_data)
    
    # 3. Stream it to the browser as a downloadable file
    return StreamingResponse(
        pdf_buffer, 
        media_type="application/pdf",
        headers={"Content-Disposition": f"attachment; filename=elm_tech_audit_{datetime.now().strftime('%Y%m%d')}.pdf"}
    )