"""Redaction rules: NER labels, deterministic regex patterns, and words never to redact."""

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
