"""Reversible PII redaction: the EntityVault pipeline and the in-memory client hash set.

Importing this module is cheap. The GLiNER2 model loads on first use via ner.get_model(),
and nothing here imports main.py, so the engine can run outside the web app.
"""
import hashlib
import re
from collections import defaultdict
from typing import Dict, List

from zt_firewall.redaction import ner
from zt_firewall.redaction.patterns import PII_LABELS, REGEX_PATTERNS, STOPWORDS

# Hashes of the firm's protected client names (never the names themselves). Shared with
# main.py, which loads and syncs it; always mutate it in place, never reassign it.
CLIENT_HASH_VAULT = set()


def generate_secure_hash(text: str) -> str:
    # Normalizes text (lowercases, strips punctuation) to ensure reliable hashing
    normalized = re.sub(r'[^a-z0-9]', '', text.lower())
    return hashlib.sha256(normalized.encode('utf-8')).hexdigest()


def chunk_text(text: str, max_words: int = 400) -> List[str]:
    words = text.split(" ")
    chunks = []
    for i in range(0, len(words), max_words):
        chunks.append(" ".join(words[i:i + max_words]))
    return chunks


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
            extraction_results = ner.get_model().extract_entities(
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
