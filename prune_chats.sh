#!/bin/bash
# ---------------------------------------------------------
# Open WebUI Comprehensive Ephemeral Prune Script
# ---------------------------------------------------------

echo "[$(date)] Starting comprehensive zero-retention wipe..."

# 1. Purge the Database Tables
# Deletes chats, messages, and document metadata while preserving users and settings.
docker exec open-webui sqlite3 /app/backend/data/webui.db "
DELETE FROM chat;
DELETE FROM message;
DELETE FROM document;
DELETE FROM file;
VACUUM;
"
echo "[$(date)] SQLite tables pruned and vacuumed."

# 2. Purge the Physical Files & Vector Embeddings
# Wipes the uploaded PDFs, images, and their associated searchable vector data.
docker exec open-webui sh -c "rm -rf /app/backend/data/uploads/*"
docker exec open-webui sh -c "rm -rf /app/backend/data/vector_db/*"
docker exec open-webui sh -c "rm -rf /app/backend/data/cache/*"
echo "[$(date)] Physical uploads and vector embeddings destroyed."

# 3. Flush the RAM Cache
# Restarts the container to clear any lingering active memory.
docker restart open-webui
echo "[$(date)] Open WebUI container restarted successfully. Wipe complete."