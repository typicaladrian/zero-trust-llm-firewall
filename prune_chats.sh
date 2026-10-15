#!/bin/bash
# ---------------------------------------------------------
# Open WebUI Comprehensive Ephemeral Prune Script
# ---------------------------------------------------------

echo "[$(date)] Starting comprehensive zero-retention wipe..."

# 1. Purge the Database Tables
# Uses Python's built-in sqlite3 library since the sqlite3 CLI is not in the container
docker exec open-webui python -c "import sqlite3; conn=sqlite3.connect('/app/backend/data/webui.db'); conn.executescript('DELETE FROM chat; DELETE FROM message; DELETE FROM document; DELETE FROM file; VACUUM;'); conn.close()"

echo "[$(date)] SQLite tables pruned and vacuumed."

# 2. Purge the Physical Files & Vector Embeddings
# Wipes the uploaded PDFs, images, and their associated searchable vector data.
docker exec open-webui sh -c "rm -rf /app/backend/data/uploads/* /app/backend/data/vector_db/* /app/backend/data/cache/*"
echo "[$(date)] Physical uploads and vector embeddings destroyed."

# 3. Flush the RAM Cache
# Restarts the container to clear any lingering active memory.
docker restart open-webui
echo "[$(date)] Open WebUI container restarted successfully. Wipe complete."