import sqlite3
import json

conn = sqlite3.connect("audit_log.db")
cursor = conn.cursor()
cursor.execute("SELECT * FROM security_logs")
rows = cursor.fetchall()

print(f"\n=== Total Intercepted Transactions: {len(rows)} ===")
for row in rows:
    print(f"ID: {row[0]} | Time: {row[1][:19]} | Length: {row[2]} characters | Bypassed: {bool(row[4])}")
    print(f"   -> Masked Metadata: {json.loads(row[3])}\n")

conn.close()