import sqlite3
import tempfile
import os

with tempfile.NamedTemporaryFile(suffix='.db', delete=False) as f:
    db_path = f.name

print(f'db_path: {db_path}')
conn = sqlite3.connect(db_path, check_same_thread=False)
print(f'conn: {conn}')
conn.execute('PRAGMA journal_mode=WAL')
print('WAL mode set')
conn.execute('PRAGMA foreign_keys=ON')
print('foreign keys on')
conn.execute('PRAGMA busy_timeout=10000')
print('busy timeout set')
conn.execute('CREATE TABLE users (user_id TEXT PRIMARY KEY, role TEXT, status TEXT, epoch INTEGER, created_at TEXT)')
print('Table created')
row = ('test', 'admin', 'active', 1, '2024-01-01')
conn.execute('INSERT INTO users VALUES (?, ?, ?, ?, ?)', row)
conn.commit()
print('Insert done')
cur = conn.execute('SELECT * FROM users WHERE user_id = ?', ('test',))
r = cur.fetchone()
print(f'Row: {r}')
conn.close()
os.unlink(db_path)
print('Success!')