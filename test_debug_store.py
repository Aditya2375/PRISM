import tempfile
import os

# Set DB path before importing kig
with tempfile.NamedTemporaryFile(suffix='.db', delete=False) as f:
    db_path = f.name

os.environ['KIG_DB_PATH'] = db_path

print(f'DB path: {db_path}')

from kig.store.db import get_connection, initialize_schema, close

print('Importing done, about to get connection...')
conn = get_connection()
print(f'Connection: {conn}')

print('About to initialize schema...')
initialize_schema()
print('Schema initialized')

print('About to insert...')
cur = conn.execute('INSERT INTO users VALUES (?, ?, ?, ?, ?)', ('test', 'admin', 'active', 1, '2024-01-01'))
conn.commit()
print('Insert done')

print('About to query...')
cur = conn.execute('SELECT * FROM users WHERE user_id = ?', ('test',))
row = cur.fetchone()
print(f'Row: {row}')

print('About to close...')
close()
print('Closed')

if os.path.exists(db_path):
    os.unlink(db_path)
print('Success! Exiting normally')