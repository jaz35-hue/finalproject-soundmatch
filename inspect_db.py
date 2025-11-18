import sqlite3, os

DB = 'database.db'
print('DB path:', os.path.abspath(DB))
if not os.path.exists(DB):
    print('database file not found')
    raise SystemExit(1)

conn = sqlite3.connect(DB)
cur = conn.cursor()
cur.execute("SELECT name, type, sql FROM sqlite_master WHERE type IN ('table','view')")
rows = cur.fetchall()
if not rows:
    print('No tables or views found in database.')
else:
    print('Tables/Views found:')
    for name, typ, sql in rows:
        print('-', name, f'({typ})')
        try:
            cur.execute(f'SELECT COUNT(*) FROM "{name}"')
            print('  rows:', cur.fetchone()[0])
        except Exception as e:
            print('  count error:', e)

conn.close()