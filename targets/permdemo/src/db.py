import sqlite3


def run_query(sql):
    conn = sqlite3.connect("app.db")
    return conn.execute(sql).fetchall()
