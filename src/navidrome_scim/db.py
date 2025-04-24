
import sqlite3
import datetime

from flask import current_app, g

def get_db():
    if 'db' not in g:
        dbname = current_app.config['DATABASE']
        try:
            g.db = sqlite3.connect(
                dbname,
                detect_types=sqlite3.PARSE_DECLTYPES
            )
        except sqlite3.OperationalError as exc:
            raise RuntimeError(f'Problem opening database {dbname}') from exc
        g.db.row_factory = sqlite3.Row

    return g.db


def close_db(e=None):
    db = g.pop('db', None)

    if db is not None:
        db.close()

sqlite3.register_converter(
    "datetime", lambda v: datetime.datetime.fromisoformat(v.decode())
)

def init_app(app):
    app.teardown_appcontext(close_db)
