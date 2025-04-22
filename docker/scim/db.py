
import sqlite3
import datetime

from flask import current_app, g
import click

def get_db():
    if 'db' not in g:
        dbname = current_app.config['DATABASE']
        # print(f'Connecting to database {dbname}')
        g.db = sqlite3.connect(
            dbname,
            detect_types=sqlite3.PARSE_DECLTYPES
        )
        g.db.row_factory = sqlite3.Row

    return g.db


def close_db(e=None):
    db = g.pop('db', None)

    if db is not None:
        db.close()

sqlite3.register_converter(
    "timestamp", lambda v: datetime.datetime.fromisoformat(v.decode())
)

def init_db():
    db = get_db()


@click.command('init-db')
def init_db_command():
    """Clear the existing data and create new tables."""
    init_db()
    click.echo('Initialized the database.')

def init_app(app):
    app.teardown_appcontext(close_db)
    app.cli.add_command(init_db_command)
