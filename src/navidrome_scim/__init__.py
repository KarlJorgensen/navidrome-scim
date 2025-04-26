import os

import click
from flask import Flask
from flask.cli import FlaskGroup

from . import scim

def create_app(test_config=None):
    # create and configure the app
    app = Flask(__name__, instance_relative_config=True)

    if test_config is None:
        # load the instance config, if it exists, when not testing
        app.config.from_pyfile('config.py', silent=True)
    else:
        # load the test config if passed in
        app.config.from_mapping(test_config)

    app.register_blueprint(scim.blueprint)

    @app.route('/ping')
    def ping():
        return 'Alive'

    return app

@click.group(cls=FlaskGroup, create_app=create_app)
def run():
    pass
