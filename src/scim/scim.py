#!/usr/bin/python3
"""A (naive) SCIM provider for Navidrome

Navidrome does not natively support SCIM. Or SAML for that matter.
But it *does* support being behind a proxy which is expected to inject
user-information headers into the HTTP requests which reach navidrome.

But those users cannot actually _access_ Navidrome unless Navidrome
recognises them as legitimate users (they get a login box instead at
which point they're stuck).

This implements a (rather basic) SCIM provider for Navidrome which
creates/updates/deletes Navidrome users in response to requests from
the identity provider of your choice.

NOTE: This does not use the Navidrome API - it accesses the underlying
      Navidrome database directly, and will thus be sensitive to any
      schema/logic changes in Navidrome.

      This was developed for version 0.55.2 of Navidrome; although it
      is likely to work on later versions too, no guarantees can be
      offered. Sorry.

"""
# Json Schema: https://datatracker.ietf.org/doc/html/draft-scim-core-schema-01
# SCIM Protocol: https://datatracker.ietf.org/doc/html/rfc7644

# Implementation notes:
#
# Passwords: The password column is mandatory in Navidrome. But if
# Navidrome is behind an authenticating proxy, there is really no need
# for Navidrome to _know_ the password. And the identity provider is
# unlikely to pass it along anyway. So it is set to a random string.
#
# `active` status: The SCIM standard has the concepts of users being
# `active` or `inactive`. Inactive users exist, but cannot
# authenticate. Navidrome has no such concept, so it is simply not
# represented here.  Inactive users are NOT deleted as that would
# eradicate their playlists etc.
#
# Navidrome does not support groups. It is simply not a thing.

import datetime
import dataclasses
import json
import random
import string
import sqlite3
import warnings

import flask

from flask import (
    Blueprint, flash, g, redirect, render_template, request, session, url_for
)
from werkzeug.security import check_password_hash, generate_password_hash
from werkzeug.exceptions import NotFound, BadRequest, Conflict

from .db import get_db

# The `/v2` is mandatory - see https://datatracker.ietf.org/doc/html/rfc7644#section-3.13
bp = Blueprint('scim', __name__, url_prefix='/scim/v2')

@bp.route('/help')
@bp.route('/')
def help():
    """Basic help.

    Doesn't really help much, and isn't even mentioned by the RFCs but
    at least it gives an idea...

    """
    resp = flask.make_response(__doc__, 200)
    resp.content_type = 'text/plain'
    return resp

@bp.route('/ServiceProviderConfig')
def config():
    """Return the ServiceProvider structure.

    This allows the iDP to determine which features we provide
    """
    # See https://datatracker.ietf.org/doc/html/rfc7643#section-5
    # See example at https://datatracker.ietf.org/doc/html/rfc7643#section-8.5
    return {
        "schemas": [
            "urn:ietf:params:scim:schemas:core:2.0:ServiceProviderConfig"
        ],
        "documentationUri": flask.url_for('.help', _external=True),
        "meta": {
            "location": flask.url_for('.config', _external=True),
            "resourceType": "ServiceProviderConfig",
            "created": "2010-01-23T04:56:22Z",
            "lastModified": "2011-05-13T04:42:34Z",
            "version": "W\/\"3694e05e9dff594\""
        },
        "patch": {
            "supported": False,
        },
        "bulk": {
            "supported": False,
        },
        "filter": {
            "supported": False,
        },
        "changePassword": {
            "supported": False,
        },
        "sort": {
            "supported": False,
        },
        "etag": {
            "supported": False,
        },
        "authenticationSchemes": [
            {
                "name": "OAuth Bearer Token",
                "description":
                "Authentication scheme using the OAuth Bearer Token Standard",
                "specUri": "http://www.rfc-editor.org/info/rfc6750",
                "documentationUri": "http://example.com/help/oauth.html",
                "type": "oauthbearertoken",
                "primary": True
            },
            # {
            #     "name": "HTTP Basic",
            #     "description": "Authentication scheme using the HTTP Basic Standard",
            #     "specUri": "http://www.rfc-editor.org/info/rfc2617",
            #     "documentationUri": "http://example.com/help/httpBasic.html",
            #     "type": "httpbasic"
            # }
        ],
    }

@bp.route('/Schemas')
def schemas():
    # An HTTP GET to this endpoint is used to retrieve information about
    # resource schemas supported by a SCIM service provider.  An HTTP
    # GET to the endpoint "/Schemas" SHALL return all supported schemas
    # in ListResponse format (see Figure 3).  Individual schema
    # definitions can be returned by appending the schema URI to the
    # /Schemas endpoint.  For example:
    #
    #       /Schemas/urn:ietf:params:scim:schemas:core:2.0:User
    #
    # The contents of each schema returned are described in Section 7 of
    # [RFC7643].  An example representation of SCIM schemas may be found
    # in Section 8.7 of [RFC7643].

    # See https://datatracker.ietf.org/doc/html/rfc7643#section-7
    # See https://datatracker.ietf.org/doc/html/rfc7643#section-8.7

    return {
        "totalResults": 2,
        "itemsPerPage": 10,
        "startIndex": 1,
        "schemas": [
            "urn:ietf:params:scim:api:messages:2.0:ListResponse"
        ],
        "Resources": []
        # TODO: Implement this
    }

@bp.route('/ResourceTypes')
def resource_types():
    # An HTTP GET to this endpoint is used to discover the types of
    # resources available on a SCIM service provider (e.g., Users and
    # Groups).  Each resource type defines the endpoints, the core
    # schema URI that defines the resource, and any supported schema
    # extensions.  The attributes defining a resource type can be found
    # in Section 6 of [RFC7643], and an example representation can be
    # found in Section 8.6 of [RFC7643].

    # See https://datatracker.ietf.org/doc/html/rfc7643#section-6
    # See https://datatracker.ietf.org/doc/html/rfc7643#section-8.6
    return {
        "totalResults": 1,
        "itemsPerPage": 10,
        "startIndex": 1,
        "schemas": [
            "urn:ietf:params:scim:api:messages:2.0:ListResponse"
        ],
        "Resources": [
            resource_type_user(),
        ]
    }

@bp.route('/Schemas/urn:ietf:params:scim:schemas:core:2.0:User')
def resource_type_user():
    # See https://datatracker.ietf.org/doc/html/rfc7643#section-6
    # See https://datatracker.ietf.org/doc/html/rfc7643#section-8.6
    return {
        "schemas": [
            "urn:ietf:params:scim:schemas:core:2.0:ResourceType"
        ],
        "id":"User",
        "name":"User",
        "endpoint": "/Users",
        "description": "User Account",
        "schema": "urn:ietf:params:scim:schemas:core:2.0:User",
        "schemaExtensions": [],
        "meta": {
            "location": flask.url_for('.resource_type_user', _external=True),
            "resourceType": "ResourceType"
        }
    }

def parse_payload():
    """Parse the JSON payload

    This is basically just json-decoding it, but this makes sure that
    the correct HTTP response code is given in case of errors.

    """
    try:
        payload = json.loads(flask.request.get_data())
        return payload
    except (json.decoder.JSONDecodeError, TypeError) as exc:
        raise BadRequest(description=str(exc))

@dataclasses.dataclass
class User:
    """Our internal representation of a user.

    This functions as a sensible pythonic data structure, which can
    communicate with both a SCIM provider and the underlying sqlite3
    database.

    """
    # This could really have been an SQLObject thing... Maybe later.
    display_name: str
    user_name: str
    email: str
    user_id: str=None
    password: str = None
    is_admin: bool = False
    created_at: datetime.datetime = None
    updated_at: datetime.datetime = None

    # Mapping between our attributes and corresponding database columns
    _mapping = {
        'user_id': 'id',
        'user_name': 'user_name',
        'display_name': 'name',
        'email': 'email',
        'is_admin': 'is_admin',
        'created_at': 'created_at',
        'updated_at': 'updated_at',
        'password': 'password',
    }

    def __post_init__(self):
        """Set sensible values on fields that are mandatory"""
        if self.user_id is None:
            self.user_id = random_id()
        if self.password is None:
            self.password = random_password()
        if self.created_at is None:
            self.created_at = datetime.datetime.utcnow()
        if isinstance(self.created_at, str):
            self.created_at = datetime.datetime.fromisoformat(self.created_at)
        if self.updated_at is None:
            self.updated_at = datetime.datetime.utcnow()
        if isinstance(self.updated_at, str):
            self.updated_at = datetime.datetime.fromisoformat(self.updated_at)
        if self.email is None:
            self.email = self.user_name + '@invalid'

    @classmethod
    def lookup(cls, user_id: str=None, user_name=None):
        """Get a user from the database

        If the user cannot be found, NotFound will be raised
        """
        if user_id is None and user_name is None:
            raise ValueError('Need at least one not-None parameter')

        cur = get_db().cursor()
        try:
            if user_id is not None:
                thequery = f'select {", ".join(cls._mapping.values())} from user where id = ?', (user_id, )
            else:
                thequery = f'select {", ".join(cls._mapping.values())} from user where user_name = ?', (user_name, )
            # print(f'{thequery=}')
            cur.execute(*thequery)
            res = cur.fetchone()
            if res is None:
                raise NotFound('User not found')
        finally:
            cur.close()

        return cls(**{attrib: value
                      for attrib, value in zip(cls._mapping.keys(), res)})

    def insert(self):
        """Insert the user into the database.

        This assumes that the user does not already exist. Attempting
        to insert an user which already exists will result in Conflict
        being raised.

        """
        db = get_db()
        cur = db.cursor()
        try:
            insert_part = f'insert into user({", ".join(self._mapping.values())})'
            values_part = f'values ({", ".join(["?" for x in self._mapping.keys()])})'
            theinsert = insert_part + ' ' + values_part, tuple([getattr(self, attrib)
                                                                for attrib in self._mapping.keys()])
            # print(f'{theinsert=}')
            cur.execute(*theinsert)
            db.commit()
        except sqlite3.IntegrityError as exc:
            raise Conflict(description=str(exc))
        finally:
            cur.close()

    def update(self):
        """Update the database to match the user datastructure.

        This silently assumes that the user already exists in the database.
        """
        db = get_db()
        cur = db.cursor()
        try:
            colpart = ", ".join([f'{colname} = ?'
                                 for colname in self._mapping.values()])
            theupdate = [f'update user set {colpart} where id = ?',
                         tuple([getattr(self, attrib)
                                for attrib in self._mapping.keys()
                                ] + [self.user_id])]
            # print(f'{theupdate=}')
            cur.execute(*theupdate)
            db.commit()
        finally:
            cur.close()

    def delete(self):
        """Delete the user from the database.

        """
        db = get_db()
        cur = db.cursor()
        try:
            thedelete = f'delete from user where id = ?', (self.user_id, )
            # print(f'{thedelete=}')
            cur.execute(*thedelete)
            db.commit();
        finally:
            cur.close()

    def amend(self, payload: dict):
        """Amend the user according to a SCIM payload

        The SCIM payload is expected to conform to
        https://datatracker.ietf.org/doc/html/draft-scim-core-schema-01#section-5.1

        """
        if 'userName' in payload:
            self.user_name = payload['userName']
        if 'displayName' in payload:
            self.display_name = payload['displayName']

        email = derive_email(payload)
        if email:
            self.email = email

    def as_scim_user(self) -> dict:
        """Return a structure to represent the SCIM user

        This only includes what we know about the user; i.e. no externalId.

        See also https://datatracker.ietf.org/doc/html/draft-scim-core-schema-01#section-5.1
        """
        return {
            "schemas":[
                "urn:ietf:params:scim:schemas:core:2.0:User"
            ],
            "id": self.user_id,
            "displayName": self.display_name,
            "active": True,
            "emails": [
                {
                    "value": self.email,
                    "type": "other",
                    "primary": True
                }
            ],
            "meta": {
                "resourceType": "User",
                "created": self.created_at.isoformat(),
                "lastModified": self.updated_at.isoformat(),
                "location": flask.url_for('.get_existing_user', _external=True, user_id=self.user_id),
                "version": "W/Unknown", # TODO: figure this out
                # See https://datatracker.ietf.org/doc/html/rfc7643#section-3.1
            }
        }

@bp.route('/Me', methods=['GET', 'POST', 'PATCH', 'DELETE'])
def me():
    # See also https://datatracker.ietf.org/doc/html/rfc7644#section-3.11
    return flask.make_response('Not implemented.\nSorry\n', 500)


def derive_display_name(payload: dict) -> str:
    """Figure out the display name of the SCIM payload.

    There are several arguably-correct ways of doing this, as the
    payload can represent it in different ways.

    """
    return payload.get('displayName',
                    payload.get('name', {}).get('formatted', user['userName']))

def derive_email(payload: dict) -> str:
    """Figure out the email address of the user in the SCIM payload

    In navidrome we only support _one_ email address, whereas the SCIM
    payload has support for multiple.

    We are simple minded, so we simply pick the first.

    If no email address is present, None will be returned.

    """
    try:
        return payload['emails'][0]['value']
    except (IndexError, KeyError):
        return None

def random_id() -> str:
    """Generate a random ID suitable for a primary key for the user table"""
    return ''.join(random.choices(string.ascii_letters + string.digits, k=22))

def random_password() -> str:
    """Generate a random password.

    Arguably, this is not cryptographically strong, but at 40
    characters it should be strong enough for most purposes.

    """
    return ''.join(random.choices(string.ascii_letters + string.digits, k=40))


@bp.route('/Users', methods=['POST'])
def users():
    """Create a user
    """

    # See https://datatracker.ietf.org/doc/html/rfc7644#section-3.3
    payload = parse_payload()

    try:
        user = User(user_name=payload['userName'],
                    display_name=derive_display_name(payload),
                    email=derive_email(payload),
                    password=random_password())
        user.insert()

        return flask.make_response(user.as_scim_user(), 201)
    except Conflict:
        # The iDP is probably trying to create a user that already exists.
        #
        # Technically: We should reject this. But it is also possible
        # that Navidrome and the iDP are "out-of-sync", and doing this
        # helps things sync up nicely.
        #
        warnings.warn(f'iDP is trying to create a user which already exists: {payload["userName"]}.'
                      ' Updating existing user instead')
        user = User.lookup(user_name=payload['userName'])
        user.amend(payload)
        user.update()
        return flask.make_response(user.as_scim_user(), 201)

@bp.route('/Users/<user_id>', methods=['GET'])
def get_existing_user(user_id: str):
    """Lookup an existing user by ID

    """
    # the ID is NOT the user name, but the primary key from the `user`
    # table. Usually some random string.
    user = User.lookup(user_id=user_id)
    return user.as_scim_user()

@bp.route('/Users/<user_id>', methods=['PUT'])
def update_existing_user(user_id: str):
    """Update an existing user
    """
    # the ID is NOT the user name, but the primary key from the `user`
    # table. Usually some random string.
    #
    # See https://datatracker.ietf.org/doc/html/rfc7644#section-3.5.1
    payload = parse_payload()
    if user_id != payload['id']:
        raise BadRequest(description=f'Mismatch between name in url ("{user_id}") and id in payload ("{payload["id"]}")')

    try:
        user = User.lookup(user_id=user_id)
    except NotFound:
        user = User.lookup(user_name=payload['userName'])

    user.amend(payload)
    user.update()
    return user.as_scim_user()

@bp.route('/Users/<user_id>', methods=['DELETE'])
def delete_existing_user(user_id: str):
    """Delete an existing user

    If the user does not exist, this will raise NotFound

    """
    our_user = User.lookup(user_id=user_id) # raises NotFound if
                                            # ... not found
    our_user.delete()
    return {}

# @bp.before_request
def print_request():
    print(f'Got {flask.request.method} request for {flask.request.url}')

    print('Headers:')
    for header, value in flask.request.headers.items():
        print(f'  {header}: {value}')

    payload = flask.request.get_data()
    if not payload:
        print('No payload')
    else:
        try:
            payload = json.loads(payload)
            print('JSON payload:')
            print(json.dumps(payload, indent=2))
        except (json.decoder.JSONDecodeError, TypeError):
            print('Non-JSON payload! <<<<<<<<<<<<<<<<')
            print(payload)

    print('-' * 72)

# @bp.after_request
def print_response(resp):
    print(f'Sending Response:\n{resp}')
    payload = resp.get_data()
    if payload:
        print(f'Payload:\n{payload}')
    return resp

# Local Variables:
# mode: python
# compile-command: "flask --app scim run --host=0.0.0.0 --debug"
# End:
