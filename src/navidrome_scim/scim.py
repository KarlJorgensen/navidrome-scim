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

NOTE: This was developed for version 0.55.2 of Navidrome; although it
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

import dataclasses
import datetime
import json
import os
import random
import string
import sys

import flask
import requests

from flask import (
    Blueprint, flash, g, redirect, render_template, request, session, url_for
)
from werkzeug.security import check_password_hash, generate_password_hash
from werkzeug.exceptions import NotFound, BadRequest, Conflict

# TODO: Proper error messages around missing env vars
NAVIDROME_BASE_URL = os.environ.get('NAVIDROME_BASE_URL', 'http://navidrome.svc:4533')

NAVIDROME_USER = os.environ.get('USERNAME', 'admin')

NAVIDROME_HEADERS = {
    os.environ.get('USERNAME_HEADER', 'X-Authentik-Username'): NAVIDROME_USER
}

# The `/v2` is mandatory - see https://datatracker.ietf.org/doc/html/rfc7644#section-3.13
blueprint = Blueprint('scim', __name__, url_prefix='/scim/v2')

@blueprint.route('/help')
@blueprint.route('/')
def help():
    """Basic help.

    Doesn't really help much, and isn't even mentioned by the RFCs but
    at least it gives an idea...

    """
    resp = flask.make_response(__doc__, 200)
    resp.content_type = 'text/plain'
    return resp

@blueprint.route('/ServiceProviderConfig')
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

@blueprint.route('/Schemas')
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

@blueprint.route('/ResourceTypes')
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

@blueprint.route('/Schemas/urn:ietf:params:scim:schemas:core:2.0:User')
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


@blueprint.route('/Me', methods=['GET', 'POST', 'PATCH', 'DELETE'])
def me():
    # See also https://datatracker.ietf.org/doc/html/rfc7644#section-3.11
    return flask.make_response('Not implemented.\nSorry\n', 500)

@blueprint.route('/Users', methods=['POST'])
def users():
    """Create a user
    """

    # See https://datatracker.ietf.org/doc/html/rfc7644#section-3.3
    payload = parse_payload()

    user = User(user_name=payload['userName'],
                display_name=derive_display_name(payload),
                email=derive_email(payload),
                password=random_password())
    if user.user_name == NAVIDROME_USER:
        # Uh-oh. SCIM is trying to create the user that we are using
        # for SCIM. That cannot possibly work - it has to already
        # exist.
        #
        # And we do not want it to be managed by SCIM
        msg = f'Refusing to create {user.user_name}' \
            ' as we use it ourselves.'
        print(msg, file=sys.stderr)
        return flask.make_response(msg, 409)

    try:
        user.insert()

        return flask.make_response(user.as_scim_user(), 201)
    except Conflict:
        # The iDP is probably trying to create a user that already exists.
        #
        # Technically: We should reject this. But it is also possible
        # that Navidrome and the iDP are "out-of-sync", and doing this
        # helps things sync up nicely.
        #
        print(f'iDP is trying to create a user which already exists: {payload["userName"]}.'
              ' Updating existing user instead')
        user = User.lookup_by_name(user_name=payload['userName'])
        user.amend(payload)
        user.update()
        return flask.make_response(user.as_scim_user(), 201)

@blueprint.route('/Users/<user_id>', methods=['GET'])
def get_existing_user(user_id: str):
    """Lookup an existing user by ID

    """
    # the ID is NOT the user name, but the primary key from the `user`
    # table. Usually some random string.
    user = User.lookup_by_id(user_id=user_id)
    return user.as_scim_user()

@blueprint.route('/Users/<user_id>', methods=['PUT'])
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
        user = User.lookup_by_id(user_id=user_id)
    except NotFound:
        user = User.lookup_by_name(user_name=payload['userName'])

    if user.user_name == NAVIDROME_USER:
        # Uh-oh. SCIM is trying to create the user that we are using
        # for SCIM. That cannot possibly work - it has to already
        # exist.
        #
        # And we do not want it to be managed by SCIM
        msg = f'Refusing to update {user.user_name}' \
            ' as we use it ourselves.'
        print(msg, file=sys.stderr)
        return flask.make_response(msg, 409)

    user.amend(payload)
    user.update()
    return user.as_scim_user()

@blueprint.route('/Users/<user_id>', methods=['DELETE'])
def delete_existing_user(user_id: str):
    """Delete an existing user

    If the user does not exist, this will raise NotFound

    """
    user = User.lookup_by_id(user_id=user_id) # raises NotFound if ... not found
    if user.user_name == NAVIDROME_USER:
        # Uh-oh. SCIM is trying to create the user that we are using
        # for SCIM. That cannot possibly work - it has to already
        # exist.
        #
        # And we do not want it to be managed by SCIM
        msg = f'Refusing to delete {user.user_name}' \
            ' as we use it ourselves.'
        print(msg, file=sys.stderr)
        return flask.make_response(msg, 409)

    user.delete()
    return {}

# @blueprint.before_request
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

# @blueprint.after_request
def print_response(resp):
    print(f'Sending Response:\n{resp}')
    payload = resp.get_data()
    if payload:
        print(f'Payload:\n{payload}')
    return resp

@dataclasses.dataclass(kw_only=True)
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

    def __post_init__(self):
        """Set sensible values on fields that are mandatory"""
        # if self.user_id is None:
        #     self.user_id = random_id()
        if self.password is None:
            self.password = random_password()
        if self.created_at is None:
            self.created_at = datetime.datetime.utcnow()
        if self.updated_at is None:
            self.updated_at = datetime.datetime.utcnow()
        if self.email is None:
            self.email = self.user_name + '@invalid'

    @classmethod
    def lookup_by_id(cls, user_id: str):
        resp = requests.get(NAVIDROME_BASE_URL + '/api/user/' + user_id,
                            headers=NAVIDROME_HEADERS)
        resp.raise_for_status()
        return cls._from_nd(resp.json())

    @classmethod
    def _list_all_users(cls):
        """Yields succesive users from Navidrome"""
        start = 0
        size = 10
        while True:
            resp = requests.get(NAVIDROME_BASE_URL + '/api/user',
                                params={'_start': start,
                                        '_end': start+size,
                                        '_sort': 'userName',
                                        '_order': 'ASC'})
            resp.raise_for_status()
            users = resp.json()
            yield from [cls._from_nd(user)
                        for user in users]
            if len(users) < size:
                break
            start += size

    @classmethod
    def lookup_by_name(cls, user_name: str):
        """Find a user by name"""
        # Navidrome does not appear to have a way to do this, so we
        # resort to listing _all_ the users to find the one we want
        # :-(
        users = [user
                 for user in cls._list_all_users()
                 if user.user_name == user_name]
        if not users:
            raise NotFound
        return users[0]

    @classmethod
    def _from_nd(cls, nduser: dict):
        """Construct a User entry from Navidrome"""
        return cls(user_id=nduser['id'],
                   display_name=nduser.get('name'),
                   user_name=nduser['userName'],
                   email=nduser['email'],
                   is_admin=bool(nduser.get('isAdmin', False))
                   )

    def _to_nd(self):
        return {
            # "id": self.user_id,
            "name": self.display_name,
            "userName": self.user_name,
            "email": self.email,
            "isAdmin": self.is_admin,
            "password": self.password,
        }

    def insert(self):
        """Insert the user into the database.

        This assumes that the user does not already exist. Attempting
        to insert an user which already exists will result in Conflict
        being raised.

        """
        resp = requests.post(NAVIDROME_BASE_URL + '/api/user',
                             headers=NAVIDROME_HEADERS,
                             json=self._to_nd())
        if resp.status_code == 400:
            raise Conflict
        resp.raise_for_status()
        self.user_id = resp.json()['id']
        return self

    def update(self):
        """Update the database to match the user datastructure.

        This silently assumes that the user already exists in the database.
        """
        resp = requests.put(NAVIDROME_BASE_URL + '/api/user/' + self.user_id,
                            headers=NAVIDROME_HEADERS,
                            json=self._to_nd())
        resp.raise_for_status()
        return self

    def delete(self):
        """Delete the user from the database.

        """
        resp = requests.delete(NAVIDROME_BASE_URL + '/api/user/' + self.user_id,
                               headers=NAVIDROME_HEADERS)
        resp.raise_for_status()

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
            "userName": self.user_name,
            "displayName": self.display_name,
            "active": True,
            # "profileUrl":  f'{NAVIDROME_URL}/app/#user/{self.user_id}',
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

def derive_display_name(payload: dict) -> str:
    """Figure out the display name of the SCIM payload.

    There are several arguably-correct ways of doing this, as the
    payload can represent it in different ways.

    """
    return payload.get('displayName',
                    payload.get('name', {}).get('formatted', payload['userName']))

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

# Local Variables:
# mode: python
# compile-command: "flask --app scim run --host=0.0.0.0 --debug"
# End:
