import logging
import json
import random
import time

import globus_sdk

from django.conf import settings

from .models import GlobusTokens
from .exceptions import NonexistentGlobusTokenException

logger = logging.getLogger(__name__)


def random_string(length=12):
    '''
    Used to generate a state parameter for the OAuth2 flow.
    '''
    ALLOWED_CHARS = 'abcdefghijklmnopqrstuvwxyz' \
                    'ABCDEFGHIJKLMNOPQRSTUVWXYZ' \
                    '0123456789'
    # Implementation borrowed from python social auth pkg
    try:
        random.SystemRandom()
    except NotImplementedError:
        try:
            key = settings.SECRET_KEY
        except AttributeError:
            key = ''
        seed = f'{random.getstate()}{time.time()}{key}'
        random.seed(hashlib.sha256(seed.encode()).digest())
    return ''.join([random.choice(ALLOWED_CHARS) for i in range(length)])

def get_globus_client():
    return globus_sdk.ConfidentialAppAuthClient(
        settings.GLOBUS_CLIENT_ID,
        settings.GLOBUS_CLIENT_SECRET
    )

def create_token(user, token_dict):
    token_json = json.dumps(token_dict)
    gt = GlobusTokens.objects.create(
        user = user,
        token_text = token_json
    )

def create_or_update_token(user, token_dict):
    try:
        update_tokens_in_db(user, token_dict)
    except NonexistentGlobusTokenException:
        create_token(user, token_dict)
        

def get_globus_token_from_db(user, existence_required=True):
    '''
    Returns a GlobusTokens instance (our database model)
    '''
    # TODO: implement a try/catch here
    gt = GlobusTokens.objects.filter(user = user)
    if len(gt) > 1:
        raise Exception('Found multiple tokens for user.')
    elif len(gt) == 1:
        return gt[0]
    else:
        # this means we have zero tokens for this user.
        if existence_required:
            raise NonexistentGlobusTokenException()
        return None

def get_globus_tokens(user, key=None):
    '''
    Returns the Globus token for the appropriate resource server
    specified by `key`. If `key` is None, return the entire dict,
    which will, in general, have multiple resource servers such 
    as:
    {
        "auth.globus.org": {
            "scope": "profile email openid",
            "access_token": "...",
            "refresh_token": "...",
            "token_type": "Bearer",
            "expires_at_seconds": 1659645740,
            "resource_server": "auth.globus.org"
        },
        "transfer.api.globus.org": {
            "scope": "urn:globus:auth:scope:transfer.api.globus.org:all",
            "access_token": "...",
            "refresh_token": "...",
            "token_type": "Bearer",
            "expires_at_seconds": 1659645740,
            "resource_server": "transfer.api.globus.org"
        }
    }
    '''
    gt = get_globus_token_from_db(user)

    # parse out the tokens from the json-format string
    tokens = json.loads(gt.token_text)

    if key is None:
        return tokens
    elif key in tokens:
        return tokens[key]
    else:
        Exception('Unknown key.')

def get_globus_uuid(user):
    '''
    Returns the Globus identifier for the given
    WebMeV user
    '''
    auth_tokens = get_globus_tokens(user, key='auth.globus.org')
    client = get_globus_client()
    introspection_response = client.oauth2_token_introspect(
        auth_tokens['access_token'], 
        include='session_info')
    data = introspection_response.data
    return data['sub']

def create_application_transfer_client():
    '''
    Given a WebMeV user, create/return a globus_sdk.TransferClient that 
    is associated with our application. Note that this client does NOT
    use the tokens for a user who is transferring data. This client is used, 
    for instance, to set ACLs on the Globus Collection we own/control
    '''

    client = get_globus_client()
    cc_authorizer = globus_sdk.ClientCredentialsAuthorizer(client, settings.GLOBUS_TRANSFER_SCOPE)
    return globus_sdk.TransferClient(authorizer=cc_authorizer)

def create_user_transfer_client(user):
    '''
    Given a WebMeV user, create/return a globus_sdk.TransferClient
    '''
    transfer_tokens = get_globus_tokens(user, 'transfer.api.globus.org')

    client = get_globus_client()

    # create another authorizer using the tokens for the transfer API
    transfer_rt_authorizer = globus_sdk.RefreshTokenAuthorizer(
        transfer_tokens['refresh_token'], 
        client,
        access_token=transfer_tokens['access_token'],
        expires_at = transfer_tokens['expires_at_seconds']
    )
    return globus_sdk.TransferClient(authorizer=transfer_rt_authorizer)

def refresh_globus_token(client, token):
    '''
    Performs a token refresh and returns a dict with the 
    updated token info.

    For example, a response might look like:
    {
        "transfer.api.globus.org": {
            "scope": "urn:globus:auth:scope:transfer.api.globus.org:all",
            "access_token": "...",
            "refresh_token": "...",
            "token_type": "Bearer",
            "expires_at_seconds": 1659654653,
            "resource_server": "transfer.api.globus.org"
        }
    }
    '''
    token_refresh_response = client.oauth2_refresh_token(token['refresh_token'])
    return token_refresh_response.by_resource_server

def get_active_token(client, token, resource_server):
    '''
    Given the current token (e.g. for auth.globus.org or transfer), 
    check if active.
    
    If not, refresh.
    
    Either way, this function returns an active token (a dict)
    '''
    response = client.oauth2_validate_token(token['access_token'])

    # This section establishes whether the token itself is still active.
    # This is separate from any session refreshes we might need to perform
    if not response.data['active']:
        logger.info('Token was not active. Go refresh.')
        refreshed_token_dict = refresh_globus_token(client, token)
        return refreshed_token_dict[resource_server]
    else:
        logger.info('Token was active.')
        return token

def update_tokens_in_db(user, updated_tokens):
    '''
    Updates the tokens for this user. 
    '''
    gt = get_globus_token_from_db(user)
    tokens_as_json = json.dumps(updated_tokens)
    gt.token_text = tokens_as_json
    gt.save()

def session_is_recent(client, auth_token):
    '''
    Check if the most recent session authentication was within
    the time limit. Returns a bool indicating whether the user
    has recently authenticated (True) or whether it is too old
    (False)
    '''
    logger.info('Check for sessions with: {j}'.format(
        j=json.dumps(auth_token, indent=2)))

    introspection_data = client.oauth2_token_introspect(
        auth_token['access_token'], 
        include='session_info')
    logger.info('Token data from introspect:\n', introspection_data)

    user_id = introspection_data.data['sub']
    authentications_dict = introspection_data.data['session_info']['authentications']
    logger.info('Authentications:\n{x}'.format(x=json.dumps(authentications_dict, indent=2)))
    if user_id in authentications_dict:
        auth_time = authentications_dict[user_id]['auth_time'] # in seconds since epoch
        time_delta = (time.time() - auth_time)/60 + 5 # how many minutes have passed PLUS some buffer
        logger.info('Time delta was: {x}'.format(x=time_delta))
        if time_delta > settings.GLOBUS_REAUTHENTICATION_WINDOW_IN_MINUTES:
            logger.info('Most recent session was too old')
            return False
        logger.info('Most recent session was within the limit.')
        return True
    logger.info('No session authentications found.')
    return False

def check_globus_tokens(user):
    '''
    Checks that the tokens for this user are valid.

    Note that we maintain two sets of tokens for:
    - auth.globus.org
    - transfer.api.globus.org

    We ensure that both are valid and update as necessary.
    '''

    '''
    all_tokens is a dict and looks like
    {
        "auth.globus.org": {
            "scope": "profile email openid",
            "access_token": "...",
            "refresh_token": "...",
            "token_type": "Bearer",
            "expires_at_seconds": 1659645740,
            "resource_server": "auth.globus.org"
        },
        "transfer.api.globus.org": {
            "scope": "urn:globus:auth:scope:transfer.api.globus.org:all",
            "access_token": "...",
            "refresh_token": "...",
            "token_type": "Bearer",
            "expires_at_seconds": 1659645740,
            "resource_server": "transfer.api.globus.org"
        }
    }
    '''
    all_tokens = get_globus_tokens(user)
    client = get_globus_client()
    updated_tokens = {}
    # TODO: what if we can't refresh??
    for resource_server in all_tokens.keys():
        updated_tokens[resource_server] = get_active_token(
            client, 
            all_tokens[resource_server], 
            resource_server
        )

    update_tokens_in_db(user, updated_tokens)

    # At this point we have an active token. However, we still need to 
    # ensure we have a recent session. The high-assurance storage on S3
    # requires a relatively recent session authentication.
    return session_is_recent(client, updated_tokens['auth.globus.org'])

