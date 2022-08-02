import logging
import json
import random
import time

import globus_sdk

from django.conf import settings

from .models import GlobusTokens

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

def save_token(user, token_json):
    gt = GlobusTokens.objects.create(
        user = user,
        token_text = token_json
    )

def delete_current_token(user):
    gt = GlobusTokens.objects.filter(user=user)
    if len(gt) == 1:
        gt[0].delete()
    else:
        raise Exception('Expected only a single token')

def get_globus_tokens(user, key):
    '''
    Returns the Globus token for the appropriate resource server
    specified by `key`
    '''
    # TODO: implement a try/catch here
    gt = GlobusTokens.objects.filter(user = user)
    if len(gt) != 1:
        raise Exception('failed to find a single token for this user!')
    else:
        gt = gt[0]

    # parse out the tokens from the json-format string
    tokens = json.loads(gt.token_text)
    if key in token:
        return tokens[key]
    else:
        Exception('Unknown key.')

def get_globus_uuid(user):
    '''
    Returns the Globus identifier for the given
    WebMeV user
    '''
    auth_tokens = get_globus_tokens(user, 'auth.globus.org')
    client = get_globus_client()

    # create an authorizer for the user's tokens which grant
    # us the ability to check their user info. We need the user's
    # Globus identifier
    auth_rt_authorizer = globus_sdk.RefreshTokenAuthorizer(
        auth_tokens['refresh_token'], 
        client,
        access_token=auth_tokens['access_token'],
        expires_at = auth_tokens['expires_at_seconds']
    )
    ac = globus_sdk.AuthClient(authorizer=auth_rt_authorizer)
    user_info = ac.oauth2_userinfo()
    user_info = json.loads(user_info.text)
    return user_info['sub']

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


def check_globus_token(user):

    auth_token = get_globus_tokens(user, 'auth.globus.org')
    client = get_globus_client()
    current_token = client.oauth2_validate_token(auth_token['access_token'])

    # This section establishes whether the token itself is still active.
    # This is separate from any session refreshes we might need to perform
    if not current_token.data['active']:
        logger.info('Token was not active. Go refresh.')
        token_refresh_response = client.oauth2_refresh_token(auth_token['refresh_token'])
        updated_token_dict = token_refresh_response.by_resource_server
        auth_token = updated_token_dict['auth.globus.org']
        token_json = json.dumps(updated_token_dict)
        delete_current_token(user)
        save_token(user, token_json)
    else:
        logger.info('Token was active.')

    # At this point we have an active token. We need to ensure we have a
    # recent session, however. The high-assurance storage on S3 requires
    # a relatively recent session authentication.





        # now check if we need to re-auth
        print('Check for re-auth with:\n', json.dumps(auth_tokens, indent=2))

        token_data = client.oauth2_token_introspect(
            auth_tokens['access_token'], 
            include='session_info')
        print('Token data from introspect:\n', token_data)

        user_id = token_data.data['sub']
        authentications_dict = token_data.data['session_info']['authentications']
        if user_id in authentications_dict:
            print('Found auths')
            auth_time = authentications_dict[user_id]['auth_time'] # in seconds since epoch
            time_delta = (time.time() - auth_time)/60 + 5 # how many minutes have passed PLUS some buffer
            if time_delta > REAUTHENTICATION_WINDOW_IN_MINUTES:
                print('auth was too old')
                return False
            print('auth time was ok...')
            return True
        print('no auths found')
        return False