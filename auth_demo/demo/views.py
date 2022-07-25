import requests
import random
import time
import json
import uuid
import os
import re

from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import permissions as framework_permissions
from rest_framework import status

from django.conf import settings
from django.http import HttpResponse
from django.shortcuts import render

from social_django.utils import psa
from social_core.actions import do_auth

import globus_sdk

from .models import GlobusTokens

REAUTHENTICATION_WINDOW_IN_MINUTES = 60


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

@psa()
def construct_auth_url(request, backend):
    # Note that this doesn't necessarily work with ANY backend.
    # the usual response from this function (e.g. with a google-oauth2
    # backend) is a redirect. Here, we expect that the backend will
    # return a JSON response.
    return do_auth(request.backend)

class GlobusTransfer(APIView):

    permission_classes = [
        framework_permissions.IsAuthenticated 
    ]

    def post(self, request, *args, **kwargs):
        # request.data looks like:
        # {
        #    'params': {
        #         'label': 'tty', 
        #         'endpoint': 'go#ep1', 
        #         'path': '/share/godata/', 
        #         'endpoint_id': 'ddb59aef-6d04-11e5-ba46-22000b92c6ec', 
        #         'file[0]': 'file1.txt', 
        #         'action': 'http://localhost:4200/globus/transfer-redirect/', 
        #         'method': 'GET'
        #     }
        # }
        params = request.data['params']

        # TODO: implement a sane check/try-catch here
        gt = GlobusTokens.objects.filter(user = request.user)
        if len(gt) != 1:
            raise Exception('failed to find a single token for this user!')
        else:
            gt = gt[0]

        # parse out the tokens from the json-format string
        tokens = json.loads(gt.token_text)
        auth_tokens = tokens['auth.globus.org']
        transfer_tokens = tokens['transfer.api.globus.org']

        # Establish our client
        client = globus_sdk.ConfidentialAppAuthClient(
            settings.GLOBUS_CLIENT_ID,
            settings.GLOBUS_CLIENT_SECRET
        )

        # create an authorizer for the user's tokens which grant
        # us the ability to check their user info. Could also do
        # this somewhere else and cache in the db
        auth_rt_authorizer = globus_sdk.RefreshTokenAuthorizer(
            auth_tokens['refresh_token'], 
            client,
            access_token=auth_tokens['access_token'],
            expires_at = auth_tokens['expires_at_seconds']
        )
        ac = globus_sdk.AuthClient(authorizer=auth_rt_authorizer)
        user_info = ac.oauth2_userinfo()
        user_info = json.loads(user_info.text)
        user_uuid = user_info['sub']
        print('USER UUID: ', user_uuid)

        # create another authorizer using the tokens for the transfer API
        transfer_rt_authorizer = globus_sdk.RefreshTokenAuthorizer(
            transfer_tokens['refresh_token'], 
            client,
            access_token=transfer_tokens['access_token'],
            expires_at = transfer_tokens['expires_at_seconds']
        )
        user_transfer_client = globus_sdk.TransferClient(authorizer=transfer_rt_authorizer)

        # Create another transfer client which will allow us to add an ACL. Note that THIS TransferClient
        # is based on our client credentials, not on the current client who is attempting the transfer 
        cc_authorizer = globus_sdk.ClientCredentialsAuthorizer(client, settings.GLOBUS_TRANSFER_SCOPE)
        my_transfer_client = globus_sdk.TransferClient(authorizer=cc_authorizer)
        tmp_folder = '/tmp-{x}/'.format(x=uuid.uuid4())

        # Create the rule and add it
        rule_data = {
            "DATA_TYPE": "access",
            "principal_type": "identity",
            "principal": user_uuid,
            "path": tmp_folder,
            "permissions": "rw", 
        }
        print('Rule data:\n', rule_data)
        result = my_transfer_client.add_endpoint_acl_rule(settings.GLOBUS_ENDPOINT_ID, rule_data)
        print('Added ACL. Result is:\n', result)
        # TODO: can save this to later remove the ACL
        rule_id = result['access_id']

        # Now onto the business of initiating the transfer
        source_endpoint_id = params['endpoint_id']
        destination_endpoint_id = settings.GLOBUS_ENDPOINT_ID
        print('Source endpoint:', source_endpoint_id)
        print('Destination endpoint:', destination_endpoint_id)
        transfer_data = globus_sdk.TransferData(transfer_client=user_transfer_client,
                            source_endpoint=source_endpoint_id,
                            destination_endpoint=destination_endpoint_id,
                            label=params['label'])
        file_keys = [x for x in params.keys() if re.fullmatch('file\[\d+\]', x)]
        for k in file_keys:
            source_path = os.path.join(
                params['path'],
                params[k]
            )
            destination_path = os.path.join(
                tmp_folder,
                params[k]
            )
            print('Add: {s} --> {d}'.format(
                s = source_path,
                d = destination_path
            ))
            transfer_data.add_item(
                source_path = source_path,
                destination_path = destination_path
            )
        user_transfer_client.endpoint_autoactivate(source_endpoint_id)
        user_transfer_client.endpoint_autoactivate(destination_endpoint_id)
        try:
            task_id = user_transfer_client.submit_transfer(transfer_data)['task_id']
        except globus_sdk.GlobusAPIError as ex:
            authz_params = ex.info.authorization_parameters
            if not authz_params:
                raise
            print("got authz params:", authz_params)
        print(task_id)
        return Response({'transfer_id': task_id})
        
class GlobusView(APIView):

    permission_classes = [
        framework_permissions.IsAuthenticated 
    ]

    def save_token(self, user, token_json):
        gt = GlobusTokens.objects.create(
            user = user,
            token_text = token_json
        )

    def delete_current_token(self, user):
        gt = GlobusTokens.objects.filter(user=user)
        if len(gt) == 1:
            gt[0].delete()
        else:
            raise Exception('Expected only a single token')

    def get_auth_token(self, user):
        db_tokens = GlobusTokens.objects.filter(user=user)
        current_user_token = json.loads(db_tokens[0].token_text)
        return current_user_token['auth.globus.org']

    def check_token(self, user, client, auth_tokens):

        # first check for an active token. Once that's active, we might STILL
        # need to require reauthentication
        print('validate token with:\n', json.dumps(auth_tokens, indent=2))
        active_token = client.oauth2_validate_token(auth_tokens['access_token'])
        print(active_token)
        if not active_token.data['active']:
            print('token was not active')
            token_response = client.oauth2_refresh_token(auth_tokens['refresh_token'])
            updated_token_dict = token_response.by_resource_server
            auth_tokens = updated_token_dict['auth.globus.org']
            token_json = json.dumps(updated_token_dict)
            self.delete_current_token(user)
            self.save_token(user, token_json)
            print('done and saved updated token')
        else:
            print('was ACTIVE')

        # now check if we need to re-auth
        print('Check for re-auth with:\n', json.dumps(auth_tokens, indent=2))

        token_data = client.oauth2_token_introspect(
            auth_tokens['access_token'], 
            include='session_info')
        print('Updated token ddata after introspect:\n', token_data)

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

    def get(self, request, *args, **kwargs):
        print('hi.')
        client = globus_sdk.ConfidentialAppAuthClient(
            settings.GLOBUS_CLIENT_ID,
            settings.GLOBUS_CLIENT_SECRET
        )
        client.oauth2_start_flow(
            settings.GLOBUS_AUTH_REDIRECT_URI,
            refresh_tokens=True,
            requested_scopes=settings.GLOBUS_SCOPES
        )

        if 'code' in request.query_params:
            # If here, returning from the Globus auth with a code
            code = request.query_params.get('code', '')
            print('code is: ', code)
            tokens = client.oauth2_exchange_code_for_tokens(code)
            rt = tokens.by_resource_server
            # rt looks like (a native python dict):
            # {
            #     'auth.globus.org': {
            #         'scope': 'email openid profile', 
            #         'access_token': '<TOKEN>', 
            #         'refresh_token': '<token>', 
            #         'token_type': 'Bearer', 
            #         'expires_at_seconds': 1649953535, 
            #         'resource_server': 'auth.globus.org'
                    
            #     }, 
            #     'transfer.api.globus.org': {
            #         'scope': 'urn:globus:auth:scope:transfer.api.globus.org:all', 
            #         'access_token': '<TOKEN>', 
            #         'refresh_token': '<TOKEN>', 
            #         'token_type': 'Bearer', 
            #         'expires_at_seconds': 1649953535, 
            #         'resource_server': 'transfer.api.globus.org'
            #     }
            # }
            json_str = json.dumps(rt)
            existing_db_tokens = GlobusTokens.objects.filter(user=request.user)

            # in the case of this user having other, older Globus tokens, just delete them
            if len(existing_db_tokens) > 0:
                for t in existing_db_tokens:
                    t.delete()
            self.save_token(request.user, json_str)
            return Response({
                'globus-browser-url': settings.GLOBUS_BROWSER_URI
            })

        else:
            print('no code')
            # no 'code'. This means we are not receiving a 'callback' from globus auth.
            db_tokens = GlobusTokens.objects.filter(user=request.user)
            if len(db_tokens) == 1:
                print('single token found.')
                current_user_token = json.loads(db_tokens[0].token_text)
                auth_tokens = current_user_token['auth.globus.org']

                # this user has a single existing token. Need to check that it's valid to use
                print('about to check token...')
                valid_token = self.check_token(request.user, client, auth_tokens)

                if valid_token:
                    return Response({
                        'globus-browser-url': settings.GLOBUS_BROWSER_URI
                    })
                else:
                    print('was not a valid token. Go get updated token info')
                    auth_tokens = self.get_auth_token(request.user)
                    print('updated auth_tokens:', auth_tokens)
                    # token is no longer valid- force a reauth
                    token_data = client.oauth2_token_introspect(
                        auth_tokens['access_token'], 
                        include='session_info')
                    print('Back here, token_data:\n', token_data)
                    additional_authorize_params = {}
                    additional_authorize_params['state'] = random_string()
                    additional_authorize_params['session_required_identities'] = token_data.data['sub']
                    auth_uri = client.oauth2_get_authorize_url(
                        query_params=additional_authorize_params)
                    print('return auth_uri=', auth_uri)
                    return Response({
                        'globus_auth_uri': auth_uri
                    })
            elif len(db_tokens) == 0:
                additional_authorize_params = {}
                additional_authorize_params['state'] = random_string()
                if request.query_params.get('signup'):
                    additional_authorize_params['signup'] = 1
                auth_uri = client.oauth2_get_authorize_url(
                    query_params=additional_authorize_params)
                return Response({
                    'globus_auth_uri': auth_uri
                })

            else:
                # user has > 1 tokens. That's a problem. Can later encode this into the 
                # db as a constraint
                return Response(
                    {'tokens': '!!!'}, 
                    status=status.HTTP_500_INTERNAL_SERVER_ERROR
                )


#######

            #data.data['session_info']['authentications']['37c82bcd-6824-4816-82e3-203087d7ad30']['auth_time']

           

class InfoView(APIView):
    permission_classes = [
        framework_permissions.IsAuthenticated 
    ]
    def get(self, request, *args, **kwargs):
        user = request.user
        return Response(
            {
                'email': user.email,
                'pic_url': user.profile_pic_url
            }
        )
