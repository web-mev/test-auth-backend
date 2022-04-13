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
        client = globus_sdk.ConfidentialAppAuthClient(
            settings.GLOBUS_CLIENT_ID,
            settings.GLOBUS_CLIENT_SECRET
        )
        cc_authorizer = globus_sdk.ClientCredentialsAuthorizer(client, settings.GLOBUS_TRANSFER_SCOPE)
        transfer_client = globus_sdk.TransferClient(authorizer=cc_authorizer)
        tmp_folder = '/tmp-{x}/'.format(x=uuid.uuid4())

        # Note that this adding of ACL was not necessary. The transfer still succeeded 
        # with these lines commented out:
        rule_data = {
            "DATA_TYPE": "access",
            "principal_type": "identity",
            "principal": settings.GLOBUS_CLIENT_ID,
            "path": tmp_folder,
            "permissions": "rw", 
        }
        result = transfer_client.add_endpoint_acl_rule(settings.GLOBUS_ENDPOINT_ID, rule_data)
        rule_id = result['access_id']
        source_endpoint_id = params['endpoint_id']
        destination_endpoint_id = settings.GLOBUS_ENDPOINT_ID
        transfer_data = globus_sdk.TransferData(transfer_client=transfer_client,
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
        transfer_client.endpoint_autoactivate(source_endpoint_id)
        transfer_client.endpoint_autoactivate(destination_endpoint_id)
        task_id = transfer_client.submit_transfer(transfer_data)['task_id']
        return Response({'transfer_id': task_id})
        
class GlobusView(APIView):

    permission_classes = [
        framework_permissions.IsAuthenticated 
    ]

    def get(self, request, *args, **kwargs):
        client = globus_sdk.ConfidentialAppAuthClient(
            settings.GLOBUS_CLIENT_ID,
            settings.GLOBUS_CLIENT_SECRET
        )
        client.oauth2_start_flow(
            settings.GLOBUS_AUTH_REDIRECT_URI,
            refresh_tokens=True,
            requested_scopes=settings.GLOBUS_SCOPES
        )

        # if the user already has Globus tokens, we can just immediately
        # send them to the "chooser"
        db_tokens = GlobusTokens.objects.filter(user=request.user)
        if len(db_tokens) == 1:
            return Response({
                'globus-browser-url': settings.GLOBUS_BROWSER_URI
            })
        elif len(db_tokens) > 1:
            return Response({'tokens': '!!!'}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

        # if here, there were zero Globus tokens associated with this user. Start the auth flow
        if 'code' in request.query_params:
            # If here, returning from the auth with a code
            code = request.query_params.get('code', '')
            print('code is ', code)
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
            gt = GlobusTokens.objects.create(
                user = request.user,
                token_text = json_str
            )
            gt.save()
            return Response({
                'globus-browser-url': settings.GLOBUS_BROWSER_URI
            })
        else:
            additional_authorize_params = (
                {'signup': 1} if request.query_params.get('signup') else {})
            additional_authorize_params['state'] = random_string()

            auth_uri = client.oauth2_get_authorize_url(
                query_params=additional_authorize_params)

            return Response({
                'globus_auth_uri': auth_uri
            })

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
