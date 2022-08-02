import requests
import random
import time
import json
import uuid
import os
import re
import logging

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
import boto3

from .models import GlobusTokens, Resource

REAUTHENTICATION_WINDOW_IN_MINUTES = 60

logger = logging.getLogger(__name__)


@psa()
def construct_auth_url(request, backend):
    # Note that this doesn't necessarily work with ANY backend.
    # the usual response from this function (e.g. with a google-oauth2
    # backend) is a redirect. Here, we expect that the backend will
    # return a JSON response.
    return do_auth(request.backend)


class ListFilesView(APIView):
    '''
    Returns an array of the files associated
    with the current user.
    '''

    permission_classes = [
        framework_permissions.IsAuthenticated 
    ]

    def get(self, request, *args, **kwargs):
        r = Resource.objects.filter(owner = request.user)
        response = []
        for rr in r:
            x = {
                'name': rr.name,
                'pk': str(rr.pk)
            }
            response.append(x)
        return Response(response)


class GlobusInitView(APIView):
    '''
    A common view for intitiating either up or downloads via Globus
    '''

    permission_classes = [
        framework_permissions.IsAuthenticated 
    ]    
    
    def get(self, request, *args, **kwargs):

        transfer_direction = request.query_params.get('direction')



class DownloadFilesView(APIView):

    permission_classes = [
        framework_permissions.IsAuthenticated 
    ]    
    
    def post(self, request, *args, **kwargs):
        print('data=', request.data)
        pk = request.data['pk']
        r = Resource.objects.get(pk=pk)
        print(r)

        url = settings.GLOBUS_BROWSER_DOWNLOAD_URI + '&ep=' + pk
        return Response(
            {'globus-browser-url': url}
        )

class GlobusDownloadView(APIView):

    permission_classes = [
        framework_permissions.IsAuthenticated 
    ]  

    def post(self, request, *args, **kwargs):

        print('data=', request.data)
        # pk = request.data['pk']
        # r = Resource.objects.get(pk=pk)
        # print(r)

        return Response({'transfer_id': 'abc123'})
        # # copy the file to some other location.
        # # For Globus to 'see' it, needs to be in the same folder
        # # accessible by the collection
        # data_location = os.path.join(
        #     settings.S3_BUCKET_ROOT_DIR,
        #     r.path
        # )
        # tmp_folder = 'tmp-{x}/'.format(x=uuid.uuid4())
        # # where the data will go TO, relative to the bucket
        # tmp_data_location = os.path.join(
        #     settings.S3_BUCKET_ROOT_DIR,
        #     tmp_folder,
        #     os.path.basename(r.path)
        # )
        # # boto copy...
        # s3 = boto3.resource('s3')
        # dest_obj = s3.Object(settings.S3_BUCKET, tmp_data_location)
        # cp_src = {
        #     'Bucket': settings.S3_BUCKET,
        #     'Key': data_location
        # }
        # dest_obj.copy(cp_src)

        # my_transfer_client, user_uuid = create_transfer_client(request.user)

        # # Create the rule and add it
        # rule_data = {
        #     "DATA_TYPE": "access",
        #     "principal_type": "identity",
        #     "principal": user_uuid,
        #     "path": tmp_data_location,
        #     "permissions": "rw", 
        # }
        # print('Rule data:\n', rule_data)
        # result = my_transfer_client.add_endpoint_acl_rule(settings.GLOBUS_ENDPOINT_ID, rule_data)
        # print('Added ACL. Result is:\n', result)
        # # TODO: can save this to later remove the ACL
        # rule_id = result['access_id']

        # # Now onto the business of initiating the transfer
        # # TODO: get the endpoint based on where the user wants to put their files.
        # destination_endpoint_id = params['endpoint_id']
        # source_endpoint_id = settings.GLOBUS_ENDPOINT_ID
        # print('Source endpoint:', source_endpoint_id)
        # print('Destination endpoint:', destination_endpoint_id)
        # transfer_data = globus_sdk.TransferData(transfer_client=user_transfer_client,
        #                     source_endpoint=source_endpoint_id,
        #                     destination_endpoint=destination_endpoint_id,
        #                     label=params['label'])

        # source_path = os.path.join(
        #     tmp_folder,
        #     os.path.basename(r.path) 
        # )
        # # TODO: determine where the file will go based on user input
        # destination_path = ...
        # print('Add: {s} --> {d}'.format(
        #     s = source_path,
        #     d = destination_path
        # ))
        # transfer_data.add_item(
        #     source_path = source_path,
        #     destination_path = destination_path
        # )
        # user_transfer_client.endpoint_autoactivate(source_endpoint_id)
        # user_transfer_client.endpoint_autoactivate(destination_endpoint_id)
        # try:
        #     task_id = user_transfer_client.submit_transfer(transfer_data)['task_id']
        # except globus_sdk.GlobusAPIError as ex:
        #     authz_params = ex.info.authorization_parameters
        #     if not authz_params:
        #         raise
        #     print("got authz params:", authz_params)
        # print(task_id)
        # return Response({'transfer_id': task_id})

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

        my_transfer_client, user_uuid = create_transfer_client(request.user)
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
        transfer_data = globus_sdk.TransferData(transfer_client=my_transfer_client,
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
        r = Resource.objects.create(
            path = destination_path,
            owner = request.user,
            name = ''
        )
        return Response({'transfer_id': task_id})
        
class GlobusInitDownloadView(APIView):

    permission_classes = [
        framework_permissions.IsAuthenticated 
    ]

    def get(self, request, *args, **kwargs):
        pass


class GlobusInitUploadView(APIView):

    permission_classes = [
        framework_permissions.IsAuthenticated 
    ]

    def get(self, request, *args, **kwargs):
        pass


class GlobusAuthMixin(object):

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

    def my_introspect(self, client, rt, key):
        token_data = client.oauth2_token_introspect(
            rt[key]['access_token'], 
            include='session_info')
        print('In the "code" response block, token data (%s) from introspect:\n' % key, token_data)

        user_id = token_data.data['sub']
        authentications_dict = token_data.data['session_info']['authentications']
        if user_id in authentications_dict:
            print('In introspect, found auths')
            auth_time = authentications_dict[user_id]['auth_time'] # in seconds since epoch
            time_delta = (time.time() - auth_time)/60 + 5 # how many minutes have passed PLUS some buffer
            if time_delta > REAUTHENTICATION_WINDOW_IN_MINUTES:
                print('In introspect, auth was too old. Delta=', time_delta)
            else:
                print('In introspect, auth time was OK')

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

        upload_or_download_state = request.query_params.get('direction')

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

            ### Start temp code  #####
            self.my_introspect(client, rt, 'auth.globus.org')
            print('?'*200)
            self.my_introspect(client, rt, 'transfer.api.globus.org')

            ### End temp code  #####

            if upload_or_download_state == 'upload':
                return Response({
                    'globus-browser-url': settings.GLOBUS_BROWSER_UPLOAD_URI
                })
            elif upload_or_download_state == 'download':
                return Response({
                    'globus-browser-url': settings.GLOBUS_BROWSER_DOWNLOAD_URI
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
                    if upload_or_download_state == 'upload':
                        return Response({
                            'globus-browser-url': settings.GLOBUS_BROWSER_UPLOAD_URI
                        })
                    elif upload_or_download_state == 'download':
                        return Response({
                            'globus-browser-url': settings.GLOBUS_BROWSER_DOWNLOAD_URI
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
                    additional_authorize_params['prompt'] = 'login'
                    additional_authorize_params['direction'] = upload_or_download_state
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
                additional_authorize_params['direction'] = upload_or_download_state
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
