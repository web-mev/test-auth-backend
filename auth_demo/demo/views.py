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
from .utils import random_string, \
    get_globus_client, \
    create_or_update_token, \
    get_globus_token_from_db, \
    get_globus_uuid, \
    check_globus_tokens, \
    create_user_transfer_client, \
    create_application_transfer_client

SESSION_MESSAGE = ('Since this is a high-assurance Globus collection, we'
    ' require a recent authentication. Please sign-in again.'
)

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


# class GlobusInitView(APIView):
#     '''
#     A common view for intitiating either up or downloads via Globus
#     '''

#     permission_classes = [
#         framework_permissions.IsAuthenticated 
#     ]    
    
#     def get(self, request, *args, **kwargs):

#         transfer_direction = request.query_params.get('direction')

# class DownloadFilesView(APIView):

#     permission_classes = [
#         framework_permissions.IsAuthenticated 
#     ]    
    
#     def post(self, request, *args, **kwargs):
#         print('data=', request.data)
#         pk = request.data['pk']
#         r = Resource.objects.get(pk=pk)
#         print(r)

#         url = settings.GLOBUS_BROWSER_DOWNLOAD_URI + '&ep=' + pk
#         return Response(
#             {'globus-browser-url': url}
#         )

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

class GlobusUploadView(APIView):

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

        app_transfer_client = create_application_transfer_client()
        user_uuid = get_globus_uuid(request.user)
        tmp_folder = '/tmp-{x}/'.format(x=uuid.uuid4())

        # Create the rule and add it
        rule_data = {
            "DATA_TYPE": "access",
            "principal_type": "identity",
            "principal": user_uuid,
            "path": tmp_folder,
            "permissions": "rw", 
        }
        logger.info('Rule data:\n{data}'.format(data=rule_data))
        result = app_transfer_client.add_endpoint_acl_rule(settings.GLOBUS_ENDPOINT_ID, rule_data)
        logger.info('Added ACL. Result is:\n{r}'.format(r=result))

        # TODO: can save this to later remove the ACL
        rule_id = result['access_id']

        # Now onto the business of initiating the transfer
        source_endpoint_id = params['endpoint_id']
        destination_endpoint_id = settings.GLOBUS_ENDPOINT_ID
        logger.info('Source endpoint: {e}'.format(e=source_endpoint_id))
        logger.info('Destination endpoint: {e}'.format(e=destination_endpoint_id))
        transfer_data = globus_sdk.TransferData(
            transfer_client=app_transfer_client,
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
            logger.info('Add: {s} --> {d}'.format(
                s = source_path,
                d = destination_path
            ))
            transfer_data.add_item(
                source_path = source_path,
                destination_path = destination_path
            )
            # r = Resource.objects.create(
            #     path = destination_path,
            #     owner = request.user,
            #     name = os.path.basename(source_path)
            # )
        user_transfer_client = create_user_transfer_client(request.user)
        user_transfer_client.endpoint_autoactivate(source_endpoint_id)
        user_transfer_client.endpoint_autoactivate(destination_endpoint_id)
        try:
            task_id = user_transfer_client.submit_transfer(transfer_data)['task_id']
        except globus_sdk.GlobusAPIError as ex:
            authz_params = ex.info.authorization_parameters
            if not authz_params:
                raise
            logger.info("got authz params:", authz_params)

        return Response({'transfer_id': task_id})
        
# class GlobusInitDownloadView(APIView):

#     permission_classes = [
#         framework_permissions.IsAuthenticated 
#     ]

#     def get(self, request, *args, **kwargs):
#         pass


class GlobusInitiate(APIView):

    def return_globus_browser_url(self, direction):
        if direction == 'upload':
            return Response({
                'globus-browser-url': settings.GLOBUS_BROWSER_UPLOAD_URI
            })
        elif direction == 'download':
            return Response({
                'globus-browser-url': settings.GLOBUS_BROWSER_DOWNLOAD_URI
            })  
        else:
            return Response(status=status.HTTP_400_BAD_REQUEST)

    def get(self, request, *args, **kwargs):

        client = get_globus_client()
        client.oauth2_start_flow(
            settings.GLOBUS_AUTH_REDIRECT_URI,
            refresh_tokens=True,
            requested_scopes=settings.GLOBUS_SCOPES
        )

        upload_or_download_state = request.query_params.get('direction')

        if 'code' in request.query_params:
            # If here, returning from the Globus auth with a code
            code = request.query_params.get('code', '')
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
            create_or_update_token(request.user, rt)
            return self.return_globus_browser_url(upload_or_download_state)   

        else:
            logger.info('No "code" present in request params')
            # no 'code'. This means we are not receiving a 'callback' from globus auth.

            # this will be None if the current user does not have Globus tokens
            existing_globus_tokens = get_globus_token_from_db(
                request.user, existence_required=False)

            if existing_globus_tokens:
                has_recent_globus_session = check_globus_tokens(request.user)
                if has_recent_globus_session:
                    return self.return_globus_browser_url(upload_or_download_state)   
                else:
                    globus_user_uuid = get_globus_uuid(request.user)
                    additional_authorize_params = {}
                    additional_authorize_params['state'] = random_string()
                    additional_authorize_params['session_required_identities'] = globus_user_uuid
                    additional_authorize_params['prompt'] = 'login'
                    additional_authorize_params['session_message'] = SESSION_MESSAGE
                    auth_uri = client.oauth2_get_authorize_url(
                        query_params=additional_authorize_params)
                    return Response({
                        'globus-auth-url': auth_uri
                    })
            else:
                # existing_globus_tokens was None, so we need to
                # initiate the start of the oauth2 flow.
                additional_authorize_params = {}
                additional_authorize_params['state'] = random_string()
                if request.query_params.get('signup'):
                    additional_authorize_params['signup'] = 1
                auth_uri = client.oauth2_get_authorize_url(
                    query_params=additional_authorize_params)
                return Response({
                    'globus-auth-url': auth_uri
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
