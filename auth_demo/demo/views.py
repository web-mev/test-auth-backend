import requests
import random
import time

from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import permissions as framework_permissions

from django.conf import settings
from django.http import HttpResponse
from django.shortcuts import render

from social_django.utils import psa
from social_core.actions import do_auth

import globus_sdk

def random_string(length=12):
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


class GlobusAuthView(APIView):
    def get(self, request, *args, **kwargs):
        client = globus_sdk.ConfidentialAppAuthClient(
            settings.GLOBUS_CLIENT_ID,
            settings.GLOBUS_CLIENT_SECRET
        )
        redirect_uri = 'http://localhost:4200/globus/auth-redirect/'
        client.oauth2_start_flow(
            redirect_uri,
            refresh_tokens=True,
            requested_scopes=settings.GLOBUS_SCOPES
        )
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
