import requests

from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import permissions as framework_permissions

from django.conf import settings
from django.http import HttpResponse
from django.shortcuts import render

def basic(request):
    return render(request, 'demo/something.html', {})

class AuthLinkView(APIView):
    def get(self, request, *args, **kwargs):
        url = 'https://accounts.google.com/o/oauth2/v2/auth'
        client_id = settings.CLIENT_ID
        redirect_uri = settings.REDIRECT_URI
        access_type = 'online'
        response_type = 'code'
        scope = 'https://www.googleapis.com/auth/userinfo.email'
        url += '?scope={scope}&client_id={client_id}&redirect_uri={redirect_uri}&access_type={access_type}&response_type={response_type}'.format(
            scope = scope,
            client_id = client_id,
            redirect_uri = redirect_uri,
            access_type = access_type,
            response_type = response_type
        )
        return Response({'url': url})

class RemoteAuthTokenView(APIView):
    def post(self, request, *args, **kwargs):
        # get the code and exchange for a token
        url = 'https://oauth2.googleapis.com/token'
        data = request.data
        code = data['code']
        client_secret = settings.CLIENT_SECRET
        client_id = settings.CLIENT_ID
        redirect_uri = settings.REDIRECT_URI
        grant_type = 'authorization_code'
        post_data = {
            'client_id' : client_id,
            'client_secret' : client_secret,
            'redirect_uri': redirect_uri,
            'grant_type' : grant_type,
            'code' : code
        }
        r = requests.post(url, data=post_data)
        if r.status_code == 200:
            j = r.json()
            access_token = j['access_token']
            print('have token:', access_token)
            info_url = 'https://www.googleapis.com/oauth2/v3/userinfo'
            headers={
                'Authorization': 'Bearer %s' % access_token,
            }
            info_get = requests.get(info_url, headers=headers)
            j = info_get.json()
            print(j)
            return Response(j)

class GoogleOauth2View(APIView):
    def post(self, request, *args, **kwargs):
        code = data['code']
        client_secret = settings.CLIENT_SECRET
        client_id = settings.CLIENT_ID
        redirect_uri = settings.REDIRECT_URI

class InfoView(APIView):
    def get(self, request, *args, **kwargs):
        # Use the authToken to get info about the user
        return Response({'url': 'something'})

class ProtectedView(APIView):
    permission_classes = [
        framework_permissions.IsAuthenticated 
    ]
    def get(self, request, *args, **kwargs):
        return Response({'info': 'something protected'})
