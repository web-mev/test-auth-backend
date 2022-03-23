from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import permissions as framework_permissions

from django.conf import settings

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
        return Response({'url': 'something'})

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
