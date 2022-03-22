from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import permissions as framework_permissions

class AuthLinkView(APIView):
    def get(self, request, *args, **kwargs):
        return Response({'url': 'something'})

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
