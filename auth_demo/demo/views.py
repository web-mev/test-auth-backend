import requests

from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import permissions as framework_permissions

from django.conf import settings
from django.http import HttpResponse
from django.shortcuts import render

from social_django.utils import psa
from social_core.actions import do_auth

def show_link(request):
    return render(request, 'demo/something.html', {})

@psa()
def other(request, backend):
    return do_auth(request.backend)

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
