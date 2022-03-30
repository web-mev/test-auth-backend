from rest_social_auth.strategy import DRFStrategy
from django.http import JsonResponse
from django.conf import settings

class XYZStrategy(DRFStrategy):
    
    def redirect(self, url):
        '''
        This override allows us to return a JSON payload
        rather than issuing a browser redirect as the 
        DjangoStrategy dictates
        '''
        return JsonResponse({
            'url':url
        })

    def build_absolute_uri(self, path=None):
        '''
        This override allows us to specify a redirect URI
        that is not from the domain hosting 
        '''
        frontend_domain = settings.FRONTEND_DOMAIN
        redirect_uri = settings.REST_SOCIAL_OAUTH_REDIRECT_URI
        uri = frontend_domain + redirect_uri
        return uri