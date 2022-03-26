from social_core.backends.google import GoogleOAuth2 
from django.http import JsonResponse

class CustomGoogleOAuth2(GoogleOAuth2):
    name = 'custom-google-oauth2'

    def start(self):
        url = self.auth_url()
        return JsonResponse({
            'url':url
        })

    def get_redirect_uri(self, state=None):
        """Build redirect with redirect_state parameter."""
        uri = 'http://localhost:4200/redirect/'
        if self.REDIRECT_STATE and state:
            uri = url_add_parameters(uri, {'redirect_state': state})
        return uri