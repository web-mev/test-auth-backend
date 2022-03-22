from django.urls import path
from rest_framework_simplejwt.views import (
    TokenObtainPairView,
    TokenRefreshView,
)
from . import views

urlpatterns = [
    path('token/', TokenObtainPairView.as_view(), name='token_obtain_pair'),
    path('token/refresh/', TokenRefreshView.as_view(), name='token_refresh'),
    path('auth-page/', views.AuthLinkView.as_view(), name='get-auth-page'),
    path('get-remote-token/', views.RemoteAuthTokenView.as_view(), name='get-token'),
    path('info/', views.InfoView.as_view(), name='info-page'),
    path('protected/', views.ProtectedView.as_view(), name='secret-page'),
]

