from django.urls import path
from rest_framework_simplejwt.views import (
    TokenObtainPairView,
    TokenRefreshView,
)
from . import views

urlpatterns = [
    path('google-signin/', views.GoogleOauth2View.as_view(), name='google-social'),
    path('token/', TokenObtainPairView.as_view(), name='token_obtain_pair'),
    path('token/refresh/', TokenRefreshView.as_view(), name='token_refresh'),
    path('info/', views.InfoView.as_view(), name='info-page'),
    path('protected/', views.ProtectedView.as_view(), name='secret-page'),
    path('xyz/', views.basic, name='basic-google')
]

