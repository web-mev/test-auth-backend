from django.urls import path, include
from rest_framework_simplejwt.views import (
    TokenObtainPairView,
    TokenRefreshView,
)
from . import views

urlpatterns = [

    # For username/pass token generation and refresh
    path('token/', TokenObtainPairView.as_view(), name='token_obtain_pair'),
    path('token/refresh/', TokenRefreshView.as_view(), name='token_refresh'),

    # Returns info about a user. Protected view.
    path('info/', views.InfoView.as_view(), name='info-page'),

    # This returns a url for the auth redirect
    path('auth/<str:backend>/', views.construct_auth_url),

    # This takes a response code and returns a JWT pair
    path('login/', include('rest_social_auth.urls_jwt_pair')),

    # For globus 
    path('globus/initiate/', views.GlobusView.as_view()),
    path('globus/transfer/', views.GlobusTransfer.as_view())

]

