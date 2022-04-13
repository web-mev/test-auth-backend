"""
Django settings for auth_demo project.

Generated by 'django-admin startproject' using Django 4.0.3.

For more information on this file, see
https://docs.djangoproject.com/en/4.0/topics/settings/

For the full list of settings and their values, see
https://docs.djangoproject.com/en/4.0/ref/settings/
"""

from pathlib import Path
import os
from dotenv import load_dotenv
from datetime import timedelta

load_dotenv()

# Build paths inside the project like this: BASE_DIR / 'subdir'.
BASE_DIR = Path(__file__).resolve().parent.parent


# Quick-start development settings - unsuitable for production
# See https://docs.djangoproject.com/en/4.0/howto/deployment/checklist/

# SECURITY WARNING: keep the secret key used in production secret!
SECRET_KEY = 'django-insecure-0=&7e-ct#)n$ut)b)3m)%aq3t#(ft(t3pti^u44v*8j08$w^-%'

# SECURITY WARNING: don't run with debug turned on in production!
DEBUG = True

ALLOWED_HOSTS = []

FRONTEND_DOMAIN = 'http://localhost:4200'

CORS_ALLOWED_ORIGINS = [
    FRONTEND_DOMAIN
]
# Application definition

INSTALLED_APPS = [
    'django.contrib.admin',
    'django.contrib.auth',
    'django.contrib.contenttypes',
    'django.contrib.sessions',
    'django.contrib.messages',
    'django.contrib.staticfiles',
    'rest_framework',
    'corsheaders',
    'social_django',
    'rest_social_auth',
    'demo'
]

MIDDLEWARE = [
    'corsheaders.middleware.CorsMiddleware',
    'django.middleware.security.SecurityMiddleware',
    'django.contrib.sessions.middleware.SessionMiddleware',
    'django.middleware.common.CommonMiddleware',
    'django.middleware.csrf.CsrfViewMiddleware',
    'django.contrib.auth.middleware.AuthenticationMiddleware',
    'django.contrib.messages.middleware.MessageMiddleware',
    'django.middleware.clickjacking.XFrameOptionsMiddleware',
]

ROOT_URLCONF = 'auth_demo.urls'

TEMPLATES = [
    {
        'BACKEND': 'django.template.backends.django.DjangoTemplates',
        'DIRS': [],
        'APP_DIRS': True,
        'OPTIONS': {
            'context_processors': [
                'django.template.context_processors.debug',
                'django.template.context_processors.request',
                'django.contrib.auth.context_processors.auth',
                'django.contrib.messages.context_processors.messages',
            ],
        },
    },
]

# A custom user model which treats the email as the username
AUTH_USER_MODEL = 'demo.CustomUser'

# for the simple JWT framework. We use a UUID to identify a user
# (instead of an integer pk)
SIMPLE_JWT = {
    'USER_ID_FIELD': 'user_uuid',
    'ACCESS_TOKEN_LIFETIME': timedelta(minutes=30)
}

WSGI_APPLICATION = 'auth_demo.wsgi.application'


AUTHENTICATION_BACKENDS = (
    'social_core.backends.google.GoogleOAuth2',
    'django.contrib.auth.backends.ModelBackend',
)

# Database
# https://docs.djangoproject.com/en/4.0/ref/settings/#databases

DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.sqlite3',
        'NAME': BASE_DIR / 'db.sqlite3',
    }
}


# Password validation
# https://docs.djangoproject.com/en/4.0/ref/settings/#auth-password-validators

AUTH_PASSWORD_VALIDATORS = [
    {
        'NAME': 'django.contrib.auth.password_validation.UserAttributeSimilarityValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.MinimumLengthValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.CommonPasswordValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.NumericPasswordValidator',
    },
]


# Internationalization
# https://docs.djangoproject.com/en/4.0/topics/i18n/

LANGUAGE_CODE = 'en-us'

TIME_ZONE = 'UTC'

USE_I18N = True

USE_TZ = True


# Static files (CSS, JavaScript, Images)
# https://docs.djangoproject.com/en/4.0/howto/static-files/

STATIC_URL = 'static/'
STATIC_ROOT = os.path.join(BASE_DIR, 'static')

# Default primary key field type
# https://docs.djangoproject.com/en/4.0/ref/settings/#default-auto-field

DEFAULT_AUTO_FIELD = 'django.db.models.BigAutoField'

REST_FRAMEWORK = {
    'DEFAULT_AUTHENTICATION_CLASSES': (
        'rest_framework_simplejwt.authentication.JWTAuthentication',
    )
}

SOCIAL_AUTH_GOOGLE_OAUTH2_PIPELINE = (
    'social_core.pipeline.social_auth.social_details', 
    'social_core.pipeline.social_auth.social_uid', 
    'social_core.pipeline.social_auth.auth_allowed', 
    'social_core.pipeline.social_auth.social_user', 
    'social_core.pipeline.user.get_username', 
    'social_core.pipeline.user.create_user', 
    'social_core.pipeline.social_auth.associate_user', 
    'social_core.pipeline.social_auth.load_extra_data', 
    'social_core.pipeline.user.user_details',
    'demo.pipeline_components.save_picture'
)

SOCIAL_AUTH_STRATEGY = 'demo.strategy.XYZStrategy'

# sets the proper redirect URL (e.g. localhost:4200/redirect/)
# which is the frontend client
REST_SOCIAL_OAUTH_REDIRECT_URI = '/redirect/'

# This is the default, but we are being explicit here that the redirect
# URL should correspond to the frontend.
REST_SOCIAL_DOMAIN_FROM_ORIGIN = True

SOCIAL_AUTH_GOOGLE_OAUTH2_KEY = os.environ['GOOGLE_CLIENT_ID']
SOCIAL_AUTH_GOOGLE_OAUTH2_SECRET = os.environ['GOOGLE_CLIENT_SECRET']

GLOBUS_AUTH_REDIRECT_URI = 'http://localhost:4200/globus/auth-redirect/'
GLOBUS_TRANSFER_REDIRECT_URI = 'http://localhost:4200/globus/transfer-redirect/'
GLOBUS_TRANSFER_CALLBACK_METHOD = 'GET'
GLOBUS_BROWSER_URI = 'https://app.globus.org/file-manager?action={URI}&method={callback_method}'.format(
    URI=GLOBUS_TRANSFER_REDIRECT_URI,
    callback_method = GLOBUS_TRANSFER_CALLBACK_METHOD    
)
GLOBUS_CLIENT_ID = os.environ['GLOBUS_CLIENT_ID']
GLOBUS_CLIENT_SECRET = os.environ['GLOBUS_CLIENT_SECRET']
GLOBUS_TRANSFER_SCOPE = 'urn:globus:auth:scope:transfer.api.globus.org:all'
GLOBUS_SCOPES = (
    "openid",
    "profile",
    "email",
    GLOBUS_TRANSFER_SCOPE,
)
GLOBUS_ENDPOINT_ID=os.environ['GLOBUS_ENDPOINT_ID']