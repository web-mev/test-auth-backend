import uuid
from django.db import models
from django.contrib.auth.base_user import AbstractBaseUser, BaseUserManager
from django.contrib.auth.models import PermissionsMixin
from django.utils.translation import gettext_lazy as _
from django.utils import timezone
from django.contrib.auth import get_user_model

'''
The CustomUser model below and its manager are essentially copies of the basic django.contrib.auth
implementation of User.  However, we modify to allow the email to serve as the username.
'''

class CustomUserManager(BaseUserManager):

    use_in_migrations = True

    def create_user(self, email, password=None, **extra_fields):
        """
        Create and save a user with the given email, and password.
        """
        if not email:
            raise ValueError('Email must be set')
        email = self.normalize_email(email)
        user = self.model(email=email, **extra_fields)
        user.set_password(password)
        user.save(using=self._db)
        return user

    def create_superuser(self, email, password, **extra_fields):
        extra_fields.setdefault('is_staff', True)
        extra_fields.setdefault('is_superuser', True)

        if extra_fields.get('is_staff') is not True:
            raise ValueError('Superuser must have is_staff=True.')
        if extra_fields.get('is_superuser') is not True:
            raise ValueError('Superuser must have is_superuser=True.')

        return self.create_user(email, password=password, **extra_fields)


class CustomUser(AbstractBaseUser, PermissionsMixin):
    """
    Custom model implementing the email as the username
    """
    email = models.EmailField(_('email address'), unique=True, null=False, max_length=100)
    user_uuid = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    is_staff = models.BooleanField(
        _('staff status'),
        default=False,
        help_text=_('Designates whether the user can log into this admin site.'),
    )
    is_active = models.BooleanField(
        _('active'),
        default=True,
        help_text=_(
            'Designates whether this user should be treated as active. '
            'Unselect this instead of deleting accounts.'
        ),
    )
    date_joined = models.DateTimeField(_('date joined'), default=timezone.now)
    profile_pic_url = models.URLField(null=True) 

    objects = CustomUserManager()

    USERNAME_FIELD = 'email'

    class Meta:
        verbose_name = _('user')
        verbose_name_plural = _('users')

    def clean(self):
        super().clean()
        self.email = self.__class__.objects.normalize_email(self.email)

    def get_full_name(self):
        """
        The original method is intended to return someone's first and last name.
        To preserve functionality, we keep the method and simply return the email.
        If a profile (or similar) is implemented, we could potentially have first/last
        names associated with an account

        Original docstring was:
        Return the first_name plus the last_name, with a space in between.

        """
        return self.email

    def get_short_name(self):
        """Return the short name for the user."""
        return self.email

    def email_user(self, subject, message, from_email=None, **kwargs):
        """Send an email to this user."""
        pass

class GlobusTokens(models.Model):
    user = models.ForeignKey(
        get_user_model(),
        related_name = 'globus_tokens',
        on_delete = models.CASCADE
    )
    # since sqLite doesn't support JSON, just store as a string
    token_text = models.CharField(max_length=2500)

class Resource(models.Model):
    owner = models.ForeignKey(
        get_user_model(),
        related_name = 'resources',
        on_delete = models.CASCADE
    )
    path = models.CharField(max_length=100)
    name = models.CharField(max_length=25)