import urllib
import urlparse

from allauth.socialaccount.providers.base import AuthProcess
from allauth.account.adapter import get_adapter
from allauth.socialaccount.models import SocialLogin
from allauth.account.utils import perform_login
from allauth.socialaccount import app_settings
from django.contrib.auth import logout
from django.core.exceptions import ValidationError
from django.core.urlresolvers import reverse, NoReverseMatch
from django.http import HttpResponseBadRequest, HttpResponseForbidden
from django.views.generic import RedirectView, View
from rest_framework.exceptions import AuthenticationFailed

from badgrsocialauth.utils import set_url_query_params, set_session_badgr_app, get_session_badgr_app, \
    get_session_verification_email, set_session_authcode
from mainsite.models import BadgrApp
from badgeuser.models import BadgeUser
from badgrsocialauth.permissions import UserIsSuperUserPermissionMixin


class BadgrSocialLogin(RedirectView):
    def get(self, request, *args, **kwargs):
        try:
            logout(request)
            return super(BadgrSocialLogin, self).get(request, *args, **kwargs)
        except ValidationError as e:
            return HttpResponseBadRequest(e.message)
        except AuthenticationFailed as e:
            return HttpResponseForbidden(e.detail)

    def get_redirect_url(self):
        provider_name = self.request.GET.get('provider', None)
        if provider_name is None:
            raise ValidationError('No provider specified')

        badgr_app = BadgrApp.objects.get_current(request=self.request)
        if badgr_app is not None:
            set_session_badgr_app(self.request, badgr_app)
        else:
            raise ValidationError('Unable to save BadgrApp in session')

        try:
            redirect_url = reverse('{}_login'.format(self.request.GET.get('provider')))
        except NoReverseMatch:
            raise ValidationError('No {} provider found'.format(provider_name))

        authcode = self.request.GET.get('authCode', None)
        if authcode is not None:
            set_session_authcode(self.request, authcode)
            return set_url_query_params(redirect_url, process=AuthProcess.CONNECT)
        else:
            return redirect_url


class BadgrSocialLoginCancel(RedirectView):
    def get_redirect_url(self):
        badgr_app = get_session_badgr_app(self.request)
        if badgr_app is not None:
            return set_url_query_params(badgr_app.ui_login_redirect)


class BadgrSocialEmailExists(RedirectView):
    def get_redirect_url(self):
        badgr_app = get_session_badgr_app(self.request)
        if badgr_app is not None:
            return set_url_query_params(badgr_app.ui_login_redirect,
                                        authError='An account already exists with provided email address')


class BadgrSocialAccountVerifyEmail(RedirectView):
    def get_redirect_url(self):
        badgr_app = get_session_badgr_app(self.request)
        verification_email = get_session_verification_email(self.request)

        if verification_email is not None:
            verification_email = urllib.quote(verification_email.encode('utf-8'))
        else:
            verification_email = ''

        if badgr_app is not None:
            return urlparse.urljoin(badgr_app.ui_signup_success_redirect.rstrip('/') + '/', verification_email)


class BadgrAccountConnected(RedirectView):
    def get_redirect_url(self):
        badgr_app = get_session_badgr_app(self.request)
        if badgr_app is not None:
            return set_url_query_params(badgr_app.ui_connect_success_redirect)


class ImpersonateUser(UserIsSuperUserPermissionMixin, View):

    def get(self, *args, **kwargs):
        user = BadgeUser.objects.get(pk=kwargs['id'])
        social_account = user.get_social_account()
        get_adapter(self.request).logout(self.request)
        sociallogin = SocialLogin(account=social_account, email_addresses=[email for email in user.email_items])
        sociallogin.user = user
        badgr_app = BadgrApp.objects.filter(pk=user.badgrapp_id).first()
        if not badgr_app:
            badgr_app = BadgrApp.objects.all().first()
        set_session_badgr_app(self.request, badgr_app)
        ret = perform_login(self.request, sociallogin.user,
                      email_verification=app_settings.EMAIL_VERIFICATION,
                      redirect_url=sociallogin.get_redirect_url(self.request),
                      signal_kwargs={"sociallogin": sociallogin})
        return ret