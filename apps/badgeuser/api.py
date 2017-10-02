import re

from allauth.account.adapter import get_adapter
from allauth.account.models import EmailConfirmation, EmailConfirmationHMAC
from allauth.account.utils import user_pk_to_url_str, url_str_to_user_pk
from django.contrib.auth import get_user_model
from django.contrib.auth.tokens import default_token_generator
from django.contrib.sites.shortcuts import get_current_site
from django.core.exceptions import ValidationError as DjangoValidationError
from django.core.urlresolvers import reverse
from django.http import Http404
from oauth2_provider.models import AccessToken
from rest_framework import permissions, serializers
from rest_framework.exceptions import ValidationError as RestframeworkValidationError
from rest_framework.response import Response
from rest_framework.serializers import BaseSerializer
from rest_framework.status import HTTP_302_FOUND, HTTP_200_OK, HTTP_404_NOT_FOUND, HTTP_201_CREATED

from badgeuser.models import BadgeUser, CachedEmailAddress
from badgeuser.permissions import BadgeUserIsAuthenticatedUser
from badgeuser.serializers_v1 import BadgeUserProfileSerializerV1, BadgeUserTokenSerializerV1
from badgeuser.serializers_v2 import BadgeUserTokenSerializerV2, BadgeUserSerializerV2, AccessTokenSerializerV2
from badgeuser.tasks import process_email_verification
from badgrsocialauth.utils import set_url_query_params
from entity.api import BaseEntityDetailView, BaseEntityListView
from entity.serializers import BaseSerializerV2
from mainsite.decorators import apispec_get_operation, apispec_put_operation, apispec_operation
from mainsite.models import BadgrApp
from mainsite.utils import OriginSetting


class BadgeUserDetail(BaseEntityDetailView):
    model = BadgeUser
    v1_serializer_class = BadgeUserProfileSerializerV1
    v2_serializer_class = BadgeUserSerializerV2
    permission_classes = (permissions.AllowAny,)

    def post(self, request, **kwargs):
        """
        Signup for a new account
        """
        if request.version == 'v1':
            serializer_cls = self.get_serializer_class()
            serializer = serializer_cls(
                data=request.data, context={'request': request}
            )
            serializer.is_valid(raise_exception=True)
            try:
                new_user = serializer.save()
            except DjangoValidationError as e:
                raise RestframeworkValidationError(e.message)
            return Response(serializer.data, status=HTTP_201_CREATED)

        return Response(status=HTTP_404_NOT_FOUND)

    @apispec_get_operation('BadgeUser',
        summary="Get a single BadgeUser profile",
        description="Use the entityId 'self' to retrieve the authenticated user's profile",
        tags=['BadgeUsers']
    )
    def get(self, request, **kwargs):
        return super(BadgeUserDetail, self).get(request, **kwargs)

    @apispec_put_operation('BadgeUser',
        summary="Update a BadgeUser",
        description="Use the entityId 'self' to update the authenticated user's profile",
        tags=['BadgeUsers']
    )
    def put(self, request, **kwargs):
        return super(BadgeUserDetail, self).put(request, allow_partial=True, **kwargs)

    def get_object(self, request, **kwargs):
        version = getattr(request, 'version', 'v1')
        if version == 'v2':
            entity_id = kwargs.get('entity_id')
            if entity_id == 'self':
                self.object = request.user
                return self.object
            try:
                self.object = BadgeUser.cached.get(entity_id=entity_id)
            except BadgeUser.DoesNotExist:
                pass
            else:
                return self.object
        elif version == 'v1':
            if request.user.is_authenticated():
                self.object = request.user
                return self.object
        raise Http404

    def has_object_permissions(self, request, obj):
        method = request.method.lower()
        if method == 'post':
            return True

        if isinstance(obj, BadgeUser):

            if method == 'get':
                if request.user.id == obj.id:
                    # always have access to your own user
                    return True
                if obj in request.user.peers:
                    # you can see some info about users you know about
                    return True

            if method == 'put':
                # only current user can update their own profile
                return request.user.id == obj.id
        return False

    def get_context_data(self, **kwargs):
        context = super(BadgeUserDetail, self).get_context_data(**kwargs)
        context['isSelf'] = (self.object.id == self.request.user.id)
        return context


class BadgeUserToken(BaseEntityDetailView):
    model = BadgeUser
    permission_classes = (BadgeUserIsAuthenticatedUser,)
    v1_serializer_class = BadgeUserTokenSerializerV1
    v2_serializer_class = BadgeUserTokenSerializerV2

    def get_object(self, request, **kwargs):
        return request.user

    @apispec_get_operation('BadgeUserToken',
        summary="Get the authenticated user's auth token",
        description="A new auth token will be created if none already exist for this user",
        tags=['Authentication'],
    )
    def get(self, request, **kwargs):
        return super(BadgeUserToken, self).get(request, **kwargs)

    @apispec_operation(
        summary="Invalidate the old token and create a new one",
        tags=['Authentication'],
    )
    def put(self, request, **kwargs):
        request.user.replace_token()  # generate new token first
        self.token_replaced = True
        return super(BadgeUserToken, self).put(request, **kwargs)

    def get_context_data(self, **kwargs):
        context = super(BadgeUserToken, self).get_context_data(**kwargs)
        context['tokenReplaced'] = getattr(self, 'token_replaced', False)
        return context


class BaseUserRecoveryView(BaseEntityDetailView):
    def _get_user(self, uidb36):
        User = get_user_model()
        try:
            pk = url_str_to_user_pk(uidb36)
            return User.objects.get(pk=pk)
        except (ValueError, User.DoesNotExist):
            return None

    def get_response(self, obj={}, status=HTTP_200_OK):
        context = self.get_context_data()
        serializer_class = self.get_serializer_class()
        serializer = serializer_class(obj, context=context)
        return Response(serializer.data, status=status)


class BadgeUserForgotPassword(BaseUserRecoveryView):
    authentication_classes = ()
    permission_classes = (permissions.AllowAny,)
    v1_serializer_class = serializers.Serializer
    v2_serializer_class = BaseSerializerV2

    def get(self, request, *args, **kwargs):
        badgr_app = BadgrApp.objects.get_current(request)
        redirect_url = badgr_app.forgot_password_redirect
        token = request.GET.get('token', '')
        tokenized_url = "{}{}".format(redirect_url, token)
        return Response(status=HTTP_302_FOUND, headers={'Location': tokenized_url})

    @apispec_operation(
        summary="Request an account recovery email",
        tags=["Authentication"],
        parameters=[
            {
                "in": "body",
                "name": "body",
                "required": True,
                "schema": {
                    "type": "object",
                    "properties": {
                        "email": {
                            "type": "string",
                            "format": "email",
                            "description": "The email address on file to send recovery email to"
                        }
                    }
                },
            }
        ]
    )
    def post(self, request, **kwargs):
        email = request.data.get('email')
        try:
            email_address = CachedEmailAddress.cached.get(email=email)
        except CachedEmailAddress.DoesNotExist:
            # return 200 here because we don't want to expose information about which emails we know about
            return self.get_response()

        #
        # taken from allauth.account.forms.ResetPasswordForm
        #

        # fetch user from database directly to avoid cache
        UserCls = get_user_model()
        try:
            user = UserCls.objects.get(pk=email_address.user_id)
        except UserCls.DoesNotExist:
            return self.get_response()

        temp_key = default_token_generator.make_token(user)
        token = "{uidb36}-{key}".format(uidb36=user_pk_to_url_str(user),
                                        key=temp_key)

        api_path = reverse('{version}_api_auth_forgot_password'.format(version=request.version))
        reset_url = "{origin}{path}?token={token}".format(
            origin=OriginSetting.HTTP,
            path=api_path,
            token=token)

        email_context = {
            "site": get_current_site(request),
            "user": user,
            "password_reset_url": reset_url,
        }
        get_adapter().send_mail('account/email/password_reset_key', email, email_context)

        return self.get_response()

    @apispec_operation(
        summary="Recover an account and set a new password",
        tags=["Authentication"],
        parameters=[
            {
                "in": "body",
                "name": "body",
                "required": True,
                "schema": {
                    "type": "object",
                    "properties": {
                        "token": {
                            "type": "string",
                            "format": "string",
                            "description": "The token recieved in the recovery email",
                            'required': True
                        },
                        "password": {
                            'type': "string",
                            'description': "The new password to use",
                            'required': True
                        }
                    }
                },
            }
        ]
    )
    def put(self, request, **kwargs):
        token = request.data.get('token')
        password = request.data.get('password')

        matches = re.search(r'([0-9A-Za-z]+)-(.*)', token)
        if not matches:
            return Response(status=HTTP_404_NOT_FOUND)
        uidb36 = matches.group(1)
        key = matches.group(2)
        if not (uidb36 and key):
            return Response(status=HTTP_404_NOT_FOUND)

        user = self._get_user(uidb36)
        if user is None:
            return Response(status=HTTP_404_NOT_FOUND)

        if not default_token_generator.check_token(user, key):
            return Response(status=HTTP_404_NOT_FOUND)

        user.set_password(password)
        user.save()
        return self.get_response()


class BadgeUserEmailConfirm(BaseUserRecoveryView):
    permission_classes = (permissions.AllowAny,)
    v1_serializer_class = BaseSerializer
    v2_serializer_class = BaseSerializerV2

    def get(self, request, **kwargs):
        """
        Confirm an email address with a token provided in an email
        ---
        parameters:
            - name: token
              type: string
              paramType: form
              description: The token received in the recovery email
              required: true
        """

        token = request.query_params.get('token')

        emailconfirmation = EmailConfirmationHMAC.from_key(kwargs.get('confirm_id'))
        if emailconfirmation is None:
            return Response(status=HTTP_404_NOT_FOUND)

        try:
            email_address = CachedEmailAddress.cached.get(pk=emailconfirmation.email_address.pk)
        except CachedEmailAddress.DoesNotExist:
            return Response(status=HTTP_404_NOT_FOUND)

        matches = re.search(r'([0-9A-Za-z]+)-(.*)', token)
        if not matches:
            return Response(status=HTTP_404_NOT_FOUND)
        uidb36 = matches.group(1)
        key = matches.group(2)
        if not (uidb36 and key):
            return Response(status=HTTP_404_NOT_FOUND)

        user = self._get_user(uidb36)
        if user is None or not default_token_generator.check_token(user, key):
            return Response(status=HTTP_404_NOT_FOUND)

        if email_address.user != user:
            return Response(status=HTTP_404_NOT_FOUND)

        old_primary = CachedEmailAddress.objects.get_primary(user)
        if old_primary is None:
            email_address.primary = True
        email_address.verified = True
        email_address.save()

        process_email_verification.delay(email_address.pk)

        # get badgr_app url redirect
        redirect_url = get_adapter().get_email_confirmation_redirect_url(request)

        redirect_url = set_url_query_params(redirect_url, authToken=user.auth_token)

        return Response(status=HTTP_302_FOUND, headers={'Location': redirect_url})


class AccessTokenList(BaseEntityListView):
    model = AccessToken
    v2_serializer_class = AccessTokenSerializerV2
    valid_scopes = []
    permission_classes = (permissions.IsAuthenticated,)

    def get_objects(self, request, **kwargs):
        return request.user.oauth2_provider_accesstoken.all()

    @apispec_operation(
        summary='Get a list of access tokens for authenticated user',
        tags=['Authentication']
    )
    def get(self, request, **kwargs):
        return super(AccessTokenList, self).get(request, **kwargs)
