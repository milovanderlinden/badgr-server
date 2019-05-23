from rest_framework import permissions
from django.contrib.auth.mixins import PermissionRequiredMixin


class IsSocialAccountOwner(permissions.BasePermission):
    """
    Only grant access to owner of SocialAccount.
    """

    def has_object_permission(self, request, view, obj):
        return obj.user == request.user


class UserIsSuperUserPermissionMixin(PermissionRequiredMixin):

    def has_permission(self):
        return self.request.user.is_superuser
