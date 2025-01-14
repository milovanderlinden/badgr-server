from __future__ import unicode_literals

import StringIO
import datetime
import re
import uuid
import logging
from collections import OrderedDict
from email.mime.base import MIMEBase
from email import encoders

import cachemodel
import os
from allauth.account.adapter import get_adapter
from django.apps import apps
from django.conf import settings
from django.contrib.auth import get_user_model
from django.core.exceptions import ValidationError
from django.core.files.base import ContentFile
from django.core.files.storage import default_storage
from django.core.urlresolvers import reverse
from django.db import models, transaction
from django.db.models import ProtectedError
from json import loads as json_loads
from json import dumps as json_dumps
from jsonfield import JSONField
from openbadges_bakery import bake
from django.utils import timezone
from rest_framework import serializers

from entity.models import BaseVersionedEntity
from issuer.managers import BadgeInstanceManager, IssuerManager, BadgeClassManager, BadgeInstanceEvidenceManager
from mainsite.managers import SlugOrJsonIdCacheModelManager
from mainsite.mixins import ResizeUploadedImage, ScrubUploadedSvgImage
from mainsite.models import (BadgrApp, EmailBlacklist)
from mainsite.utils import OriginSetting, generate_entity_uri
from signing.models import PublicKey, SymmetricKey
from signing import tsob
from .utils import generate_sha256_hashstring, CURRENT_OBI_VERSION, get_obi_context, add_obi_version_ifneeded, \
    UNVERSIONED_BAKED_VERSION


AUTH_USER_MODEL = getattr(settings, 'AUTH_USER_MODEL', 'auth.User')
logger = logging.getLogger('Badgr.Debug')


class BaseAuditedModel(cachemodel.CacheModel):
    created_at = models.DateTimeField(auto_now_add=True)
    created_by = models.ForeignKey('badgeuser.BadgeUser', blank=True, null=True, related_name="+")
    updated_at = models.DateTimeField(auto_now=True)
    updated_by = models.ForeignKey('badgeuser.BadgeUser', blank=True, null=True, related_name="+")

    class Meta:
        abstract = True

    @property
    def cached_creator(self):
        from badgeuser.models import BadgeUser
        return BadgeUser.cached.get(id=self.created_by_id)


class OriginalJsonMixin(models.Model):
    original_json = models.TextField(blank=True, null=True, default=None)

    class Meta:
        abstract = True

    def get_original_json(self):
        if self.original_json:
            try:
                return json_loads(self.original_json)
            except (TypeError, ValueError) as e:
                pass

    def get_filtered_json(self, excluded_fields=()):
        original = self.get_original_json()
        if original is not None:
            return {key: original[key] for key in filter(lambda k: k not in excluded_fields, original.keys())}


class BaseOpenBadgeObjectModel(OriginalJsonMixin, cachemodel.CacheModel):
    source = models.CharField(max_length=254, default='local')
    source_url = models.CharField(max_length=254, blank=True, null=True, default=None)

    class Meta:
        abstract = True

    def get_extensions_manager(self):
        raise NotImplementedError()

    @cachemodel.cached_method(auto_publish=True)
    def cached_extensions(self):
        return self.get_extensions_manager().all()

    @property
    def extension_items(self):
        return {e.name: json_loads(e.original_json) for e in self.cached_extensions()}

    @extension_items.setter
    def extension_items(self, value):
        if value is None:
            value = {}
        touched_idx = []

        with transaction.atomic():
            if not self.pk and value:
                self.save()

            # add new
            for ext_name, ext in value.items():
                ext_json = json_dumps(ext)
                ext, ext_created = self.get_extensions_manager().get_or_create(name=ext_name, defaults=dict(
                    original_json=ext_json
                ))
                if not ext_created:
                    ext.original_json = ext_json
                    ext.save()
                touched_idx.append(ext.pk)

            # remove old
            for extension in self.cached_extensions():
                if extension.pk not in touched_idx:
                    extension.delete()


class BaseOpenBadgeExtension(cachemodel.CacheModel):
    name = models.CharField(max_length=254)
    original_json = models.TextField(blank=True, null=True, default=None)

    def __unicode__(self):
        return self.name

    class Meta:
        abstract = True



class Issuer(ResizeUploadedImage,
             ScrubUploadedSvgImage,
             BaseAuditedModel,
             BaseVersionedEntity,
             BaseOpenBadgeObjectModel):
    entity_class_name = 'Issuer'


    staff = models.ManyToManyField(AUTH_USER_MODEL, through='IssuerStaff')

    # slug has been deprecated for now, but preserve existing values
    slug = models.CharField(max_length=255, blank=True, null=True, default=None)
    #slug = AutoSlugField(max_length=255, populate_from='name', unique=True, blank=False, editable=True)

    badgrapp = models.ForeignKey('mainsite.BadgrApp', blank=True, null=True, default=None)

    name = models.CharField(max_length=1024)
    image = models.FileField(upload_to='uploads/issuers', blank=True, null=True)
    description = models.TextField(blank=True, null=True, default=None)
    url = models.CharField(max_length=254, blank=True, null=True, default=None)
    email = models.CharField(max_length=254, blank=True, null=True, default=None)
    old_json = JSONField()

    objects = IssuerManager()
    cached = SlugOrJsonIdCacheModelManager(slug_kwarg_name='entity_id', slug_field_name='entity_id')
    faculty = models.ForeignKey('institution.Faculty', blank=True, null=True, default=None)

    def publish(self, *args, **kwargs):
        super(Issuer, self).publish(*args, **kwargs)
        for member in self.cached_issuerstaff():
            member.cached_user.publish()

    def delete(self, *args, **kwargs):
        if self.recipient_count > 0:
            raise ProtectedError("Issuer can not be deleted because it has previously issued badges.", self)

        # remove any unused badgeclasses owned by issuer
        for bc in self.cached_badgeclasses():
            bc.delete()

        staff = self.cached_issuerstaff()
        ret = super(Issuer, self).delete(*args, **kwargs)

        # remove membership records
        for membership in staff:
            membership.delete(publish_issuer=False)

        if apps.is_installed('badgebook'):
            # badgebook shim
            try:
                from badgebook.models import LmsCourseInfo
                # update LmsCourseInfo's that were using this issuer as the default_issuer
                for course_info in LmsCourseInfo.objects.filter(default_issuer=self):
                    course_info.default_issuer = None
                    course_info.save()
            except ImportError:
                pass

        return ret

    def save(self, *args, **kwargs):
        ret = super(Issuer, self).save(*args, **kwargs)

        # if no owner staff records exist, create one for created_by
        if len(self.owners) < 1 and self.created_by_id:
            IssuerStaff.objects.create(issuer=self, user=self.created_by, role=IssuerStaff.ROLE_OWNER)

        return ret

    def get_absolute_url(self):
        return reverse('issuer_json', kwargs={'entity_id': self.entity_id})

    def get_url_with_public_key(self, public_key):
        if public_key.issuer != self:
            raise ValueError('Public key does not belong to this Issuer.')
        return self.jsonld_id + '/pubkey/{}'.format(public_key.entity_id)

    @property
    def institution(self):
        if self.faculty:
            return self.faculty.institution
        return None

    @property
    def public_url(self):
        return OriginSetting.HTTP+self.get_absolute_url()

    @property
    def jsonld_id(self):
        if self.source_url:
            return self.source_url
        return OriginSetting.HTTP + self.get_absolute_url()

    @property
    def editors(self):
        return self.staff.filter(issuerstaff__role__in=(IssuerStaff.ROLE_EDITOR, IssuerStaff.ROLE_OWNER))

    @property
    def owners(self):
        return self.staff.filter(issuerstaff__role=IssuerStaff.ROLE_OWNER)

    @cachemodel.cached_method(auto_publish=True)
    def cached_issuerstaff(self):
        return IssuerStaff.objects.filter(issuer=self)

    @property
    def current_signers(self):
        return [staff for staff in self.staff_items if staff.is_signer]

    @property
    def staff_items(self):
        return self.cached_issuerstaff()

    @staff_items.setter
    def staff_items(self, value):
        """
        Update this issuers IssuerStaff from a list of IssuerStaffSerializerV2 data
        """
        existing_staff_idx = {s.cached_user: s for s in self.staff_items}
        new_staff_idx = {s['cached_user']: s for s in value}

        with transaction.atomic():
            # add missing staff records
            for staff_data in value:
                if staff_data['cached_user'] not in existing_staff_idx:
                    staff_record, created = IssuerStaff.cached.get_or_create(
                        issuer=self,
                        user=staff_data['cached_user'],
                        defaults={
                            'role': staff_data['role']
                        })
                    if not created:
                        staff_record.role = staff_data['role']
                        staff_record.save()

            # remove old staff records -- but never remove the only OWNER role
            for staff_record in self.staff_items:
                if staff_record.cached_user not in new_staff_idx:
                    if staff_record.role != IssuerStaff.ROLE_OWNER or len(self.owners) > 1:
                        staff_record.delete()

    def get_extensions_manager(self):
        return self.issuerextension_set

    @cachemodel.cached_method(auto_publish=True)
    def cached_editors(self):
        UserModel = get_user_model()
        return UserModel.objects.filter(issuerstaff__issuer=self, issuerstaff__role=IssuerStaff.ROLE_EDITOR)

    @cachemodel.cached_method(auto_publish=True)
    def cached_badgeclasses(self):
        return self.badgeclasses.all()


    @cachemodel.cached_method(auto_publish=True)
    def cached_pathways(self):
        return self.pathway_set.filter(is_active=True)

    @cachemodel.cached_method(auto_publish=True)
    def cached_recipient_groups(self):
        return self.recipientgroup_set.all()

    @property
    def recipient_count(self):
        return sum(bc.recipient_count() for bc in self.cached_badgeclasses())

    @property
    def image_preview(self):
        return self.image

    def create_private_key(self, password, symmetric_key):
        symmetric_key.validate_password(password)
        return tsob.create_new_private_key(password, symmetric_key, self)

    def get_json(self, obi_version=CURRENT_OBI_VERSION, include_extra=True, use_canonical_id=False, signed=False,
                 public_key=None, expand_public_key=False):
        if signed and not public_key:
            raise ValueError('Cannot return signed issuer json without knowing which public key is used.')
        if public_key:
            if public_key.issuer != self:
                raise ValueError('Public key does not belong ot this issuer.')
        obi_version, context_iri = get_obi_context(obi_version)

        json = OrderedDict({'@context': context_iri})
        json.update(OrderedDict(
            type='Issuer',
            name=self.name,
            url=self.url,
            email=self.email,
            description=self.description))
        if not signed:
            json['id'] = self.jsonld_id if use_canonical_id else add_obi_version_ifneeded(self.jsonld_id, obi_version)
        elif signed:
            json['id'] = self.get_url_with_public_key(public_key)

        if self.image:
            image_url = OriginSetting.HTTP + reverse('issuer_image', kwargs={'entity_id': self.entity_id})
            json['image'] = image_url
            if self.original_json:
                image_info = self.get_original_json().get('image', None)
                if isinstance(image_info, dict):
                    json['image'] = image_info
                    json['image']['id'] = image_url

        # source url
        if self.source_url:
            if obi_version == '1_1':
                json["source_url"] = self.source_url
                json["hosted_url"] = OriginSetting.HTTP + self.get_absolute_url()
            elif obi_version == '2_0':
                json["sourceUrl"] = self.source_url
                json["hostedUrl"] = OriginSetting.HTTP + self.get_absolute_url()

        # extensions
        if len(self.cached_extensions()) > 0:
            for extension in self.cached_extensions():
                json[extension.name] = json_loads(extension.original_json)

        # pass through imported json
        if include_extra:
            extra = self.get_filtered_json()
            if extra is not None:
                for k,v in extra.items():
                    if k not in json:
                        json[k] = v

        try:
            if signed:
                json['verification'] = {"type": "SignedBadge", "creator": public_key.public_url}
                if expand_public_key:
                    json['publicKey'] = public_key.get_json()
                else:
                    json['publicKey'] = public_key.public_url
        except PublicKey.DoesNotExist:
            pass
        return json

    @property
    def json(self):
        return self.get_json()

    def get_filtered_json(self, excluded_fields=('@context', 'id', 'type', 'name', 'url', 'description', 'image', 'email')):
        return super(Issuer, self).get_filtered_json(excluded_fields=excluded_fields)

    @property
    def cached_badgrapp(self):
        id = self.badgrapp_id if self.badgrapp_id else getattr(settings, 'BADGR_APP_ID', 1)
        return BadgrApp.cached.get(id=id)

    def __unicode__(self):
        return self.name


class IssuerStaff(cachemodel.CacheModel):
    ROLE_OWNER = 'owner'
    ROLE_EDITOR = 'editor'
    ROLE_STAFF = 'staff'
    ROLE_CHOICES = (
        (ROLE_OWNER, 'Owner'),
        (ROLE_EDITOR, 'Editor'),
        (ROLE_STAFF, 'Staff'),
    )
    issuer = models.ForeignKey(Issuer)
    user = models.ForeignKey(AUTH_USER_MODEL)
    role = models.CharField(max_length=254, choices=ROLE_CHOICES, default=ROLE_STAFF)
    is_signer = models.BooleanField(default=False)

    class Meta:
        unique_together = ('issuer', 'user')

    def publish(self):
        super(IssuerStaff, self).publish()
        self.issuer.publish()
        self.user.publish()

    def delete(self, *args, **kwargs):
        publish_issuer = kwargs.pop('publish_issuer', True)
        super(IssuerStaff, self).delete()
        if publish_issuer:
            self.issuer.publish()
        self.user.publish()

    @property
    def may_become_signer(self):
        return self.user.may_sign_assertions and SymmetricKey.objects.filter(user=self.user, current=True).exists()

    @property
    def cached_user(self):
        from badgeuser.models import BadgeUser
        return BadgeUser.cached.get(pk=self.user_id)

    @property
    def cached_issuer(self):
        return Issuer.cached.get(pk=self.issuer_id)


class BadgeClass(ResizeUploadedImage,
                 ScrubUploadedSvgImage,
                 BaseAuditedModel,
                 BaseVersionedEntity,
                 BaseOpenBadgeObjectModel):
    entity_class_name = 'BadgeClass'

    issuer = models.ForeignKey(Issuer, blank=False, null=False, on_delete=models.CASCADE, related_name="badgeclasses")

    # slug has been deprecated for now, but preserve existing values
    slug = models.CharField(max_length=255, blank=True, null=True, default=None)
    #slug = AutoSlugField(max_length=255, populate_from='name', unique=True, blank=False, editable=True)

    name = models.CharField(max_length=255)
    image = models.FileField(upload_to='uploads/badges', blank=True)
    description = models.TextField(blank=True, null=True, default=None)

    criteria_url = models.CharField(max_length=254, blank=True, null=True, default=None)
    criteria_text = models.TextField(blank=True, null=True)

    old_json = JSONField()

    objects = BadgeClassManager()
    cached = SlugOrJsonIdCacheModelManager(slug_kwarg_name='entity_id', slug_field_name='entity_id')

    class Meta:
        verbose_name_plural = "Badge classes"

    def publish(self):
        super(BadgeClass, self).publish()
        self.issuer.publish()

    def delete(self, *args, **kwargs):
        if self.recipient_count() > 0:
            raise ProtectedError("BadgeClass may only be deleted if all BadgeInstances have been revoked.", self)

        if self.pathway_element_count() > 0:
            raise ProtectedError("BadgeClass may only be deleted if all PathwayElementBadge have been removed.", self)

        if len(self.cached_completion_elements()) > 0:
            raise ProtectedError("Badge could not be deleted. It is being used as a pathway completion badge.", self)

        issuer = self.issuer
        super(BadgeClass, self).delete(*args, **kwargs)
        issuer.publish()

    def get_absolute_url(self):
        return reverse('badgeclass_json', kwargs={'entity_id': self.entity_id})

    def get_url_with_public_key(self, public_key):
        if public_key.issuer != self.issuer:
            raise ValueError('Public key does not belong to this Issuer.')
        return self.jsonld_id + '/pubkey/{}'.format(public_key.entity_id)

    @property
    def public_url(self):
        return OriginSetting.HTTP+self.get_absolute_url()

    @property
    def jsonld_id(self):
        if self.source_url:
            return self.source_url
        return OriginSetting.HTTP + self.get_absolute_url()

    @property
    def issuer_jsonld_id(self):
        return self.cached_issuer.jsonld_id

    def get_criteria_url(self):
        if self.criteria_url:
            return self.criteria_url
        return OriginSetting.HTTP+reverse('badgeclass_criteria', kwargs={'entity_id': self.entity_id})

    @property
    def description_nonnull(self):
        return self.description if self.description else ""

    @description_nonnull.setter
    def description_nonnull(self, value):
        self.description = value

    @property
    def owners(self):
        return self.cached_issuer.owners

    @property
    def cached_issuer(self):
        return Issuer.cached.get(pk=self.issuer_id)

    @cachemodel.cached_method(auto_publish=True)
    def recipient_count(self):
        return self.badgeinstances.filter(revoked=False).count()

    # @cachemodel.cached_method(auto_publish=True)
    def enrollment_count(self):
        from lti_edu.models import StudentsEnrolled
        return StudentsEnrolled.objects.filter(badge_class=self,
                                               denied=False,
                                               date_awarded=None).count()

    def pathway_element_count(self):
        return len(self.cached_pathway_elements())

    @cachemodel.cached_method(auto_publish=True)
    def cached_alignments(self):
        return self.badgeclassalignment_set.all()

    @property
    def alignment_items(self):
        return self.cached_alignments()

    @alignment_items.setter
    def alignment_items(self, value):
        if value is None:
            value = []
        keys = ['target_name','target_url','target_description','target_framework', 'target_code']

        def _identity(align):
            """build a unique identity from alignment json"""
            return "&".join("{}={}".format(k, align.get(k, None)) for k in keys)

        def _obj_identity(alignment):
            """build a unique identity from alignment json"""
            return "&".join("{}={}".format(k, getattr(alignment, k)) for k in keys)

        existing_idx = {_obj_identity(a): a for a in self.alignment_items}
        new_idx = {_identity(a): a for a in value}

        with transaction.atomic():
            # HACKY, but force a save to self otherwise we can't create related objects here
            if not self.pk:
                self.save()

            # add missing records
            for align in value:
                if _identity(align) not in existing_idx:
                    alignment = self.badgeclassalignment_set.create(**align)

            # remove old records
            for alignment in self.alignment_items:
                if _obj_identity(alignment) not in new_idx:
                    alignment.delete()

    @cachemodel.cached_method(auto_publish=True)
    def cached_tags(self):
        return self.badgeclasstag_set.all()

    @property
    def tag_items(self):
        return self.cached_tags()

    @tag_items.setter
    def tag_items(self, value):
        if value is None:
            value = []
        existing_idx = [t.name for t in self.tag_items]
        new_idx = value

        with transaction.atomic():
            if not self.pk:
                self.save()

            # add missing
            for t in value:
                if t not in existing_idx:
                    tag = self.badgeclasstag_set.create(name=t)

            # remove old
            for tag in self.tag_items:
                if tag.name not in new_idx:
                    tag.delete()

    def get_extensions_manager(self):
        return self.badgeclassextension_set

    @cachemodel.cached_method(auto_publish=True)
    def cached_pathway_elements(self):
        return [peb.element for peb in self.pathwayelementbadge_set.all()]

    @cachemodel.cached_method(auto_publish=True)
    def cached_completion_elements(self):
        return [pce for pce in self.completion_elements.all()]

    def issue(self, recipient_id=None, evidence=None, narrative=None, notify=False, created_by=None, allow_uppercase=False, badgr_app=None, **kwargs):
        return BadgeInstance.objects.create(
            badgeclass=self, recipient_identifier=recipient_id, narrative=narrative, evidence=evidence,
            notify=notify, created_by=created_by, allow_uppercase=allow_uppercase,
            badgr_app=badgr_app,
            **kwargs
        )

    def issue_signed(self, signer=None, password=None, recipient_id=None, evidence=None, narrative=None, notify=False, created_by=None, allow_uppercase=False, badgr_app=None, **kwargs):
        if not signer.may_sign_assertions:
            raise serializers.ValidationError('You do not have permission to sign badges.')
        if not signer in [staff.user for staff in self.issuer.current_signers]:
            raise serializers.ValidationError('You are not a signer for this issuer.')
        if not password:
            raise serializers.ValidationError('Cannot sign badges: no password provided.')
        assertion = BadgeInstance.objects.create(
            badgeclass=self, recipient_identifier=recipient_id, narrative=narrative, evidence=evidence,
            notify=False,  # notify after signing
            created_by=created_by, allow_uppercase=allow_uppercase,
            badgr_app=badgr_app,
            **kwargs
        )
        try:
            symkey = SymmetricKey.objects.get(user=signer, current=True)
        except SymmetricKey.DoesNotExist:
            raise serializers.ValidationError("You don't have a password set. Please set one first.")
        try:
            private_key = self.issuer.create_private_key(password, symkey)
            assertion_json = assertion.get_json(expand_badgeclass=True, expand_issuer=True, signed=True,
                                                public_key=private_key.public_key)
            signed_assertions = tsob.sign_badges([assertion_json], private_key, symkey, password)
            signature = signed_assertions[0]['signature']  # TODO: batch-wise signing
        except ValueError as e:
            raise serializers.ValidationError(e.message)

        new_image = StringIO.StringIO()
        bake(image_file=assertion.cached_badgeclass.image.file,
             assertion_json_string=signature,
             output_file=new_image)
        if notify:
            attach = MIMEBase('image', 'png')
            attach.set_payload(new_image.read())
            encoders.encode_base64(attach)
            assertion.recipient_user.email_user(subject='You have received a signed badge',
                                                message='Congrats, this is your signed badge',
                                                attachments=[attach])

        assertion.signature = signature
        assertion.save()
        filename = os.path.basename(assertion.image.file.name)
        assertion.image.delete()  # replace image
        assertion.image.save(name=filename, content=new_image)
        return assertion

    def get_json(self, obi_version=CURRENT_OBI_VERSION, include_extra=True, use_canonical_id=False, signed=False, public_key=None):
        if not public_key and signed:
            raise ValueError('Cannot returned signed version of json without knowing which private key was used.')
        obi_version, context_iri = get_obi_context(obi_version)
        json = OrderedDict({'@context': context_iri})
        json.update(OrderedDict(
            type='BadgeClass',

            name=self.name,
            description=self.description_nonnull,

        ))

        if not signed:
            json['id'] = self.jsonld_id if use_canonical_id else add_obi_version_ifneeded(self.jsonld_id, obi_version)
            json['issuer'] = self.cached_issuer.jsonld_id if use_canonical_id else add_obi_version_ifneeded(self.cached_issuer.jsonld_id, obi_version)
        if signed:
            json['id'] = self.get_url_with_public_key(public_key)
            json['issuer'] = self.issuer.get_url_with_public_key(public_key)

        # image
        if self.image:
            image_url = OriginSetting.HTTP + reverse('badgeclass_image', kwargs={'entity_id': self.entity_id})
            json['image'] = image_url
            if self.original_json:
                original_json = self.get_original_json()
                if original_json is not None:
                    image_info = original_json.get('image', None)
                    if isinstance(image_info, dict):
                        json['image'] = image_info
                        json['image']['id'] = image_url

        # criteria
        if obi_version == '1_1':
            json["criteria"] = self.get_criteria_url()
        elif obi_version == '2_0':
            json["criteria"] = {}
            if self.criteria_url:
                json['criteria']['id'] = self.criteria_url
            if self.criteria_text:
                json['criteria']['narrative'] = self.criteria_text

        # source_url
        if self.source_url:
            if obi_version == '1_1':
                json["source_url"] = self.source_url
                json["hosted_url"] = OriginSetting.HTTP + self.get_absolute_url()
            elif obi_version == '2_0':
                json["sourceUrl"] = self.source_url
                json["hostedUrl"] = OriginSetting.HTTP + self.get_absolute_url()

        # alignment / tags
        if obi_version == '2_0':
            json['alignment'] = [ a.get_json(obi_version=obi_version) for a in self.cached_alignments() ]
            json['tags'] = list(t.name for t in self.cached_tags())

        # extensions
        if len(self.cached_extensions()) > 0:
            for extension in self.cached_extensions():
                json[extension.name] = json_loads(extension.original_json)

        # pass through imported json
        if include_extra:
            extra = self.get_filtered_json()
            if extra is not None:
                for k,v in extra.items():
                    if k not in json:
                        json[k] = v
        return json

    @property
    def json(self):
        return self.get_json()

    def get_filtered_json(self, excluded_fields=('@context', 'id', 'type', 'name', 'description', 'image', 'criteria', 'issuer')):
        return super(BadgeClass, self).get_filtered_json(excluded_fields=excluded_fields)

    @property
    def cached_badgrapp(self):
        return self.cached_issuer.cached_badgrapp


class BadgeInstance(BaseAuditedModel,
                    BaseVersionedEntity,
                    BaseOpenBadgeObjectModel):
    entity_class_name = 'Assertion'

    issued_on = models.DateTimeField(blank=False, null=False, default=timezone.now)

    badgeclass = models.ForeignKey(BadgeClass, blank=False, null=False, on_delete=models.CASCADE, related_name='badgeinstances')
    issuer = models.ForeignKey(Issuer, blank=False, null=False)
    # timestamp_pending = models.BooleanField(default=True)
    # timestamp_proof = models.CharField(max_length=258798798)


    RECIPIENT_TYPE_EMAIL = 'email'
    RECIPIENT_TYPE_ID = 'openBadgeId'
    RECIPIENT_TYPE_TELEPHONE = 'telephone'
    RECIPIENT_TYPE_URL = 'url'
    RECIPIENT_TYPE_EDUID = 'id'
    RECIPIENT_TYPE_CHOICES = (
        (RECIPIENT_TYPE_EMAIL, 'email'),
        (RECIPIENT_TYPE_ID, 'openBadgeId'),
        (RECIPIENT_TYPE_TELEPHONE, 'telephone'),
        (RECIPIENT_TYPE_URL, 'url'),
        (RECIPIENT_TYPE_EDUID, 'id'),
    )
    
    recipient_identifier = models.CharField(max_length=512, blank=False, null=False, db_index=True)
    recipient_type = models.CharField(max_length=255, choices=RECIPIENT_TYPE_CHOICES, default=RECIPIENT_TYPE_EDUID, blank=False, null=False)

    image = models.FileField(upload_to='uploads/badges', blank=True)

    # slug has been deprecated for now, but preserve existing values
    slug = models.CharField(max_length=255, blank=True, null=True, default=None)
    #slug = AutoSlugField(max_length=255, populate_from='get_new_slug', unique=True, blank=False, editable=False)

    revoked = models.BooleanField(default=False)
    revocation_reason = models.CharField(max_length=255, blank=True, null=True, default=None)

    expires_at = models.DateTimeField(blank=True, null=True, default=None)

    ACCEPTANCE_UNACCEPTED = 'Unaccepted'
    ACCEPTANCE_ACCEPTED = 'Accepted'
    ACCEPTANCE_REJECTED = 'Rejected'
    ACCEPTANCE_CHOICES = (
        (ACCEPTANCE_UNACCEPTED, 'Unaccepted'),
        (ACCEPTANCE_ACCEPTED, 'Accepted'),
        (ACCEPTANCE_REJECTED, 'Rejected'),
    )
    acceptance = models.CharField(max_length=254, choices=ACCEPTANCE_CHOICES, default=ACCEPTANCE_UNACCEPTED)

    hashed = models.BooleanField(default=True)
    salt = models.CharField(max_length=254, blank=True, null=True, default=None)

    narrative = models.TextField(blank=True, null=True, default=None)

    old_json = JSONField()

    signature = models.TextField(blank=True, null=True, default=None)

    public = models.BooleanField(default=False)

    objects = BadgeInstanceManager()
    cached = SlugOrJsonIdCacheModelManager(slug_kwarg_name='entity_id', slug_field_name='entity_id')

    class Meta:
        index_together = (
                ('recipient_identifier', 'badgeclass', 'revoked'),
        )

    @property
    def extended_json(self):
        extended_json = self.json
        extended_json['badge'] = self.badgeclass.json
        extended_json['badge']['issuer'] = self.issuer.json

        return extended_json

    def image_url(self):
        if getattr(settings, 'MEDIA_URL').startswith('http'):
            return default_storage.url(self.image.name)
        else:
            return getattr(settings, 'HTTP_ORIGIN') + default_storage.url(self.image.name)

    @property
    def share_url(self):
        return self.public_url
        # return OriginSetting.HTTP+reverse('backpack_shared_assertion', kwargs={'share_hash': self.entity_id})

    @property
    def cached_issuer(self):
        return Issuer.cached.get(pk=self.issuer_id)

    @property
    def cached_badgeclass(self):
        return BadgeClass.cached.get(pk=self.badgeclass_id)

    def get_absolute_url(self):
        return reverse('badgeinstance_json', kwargs={'entity_id': self.entity_id})

    @property
    def jsonld_id(self):
        if self.source_url:
            return self.source_url
        return OriginSetting.HTTP + self.get_absolute_url()

    @property
    def badgeclass_jsonld_id(self):
        return self.cached_badgeclass.jsonld_id

    @property
    def issuer_jsonld_id(self):
        return self.cached_issuer.jsonld_id

    @property
    def public_url(self):
        return OriginSetting.HTTP+self.get_absolute_url()

    @property
    def owners(self):
        return self.issuer.owners

    def create_random_uuid(self):
        return uuid.uuid4().urn

    def get_email_address(self):
        '''
        uses self.recipient_identifier to get email adress to email an assertion to
        the recipient_identifier can be either the email address or it can be an edu_id
        '''
        from allauth.socialaccount.models import SocialAccount
        if self.recipient_identifier.startswith('urn:mace:eduid'): # is EduID
            account = SocialAccount.objects.get(uid=self.recipient_identifier)
            return account.user.primary_email
        else: # recipient identifier is an email
            return self.recipient_identifier

    def save(self, *args, **kwargs):
        created = False
        if self.pk is None:
            created = True
            self.salt = uuid.uuid4().hex
            self.created_at = datetime.datetime.now()

            # do this now instead of in AbstractVersionedEntity.save() so we can use it for image name
            if self.entity_id is None:
                self.entity_id = generate_entity_uri()

            if not self.image:
                badgeclass_name, ext = os.path.splitext(self.badgeclass.image.file.name)
                new_image = StringIO.StringIO()
                bake(image_file=self.cached_badgeclass.image.file,
                     assertion_json_string=json_dumps(self.get_json(obi_version=UNVERSIONED_BAKED_VERSION), indent=2),
                     output_file=new_image)
                self.image.save(name='assertion-{id}{ext}'.format(id=self.entity_id, ext=ext),
                                content=ContentFile(new_image.read()),
                                save=False)

            try:
                from badgeuser.models import CachedEmailAddress
                email_address = self.get_email_address()
                existing_email = CachedEmailAddress.cached.get_student_email(email_address)
                if email_address != existing_email.email and \
                        email_address not in [e.email for e in existing_email.cached_variants()]:
                    existing_email.add_variant(email_address)
            except CachedEmailAddress.DoesNotExist:
                pass

        if self.revoked is False:
            self.revocation_reason = None

        super(BadgeInstance, self).save(*args, **kwargs)
        if created:
            for extension in self.badgeclass.badgeclassextension_set.all():
                BadgeInstanceExtension.objects.create(badgeinstance=self,
                                                      name=extension.name,
                                                      original_json=extension.original_json)

    def rebake(self, obi_version=CURRENT_OBI_VERSION, save=True):
        if self.source_url:
            # dont rebake imported assertions
            return

        new_image = StringIO.StringIO()
        bake(
            image_file=self.cached_badgeclass.image.file,
            assertion_json_string=json_dumps(self.get_json(obi_version=obi_version), indent=2),
            output_file=new_image
        )
        new_name = default_storage.save(self.image.name, ContentFile(new_image.read()))
        self.image.name = new_name
        if save:
            self.save()

    def publish(self):
        super(BadgeInstance, self).publish()
        self.badgeclass.publish()
        if self.cached_recipient_profile:
            self.cached_recipient_profile.publish()
        if self.recipient_user:
            self.recipient_user.publish()

        # publish all collections this instance was in
        for collection in self.backpackcollection_set.all():
            collection.publish()

        self.publish_by('entity_id', 'revoked')

    def delete(self, *args, **kwargs):
        badgeclass = self.badgeclass
        recipient_profile = self.cached_recipient_profile
        super(BadgeInstance, self).delete(*args, **kwargs)
        badgeclass.publish()
        if recipient_profile:
            recipient_profile.publish()
        if self.recipient_user:
            self.recipient_user.publish()
        self.publish_delete('entity_id', 'revoked')

    def revoke(self, revocation_reason):
        if self.revoked:
            raise ValidationError("Assertion is already revoked")

        if not revocation_reason:
            raise ValidationError("revocation_reason is required")

        self.revoked = True
        self.revocation_reason = revocation_reason
        self.image.delete()
        self.save()

        # remove BadgeObjectiveAwards from badgebook if needed
        if apps.is_installed('badgebook'):
            try:
                from badgebook.models import BadgeObjectiveAward, LmsCourseInfo
                try:
                    award = BadgeObjectiveAward.cached.get(badge_instance_id=self.id)
                except BadgeObjectiveAward.DoesNotExist:
                    pass
                else:
                    award.delete()
            except ImportError:
                pass

    def notify_earner(self, badgr_app=None):
        """
        Sends an email notification to the badge earner.
        This process involves creating a badgeanalysis.models.OpenBadge
        returns the EarnerNotification instance.

        TODO: consider making this an option on initial save and having a foreign key to
        the notification model instance (which would link through to the OpenBadge)
        """

        email_address = self.get_email_address()
        
        try:
            EmailBlacklist.objects.get(email=email_address)
        except EmailBlacklist.DoesNotExist:
            # Allow sending, as this email is not blacklisted.
            pass
        else:
            return
            # TODO: Report email non-delivery somewhere.

        if badgr_app is None:
            badgr_app = BadgrApp.objects.get_current(None)

        try:
            if self.issuer.image:
                issuer_image_url = self.issuer.public_url + '/image'
            else:
                issuer_image_url = None

            email_context = {
                'badge_name': self.badgeclass.name,
                'badge_id': self.entity_id,
                'badge_description': self.badgeclass.description,
                'expiration_date': self.expires_at.date() if self.expires_at else self.expires_at,
                'help_email': getattr(settings, 'HELP_EMAIL', 'help@badgr.io'),
                'issuer_name': self.issuer.name,
                'issuer_url': self.issuer.url,
                'issuer_email': self.issuer.email,
                'issuer_detail': self.issuer.public_url,
                'issuer_image_url': issuer_image_url,
                'badge_instance_url': self.public_url,
                'image_url': self.public_url + '/image',
                'download_url': self.public_url + "?action=download",
                'unsubscribe_url': getattr(settings, 'HTTP_ORIGIN') + EmailBlacklist.generate_email_signature(
                    email_address),
                'site_name': badgr_app.name,
                'site_url': badgr_app.signup_redirect,
                'badgr_app': badgr_app,
            }
            if badgr_app.cors == 'badgr.io':
                email_context['promote_mobile'] = True
        except KeyError as e:
            # A property isn't stored right in json
            raise e

        template_name = 'issuer/email/notify_earner'
        try:
            from badgeuser.models import CachedEmailAddress
            email = CachedEmailAddress.cached.get_student_email(email_address)
            template_name = 'issuer/email/notify_account_holder'
            email_context['site_url'] = badgr_app.email_confirmation_redirect
        except CachedEmailAddress.DoesNotExist:
            pass

        adapter = get_adapter()
        try:
            adapter.send_mail(template_name, email_address, context=email_context)
        except Exception as e:
            logger.exception('Mail failure with error {} : {}'.format(type(e), e.message))      

    def get_extensions_manager(self):
        return self.badgeinstanceextension_set

    @property
    def cached_recipient_profile(self):
        from recipient.models import RecipientProfile
        try:
            return RecipientProfile.cached.get(recipient_identifier=self.recipient_identifier)
        except RecipientProfile.MultipleObjectsReturned:
            return RecipientProfile.objects.filter(recipient_identifier=self.recipient_identifier).first()
        except RecipientProfile.DoesNotExist:
            return None

    @property
    def recipient_user(self):
        from badgeuser.models import CachedEmailAddress
        try:
            email_address = CachedEmailAddress.cached.get_student_email(self.get_email_address())
            if email_address.verified:
                return email_address.user
        except CachedEmailAddress.DoesNotExist:
            pass
        return None

    def get_json(self, obi_version=CURRENT_OBI_VERSION, expand_badgeclass=False, expand_issuer=False,
                 include_extra=True, use_canonical_id=False, signed=False, public_key=None):

        if signed:
            if expand_issuer != True or expand_badgeclass != True:
                raise ValueError('Must expand issuer and badgeclass if signed is set to true.')
            if not public_key:
                raise ValueError('Must add public key if signed is set to true.')
            if public_key.issuer != self.issuer:
                raise ValueError('Public key issuer does not match assertion issuer')

        obi_version, context_iri = get_obi_context(obi_version)

        json = OrderedDict([
            ('@context', context_iri),
            ('type', 'Assertion'),
        ])

        if signed:
            json['id'] = self.create_random_uuid()
        else:
            json['id'] = add_obi_version_ifneeded(self.jsonld_id, obi_version)
            json['badge'] = add_obi_version_ifneeded(self.cached_badgeclass.jsonld_id, obi_version)

        image_url = OriginSetting.HTTP + reverse('badgeinstance_image', kwargs={'entity_id': self.entity_id})
        json['image'] = image_url
        if self.original_json:
            image_info = self.get_original_json().get('image', None)
            if isinstance(image_info, dict):
                json['image'] = image_info
                json['image']['id'] = image_url

        if expand_badgeclass:
            json['badge'] = self.cached_badgeclass.get_json(obi_version=obi_version, include_extra=include_extra)
            if signed:
                json['badge']['id'] = self.cached_badgeclass.get_url_with_public_key(public_key)
            if expand_issuer:
                json['badge']['issuer'] = self.cached_issuer.get_json(obi_version=obi_version, include_extra=include_extra, signed=signed,
                                                                      expand_public_key=True, public_key=public_key)

        if self.revoked:
            return OrderedDict([
                ('@context', context_iri),
                ('type', 'Assertion'),
                ('id', self.jsonld_id if use_canonical_id else add_obi_version_ifneeded(self.jsonld_id, obi_version)),
                ('revoked', self.revoked),
                ('revocationReason', self.revocation_reason if self.revocation_reason else "")
            ])

        if obi_version == '1_1':
            json["uid"] = self.entity_id
            json["verify"] = {
                "url": self.public_url if use_canonical_id else add_obi_version_ifneeded(self.public_url, obi_version),
                "type": "hosted"
            }
        elif obi_version == '2_0':
            if signed:
                json["verification"] = {
                    "type": "SignedBadge",
                    "creator": public_key.public_url
                }
            else:
                json["verification"] = {
                    "type": "HostedBadge"
                }

        # source url
        if self.source_url:
            if obi_version == '1_1':
                json["source_url"] = self.source_url
                json["hosted_url"] = OriginSetting.HTTP + self.get_absolute_url()
            elif obi_version == '2_0':
                json["sourceUrl"] = self.source_url
                json["hostedUrl"] = OriginSetting.HTTP + self.get_absolute_url()

        # evidence
        if self.evidence_url:
            if obi_version == '1_1':
                # obi v1 single evidence url
                json['evidence'] = self.evidence_url
            elif obi_version == '2_0':
                # obi v2 multiple evidence
                json['evidence'] = [e.get_json(obi_version) for e in self.cached_evidence()]

        # narrative
        if self.narrative and obi_version == '2_0':
            json['narrative'] = self.narrative

        # issuedOn / expires
        json['issuedOn'] = self.issued_on.isoformat()
        if self.expires_at:
            json['expires'] = self.expires_at.isoformat()

        # recipient
        if self.hashed:
            json['recipient'] = {
                "hashed": True,
                "type": self.recipient_type,
                "identity": generate_sha256_hashstring(self.recipient_identifier.lower(), self.salt),
            }
            if self.salt:
                json['recipient']['salt'] = self.salt
        else:
            json['recipient'] = {
                "hashed": False,
                "type": self.recipient_type,
                "identity": self.recipient_identifier
            }

        # extensions
        if len(self.cached_extensions()) > 0:
            for extension in self.cached_extensions():
                json[extension.name] = json_loads(extension.original_json)
        if self.pk is None:
            for extension in self.badgeclass.badgeclassextension_set.all():
                json[extension.name] = json_loads(extension.original_json)
        # pass through imported json
        if include_extra:
            extra = self.get_filtered_json()
            if extra is not None:
                for k,v in extra.items():
                    if k not in json:
                        json[k] = v

        return json

    @property
    def json(self):
        return self.get_json()

    def get_filtered_json(self, excluded_fields=('@context', 'id', 'type', 'uid', 'recipient', 'badge', 'issuedOn', 'image', 'evidence', 'narrative', 'revoked', 'revocationReason', 'verify', 'verification')):
        return super(BadgeInstance, self).get_filtered_json(excluded_fields=excluded_fields)

    @cachemodel.cached_method(auto_publish=True)
    def cached_evidence(self):
        return self.badgeinstanceevidence_set.all()


    @property
    def evidence_url(self):
        """Exists for compliance with ob1.x badges"""
        evidence_list = self.cached_evidence()
        if len(evidence_list) > 1:
            return self.public_url
        if len(evidence_list) == 1 and evidence_list[0].evidence_url:
            return evidence_list[0].evidence_url
        elif len(evidence_list) == 1:
            return self.public_url

    @property
    def evidence_items(self):
        """exists to cajole EvidenceItemSerializer"""
        return self.cached_evidence()

    @evidence_items.setter
    def evidence_items(self, value):
        def _key(narrative, url):
            return u'{}-{}'.format(narrative, url)
        existing_evidence_idx = {_key(e.narrative, e.evidence_url): e for e in self.evidence_items}
        new_evidence_idx = {_key(v.get('narrative',''), v.get('evidence_url','')): v for v in value}

        with transaction.atomic():
            if not self.pk:
                self.save()

            # add missing
            for evidence_data in value:
                key = _key(evidence_data.get('narrative',''), evidence_data.get('evidence_url',''))
                if key not in existing_evidence_idx:
                    evidence_record, created = BadgeInstanceEvidence.cached.get_or_create(
                        badgeinstance=self,
                        narrative=evidence_data.get('narrative', None),
                        evidence_url=evidence_data.get('evidence_url', None)
                    )

            # remove old
            for evidence_record in self.evidence_items:
                key = _key(evidence_record.narrative or '', evidence_record.evidence_url or '')
                if key not in new_evidence_idx:
                    evidence_record.delete()

    @property
    def cached_badgrapp(self):
        return self.cached_issuer.cached_badgrapp

    def get_baked_image_url(self, obi_version=CURRENT_OBI_VERSION):
        if obi_version == UNVERSIONED_BAKED_VERSION:
            # requested version is the one referenced in assertion.image
            return self.image.url

        try:
            baked_image = BadgeInstanceBakedImage.cached.get(badgeinstance=self, obi_version=obi_version)
        except BadgeInstanceBakedImage.DoesNotExist:
            # rebake
            baked_image = BadgeInstanceBakedImage(badgeinstance=self, obi_version=obi_version)

            json_to_bake = self.get_json(
                obi_version=obi_version,
                expand_issuer=True,
                expand_badgeclass=True,
                include_extra=True
            )
            badgeclass_name, ext = os.path.splitext(self.badgeclass.image.file.name)
            new_image = StringIO.StringIO()
            bake(image_file=self.cached_badgeclass.image.file,
                 assertion_json_string=json_dumps(json_to_bake, indent=2),
                 output_file=new_image)
            baked_image.image.save(
                name='assertion-{id}-{version}{ext}'.format(id=self.entity_id, ext=ext, version=obi_version),
                content=ContentFile(new_image.read()),
                save=False
            )
            baked_image.save()

        return baked_image.image.url


def _baked_badge_instance_filename_generator(instance, filename):
    return "baked/{version}/{filename}".format(
        version=instance.obi_version,
        filename=filename
    )


class BadgeInstanceBakedImage(cachemodel.CacheModel):
    badgeinstance = models.ForeignKey('issuer.BadgeInstance')
    obi_version = models.CharField(max_length=254)
    image = models.FileField(upload_to=_baked_badge_instance_filename_generator, blank=True)

    def publish(self):
        self.publish_by('badgeinstance', 'obi_version')
        return super(BadgeInstanceBakedImage, self).publish()

    def delete(self, *args, **kwargs):
        self.publish_delete('badgeinstance', 'obi_version')
        return super(BadgeInstanceBakedImage, self).delete(*args, **kwargs)


class BadgeInstanceEvidence(OriginalJsonMixin, cachemodel.CacheModel):
    badgeinstance = models.ForeignKey('issuer.BadgeInstance')
    evidence_url = models.CharField(max_length=2083, blank=True, null=True, default=None)
    narrative = models.TextField(blank=True, null=True, default=None)

    objects = BadgeInstanceEvidenceManager()

    def publish(self):
        super(BadgeInstanceEvidence, self).publish()
        self.badgeinstance.publish()

    def delete(self, *args, **kwargs):
        badgeinstance = self.badgeinstance
        ret = super(BadgeInstanceEvidence, self).delete(*args, **kwargs)
        badgeinstance.publish()
        return ret

    def get_json(self, obi_version=CURRENT_OBI_VERSION, include_context=False):
        json = OrderedDict()
        if include_context:
            obi_version, context_iri = get_obi_context(obi_version)
            json['@context'] = context_iri

        json['type'] = 'Evidence'
        if self.evidence_url:
            json['id'] = self.evidence_url
        if self.narrative:
            json['narrative'] = self.narrative
        return json


class BadgeClassAlignment(OriginalJsonMixin, cachemodel.CacheModel):
    badgeclass = models.ForeignKey('issuer.BadgeClass')
    target_name = models.TextField()
    target_url = models.CharField(max_length=2083)
    target_description = models.TextField(blank=True, null=True, default=None)
    target_framework = models.TextField(blank=True, null=True, default=None)
    target_code = models.TextField(blank=True, null=True, default=None)

    def publish(self):
        super(BadgeClassAlignment, self).publish()
        self.badgeclass.publish()

    def delete(self, *args, **kwargs):
        super(BadgeClassAlignment, self).delete(*args, **kwargs)
        self.badgeclass.publish()

    def get_json(self, obi_version=CURRENT_OBI_VERSION, include_context=False):
        json = OrderedDict()
        if include_context:
            obi_version, context_iri = get_obi_context(obi_version)
            json['@context'] = context_iri

        json['targetName'] = self.target_name
        json['targetUrl'] = self.target_url
        if self.target_description:
            json['targetDescription'] = self.target_description
        if self.target_framework:
            json['targetFramework'] = self.target_framework
        if self.target_code:
            json['targetCode'] = self.target_code

        return json


class BadgeClassTag(cachemodel.CacheModel):
    badgeclass = models.ForeignKey('issuer.BadgeClass')
    name = models.CharField(max_length=254, db_index=True)

    def __unicode__(self):
        return self.name

    def publish(self):
        super(BadgeClassTag, self).publish()
        self.badgeclass.publish()

    def delete(self, *args, **kwargs):
        super(BadgeClassTag, self).delete(*args, **kwargs)
        self.badgeclass.publish()


class IssuerExtension(BaseOpenBadgeExtension):
    issuer = models.ForeignKey('issuer.Issuer')

    def publish(self):
        super(IssuerExtension, self).publish()
        self.issuer.publish()

    def delete(self, *args, **kwargs):
        super(IssuerExtension, self).delete(*args, **kwargs)
        self.issuer.publish()


class BadgeClassExtension(BaseOpenBadgeExtension):
    badgeclass = models.ForeignKey('issuer.BadgeClass')

    def publish(self):
        super(BadgeClassExtension, self).publish()
        self.badgeclass.publish()

    def delete(self, *args, **kwargs):
        super(BadgeClassExtension, self).delete(*args, **kwargs)
        self.badgeclass.publish()


class BadgeInstanceExtension(BaseOpenBadgeExtension):
    badgeinstance = models.ForeignKey('issuer.BadgeInstance')

    def publish(self):
        super(BadgeInstanceExtension, self).publish()
        self.badgeinstance.publish()

    def delete(self, *args, **kwargs):
        super(BadgeInstanceExtension, self).delete(*args, **kwargs)
        self.badgeinstance.publish()
