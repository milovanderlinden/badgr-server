# encoding: utf-8
from __future__ import unicode_literals

import json
import unittest

from django.urls import reverse

from badgeuser.models import BadgrAccessToken
from mainsite.tests import SetupIssuerHelper, BadgrTestCase, SetupOAuth2ApplicationHelper


class PublicAPITests(SetupOAuth2ApplicationHelper, SetupIssuerHelper, BadgrTestCase):
    #@unittest.skip('For debug speedup')
    def test_client_credentials_token(self):
        # define oauth application
        application_user = self.setup_user(authenticate=False)
        application = self.setup_oauth2_application(
            user=application_user,
            allowed_scopes="rw:issuer rw:backpack rw:profile",
            trust_email=True)

        # retrieve an rw:issuer token
        response = self.client.post('/o/token', data=dict(
            grant_type="client_credentials",
            client_id=application.client_id,
            client_secret=application.client_secret,
            scope="rw:issuer"
        ))
        self.assertEqual(response.status_code, 200)

    #@unittest.skip('For debug speedup')
    def test_can_get_issuer_scoped_token(self):
        # create an oauth2 application
        application_user = self.setup_user(authenticate=False)
        application = self.setup_oauth2_application(user=application_user, allowed_scopes="rw:issuer rw:issuer:*")

        badgr_user = self.setup_user(authenticate=False, teacher=True)
        issuer = self.setup_issuer(owner=badgr_user)

        # application can retrieve a token
        response = self.client.post(reverse('oauth2_provider_token'), data=dict(
            grant_type=application.authorization_grant_type.replace('-','_'),
            client_id=application.client_id,
            client_secret=application.client_secret,
            scope='rw:issuer:{}'.format(issuer.entity_id)
        ))
        self.assertEqual(response.status_code, 200)

    #@unittest.skip('For debug speedup')
    def test_can_get_batch_issuer_tokens(self):

        # create an oauth2 application
        application_user = self.setup_user(email='service@email.test', authenticate=False)
        application = self.setup_oauth2_application(user=application_user, allowed_scopes='rw:issuer')

        # application can retrieve a token
        response = self.client.post(reverse('oauth2_provider_token'), data=dict(
            grant_type=application.authorization_grant_type.replace('-','_'),
            client_id=application.client_id,
            client_secret=application.client_secret,
            scope='rw:issuer'
        ))
        self.assertEqual(response.status_code, 200)
        result = response.json()
        # result should contain token_type and access_token
        self.assertFalse(any(result.get(k, None) is None for k in ['token_type','access_token']))
        auth_headers = {
            'Authorization': "{type} {token}".format(type=result.get("token_type"), token=result.get("access_token"))
        }

        # create a badgr user who owns several issuers
        badgr_user = self.setup_user(email='user@email.test', authenticate=False, teacher=True, surfconext_id='somerandomid')
        issuers = [self.setup_issuer(owner=badgr_user, name="issuer #{}".format(i)) for i in range(1, 4)]
        issuer_ids = [i.entity_id for i in issuers]

        # get rw:issuer:* tokens for the issuers
        response = self.client.post(reverse('v2_api_tokens_list'), data=dict(
            issuers=issuer_ids
        ), format="json", **auth_headers)
        self.assertEqual(response.status_code, 200)
        result = json.loads(response.content)
        self.assertDictEqual(result.get('status'), dict(success=True, description="ok"))

        # we should receive tokens for each issuer
        issuer_tokens = {r.get('issuer'): r.get('token') for r in result.get('result')}
        self.assertEqual(set(issuer_tokens.keys()), set(issuer_ids))

        access_tokens = [BadgrAccessToken.objects.get(token=t) for t in issuer_tokens.values()]
        self.assertEqual(len(access_tokens), len(issuer_tokens))

        # We don't use V2
        # # we should be able to use tokens to access the issuer
        # for issuer_id, issuer_token in issuer_tokens.items():
        #     response = self.client.get(reverse('v2_api_issuer_detail', kwargs=dict(entity_id=issuer_id)),
        #          format="json",
        #          Authorization="Bearer {}".format(issuer_token)
        #     )
        #     self.assertEqual(response.status_code, 200)

        # ensure that issuer tokens didnt change and still have same expiration
        for access_token in access_tokens:
            updated_access_token = BadgrAccessToken.objects.get(pk=access_token.pk)
            self.assertEqual(updated_access_token.token, access_token.token)
            self.assertEqual(updated_access_token.expires, access_token.expires)



