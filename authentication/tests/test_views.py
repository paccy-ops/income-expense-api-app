import email

from .test_setup import TestSetup
from ..models import User


class TestView(TestSetup):

    def test_user_cannot_register_with_no_data(self):
        res = self.client.post(self.register_url)
        self.assertEqual(res.status_code, 400)

    def test_user_can_register(self):
        res = self.client.post(
            self.register_url,
            self.user_data, format="json")

        # import pdb
        # pdb.set_trace()
        self.assertEqual(res.data['user']['email'], self.user_data['email'])
        self.assertEqual(res.data['user']['username'], self.user_data['username'])
        self.assertEqual(res.status_code, 201)

    def test_user_cannot_login_with_unverified_email(self):
        self.client.post(
            self.register_url, self.user_data, format="json"
        )
        res = self.client.post(self.login_url, self.user_data, format="json")
        self.assertEqual(res.status_code, 401)

    def test_user_can_login_with_verified_email(self):
        res = self.client.post(
            self.register_url, self.user_data, format="json"
        )
        email = res.data['user']['email']
        user = User.objects.get(email=email)
        user.is_verified = True
        user.save()
        res = self.client.post(self.login_url, self.user_data, format="json")
        self.assertEqual(res.status_code, 200)
