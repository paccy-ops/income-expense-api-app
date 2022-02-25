from django.urls import reverse
from faker import Faker
from rest_framework.test import APITestCase


class TestSetup(APITestCase):
    def setUp(self):
        self.register_url = reverse('authentication:register')
        self.login_url = reverse('authentication:login')
        self.fake = Faker()

        self.user_data = {
            "email": self.fake.email(),
            "username": self.fake.email().split('@')[0],
            "password": self.fake.password()

        }

        return super().setUp()

    def tearDown(self):
        return super().tearDown()
