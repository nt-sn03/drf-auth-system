from django.contrib.auth.hashers import make_password
from rest_framework import serializers
from rest_framework.exceptions import ValidationError

from .models import User


class RegisterSerializer(serializers.ModelSerializer):
    confirm = serializers.CharField(required=True)

    class Meta:
        model = User
        fields = ('username', 'password', 'confirm', 'first_name', 'last_name', 'email', 'phone_number')

    def validate(self, attrs):
        if attrs['password'] != attrs['confirm']:
            raise ValidationError('password and confirm must be the same.')
        
        attrs.pop('confirm')
        attrs['password'] = make_password(attrs['password'])

        return super().validate(attrs)


class LoginSerializer(serializers.Serializer):
    username = serializers.CharField(max_length=127)
    password = serializers.CharField(max_length=127)
    