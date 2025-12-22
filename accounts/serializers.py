from rest_framework import serializers
from accounts.models import Accounts
from django.contrib.auth.hashers import make_password

class UserRegistrationSerializer(serializers.ModelSerializer):
    password = serializers.CharField(write_only=True)
    class Meta:
        model=Accounts
        fields="__all__"
    
    def create(self, validated_data):
        hashed = make_password(validated_data['password'])
        # print("Hashed password:", hashed)
        validated_data['password'] = hashed
        return Accounts.objects.create(**validated_data)


class ProfileSerializer(serializers.ModelSerializer):

    class Meta:
        model=Accounts
        fields='__all__'
        