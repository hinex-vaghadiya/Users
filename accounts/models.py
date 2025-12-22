from django.db import models
from django.contrib.auth.models import AbstractUser
# Create your models here.

class Accounts(AbstractUser):
    name=models.CharField(max_length=30,null=False,default=" ")
    username=models.CharField(max_length=30,unique=True)
    email=models.EmailField(max_length=50)
    password=models.CharField(max_length=1000)
    role=models.CharField(choices=(('user','user'),('reseller','reseller')),default='user')
    address=models.CharField(max_length=200,default=" ",null=False)
    mobile_number=models.IntegerField(null=False,default=100)
    profile_pic=models.CharField(default=" ",null=False)
    is_active=models.BooleanField(default=True)

    