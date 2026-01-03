from django.shortcuts import render

from rest_framework.views import APIView
from accounts.serializers import UserRegistrationSerializer,ProfileSerializer
from rest_framework.response import Response
from rest_framework import status,permissions
from accounts.models import Accounts
from django.contrib.auth.hashers import check_password
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework.permissions import IsAuthenticated
from rest_framework_simplejwt.authentication import JWTAuthentication
# Create your views here.

class RegisterView(APIView):
    def post(self,request):
        serializer=UserRegistrationSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response({"message":"sucess"},status=status.HTTP_201_CREATED)
        else:
            return Response({"error":""},status=status.HTTP_400_BAD_REQUEST)
    def get(self,request):
        users=Accounts.objects.all()
        serializer=UserRegistrationSerializer(users,many=True)
        return Response(serializer.data,status=status.HTTP_200_OK)


class LoginView(APIView):
    def post(self,request):
        data=request.data
        username=data.get('username')
        password=data.get('password')
        try:
            user = Accounts.objects.get(username=username)
            if check_password(password, user.password):
                refresh=RefreshToken.for_user(user) # <- Use check_password
                return Response({
                    "access_token":str(refresh.access_token),
                    "refresh_token":str(refresh),
                    "user_id":user.id,
                    "user_name":user.username
                }, status=status.HTTP_200_OK)
            else:
                return Response({"message": "password incorrect"}, status=status.HTTP_401_UNAUTHORIZED)
        except Accounts.DoesNotExist:
            return Response({"message": "user doesn't exist"}, status=status.HTTP_404_NOT_FOUND)

class profileView(APIView):
    permission_classes=[IsAuthenticated]
    def get(self,request):
        user=request.user
        serializer=ProfileSerializer(user)
        return Response(serializer.data)
    def put(self,request):
        serializer=ProfileSerializer(
            request.user,
            data=request.data,
            partial=True
        )
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_200_OK) 
        else:
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        
        
