from django.shortcuts import render
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status, permissions
from accounts.serializers import UserRegistrationSerializer, ProfileSerializer
from accounts.models import Accounts
from django.contrib.auth.hashers import check_password
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework.permissions import IsAuthenticated
from rest_framework_simplejwt.authentication import JWTAuthentication

# --- CUSTOM AUTHENTICATION CLASS ---
class CookieJWTAuthentication(JWTAuthentication):
    def authenticate(self, request):
        # 1. Check Header
        header_user_token = super().authenticate(request)
        if header_user_token is not None:
            return header_user_token

        # 2. Check Cookie
        raw_token = request.COOKIES.get('access_token')
        if raw_token is None:
            return None

        # 3. Validate
        try:
            validated_token = self.get_validated_token(raw_token)
            return self.get_user(validated_token), validated_token
        except:
            return None

# --- VIEWS ---

class RegisterView(APIView):
    def post(self, request):
        serializer = UserRegistrationSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response({"message": "success"}, status=status.HTTP_201_CREATED)
        else:
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    def get(self, request):
        users = Accounts.objects.all()
        serializer = UserRegistrationSerializer(users, many=True)
        return Response(serializer.data, status=status.HTTP_200_OK)


class LoginView(APIView):
    permission_classes = [permissions.AllowAny]

    def post(self, request):
        data = request.data
        username = data.get('username')
        password = data.get('password')

        try:
            user = Accounts.objects.get(username=username)
            
            if check_password(password, user.password):
                refresh = RefreshToken.for_user(user)
                
                # Basic response
                response = Response({
                    "message": "Login successful",
                    "user_id": user.id,
                    "user_name": user.username
                }, status=status.HTTP_200_OK)

                # --- 1. SECURE AUTH COOKIES (HttpOnly=True) ---
                # JavaScript CANNOT read these. This is for security.
                response.set_cookie(
                    key='access_token',
                    value=str(refresh.access_token),
                    httponly=True, 
                    secure=False, 
                    samesite='Lax', 
                    max_age=300 
                )
                response.set_cookie(
                    key='refresh_token',
                    value=str(refresh),
                    httponly=True,
                    secure=False,
                    samesite='Lax',
                    max_age=86400 
                )

                # --- 2. USER INFO COOKIES (HttpOnly=False) ---
                # JavaScript CAN read these. Use this to update your UI (e.g., "Welcome User").
                response.set_cookie(
                    key='user_id',
                    value=str(user.id),
                    httponly=False,  # <--- Allow JS access
                    secure=False,
                    samesite='Lax',
                    max_age=86400
                )
                response.set_cookie(
                    key='user_name',
                    value=user.username,
                    httponly=False,  # <--- Allow JS access
                    secure=False,
                    samesite='Lax',
                    max_age=86400
                )

                return response

            else:
                return Response({"message": "Password incorrect"}, status=status.HTTP_401_UNAUTHORIZED)
        
        except Accounts.DoesNotExist:
            return Response({"message": "User doesn't exist"}, status=status.HTTP_404_NOT_FOUND)


class LogoutView(APIView):
    def post(self, request):
        response = Response({"message": "Logout successful"}, status=status.HTTP_200_OK)
        
        # Delete ALL cookies
        response.delete_cookie('access_token')
        response.delete_cookie('refresh_token')
        response.delete_cookie('user_id')
        response.delete_cookie('user_name')
        
        return response


class profileView(APIView):
    authentication_classes = [CookieJWTAuthentication]
    permission_classes = [IsAuthenticated]

    def get(self, request):
        user = request.user
        serializer = ProfileSerializer(user)
        return Response(serializer.data)

    def put(self, request):
        serializer = ProfileSerializer(
            request.user,
            data=request.data,
            partial=True
        )
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_200_OK) 
        else:
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
