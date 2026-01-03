from django.urls import path,include
from accounts.views import RegisterView,LoginView,profileView,LogoutView
from rest_framework_simplejwt.views import (
    TokenObtainPairView,
    TokenRefreshView,
)
urlpatterns =[
    path('register',RegisterView.as_view()),
    path('login',LoginView.as_view()),
    path('account',profileView.as_view()),
    path('refresh/', TokenRefreshView.as_view(), name='token_refresh'),
    path('logout',LogoutView.as_view()),
    

]
