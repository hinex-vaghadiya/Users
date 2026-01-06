from django.urls import path,include
from accounts.views import RegisterView,LoginView,profileView,LogoutView
from rest_framework_simplejwt.views import (
    TokenObtainPairView,
    TokenRefreshView,
)
# from drf_spectacular.views import SpectacularAPIView, SpectacularSwaggerView, SpectacularRedocView

urlpatterns =[
    path('register',RegisterView.as_view()),
    path('login',LoginView.as_view()),
    path('account',profileView.as_view()),
    path('refresh/', TokenRefreshView.as_view(), name='token_refresh'),
    path('logout',LogoutView.as_view()),
    # path('api/schema/', SpectacularAPIView.as_view(), name='schema'),
    # # Optional UI:
    # path('api/schema/swagger-ui/', SpectacularSwaggerView.as_view(url_name='schema'), name='swagger-ui'),
    # path('api/schema/redoc/', SpectacularRedocView.as_view(url_name='schema'), name='redoc')
    
    

]
