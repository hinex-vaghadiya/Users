from django.urls import path,include
from accounts.views import RegisterView,LoginView,profileView

urlpatterns =[
    path('register',RegisterView.as_view()),
    path('login',LoginView.as_view()),
    path('account',profileView.as_view()),

]