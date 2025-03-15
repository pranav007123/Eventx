from django.urls import path
from django.contrib.auth import views as auth_views
from . import views

urlpatterns = [
    # Public Views
    path("", views.index, name="index"),
    path("event/<int:event_id>/", views.event_detail, name="event_detail"),
    
    # Authentication
    path("register/", views.register, name="register"),
    path("login/", views.custom_login, name="login"),
    path("logout/", views.logout_view, name="logout"),
    
    # Seller Dashboard
    path("seller/dashboard/", views.seller_dashboard, name="seller_dashboard"),
    
    # Admin Dashboard
    path("admin/login/", views.custom_admin_login, name="custom_admin_login"),
    path("admin/dashboard/", views.admin_dashboard, name="admin_dashboard"),
     path('accounts/logout/', auth_views.LogoutView.as_view(next_page='index'), name='logout'),
    
]
