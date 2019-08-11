from .views import *
from django.urls import path
from django.conf.urls import include
from django.contrib.auth import views
from django.conf import settings
from django.conf.urls.static import static



urlpatterns = [
    path('login/', user_login,name='login'),
    path('signup/',signup,name='signup'),
    path('home/logout/',user_logout,name='logout'),
    path('',home,name='home'),
    path('home/',home,name='Main'),
    path('viewprofile/',viewprofile,name='viewprofile'),
    path('viewprofile/editprofile/',edit_profile,name='editprofile'),
    path('viewprofile/password/',change_password, name='change_password'),
    path('', main_page, name='main_page'),
    # path('home/', MovieListView.as_view(), name='home'),
   # path('', MovieListView.as_view(), name='main_page'),
   #  path('Movie/<int:pk>/', MovieDetailView.as_view(), name='Movie-detail'),
    path(r'^activate/(?P<uidb64>[0-9A-Za-z_\-]+)/(?P<token>[0-9A-Za-z]{1,13}-[0-9A-Za-z]{1,20})/$', activate,name='activate'),
    path('about/',about_page , name='about'),
    # path('movies_events/',movies_events , name='movies_events'),
    path('contact/', contact, name='contact'),
    path('api/v1/', include('social_django.urls', namespace='social')),
    path('reset/<uidb64>/<token>/',user_password_reset, name='user_password_reset'),
    path('forgotpassword/',change_user_password, name='fp'),
]

if settings.DEBUG:
    urlpatterns += static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)
