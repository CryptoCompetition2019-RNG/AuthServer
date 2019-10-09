from django.urls import path

from .register_views import register_api
from .pcauth_views import pcauth_api1, pcauth_api2, pcauth_api3
from .mobileauth_views import mobileauth_api1, mobileauth_api2
from .dynamicauth_views import dynamicauth_api1, dynamicauth_api2, dynamicauth_api3

urlpatterns = [
    path('register_api/', register_api),

    path('pcauth_api1/', pcauth_api1),
    path('pcauth_api2/', pcauth_api2),
    path('pcauth_api3/', pcauth_api3),

    path('mobileauth_api1/', mobileauth_api1),
    path('mobileauth_api2/', mobileauth_api2),

    path('dynamicauth_api1/', dynamicauth_api1),
    path('dynamicauth_api2/', dynamicauth_api2),
    path('dynamicauth_api3/', dynamicauth_api3),
]
