from django.urls import path

from .views import LookupAPIView

urlpatterns = [
    path("lookup/", LookupAPIView.as_view(), name="lookup"),
]
