from django.urls import path, re_path
from . import views

urlpatterns = [
    path("users/<int:id>/", views.user_detail, name="user-detail"),
    path("admin/stats/", views.AdminStatsView.as_view(), name="admin-stats"),
    path("upload/", views.upload_avatar, name="upload"),
    re_path(r"^legacy/(?P<slug>[-\\w]+)/$", views.legacy, name="legacy"),
    # path("commented-out/", views.nope),
]
