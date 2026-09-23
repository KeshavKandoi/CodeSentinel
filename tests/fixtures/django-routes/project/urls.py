from django.urls import include, path

urlpatterns = [
    path("api/", include("app.urls")),
    path("health/", lambda request: None),
]
