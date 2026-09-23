from django.contrib.auth.decorators import login_required, permission_required
from django.views import View
from rest_framework.permissions import IsAdminUser

@login_required
def user_detail(request, id):
    return None

class AdminStatsView(View):
    permission_classes = [IsAdminUser]

    def get(self, request):
        return None

@permission_required("app.upload")
def upload_avatar(request):
    file = request.FILES["avatar"]
    return None

def legacy(request, slug):
    return None

not_a_route = 'path("string-only/", views.fake)'
