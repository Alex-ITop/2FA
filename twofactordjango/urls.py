
from django.contrib import admin
from django.urls import path, include, re_path

from django.contrib import admin
# from django_otp.admin import OTPAdminSite

# class OTPAdmin(OTPAdminSite):
#     pass
# from django.contrib.auth.models import  User
# from django_otp.plugins.otp_totp.models import  TOTPDevice
# admin_site = OTPAdmin(name="OTPAdmin")
# admin_site.register(User)
# admin_site.register(TOTPDevice)

from two_factor.admin import AdminSiteOTPRequired
from two_factor.urls import urlpatterns as tf_urls

from django.conf import settings
from django.http import  HttpResponseRedirect
from django.contrib.auth import REDIRECT_FIELD_NAME
from django.contrib.auth.views import redirect_to_login
from django.shortcuts import resolve_url
from django.urls import reverse
from django.utils.http import url_has_allowed_host_and_scheme
from two_factor.admin import AdminSiteOTPRequired, AdminSiteOTPRequiredMixin


class AdminSiteOTPRequiredMixinRedirSetup(AdminSiteOTPRequired):
    def login(self, request, extra_context=None):
        redirect_to = request.POST.get(
            REDIRECT_FIELD_NAME, request.GET.get(REDIRECT_FIELD_NAME)
        )
        # For users not yet verified the AdminSiteOTPRequired.has_permission
        # will fail. So use the standard admin has_permission check:
        # (is_active and is_staff) and then check for verification.
        # Go to index if they pass, otherwise make them setup OTP device.
        if request.method == "GET" and super(
            AdminSiteOTPRequiredMixin, self
        ).has_permission(request):
            # Already logged-in and verified by OTP
            if request.user.is_verified():
                # User has permission
                index_path = reverse("admin:index", current_app=self.name)
            else:
                # User has permission but no OTP set:
                index_path = reverse("two_factor:setup", current_app=self.name)
            return HttpResponseRedirect(index_path)

        if not redirect_to or not url_has_allowed_host_and_scheme(
            url=redirect_to, allowed_hosts=[request.get_host()]
        ):
            redirect_to = resolve_url(settings.LOGIN_REDIRECT_URL)

        return redirect_to_login(redirect_to)
from django.contrib import admin
admin.site.__class__ = AdminSiteOTPRequiredMixinRedirSetup

urlpatterns = [
    path('admin/', admin.site.urls),
    path('', include(tf_urls, "two_factor")),

]
