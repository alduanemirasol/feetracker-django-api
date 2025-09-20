from django.contrib import admin
from django.utils.crypto import get_random_string
from django.contrib.auth.hashers import make_password
from django.core.mail import send_mail
from .models import TreasurerAccount

@admin.register(TreasurerAccount)
class TreasurerAdmin(admin.ModelAdmin):
    list_display = ('username', 'email', 'must_change_password')
    fields = ('username', 'email', 'password', 'must_change_password')

    def save_model(self, request, obj, form, change):
        if not change or 'password' in form.changed_data:
            if not obj.password:
                temp_password = get_random_string(length=8)
                obj.password = make_password(temp_password)
            else:
                temp_password = form.cleaned_data['password']
                obj.password = make_password(temp_password)

            super().save_model(request, obj, form, change)

            if not change:
                send_mail(
                    subject="Welcome to FeeTracker!",
                    message=(
                        f"Hi,\n"
                        f"Your Treasurer account is ready.\n"
                        f"Username: {obj.username}\n"
                        f"Temporary Password: {temp_password}\n"
                        f"Please log in and set a new password as soon as possible.\n"
                        f"Thanks,\nThe FeeTracker Team"
                    ),
                    from_email="noreply@feetracker.com",
                    recipient_list=[obj.email],
                    fail_silently=False
                )
        else:
            super().save_model(request, obj, form, change)