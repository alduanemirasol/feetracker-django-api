from rest_framework import serializers
from rest_framework.exceptions import ValidationError
from rest_framework_simplejwt.tokens import RefreshToken, TokenError
from rest_framework_simplejwt.serializers import TokenRefreshSerializer

class StudentTokenRefreshSerializer(TokenRefreshSerializer):
    def validate(self, attrs):
        refresh_token = attrs.get("refresh")
        if not refresh_token:
            raise ValidationError({"refresh": "Refresh token is required."})
        
        try:
            refresh = RefreshToken(refresh_token)
            access = refresh.access_token
            access["student_id"] = refresh.get("student_id")
            return {"refresh": str(refresh), "access": str(access)}
        except TokenError:
            raise ValidationError({"refresh": "Invalid refresh token."})
    
class StudentLoginSerializer(serializers.Serializer):
    student_id = serializers.CharField()
    password = serializers.CharField(write_only=True)

class StudentRegisterSerializer(serializers.Serializer):
    student_id = serializers.CharField()
    email = serializers.EmailField()
    password = serializers.CharField(write_only=True)
    first_name = serializers.CharField()
    middle_name = serializers.CharField(required=False, allow_blank=True, default="")
    last_name = serializers.CharField()
    contact_number = serializers.CharField(required=False, allow_blank=True, allow_null=True)
    birthdate = serializers.DateField(required=False)
    address = serializers.CharField(required=False, allow_blank=True)

class StudentVerifyOtpSerializer(serializers.Serializer):
    student_id = serializers.CharField(max_length=20)
    otp_code = serializers.CharField(max_length=10)

class StudentResendOtpSerializer(serializers.Serializer):
    student_id = serializers.CharField(max_length=20)
    email = serializers.EmailField()

class StudentForgotPasswordRequestSerializer(serializers.Serializer):
    student_id = serializers.CharField(max_length=20)
    email = serializers.EmailField()

class StudentForgotPasswordVerifyOtpSerializer(serializers.Serializer):
    student_id = serializers.CharField(max_length=20)
    otp_code = serializers.CharField(max_length=10)
    new_password = serializers.CharField(min_length=5, max_length=128) 

class TreasurerLoginSerializer(serializers.Serializer):
    username = serializers.CharField()
    password = serializers.CharField(write_only=True)

class TreasurerRegisterSerializer(serializers.Serializer):
    username = serializers.CharField(max_length=50)
    email = serializers.EmailField()
    password = serializers.CharField(write_only=True)
    must_change_password = serializers.BooleanField(default=False)

class TreasurerSetNewPasswordSerializer(serializers.Serializer):
    username = serializers.CharField()
    new_password = serializers.CharField(write_only=True)

class TreasurerAddPaymentSerializer(serializers.Serializer):
    student_id = serializers.CharField(max_length=20)
    semester = serializers.IntegerField()
    school_year = serializers.IntegerField()
    amount_paid = serializers.DecimalField(max_digits=8, decimal_places=2)

class AdminLoginSerializer(serializers.Serializer):
    username = serializers.CharField()
    password = serializers.CharField(write_only=True)