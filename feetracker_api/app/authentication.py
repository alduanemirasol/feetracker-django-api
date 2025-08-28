from rest_framework.permissions import BasePermission
from rest_framework_simplejwt.authentication import JWTAuthentication

class AuthlessUser:
    is_authenticated = True

class IsStudent(BasePermission):
    def has_permission(self, request, view):
        return request.auth and request.auth.get("role") == "student"
    
class IsTreasurer(BasePermission):
    def has_permission(self, request, view):
        return request.auth and request.auth.get("role") == "treasurer"

class CustomJWTAuthentication(JWTAuthentication):
    def get_user(self, validated_token):
        return AuthlessUser()

    def authenticate(self, request):
        header = self.get_header(request)
        if header is None:
            return None
        raw_token = self.get_raw_token(header)
        if raw_token is None:
            return None
        validated_token = self.get_validated_token(raw_token)
        return (AuthlessUser(), validated_token)