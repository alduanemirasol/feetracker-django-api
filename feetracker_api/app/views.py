import json
import random
import hashlib
import datetime
from .authentication import IsStudent, IsTreasurer
from rest_framework import status
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework.permissions import IsAuthenticated
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework_simplejwt.views import TokenRefreshView 
from rest_framework.parsers import MultiPartParser, FormParser
from django.core.validators import validate_email
from django.core.exceptions import ValidationError
from django.db.models import Sum, Q
from django.contrib.auth.hashers import check_password, make_password
from django.core.mail import send_mail
from django.utils import timezone
from django.utils.timezone import now
from datetime import timedelta
from decimal import Decimal

from .models import StudentRecord, StudentAccount, StudentPaymentHistory, TreasurerAccount
from .serializers import ( 
    StudentLoginSerializer, 
    StudentTokenRefreshSerializer, 
    StudentRegisterSerializer, 
    StudentVerifyOtpSerializer, 
    StudentResendOtpSerializer, 
    StudentForgotPasswordRequestSerializer,   
    StudentForgotPasswordVerifyOtpSerializer,
    TreasurerLoginSerializer,
    TreasurerSetNewPasswordSerializer,
    TreasurerAddPaymentSerializer
)

# Student Refresh View
class StudentTokenRefreshView(TokenRefreshView):
    serializer_class = StudentTokenRefreshSerializer

# Student Login View
class StudentLoginView(APIView):
    def post(self, request):
        serializer = StudentLoginSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        student_id = serializer.validated_data['student_id']
        password = serializer.validated_data['password']

        account = StudentAccount.objects.filter(student_id=student_id).first()
        if not account:
            return Response({'detail': 'Student ID not registered'}, status=status.HTTP_401_UNAUTHORIZED)

        if not account.is_verified:
            return Response({'detail': 'Account not verified'}, status=status.HTTP_403_FORBIDDEN)

        if not check_password(password, account.password):
            return Response({'detail': 'Invalid student ID or password'}, status=status.HTTP_401_UNAUTHORIZED)

        payload = {
            'student_id': account.student_id,
            'is_verified': account.is_verified,
            'role': 'student'
        }

        # Token creation
        refresh = RefreshToken()
        for k, v in payload.items():
            refresh[k] = v

        access = refresh.access_token
        for k, v in payload.items():
            access[k] = v

        return Response({
            'refresh': str(refresh),
            'access': str(access)
        })
    
# Student Register View
class StudentRegisterView(APIView):
    def post(self, request):
        serializer = StudentRegisterSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        student_id = serializer.validated_data['student_id']
        email = serializer.validated_data['email']
        password = serializer.validated_data['password']
        first_name = serializer.validated_data['first_name']
        middle_name = serializer.validated_data['middle_name']
        last_name = serializer.validated_data['last_name']
        contact_number = serializer.validated_data['contact_number']
        birthdate = serializer.validated_data['birthdate']
        address = serializer.validated_data['address']

        # Check if student_id is already verified
        if StudentAccount.objects.filter(student__student_id=student_id, is_verified=True).exists():
            return Response({'detail': 'This student ID is already verified.'}, status=status.HTTP_400_BAD_REQUEST)

        # Check if email is already used
        if StudentRecord.objects.filter(email=email).exists():
            return Response({'detail': 'This email is already registered.'}, status=status.HTTP_400_BAD_REQUEST)

        full_name = " ".join(filter(None, [first_name, middle_name, last_name]))
        otp_code = f"{random.randint(100000, 999999)}"
        otp_expiry = timezone.now() + timedelta(minutes=10)

        student_record, _ = StudentRecord.objects.update_or_create(
            student_id=student_id,
            defaults={
                'email': email,
                'first_name': first_name,
                'middle_name': middle_name,
                'last_name': last_name,
                'contact_number': contact_number,
                'birthdate': birthdate,
                'address': address,
                'full_name': full_name
            }
        )

        account, _ = StudentAccount.objects.get_or_create(student=student_record)
        account.password = make_password(password)
        account.otp_code = otp_code
        account.otp_expiry = otp_expiry
        account.is_verified = False
        account.save()  

        send_mail(
            subject="Your FeeTracker Verification Code",
            message=(
                f"Hi {full_name},\n\n"
                f"Thanks for signing up with FeeTracker! 🎉 We're really glad to have you here.\n\n"
                f"To finish setting up your account, please use the code below:\n\n"
                f"🔐 {otp_code}\n\n"
                f"This code will only work for the next 10 minutes, so don’t wait too long.\n\n"
                f"If you didn’t try to create an account, no worries — you can just ignore this message.\n\n"
                f"Talk soon,\n"
                f"The FeeTracker Team"
            ),
            from_email="noreply@feetracker.com",
            recipient_list=[email],
            fail_silently=False
        )

        return Response({'detail': 'OTP sent. Complete verification to activate your account.'}, status=status.HTTP_200_OK)
    
# Check Duplicate Student's Credentials
class CheckStudentDuplicateView(APIView):
    def post(self, request):
        student_id = request.data.get('student_id')
        email = request.data.get('email')

        if not student_id or not email:
            return Response(
                {'detail': 'Student ID and Email are required.'},
                status=status.HTTP_400_BAD_REQUEST
            )

        # Query only once for both student_id and email
        duplicates = StudentRecord.objects.filter(
            Q(student_id=student_id) | Q(email=email)
        ).values_list("student_id", "email")

        if duplicates:
            for sid, em in duplicates:
                if sid == student_id:
                    return Response(
                        {'detail': 'Student ID already exists.'},
                        status=status.HTTP_400_BAD_REQUEST
                    )
                if em == email:
                    return Response(
                        {'detail': 'Email already exists.'},
                        status=status.HTTP_400_BAD_REQUEST
                    )

        return Response(
            {'detail': 'No duplicates found.'},
            status=status.HTTP_200_OK
        )
    
# Student Verify OTP
class StudentVerifyOtpView(APIView):
    def post(self, request):
        serializer = StudentVerifyOtpSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        student_id = serializer.validated_data['student_id']
        otp_code = serializer.validated_data['otp_code']

        try:
            account = StudentAccount.objects.get(student_id=student_id)
        except StudentAccount.DoesNotExist:
            return Response({'detail': 'Account not found.'}, status=status.HTTP_404_NOT_FOUND)

        if account.is_verified:
            return Response({'detail': 'Account already verified.'}, status=status.HTTP_400_BAD_REQUEST)

        if not account.otp_code or not account.otp_expiry:
            return Response({'detail': 'No active OTP. Please request a new one.'}, status=status.HTTP_400_BAD_REQUEST)

        if timezone.now() > account.otp_expiry:
            account.otp_code = None
            account.otp_expiry = None
            account.save()
            return Response({'detail': 'OTP code has expired. Please request a new one.'}, status=status.HTTP_400_BAD_REQUEST)

        if account.otp_code != otp_code:
            return Response({'detail': 'Invalid OTP code.'}, status=status.HTTP_400_BAD_REQUEST)

        account.is_verified = True
        account.otp_code = None
        account.otp_expiry = None
        account.save()

        return Response({'detail': 'Account verified successfully.'}, status=status.HTTP_200_OK)
    
# Student Resend OTP View
class StudentResendOtpView(APIView):
    def post(self, request):
        serializer = StudentResendOtpSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        student_id = serializer.validated_data['student_id']
        email = serializer.validated_data['email']

        try:
            student = StudentRecord.objects.get(student_id=student_id, email=email)
        except StudentRecord.DoesNotExist:
            return Response({'detail': 'Student record not found or email mismatch.'}, status=status.HTTP_404_NOT_FOUND)

        try:
            account = StudentAccount.objects.get(student_id=student_id)
        except StudentAccount.DoesNotExist:
            return Response({'detail': 'Account not found. Please register first.'}, status=status.HTTP_404_NOT_FOUND)

        otp_code = f"{random.randint(100000, 999999)}"
        otp_expiry = timezone.now() + timedelta(minutes=10)

        account.otp_code = otp_code
        account.otp_expiry = otp_expiry
        account.save()

        send_mail(
            subject="FeeTracker – New OTP Code",
            message=(
                f"Hi {student.full_name},\n\n"
                f"A new OTP has been generated for your FeeTracker account.\n\n"
                f"🔐 OTP Code: {otp_code}\n\n"
                f"This code expires in 10 minutes.\n\n"
                f"If you didn’t request this, you can safely ignore it.\n\n"
                f"— FeeTracker Team"
            ),
            from_email="noreply@feetracker.com",
            recipient_list=[email],
            fail_silently=False
        )

        return Response({'detail': 'New OTP sent to your email.'}, status=status.HTTP_200_OK)
    
# Student Forgot Password Request View
class StudentForgotPasswordRequestView(APIView):
    def post(self, request):
        serializer = StudentForgotPasswordRequestSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        student_id = serializer.validated_data['student_id']
        email = serializer.validated_data['email']

        try:
            student = StudentRecord.objects.get(student_id=student_id)
        except StudentRecord.DoesNotExist:
            return Response({'detail': 'Student ID not found.'}, status=status.HTTP_404_NOT_FOUND)

        if student.email != email:
            return Response({'detail': 'This email is not registered to this Student ID.'}, status=status.HTTP_400_BAD_REQUEST)

        try:
            account = StudentAccount.objects.get(student_id=student_id)
        except StudentAccount.DoesNotExist:
            return Response({'detail': 'Account not found for this student_id.'}, status=status.HTTP_404_NOT_FOUND)

        otp_code = f"{random.randint(100000, 999999)}"
        otp_expiry = timezone.now() + timedelta(minutes=10)

        account.otp_code = otp_code
        account.otp_expiry = otp_expiry
        account.save()

        send_mail(
            subject="Your FeeTracker password reset code",
            message=(
                f"Hi {student.full_name},\n\n"
                f"You requested to reset your FeeTracker password. Here’s your one-time code:\n\n"
                f"🔐 {otp_code}\n\n"
                f"This code will work for the next 10 minutes, so please use it soon.\n"
                f"If you didn’t make this request, you can safely ignore this email.\n\n"
                f"Thanks,\n"
                f"The FeeTracker Team"
            ),
            from_email="noreply@feetracker.com",
            recipient_list=[email],
            fail_silently=False
        )

        return Response({'detail': 'Password reset OTP sent to email.'}, status=status.HTTP_200_OK)
    
# Student Forgot Password Verify OTP View
class StudentForgotPasswordVerifyOtpView(APIView):
    def post(self, request):
        serializer = StudentForgotPasswordVerifyOtpSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        student_id = serializer.validated_data['student_id']
        otp_code = serializer.validated_data['otp_code']
        new_password = serializer.validated_data['new_password']

        try:
            account = StudentAccount.objects.get(student_id=student_id)
        except StudentAccount.DoesNotExist:
            return Response({'detail': 'Account not found.'}, status=status.HTTP_404_NOT_FOUND)

        if not account.otp_code or not account.otp_expiry:
            return Response({'detail': 'No active OTP. Request a new one.'}, status=status.HTTP_400_BAD_REQUEST)

        if timezone.now() > account.otp_expiry:
            account.otp_code = None
            account.otp_expiry = None
            account.save()
            return Response({'detail': 'OTP has expired. Request a new one.'}, status=status.HTTP_400_BAD_REQUEST)

        if account.otp_code != otp_code:
            return Response({'detail': 'Invalid OTP code.'}, status=status.HTTP_400_BAD_REQUEST)

        account.password = make_password(new_password)
        account.otp_code = None
        account.otp_expiry = None
        account.save()

        return Response({'detail': 'Password has been reset successfully.'}, status=status.HTTP_200_OK)
    
# Student Profile View
class StudentProfileView(APIView):
    permission_classes = [IsAuthenticated, IsStudent]

    def get(self, request):
        student_id = request.auth.get("student_id")

        if not student_id:
            return Response({"detail": "Authentication failed."}, status=status.HTTP_401_UNAUTHORIZED)

        try:
            account = StudentAccount.objects.get(student_id=student_id)
        except StudentAccount.DoesNotExist:
            return Response({"detail": "Account not found."}, status=status.HTTP_404_NOT_FOUND)

        if not account.is_verified:
            return Response({"detail": "Account is not verified."}, status=status.HTTP_403_FORBIDDEN)

        try:
            student = StudentRecord.objects.get(student_id=student_id)
        except StudentRecord.DoesNotExist:
            return Response({"detail": "Student record not found."}, status=status.HTTP_404_NOT_FOUND)

        if not student.full_name or not student.email:
            return Response({"detail": "Incomplete student profile."}, status=status.HTTP_204_NO_CONTENT)

        birthdate_str = student.birthdate.strftime("%B %d, %Y") if student.birthdate else "Not provided"

        profile_data = {
            "student_id": student.student_id,
            "full_name": student.full_name,
            "email": student.email,
            "is_verified": "Verified" if account.is_verified else "Unverified",
            "contact_number": student.contact_number or "Not provided",
            "birthdate_str": birthdate_str,
            "address": student.address or "Not provided",
        }

        response_data = {"profile": profile_data}

        response_str = json.dumps(profile_data, sort_keys=True)
        data_hash = hashlib.sha256(response_str.encode()).hexdigest()
        response_data["data_hash"] = data_hash

        return Response(response_data, status=status.HTTP_200_OK)

# Student Email Configure
class EditStudentEmailView(APIView):
    permission_classes = [IsAuthenticated, IsStudent]

    def put(self, request):
        student_id = request.auth.get("student_id")
        if not student_id:
            return Response({"detail": "Authentication failed."}, status=status.HTTP_401_UNAUTHORIZED)

        new_email = request.data.get("email")
        if not new_email:
            return Response({"detail": "Email field is required."}, status=status.HTTP_400_BAD_REQUEST)

        try:
            validate_email(new_email)
        except ValidationError:
            return Response({"detail": "Invalid email format."}, status=status.HTTP_400_BAD_REQUEST)

        try:
            student = StudentRecord.objects.get(student_id=student_id)
        except StudentRecord.DoesNotExist:
            return Response({"detail": "Student record not found."}, status=status.HTTP_404_NOT_FOUND)

        if StudentRecord.objects.filter(email=new_email).exclude(student_id=student_id).exists():
            return Response({"detail": "This email is already in use."}, status=status.HTTP_400_BAD_REQUEST)

        student.email = new_email
        student.save()

        return Response({"detail": "Email updated successfully."}, status=status.HTTP_200_OK)

# Student Delete Account
class DeleteStudentAccountView(APIView):
    permission_classes = [IsAuthenticated, IsStudent]

    def delete(self, request):
        student_id = request.auth.get("student_id")
        if not student_id:
            return Response({"detail": "Authentication failed."}, status=status.HTTP_401_UNAUTHORIZED)

        try:
            student = StudentRecord.objects.get(student_id=student_id)
            student.delete()
            return Response({"detail": "Student account deleted successfully."}, status=status.HTTP_200_OK)
        except StudentRecord.DoesNotExist:
            return Response({"detail": "Student record not found."}, status=status.HTTP_404_NOT_FOUND)

# Student Change Password
class ChangeStudentPasswordView(APIView):
    permission_classes = [IsAuthenticated, IsStudent]

    def put(self, request):
        student_id = request.auth.get("student_id")
        if not student_id:
            return Response({"detail": "Authentication failed."}, status=status.HTTP_401_UNAUTHORIZED)

        current_password = request.data.get("current_password")
        new_password = request.data.get("new_password")

        if not current_password or not new_password:
            return Response({"detail": "Both current and new passwords are required."}, status=status.HTTP_400_BAD_REQUEST)

        try:
            student_account = StudentAccount.objects.get(student_id=student_id)
        except StudentAccount.DoesNotExist:
            return Response({"detail": "Student account not found."}, status=status.HTTP_404_NOT_FOUND)

        if not check_password(current_password, student_account.password):
            return Response({"detail": "Current password is incorrect."}, status=status.HTTP_400_BAD_REQUEST)

        if current_password == new_password:
            return Response({"detail": "New password must be different from the current password."}, status=status.HTTP_400_BAD_REQUEST)

        student_account.password = make_password(new_password)
        student_account.save()

        return Response({"detail": "Password updated successfully."}, status=status.HTTP_200_OK)
    
# Student Dashboard View
class StudentDashboardView(APIView):
    permission_classes = [IsAuthenticated, IsStudent]

    FIXED_FEE = Decimal(300)

    def get(self, request):
        student_id = request.auth.get("student_id")
        if not student_id:
            return Response({"detail": "Authentication failed."}, status=status.HTTP_401_UNAUTHORIZED)

        try:
            student = StudentRecord.objects.get(student_id=student_id)
        except StudentRecord.DoesNotExist:
            return Response({"detail": "Student record not found."}, status=status.HTTP_404_NOT_FOUND)

        payments = StudentPaymentHistory.objects.filter(student_id=student_id).order_by('-payment_date')
        total_paid = payments.aggregate(total=Sum('amount_paid'))['total'] or Decimal(0)

        summarized_payments = {}
        for payment in payments:
            key = (payment.semester, payment.school_year)
            summarized_payments[key] = summarized_payments.get(key, Decimal(0)) + payment.amount_paid

        all_payments_data = []
        for (semester, school_year), paid in sorted(
            summarized_payments.items(),
            key=lambda x: (int(x[0][1]), int(x[0][0])),
            reverse=True
        ):
            balance = max(self.FIXED_FEE - paid, Decimal(0))
            progress = round(paid / self.FIXED_FEE, 2)
            payment_status = (
                "Fully Paid" if progress >= 1
                else "On Progress" if paid > 0
                else "Unpaid"
            )
            semester_label = "1st Semester" if semester == "1" else "2nd Semester"
            school_year_display = f"{school_year}-{int(school_year) + 1}"

            all_payments_data.append({
                "semester_and_school_year": f"{semester_label} {school_year_display}",
                "amount_paid": f"Paid: ₱{paid:,.2f}",
                "balance": f"Left: ₱{balance:,.2f}",
                "progress": float(progress),
                "payment_status": payment_status,
            })

        recent_payments_data = []
        for p in payments[:5]:
            local_payment_date = timezone.localtime(p.payment_date)
            if local_payment_date.time() == datetime.time(0, 0):
                formatted_date = local_payment_date.strftime("%B %d, %Y") + " – No time data"
            else:
                formatted_date = local_payment_date.strftime("%B %d, %Y – %I:%M %p")

            recent_payments_data.append({
                "semester_and_school_year": (
                    "1st Semester" if p.semester == "1" else "2nd Semester"
                ) + f" {p.school_year}-{int(p.school_year) + 1}",
                "amount_paid": f"+₱{p.amount_paid:.2f}",
                "payment_date": formatted_date,
            })

        response_data = {
            "student": {
                "student_id": student.student_id,
                "first_name": student.first_name,
                "total_paid": f"₱{total_paid:,.2f}"
            },
            "all_payments": all_payments_data,
            "recent_payments": recent_payments_data,
        }

        response_str = json.dumps(response_data, sort_keys=True)
        data_hash = hashlib.sha256(response_str.encode()).hexdigest()
        response_data["data_hash"] = data_hash

        return Response(response_data, status=status.HTTP_200_OK)

# Student Payment History View
class StudentPaymentHistoryView(APIView):
    permission_classes = [IsAuthenticated, IsStudent]

    def get(self, request):
        student_id = request.auth.get("student_id")
        semester = request.query_params.get("semester")
        school_year = request.query_params.get("school_year")

        if not student_id:
            return Response({"detail": "Authentication failed."}, status=status.HTTP_401_UNAUTHORIZED)

        filters = {"student_id": student_id}
        if semester in ["1", "2"]:
            filters["semester"] = semester
        if school_year and school_year.isdigit():
            filters["school_year"] = school_year

        queryset = StudentPaymentHistory.objects.filter(**filters).order_by("-payment_date")

        if not queryset.exists():
            return Response({
                "payments": [],
                "data_hash": None
            }, status=status.HTTP_200_OK)

        try:
            student = StudentRecord.objects.get(student_id=student_id)
            full_name = student.full_name
        except StudentRecord.DoesNotExist:
            full_name = ""

        payments = []
        for obj in queryset:
            semester_str = "1st Semester" if obj.semester == "1" else "2nd Semester"
            try:
                sy_start = int(obj.school_year)
                school_year_str = f"{sy_start}-{sy_start + 1}"
            except:
                school_year_str = ""

            if obj.payment_date.time() == datetime.time(0, 0):
                payment_date_str = obj.payment_date.strftime("%B %d, %Y - No time data")
            else:
                payment_date_str = obj.payment_date.strftime("%B %d, %Y – %I:%M %p")

            payments.append({
                "receipt_id": obj.receipt_id,
                "student_id": obj.student_id,
                "full_name": full_name,
                "semester": obj.semester,
                "semester_str": semester_str,
                "school_year": obj.school_year,
                "school_year_str": school_year_str,
                "semester_school_year_str": f"{semester_str} {school_year_str}",
                "amount_paid": f"+₱{obj.amount_paid}",
                "amount_paid_plain": f"₱{obj.amount_paid}",
                "payment_date": obj.payment_date.isoformat() if obj.payment_date else None,
                "payment_date_str": payment_date_str
            })

        response_data = {
            "payments": payments
        }

        response_str = json.dumps(response_data, sort_keys=True)
        data_hash = hashlib.sha256(response_str.encode()).hexdigest()
        response_data["data_hash"] = data_hash

        return Response(response_data, status=status.HTTP_200_OK)
    
# Treasurer Login View
class TreasurerLoginView(APIView):
    def post(self, request):
        serializer = TreasurerLoginSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        username = serializer.validated_data['username']
        password = serializer.validated_data['password']

        try:
            account = TreasurerAccount.objects.get(username=username)
        except TreasurerAccount.DoesNotExist:
            return Response({'detail': 'Username not found'}, status=status.HTTP_401_UNAUTHORIZED)

        # Check password
        if not check_password(password, account.password):
            return Response({'detail': 'Invalid username or password'}, status=status.HTTP_401_UNAUTHORIZED)

        # Check if password is temporary
        if account.is_temporary:
            return Response(
                {
                    'is_temporary': True,
                    'detail': 'Your password is temporary. You must set a new password.'
                },
                status=status.HTTP_200_OK
            )

        # Generate JWT tokens
        refresh = RefreshToken()
        refresh['username'] = account.username
        refresh['role'] = 'treasurer'

        access = refresh.access_token
        access['username'] = account.username
        access['role'] = 'treasurer'

        return Response({
            'refresh': str(refresh),
            'access': str(access),
            'is_temporary': False
        }, status=status.HTTP_200_OK)
    
# Treasurer Set New Password View
class TreasurerSetNewPasswordView(APIView):
    def post(self, request):
        serializer = TreasurerSetNewPasswordSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        username = serializer.validated_data['username']
        new_password = serializer.validated_data['new_password']

        # Get account
        try:
            account = TreasurerAccount.objects.get(username=username)
        except TreasurerAccount.DoesNotExist:
            return Response({'detail': 'Username not found'}, status=status.HTTP_401_UNAUTHORIZED)

        # Update password
        account.password = make_password(new_password)
        account.is_temporary = False
        account.save()

        return Response(
            {'detail': 'Password changed successfully.'},
            status=status.HTTP_200_OK
        )
    
# Treasurer Dashboard View
class TreasurerDashboardView(APIView):
    permission_classes = [IsAuthenticated, IsTreasurer]

    def get(self, request):
        token_payload = getattr(request, 'auth', None)
        username = token_payload.get('username') if token_payload else None

        semester = request.query_params.get("semester")
        school_year = request.query_params.get("school_year")

        filtered_for_total = StudentPaymentHistory.objects.all()
        if semester:
            filtered_for_total = filtered_for_total.filter(semester=semester)
        if school_year:
            filtered_for_total = filtered_for_total.filter(school_year=school_year)

        total_paid = filtered_for_total.aggregate(total=Sum("amount_paid"))["total"] or 0

        recent_payments = StudentPaymentHistory.objects.order_by("-payment_date")[:7]

        recent_list = []
        semester_map = {"1": "1st", "2": "2nd"}

        for p in recent_payments:
            payment_time = p.payment_date.time()
            if payment_time == datetime.time(0, 0):
                payment_date_str = p.payment_date.strftime("%B %d, %Y - No time data")
            else:
                payment_date_str = p.payment_date.strftime("%B %d, %Y - %I:%M %p").lstrip("0").replace(" 0", " ")

            recent_list.append({
                "receipt_id": p.receipt_id,
                "student_id": p.student_id,
                "semester": p.semester,
                "school_year": p.school_year,
                "amount_paid": f"₱{p.amount_paid:,.2f}",
                "payment_date": p.payment_date.strftime("%Y-%m-%d %H:%M:%S"),
                "payment_date_str": payment_date_str,
                "semester_and_school_year_str": f"{semester_map.get(str(p.semester), p.semester)} Semester {p.school_year}-{int(p.school_year)+1}"
            })

        response_data = {
            "username": username,
            "role": "SSG Treasurer",
            "total_paid": f"₱{total_paid:,.2f}",
            "recent_payments": recent_list,
        }

        # Optional: Add hash for integrity
        response_str = json.dumps(response_data, sort_keys=True)
        data_hash = hashlib.sha256(response_str.encode()).hexdigest()
        response_data["data_hash"] = data_hash

        return Response(response_data, status=200)

# Treasurer Student Balance View
class TreasurerStudentBalanceView(APIView):
    permission_classes = [IsAuthenticated, IsTreasurer]

    # Static variable: 1 = show latest, 0 = hide latest
    SHOW_LATEST = 1

    def get(self, request, format=None):
        student_id = request.query_params.get('student_id')
        semester = request.query_params.get('semester')
        school_year = request.query_params.get('school_year')

        response_list = []

        if student_id:
            student_record = StudentRecord.objects.filter(student_id=student_id).first()
            if student_record:
                payments = StudentPaymentHistory.objects.filter(student_id=student_id)

                if semester:
                    payments = payments.filter(semester=int(semester))
                if school_year:
                    payments = payments.filter(school_year=int(school_year))

                total_paid = payments.aggregate(total=Sum('amount_paid'))['total'] or Decimal('0.00')
                TOTAL_FEE = Decimal('300.00')
                balance = TOTAL_FEE - total_paid

                response_list.append({
                    "student_id": student_id,
                    "full_name": student_record.full_name,
                    "total_paid": f"₱{total_paid:,.2f}",
                    "balance": f"₱{balance:,.2f}"
                })

        else:
            if self.SHOW_LATEST == 1:
                latest_payments = StudentPaymentHistory.objects.order_by('-receipt_id')[:10]

                for payment in latest_payments:
                    student_record = StudentRecord.objects.filter(student_id=payment.student_id).first()
                    if student_record:
                        full_name = student_record.full_name
                    else:
                        full_name = "N/A"

                    total_paid = payment.amount_paid
                    TOTAL_FEE = Decimal('300.00')
                    balance = TOTAL_FEE - total_paid

                    response_list.append({
                        "student_id": payment.student_id,
                        "full_name": full_name,
                        "total_paid": f"₱{total_paid:,.2f}",
                        "balance": f"₱{balance:,.2f}"
                    })

        # Compute hash for UI update checks
        response_data = {"data": response_list}
        response_str = json.dumps(response_list, sort_keys=True)
        data_hash = hashlib.sha256(response_str.encode()).hexdigest()
        response_data["data_hash"] = data_hash

        return Response(response_data, status=status.HTTP_200_OK)
    
# Treasurer Add New Payment
class TreasurerAddPaymentView(APIView):
    def post(self, request):
        serializer = TreasurerAddPaymentSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        student_id = serializer.validated_data['student_id']
        semester = serializer.validated_data['semester']
        school_year = serializer.validated_data['school_year']
        amount_paid = serializer.validated_data['amount_paid']

        # Check if student exists
        if not StudentRecord.objects.filter(student_id=student_id).exists():
            return Response(
                {"detail": "Student ID not found."},
                status=status.HTTP_400_BAD_REQUEST
            )

        # Auto-generate receipt_id
        last_receipt = StudentPaymentHistory.objects.order_by('-receipt_id').first()
        if last_receipt:
            try:
                last_num = int(last_receipt.receipt_id.split('-')[-1])
            except ValueError:
                last_num = 0
            receipt_id = f"RCP-{last_num+1:04d}"
        else:
            receipt_id = "RCP-0001"

        # Save payment
        payment = StudentPaymentHistory.objects.create(
            receipt_id=receipt_id,
            student_id=student_id,
            semester=semester,
            school_year=school_year,
            amount_paid=amount_paid,
            payment_date=now()
        )

        return Response(
            {
                "detail": "Payment recorded successfully.",
                "receipt_id": payment.receipt_id,
                "student_id": payment.student_id,
                "semester": payment.semester,
                "school_year": payment.school_year,
                "amount_paid": str(payment.amount_paid),
                "payment_date": payment.payment_date,
            },
            status=status.HTTP_201_CREATED
        )