import json
import random
import hashlib
import datetime
from .authentication import IsStudent, IsTreasurer, IsAdmin
from rest_framework import status
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework.permissions import IsAuthenticated
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework_simplejwt.views import TokenRefreshView 
from django.core.validators import validate_email
from django.core.exceptions import ValidationError
from django.db.models import Sum, Q, Max, F, FloatField, Case, When, Value
from django.contrib.auth.hashers import check_password, make_password
from django.core.mail import send_mail
from django.utils import timezone
from zoneinfo import ZoneInfo
from django.utils.timezone import now
from datetime import timedelta
from decimal import Decimal
from .pdf_report import generate_treasurer_report_pdf

from .models import StudentRecord, StudentAccount, StudentPaymentHistory, TreasurerAccount, AdminAccount
from .serializers import ( 
    StudentLoginSerializer, 
    StudentTokenRefreshSerializer, 
    StudentRegisterSerializer, 
    StudentVerifyOtpSerializer, 
    StudentResendOtpSerializer, 
    StudentForgotPasswordRequestSerializer,   
    StudentForgotPasswordVerifyOtpSerializer,
    TreasurerLoginSerializer,
    TreasurerRegisterSerializer,
    TreasurerSetNewPasswordSerializer,
    TreasurerAddPaymentSerializer,
    AdminLoginSerializer,
    AdminRegisterSerializer,
    AdminSetNewPasswordSerializer
)

# Global variables to track last receipt and deleted IDs
DELETED_RECEIPTS = set()

# Initialize LAST_RECEIPT_NUMBER from the DB
def get_last_receipt_number():
    last_receipt = StudentPaymentHistory.objects.aggregate(
        max_number=Max('receipt_id')
    )['max_number']

    if last_receipt and last_receipt.startswith("CTUG"):
        try:
            return int(last_receipt[4:])
        except ValueError:
            return 100
    return 100

# Get the last receipt number
LAST_RECEIPT_NUMBER = get_last_receipt_number()

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
            subject="Your FeeTracker Code",
            message=(
                f"Hi {full_name},\n\n"
                f"Welcome to FeeTracker!\n\n"
                f"Your code is: 🔐 {otp_code}\n\n"
                f"Valid for 10 minutes only.\n\n"
                f"If this wasn’t you, ignore this email.\n\n"
                f"- FeeTracker Team"
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
            subject="FeeTracker – OTP Code",
            message=(
                f"Hi {student.full_name},\n\n"
                f"Your OTP is: 🔐 {otp_code}\n\n"
                f"Valid for 10 minutes.\n\n"
                f"If not requested, ignore this email.\n\n"
                f"- FeeTracker Team"
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
            return Response({"payments": [], "data_hash": None}, status=status.HTTP_200_OK)

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

            # Convert to local time (same as dashboard)
            local_payment_date = timezone.localtime(obj.payment_date) if obj.payment_date else None

            if local_payment_date:
                if local_payment_date.time() == datetime.time(0, 0):
                    payment_date_str = local_payment_date.strftime("%B %d, %Y – No time data")
                else:
                    payment_date_str = local_payment_date.strftime("%B %d, %Y – %I:%M %p")
            else:
                payment_date_str = None

            payments.append({
                "receipt_id": obj.receipt_id,
                "student_id": obj.student_id,
                "full_name": full_name,
                "semester": obj.semester,
                "semester_str": semester_str, 
                "school_year": obj.school_year,
                "school_year_str": school_year_str,
                "semester_school_year_str": f"{semester_str} {school_year_str}",
                "amount_paid": f"+₱{obj.amount_paid:.2f}",
                "amount_paid_plain": f"₱{obj.amount_paid:.2f}",
                "payment_date": local_payment_date.isoformat() if local_payment_date else None,
                "payment_date_str": payment_date_str,
                "added_by": obj.added_by if obj.added_by else "Not specified"
            })

        response_data = {"payments": payments}

        # Compute hash
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
        if account.must_change_password:
            return Response(
                {
                    'must_change_password': True,
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
            'must_change_password': False
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
        account.must_change_password = False
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

        payments_query = StudentPaymentHistory.objects.all()

        # Apply filters only for total_paid
        filtered_payments = payments_query
        if semester:
            filtered_payments = filtered_payments.filter(semester=semester)
        if school_year:
            filtered_payments = filtered_payments.filter(school_year=school_year)

        total_paid = filtered_payments.aggregate(total=Sum("amount_paid"))["total"] or 0

        # Recent payments without filters
        recent_payments = list(payments_query.order_by("-payment_date")[:7])

        semester_map = {"1": "1st", "2": "2nd"}
        recent_list = []

        for p in recent_payments:
            local_date = p.payment_date.astimezone(ZoneInfo("Asia/Manila"))

            payment_time = local_date.time()
            if payment_time == datetime.time(0, 0):
                payment_date_str = local_date.strftime("%B %d, %Y - No time data")
            else:
                payment_date_str = local_date.strftime("%B %d, %Y - %I:%M %p").lstrip("0").replace(" 0", " ")

            recent_list.append({
                "receipt_id": p.receipt_id,
                "student_id": p.student_id,
                "semester": p.semester,
                "school_year": p.school_year,
                "amount_paid": f"₱{p.amount_paid:,.2f}",
                "payment_date": local_date.strftime("%Y-%m-%d %H:%M:%S"),
                "payment_date_str": payment_date_str,
                "semester_and_school_year_str": f"{semester_map.get(str(p.semester), p.semester)} Semester {p.school_year}-{int(p.school_year)+1}"
            })

        response_data = {
            "username": username,
            "role": "SSG Treasurer",
            "total_paid": f"₱{total_paid:,.2f}",
            "recent_payments": recent_list,
        }

        return Response(response_data, status=200)

# Treasurer Student Balance View
class TreasurerStudentBalanceView(APIView):
    permission_classes = [IsAuthenticated, IsTreasurer]

    def get(self, request, format=None):
        student_id = request.query_params.get('student_id')
        semester = request.query_params.get('semester')
        school_year = request.query_params.get('school_year')

        if not student_id:
            return Response(
                {"data": []},
                status=400
            )

        TOTAL_FEE = Decimal('300.00')

        payments_qs = StudentPaymentHistory.objects.filter(student_id=student_id)
        if semester:
            payments_qs = payments_qs.filter(semester=semester)
        if school_year:
            payments_qs = payments_qs.filter(school_year=school_year)

        total_paid = payments_qs.aggregate(total=Sum('amount_paid'))['total'] or Decimal('0.00')
        balance = TOTAL_FEE - total_paid

        response_data = [{
            "student_id": student_id,
            "total_paid": f"₱{total_paid:,.2f}",
            "balance": f"₱{balance:,.2f}"
        }]

        return Response({"data": response_data})

# Treasurer Add Payment View
class TreasurerAddPaymentView(APIView):
    permission_classes = [IsAuthenticated, IsTreasurer]
    MAX_PAID = Decimal("300.00")

    def post(self, request):
        global LAST_RECEIPT_NUMBER, DELETED_RECEIPTS

        serializer = TreasurerAddPaymentSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        student_id = serializer.validated_data['student_id']
        semester = serializer.validated_data['semester']
        school_year = serializer.validated_data['school_year']
        amount_paid = Decimal(serializer.validated_data['amount_paid'])

        if not self.can_add_payment(student_id, semester, school_year, amount_paid):
            total_paid = StudentPaymentHistory.objects.filter(
                student_id=student_id,
                semester=semester,
                school_year=school_year
            ).aggregate(total=Sum('amount_paid'))['total'] or Decimal("0.00")
            balance = self.MAX_PAID - total_paid
            return Response({"detail": f"Paid amount exceed. Balance: ₱{balance:,.2f}"}, status=400)

        # Generate receipt ID
        if DELETED_RECEIPTS:
            # Fill in deleted receipt IDs first
            receipt_id = DELETED_RECEIPTS.pop()
            number = int(receipt_id[4:])
        else:
            # Increment last receipt number
            LAST_RECEIPT_NUMBER += 1
            number = LAST_RECEIPT_NUMBER
            receipt_id = f"CTUG{number}"

        # Extract treasurer from JWT
        token_payload = getattr(request, 'auth', None)
        treasurer_username = token_payload.get('username') if token_payload else 'unknown'

        # Save payment
        payment = StudentPaymentHistory.objects.create(
            receipt_id=receipt_id,
            student_id=student_id,
            semester=semester,
            school_year=school_year,
            amount_paid=amount_paid,
            payment_date=now(),
            added_by=treasurer_username
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
                "added_by": payment.added_by
            },
            status=201
        )

    def can_add_payment(self, student_id, semester, school_year, new_amount):
        total_paid = StudentPaymentHistory.objects.filter(
            student_id=student_id,
            semester=semester,
            school_year=school_year
        ).aggregate(total=Sum('amount_paid'))['total'] or Decimal("0.00")
        return (total_paid + new_amount) <= self.MAX_PAID

# Treasurer Delete Payment View
class TreasurerDeletePaymentView(APIView):
    permission_classes = [IsAuthenticated, IsTreasurer]

    def delete(self, request, receipt_id, format=None):
        global DELETED_RECEIPTS

        receipt_id = receipt_id.strip()
        deleted_count, _ = StudentPaymentHistory.objects.filter(receipt_id=receipt_id).delete()

        if deleted_count == 0:
            return Response({"detail": f"Payment not found: {receipt_id}"}, status=status.HTTP_404_NOT_FOUND)

        # Track deleted receipt ID for reuse
        DELETED_RECEIPTS.add(receipt_id)

        return Response({"detail": f"Payment {receipt_id} deleted successfully"}, status=status.HTTP_200_OK)

# Treasurer Report View
class TreasurerReportView(APIView):
    permission_classes = [IsAuthenticated, IsTreasurer]
    
    def get(self, request):
        start_date_str = request.query_params.get('start_date')
        end_date_str = request.query_params.get('end_date')
        semester = request.query_params.get('semester')
        school_year = request.query_params.get('school_year')

        payments = StudentPaymentHistory.objects.all()

        def parse_date(date_str):
            if date_str:
                date_obj = timezone.datetime.fromisoformat(date_str)
                if timezone.is_naive(date_obj):
                    date_obj = timezone.make_aware(date_obj)
                return date_obj
            return None

        start_date = parse_date(start_date_str)
        end_date = parse_date(end_date_str)

        if start_date:
            payments = payments.filter(payment_date__gte=start_date)
        if end_date:
            end_date += timedelta(days=1)
            payments = payments.filter(payment_date__lt=end_date)
        if semester:
            payments = payments.filter(semester=semester)
        if school_year:
            payments = payments.filter(school_year=school_year)

        FULL_PAYMENT_AMOUNT = 300.00
        students = payments.values('student_id').annotate(total_paid=Sum('amount_paid'))
        total_of_students = students.count()
        total_of_fully_paid_students = students.filter(total_paid__gte=FULL_PAYMENT_AMOUNT).count()
        total_of_not_fully_paid_students = total_of_students - total_of_fully_paid_students

        total_money_received = students.aggregate(total=Sum('total_paid'))['total'] or 0
        total_balance_money = students.aggregate(
            total_balance=Sum(
                Case(
                    When(total_paid__lt=FULL_PAYMENT_AMOUNT, then=FULL_PAYMENT_AMOUNT - F('total_paid')),
                    default=Value(0),
                    output_field=FloatField()
                )
            )
        )['total_balance'] or 0
        expected_total_money_received = FULL_PAYMENT_AMOUNT * total_of_students

        fully_paid_percentage = (total_of_fully_paid_students / total_of_students * 100) if total_of_students else 0
        not_fully_paid_percentage = (total_of_not_fully_paid_students / total_of_students * 100) if total_of_students else 0

        # PDF download
        if request.query_params.get('download') == 'pdf':
            summary_data = [
                ["Total Money Received", total_money_received],
                ["Total Balance Money", total_balance_money],
                ["Expected Total Money Received", expected_total_money_received],
                ["Total Students", total_of_students],
                ["Fully Paid Students", total_of_fully_paid_students],
                ["Not Fully Paid Students", total_of_not_fully_paid_students],
                ["Fully Paid %", round(fully_paid_percentage, 2)],
                ["Not Fully Paid %", round(not_fully_paid_percentage, 2)]
            ]

            payment_data = [["Student ID", "Payment Date", "Amount Paid", "Semester", "Scho ol Year"]]
            for p in payments.order_by('student_id', 'payment_date'):
                payment_data.append([
                    p.student_id, 
                    p.payment_date.strftime("%Y-%m-%d"),
                    p.amount_paid, 
                    p.semester, 
                    p.school_year
                ])

            return generate_treasurer_report_pdf(
                summary_data,
                payment_data,
                semester or "N/A",
                school_year or "N/A",
                start_date_str or "N/A",
                end_date_str or "N/A"
            )

        # Default JSON response
        return Response({
            "total_money_received": float(total_money_received),
            "total_balance_money": float(total_balance_money),
            "expected_total_money_received": float(expected_total_money_received),
            "total_of_students": total_of_students,
            "total_of_fully_paid_students": total_of_fully_paid_students,
            "total_of_not_fully_paid_students": total_of_not_fully_paid_students,
            "fully_paid_percentage": round(fully_paid_percentage, 2),
            "not_fully_paid_percentage": round(not_fully_paid_percentage, 2)
        })
    
# Admin Login View
class AdminLoginView(APIView):
    def post(self, request):
        serializer = AdminLoginSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        username = serializer.validated_data['username']
        password = serializer.validated_data['password']

        try:
            account = AdminAccount.objects.get(username=username)
        except AdminAccount.DoesNotExist:
            return Response({'detail': 'Username not found'}, status=status.HTTP_401_UNAUTHORIZED)

        # Check password
        if not check_password(password, account.password):
            return Response({'detail': 'Invalid username or password'}, status=status.HTTP_401_UNAUTHORIZED)

        # Check if password is temporary
        if account.must_change_password:
            return Response(
                {
                    'must_change_password': True,
                    'detail': 'Your password is temporary. You must set a new password.'
                },
                status=status.HTTP_200_OK
            )

        # Generate JWT tokens
        refresh = RefreshToken()
        refresh['username'] = account.username
        refresh['role'] = 'admin'

        access = refresh.access_token
        access['username'] = account.username
        access['role'] = 'admin'

        return Response({
            'refresh': str(refresh),
            'access': str(access),
            'must_change_password': False
        }, status=status.HTTP_200_OK)

# Admin Create Student Account View
class AdminCreateStudentAccountView(APIView):
    permission_classes = [IsAuthenticated, IsAdmin]

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
            return Response({'detail': 'This Student ID is already verified.'}, status=status.HTTP_400_BAD_REQUEST)

        # Check if email is already used
        if StudentRecord.objects.filter(email=email).exists():
            return Response({'detail': 'This Email is already registered.'}, status=status.HTTP_400_BAD_REQUEST)

        full_name = " ".join(filter(None, [first_name, middle_name, last_name]))

        # Create or update student record
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

        # Create student account, bypass OTP, mark verified
        account, _ = StudentAccount.objects.get_or_create(student=student_record)
        account.password = make_password(password)
        account.otp_code = None
        account.otp_expiry = None
        account.is_verified = True
        account.save()

        return Response({'detail': 'Student account created and verified by admin.'}, status=status.HTTP_201_CREATED)
    
# Admin Create Treasurer Account View
class AdminCreateTreasurerAccountView(APIView):
    permission_classes = [IsAuthenticated, IsAdmin]

    def post(self, request):
        serializer = TreasurerRegisterSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        username = serializer.validated_data['username']
        email = serializer.validated_data['email']
        password = serializer.validated_data['password']
        must_change_password = serializer.validated_data.get('must_change_password', False)

        # Check if username is already used
        if TreasurerAccount.objects.filter(username=username).exists():
            return Response({'detail': 'This username is already registered.'}, status=status.HTTP_400_BAD_REQUEST)

        # Check if email is already used
        if TreasurerAccount.objects.filter(email=email).exists():
            return Response({'detail': 'This email is already registered.'}, status=status.HTTP_400_BAD_REQUEST)

        # Create treasurer account
        treasurer = TreasurerAccount.objects.create(
            username=username,
            email=email,
            password=make_password(password),
            must_change_password=must_change_password
        )

        return Response({'detail': 'Treasurer account successfully created.'}, status=status.HTTP_201_CREATED)

# Admin Create Admin View
class AdminCreateAdminAccountView(APIView):
    permission_classes = [IsAuthenticated, IsAdmin]

    def post(self, request):
        serializer = AdminRegisterSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        username = serializer.validated_data['username']
        email = serializer.validated_data['email']
        password = serializer.validated_data['password']
        must_change_password = serializer.validated_data.get('must_change_password', False)

        if AdminAccount.objects.filter(username=username).exists():
            return Response({'detail': 'This username is already registered.'}, status=status.HTTP_400_BAD_REQUEST)

        if AdminAccount.objects.filter(email=email).exists():
            return Response({'detail': 'This email is already registered.'}, status=status.HTTP_400_BAD_REQUEST)

        admin_account = AdminAccount.objects.create(
            username=username,
            email=email,
            password=make_password(password),
            must_change_password=must_change_password
        )

        return Response({'detail': 'Admin account successfully created.'}, status=status.HTTP_201_CREATED)
    
# Admin Set New Password View
class AdminSetNewPasswordView(APIView):
    def post(self, request):
        serializer = AdminSetNewPasswordSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        username = serializer.validated_data['username']
        new_password = serializer.validated_data['new_password']

        # Get account
        try:
            account = AdminAccount.objects.get(username=username)
        except AdminAccount.DoesNotExist:
            return Response({'detail': 'Username not found'}, status=status.HTTP_401_UNAUTHORIZED)

        # Update password
        account.password = make_password(new_password)
        account.must_change_password = False
        account.save()

        return Response(
            {'detail': 'Password changed successfully.'},
            status=status.HTTP_200_OK
        )