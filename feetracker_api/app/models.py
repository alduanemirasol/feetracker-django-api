from django.db import models

class StudentRecord(models.Model):
    student_id = models.CharField(max_length=20, primary_key=True)
    email = models.EmailField(unique=True)
    full_name = models.CharField(max_length=100)
    first_name = models.CharField(max_length=50, default='')
    middle_name = models.CharField(max_length=50, default='')
    last_name = models.CharField(max_length=50, default='')
    contact_number = models.CharField(max_length=15, blank=True, null=True)
    birthdate = models.DateField(blank=True, null=True)
    address = models.TextField(blank=True, null=True)

class StudentAccount(models.Model):
    student = models.OneToOneField(StudentRecord, on_delete=models.CASCADE, primary_key=True)
    password = models.CharField(max_length=128)
    is_verified = models.BooleanField(default=False)
    otp_code = models.CharField(max_length=6, null=True, blank=True)
    otp_expiry = models.DateTimeField(null=True, blank=True)

class StudentPaymentHistory(models.Model):
    receipt_id = models.CharField(primary_key=True, max_length=20)
    student_id = models.CharField(max_length=20)
    semester = models.CharField(max_length=10)
    school_year = models.CharField(max_length=9)
    amount_paid = models.DecimalField(max_digits=8, decimal_places=2)
    payment_date = models.DateTimeField(auto_now_add=True)
    added_by = models.CharField(max_length=50, null=True, blank=True)

class TreasurerAccount(models.Model):
    username = models.CharField(max_length=50, unique=True)
    password = models.CharField(max_length=128)
    email = models.EmailField(unique=True)
    must_change_password = models.BooleanField(default=False)

class AdminAccount(models.Model):
    username = models.CharField(max_length=50, unique=True)
    password = models.CharField(max_length=128)
    email = models.EmailField(unique=True)
    must_change_password = models.BooleanField(default=False)