import re
from django.shortcuts import render,redirect
from .forms import UserRegistrationForm
from .models import Profile
import requests
from django.contrib.auth.hashers import make_password
import random
from django.contrib.auth.models import User
from django.contrib import messages
from django.contrib.auth import authenticate, login 
from django.core.mail import send_mail
from django.conf import settings
from django.http import HttpResponse


def send_email_otp(email, otp):
    #  Implementation using your chosen email service.  Example using smtplib (less secure):
    import smtplib
    from email.mime.text import MIMEText
    msg = MIMEText(f'Your OTP is: {otp}')
    msg['Subject'] = 'Your OTP'
    msg['From'] = 'alextopig.trello@gmail.com'
    msg['To'] = email
    with smtplib.SMTP('smtp.gmail.com', 587) as smtp:  # Replace with your SMTP settings
        smtp.starttls()
        smtp.login('alextopig.trello@gmail.com', 'Njgjhrjd15092002')
        smtp.send_message(msg)
    print(f"OTP sent to {email}: {otp}") # For testing purposes, replace with actual sending logic


def Registration(request):
    if request.method == "POST":
        fm = UserRegistrationForm(request.POST)
        # up = UserProfileForm(request.POST)
        if fm.is_valid():
            email = fm.cleaned_data['email']
            username = fm.cleaned_data['username']
            password = fm.cleaned_data['password1']
            
            # phone_number = up.cleaned_data['phone_number']

            otp = random.randint(1000, 9999)
            request.session['otp'] = otp
            request.session['email'] = email  #Store email only.
            request.session['username'] = username

            send_email_otp(email, otp)  # Send OTP to email
            return redirect('/registration/otp/')

    else:
        fm = UserRegistrationForm()
        # up = UserProfileForm()
    context = {'fm': fm}
    return render(request, 'registration.html', context)


def otpRegistration(request):
    if request.method == "POST":
        user_otp = request.POST['otp']
        otp = request.session.get('otp')
        username = request.session['username']
        hashed_password = make_password(request.POST.get('password')) #Get password from POST, not session!
        email = request.session.get('email')

        if int(user_otp) == otp:
            User.objects.create(
                username=username,
                email=email,
                password=hashed_password
            )
            user_instance = User.objects.get(username=username)

            messages.success(request, 'Registration Successfully Done !!')
            return redirect('/login/')
        else:
            messages.error(request, 'Wrong OTP')
    return render(request, 'registration-otp.html')


def userLogin(request):

    try :
        if request.session.get('failed') > 2:
            return HttpResponse('<h1> You have to wait for 5 minutes to login again</h1>')
    except:
        request.session['failed'] = 0
        request.session.set_expiry(100)



    if request.method == "POST":
        username = request.POST['username']
        password = request.POST['password']
        user = authenticate(request,username=username,password=password)
        if user is not None:
            request.session['username'] = username
            request.session['password'] = password
            u = User.objects.get(username=username)
            
            otp = random.randint(1000,9999)
            request.session['login_otp'] = otp
            message = f'your otp is {otp}'
            
            return redirect('/login/otp/')
        else:
            messages.error(request,'username or password is wrong')
    return render(request,'login.html')

def otpLogin(request):
    if request.method == "POST":
        username = request.session['username']
        password = request.session['password']
        otp = request.session.get('login_otp')
        u_otp = request.POST['otp']
        if int(u_otp) == otp:
            user = authenticate(request,username=username,password=password)
            if user is not None:
                login(request,user)
                request.session.delete('login_otp')
                messages.success(request,'login successfully')
                return redirect('/')
        else:
            messages.error(request,'Wrong OTP')
    return render(request,'login-otp.html')

def home(request):
    if request.method == "POST":
        otp = random.randint(1000,9999)
        request.session['email_otp'] = otp
        message = f'your otp is {otp}'
        user_email = request.user.email

        send_mail(
            'Email Verification OTP',
            message,
            settings.EMAIL_HOST_USER,
            [user_email],
            fail_silently=False,
        )
        return redirect('/email-verify/')

    return render(request,'home.html')

def email_verification(request):
    if request.method == "POST":
        u_otp = request.POST['otp']
        otp = request.session['email_otp']
        if int(u_otp) == otp:
           p =  Profile.objects.get(user=request.user)
           p.email_verified = True
           p.save()
           messages.success(request,f'Your email {request.user.email} is verified now')
           return redirect('/')
        else:
            messages.error(request,'Wrong OTP')


    return render(request,'email-verified.html')

def forget_password(request):
    if request.method == "POST":
        email = request.POST['email']
        if User.objects.filter(email=email).exists():
            uid = User.objects.get(email=email)
            url = f'http://127.0.0.1:8000/change-password/{uid.profile.uuid}'
            send_mail(
            'Reset Password',
            url,
            settings.EMAIL_HOST_USER,
            [email],
            fail_silently=False,
        )
            return redirect('/forget-password/done/')
        else:
            messages.error(request,'email address is not exist')
    return render(request,'forget-password.html')

def change_password(request,uid):
    try:
        if Profile.objects.filter(uuid = uid).exists():
            if request.method == "POST":
                pass1 = 'password1'in request.POST and request.POST['password1']
                pass2 =  'password2'in request.POST and request.POST['password2']
                if pass1 == pass2:
                    p = Profile.objects.get(uuid=uid)
                    u = p.user
                    user = User.objects.get(username=u)
                    user.password = make_password(pass1)
                    user.save()
                    messages.success(request,'Password has been reset successfully')
                    return redirect('/login/')
                else:
                    return HttpResponse('Two Password did not match')
                
        else:
            return HttpResponse('Wrong URL')
    except:
        return HttpResponse('Wrong URL')
    return render(request,'change-password.html')