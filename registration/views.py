from django.shortcuts import render, redirect
from django.contrib.auth import login as auth_login, logout, authenticate
from .forms import UserForm, UserUpdateForm,ProfileUpdateForm,PasswordResetForm,SetNewPasswordForm
from django.contrib.auth.forms import PasswordChangeForm
from django.contrib.sites.shortcuts import get_current_site
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from django.template.loader import render_to_string
from .tokens import account_activation_token
from django.utils.encoding import force_bytes, force_text
import requests, json
from django.core.mail import EmailMessage,send_mail
from .models import *
from django.http import HttpResponseRedirect, HttpResponse
from django.urls import reverse
from django.contrib.auth.decorators import login_required
from django.views.generic.detail import DetailView
from django.views.decorators.csrf import csrf_exempt
from django.contrib import messages
from django.contrib.auth import update_session_auth_hash
from django.contrib.auth import views as auth_views
from .models import Profile

# ------------------------------------------------------------------------------------------------------------------------
def main_page(request):
    if request.user.is_authenticated:
        return render(request, 'travelers/index.html')
    return render(request, 'travelers/index.html')


# ------------------------------------------------------------------------------------------------------------------------

def about_page(request):
    return render(request, 'travelers/about.html')


def contact(request):
    return render(request, 'reg/contact.html')


def user_logout(request):
    logout(request)
    return redirect(reverse('main_page'))


def user_login(request):
    if request.method == 'POST':
        username = request.POST.get('username')
        password = request.POST.get('password')
        user = authenticate(username=username, password=password)
        if user:
            if user.is_active:
                auth_login(request, user)
                return redirect(reverse('home'))
            else:
                return HttpResponse("Your account was inactive.")
        else:
            messages.error(request, 'username or password is not correct')
            return render(request, 'reg/login.html', {})
    else:
        return render(request, 'reg/login.html', {})


def signup(request):
    registered = False
    if request.method == 'POST':
        user_form = UserForm(request.POST)
        if user_form.is_valid() and user_form.cleaned_data['password'] == user_form.cleaned_data['confirm_password']:
            user = user_form.save(commit=False)
            user.is_active = False
            user.set_password(user.password)
            user.save()
            registered = True
            current_site = get_current_site(request)
            domain = current_site.domain
            print(domain)
            message = render_to_string('reg/acc_active_email.html', {
                'user': user,
                'domain': current_site.domain,
                'uid': urlsafe_base64_encode(force_bytes(user.pk)),
                'token': account_activation_token.make_token(user),
            })
            to_email = user_form.cleaned_data.get('email')
            name = user_form.cleaned_data.get('username')
            password = user_form.cleaned_data.get('password')
            print(name)
            print(password)
            response = requests.get(
                "http://api.quickemailverification.com/v1/verify?email=" + to_email + "&apikey=15aef1e3ebf4f0e3357b6aab94bb77833e639fc261b2d32903e1895bd330")
            result = response.json()

            if (result['did_you_mean'] == '' and result['result'] == "valid"):

                mail_subject = 'Activate your blog account.'
                to_email = user_form.cleaned_data.get('email')
                email = EmailMessage(mail_subject, message, to=[to_email])
                email.send()
                return render(request, 'reg/emailsent.html', {})

            else:
                try:
                    u = User.objects.get(username=name)
                    u.delete()
                except User.DoesNotExist:
                    return HttpResponse('The email given is invalid please check it ')
                except Exception as e:
                    return render(request, 'reg/signup.html', {'user_form': user_form})
                return HttpResponse('The email given is invalid please check it ')
        elif user_form.data['password'] != user_form.data['confirm_password']:
            user_form.add_error('confirm_password', 'The passwords do not match')

    else:
        user_form = UserForm()
    return render(request, 'reg/signup.html', {'user_form': user_form, 'registered': registered})


def activate(request, uidb64, token):
    try:
        uid = force_text(urlsafe_base64_decode(uidb64))
        user = User.objects.get(pk=uid)
    except(TypeError, ValueError, OverflowError, User.DoesNotExist):
        user = None
    if user is not None and account_activation_token.check_token(user, token):
        user.is_active = True
        user.save()
        auth_login(request, user)
        return HttpResponseRedirect(reverse('home'))

    else:
        return HttpResponse('Activation link is invalid!')


# ------------------------------------------------------------------------------------------------------------------------


@csrf_exempt
class IndexView(DetailView):
    model = User
    template_name = 'reg/LoginHome.html'


# @login_required
def home(request):
    user = request.user
    context = {'user': user}
    return render(request, 'travelers/index.html', context=context)


@login_required
def viewprofile(request):
    args = {'user': request.user}
    return render(request, 'reg/viewprofile.html', args)


@login_required
def edit_profile(request):
    if request.method == 'POST':
        u_form = UserUpdateForm(request.POST, instance=request.user)
        p_form = ProfileUpdateForm(request.POST,
                                   request.FILES,
                                   instance=request.user.profile)
        if u_form.is_valid() and p_form.is_valid():
            u_form.save()
            p_form.save()
            messages.success(request, f'Your account has been updated!')
            return redirect('editprofile')

    else:
        u_form = UserUpdateForm(instance=request.user)
        p_form = ProfileUpdateForm(instance=request.user.profile)

    context = {
        'u_form': u_form,
        'p_form': p_form
    }

    return render(request, 'reg/edit_profile.html', context)

@login_required
def change_password(request):
    if request.method == 'POST':
        form = PasswordChangeForm(request.user, request.POST)
        if form.is_valid():
            user = form.save()
            update_session_auth_hash(request, user)  # Imp
            messages.success(
                request, 'Your password was successfully updated!')
            return redirect('viewprofile')
        else:
            messages.error(request, 'Please correct the error below.')
    else:
        form = PasswordChangeForm(request.user)
    return render(request, 'reg/change_password.html', {
        'form': form
    })

# --------------------------------------

def change_user_password(request):
    if request.method == 'POST':
        form = PasswordResetForm(request.POST)
        if form.is_valid():
            email = form.cleaned_data.get('Email')
            user = User.objects.get(email=email)
            if user:
                # socket.getaddrinfo('localhost', 8080)
                current_site = get_current_site(request)
                mail_subject = 'Reset Your Password'
                message = render_to_string('reg/password_reset_email.html', {
                    'user': user,
                    'domain': current_site.domain,
                    'uid': urlsafe_base64_encode(force_bytes(user.pk)),
                    'token': account_activation_token.make_token(user),
                })
                to_email = form.cleaned_data.get('Email')
                send_mail(mail_subject, message, 'sandeepsowpati99@gmail.com', [to_email])
                return render(request, 'reg/password_reset_done.html', {})
            else:
                return HttpResponse('Email does not exist')
        else:
            return HttpResponse('Please enter a valid email')
    else:
        form = PasswordResetForm()
        return render(request, 'reg/password_reset_form.html', {'form': form})


def user_password_reset(request, uidb64, token):
    if request.method == 'POST':
        form = SetNewPasswordForm(request.POST)
        if form.is_valid():
            password1 = form.cleaned_data.get('Password')
            password2 = form.cleaned_data.get('Confirm_Password')
            if password1 == password2:
                try:
                    uid = urlsafe_base64_decode(uidb64).decode()
                    user = User.objects.get(pk=uid)
                except(TypeError, ValueError, OverflowError, User.DoesNotExist):
                    user = None
                if user is not None and account_activation_token.check_token(user, token):
                    user.set_password(password1)
                    user.save()
                    return HttpResponse('Your Password is changed successfully')
                else:
                    return HttpResponse('Invalid reset link')
            else:
                return HttpResponse('Password does not match')
        else:
            return render(request, 'reg/password_reset_confirm.html', {'form': form})
    else:
        form = SetNewPasswordForm()
        return render(request, 'reg/password_reset_confirm.html', {'form': form})

