from django import forms
from django.contrib.auth.models import User
from .models import Profile

class UserForm(forms.ModelForm):
    username = forms.CharField(min_length=6,max_length=100)
    email = forms.EmailField(max_length=200)
    password = forms.CharField(min_length=6,widget=forms.PasswordInput())
    confirm_password = forms.CharField(min_length=6,widget=forms.PasswordInput())

    class Meta():
        model = User
        fields = ('username','email','password')

class UserUpdateForm(forms.ModelForm):
    email = forms.EmailField()
    class Meta:
        model = User
        fields = ['username', 'email']


class ProfileUpdateForm(forms.ModelForm):
    class Meta:
        model = Profile
        fields = ['pro_pic','mobile','firstname','lastname']


class PasswordResetForm(forms.Form):
    Email = forms.EmailField(label='Email')

    fields = 'Email'


class SetNewPasswordForm(forms.Form):
    Password = forms.CharField(widget=forms.PasswordInput())
    Confirm_Password = forms.CharField(widget=forms.PasswordInput())