from django.contrib.auth.models import User
from django.conf import settings
from django.db.models.signals import post_save
from django.dispatch import receiver
from rest_framework.authtoken.models import Token
from django.db import models
from PIL import Image
class Profile(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE,related_name='profile') #1 to 1 link with Django User
    firstname =  models.CharField(max_length=50)
    lastname = models.CharField(max_length=50)
    mobile =  models.CharField(max_length=32)
    pro_pic = models.ImageField(default="profile_pictures/default.jpg", upload_to="profile_pictures")
    def __str__(self):
        return f'{self.user.username} Profile'

    def save(self, *args, **kwargs):
        super(Profile,self).save(*args, **kwargs)
        img =Image.open(self.pro_pic.path)
        img.save(self.pro_pic.path)

@receiver(post_save, sender=User)
def create_or_update_user_profile(sender, instance, created, **kwargs):
    if created:
        Profile.objects.create(user=instance)
    instance.profile.save()

@receiver(post_save, sender=settings.AUTH_USER_MODEL)
def create_auth_token(sender, instance=None, created=False, **kwargs):
    if created:
        Token.objects.create(user=instance)

