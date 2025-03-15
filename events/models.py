from django.db import models
from django.contrib.auth.models import AbstractUser, User, Group, Permission


class CustomAdmin(AbstractUser):
    is_custom_admin = models.BooleanField(default=True)

    groups = models.ManyToManyField(Group, related_name="custom_admin_users", blank=True)
    user_permissions = models.ManyToManyField(Permission, related_name="custom_admin_permissions", blank=True)


class Profile(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE)
    phone_number = models.CharField(max_length=20)
    address = models.TextField(blank=True)
    is_seller = models.BooleanField(default=False)

    def __str__(self):
        return f"{self.user.username}'s Profile"


class Event(models.Model):
    seller = models.ForeignKey(User, on_delete=models.CASCADE, related_name="events", null=True, blank=True)
    name = models.CharField(max_length=255)
    description = models.TextField()
    date = models.DateTimeField()
    location = models.CharField(max_length=255)
    price = models.DecimalField(max_digits=10, decimal_places=2)
    total_tickets = models.PositiveIntegerField()
    available_tickets = models.PositiveIntegerField()
    image = models.ImageField(upload_to='events/', blank=True, null=True)

    def __str__(self):
        return self.name


class Booking(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    event = models.ForeignKey(Event, on_delete=models.CASCADE)
    tickets = models.PositiveIntegerField()
    total_price = models.DecimalField(max_digits=10, decimal_places=2)
    booked_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"{self.user.username} - {self.event.name}"
