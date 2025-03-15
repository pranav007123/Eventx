from django.db import models
from django.contrib.auth.models import AbstractUser, Group, Permission, User
from django.conf import settings
from django.core.exceptions import ValidationError

class CustomAdmin(AbstractUser):
    is_custom_admin = models.BooleanField(default=True)

    groups = models.ManyToManyField(
        Group,
        related_name="custom_admin_users",  # Avoids clash with auth.User.groups
        blank=True
    )
    user_permissions = models.ManyToManyField(
        Permission,
        related_name="custom_admin_permissions",  # Avoids clash with auth.User.user_permissions
        blank=True
    )

class Profile(models.Model):
    user = models.OneToOneField(settings.AUTH_USER_MODEL, on_delete=models.CASCADE)
    phone_number = models.CharField(max_length=20)
    address = models.TextField(blank=True)
    is_seller = models.BooleanField(default=False)

    def __str__(self):
        return f"{self.user.username}'s Profile"

class Seller(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE)
    
    def __str__(self):
        return self.user.first_name
class Event(models.Model):
    seller = models.ForeignKey(
        Seller,
        on_delete=models.CASCADE,
        related_name="events",  # ✅ This must match 'events' in views.py
        null=True,
        blank=True
    )
    name = models.CharField(max_length=255)
    description = models.TextField()
    date = models.DateTimeField()
    location = models.CharField(max_length=255)
    price = models.DecimalField(max_digits=10, decimal_places=2)
    total_tickets = models.PositiveIntegerField()
    available_tickets = models.PositiveIntegerField()
    image = models.ImageField(upload_to="events/", blank=True, null=True)

    def __str__(self):
        return self.name

class Ticket(models.Model):
    event = models.ForeignKey(Event, on_delete=models.CASCADE, related_name="tickets")  # ✅ Must match 'tickets' in views.py
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE)
    price = models.DecimalField(max_digits=10, decimal_places=2)
    quantity = models.PositiveIntegerField(default=1)

    def __str__(self):
        return f"{self.user.username} - {self.event.name} ({self.quantity})"

class Order(models.Model):
    seller = models.ForeignKey(Seller, on_delete=models.CASCADE)
    total_amount = models.DecimalField(max_digits=10, decimal_places=2)
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"Order {self.id} - {self.seller.user.username}"

class OrderItem(models.Model):
    order = models.ForeignKey(Order, on_delete=models.CASCADE, related_name="items")
    ticket = models.ForeignKey(Ticket, on_delete=models.CASCADE)
    quantity = models.PositiveIntegerField()

    def __str__(self):
        return f"Order {self.order.id} - {self.ticket.event.name} ({self.quantity})"

class Booking(models.Model):
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE)
    event = models.ForeignKey(Event, on_delete=models.CASCADE, related_name="bookings")
    tickets_booked = models.PositiveIntegerField(default=1)
    booking_date = models.DateTimeField(auto_now_add=True)

    def clean(self):
        """Ensure enough tickets are available before saving."""
        if self.tickets_booked > self.event.available_tickets:
            raise ValidationError("Not enough tickets available.")

    def save(self, *args, **kwargs):
        """Reduce available tickets when a booking is made."""
        self.clean()  # Ensure validation before saving
        super().save(*args, **kwargs)  # Save the booking first
        self.event.available_tickets -= self.tickets_booked
        self.event.save()

    def __str__(self):
        return f"Booking by {self.user.username} for {self.event.name} ({self.tickets_booked} tickets)"
