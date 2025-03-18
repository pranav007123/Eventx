from django.contrib import admin
from .models import Event, Order, OrderItem, Seller, Profile

admin.site.register(Event)
admin.site.register(Order)
admin.site.register(OrderItem)
admin.site.register(Seller)
admin.site.register(Profile)
