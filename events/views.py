from django.shortcuts import render, get_object_or_404, redirect
from django.contrib.auth import login, authenticate, logout,get_user_model
from django.contrib import messages
from django.contrib.auth.decorators import login_required, user_passes_test
from django.contrib.auth.models import User
from django.contrib.auth.hashers import make_password
from .models import Event, Profile , Seller, Order, OrderItem ,Ticket
from django.db.models import Sum, Count

User = get_user_model()



# ------------------------------------------------------------------
# Public Views
# ------------------------------------------------------------------

def index(request):
    """Display the homepage with a list of all events."""
    events = Event.objects.all()
    return render(request, 'events/index.html', {'events': events})


def event_detail(request, event_id):
    """Display details for a single event."""
    event = get_object_or_404(Event, id=event_id)
    return render(request, 'events/event_detail.html', {'event': event})


def register(request):
    """Handle user registration."""
    if request.method == 'POST':
        name = request.POST.get('name')
        email = request.POST.get('email')
        phone = request.POST.get('phone')
        address = request.POST.get('address')
        password = request.POST.get('password')
        confirm_password = request.POST.get('confirm_password')

        if password != confirm_password:
            messages.error(request, "Passwords do not match!")
            return redirect('register')

        if User.objects.filter(username=email).exists():
            messages.error(request, "This email is already registered!")
            return redirect('register')

        try:
            user = User.objects.create_user(username=email, email=email, password=password)
            user.first_name = name
            user.save()

            Profile.objects.create(user=user, phone_number=phone, address=address)
        except Exception as e:
            messages.error(request, f"Registration failed: {e}")
            return redirect('register')

        messages.success(request, "Registration successful! Please login.")
        return redirect('login')

    return render(request, 'registration/register.html')


def custom_login(request):
    """Single login page for all users: Admin, Seller, and Regular Users."""
    if request.method == "POST":
        username = request.POST.get("username")
        password = request.POST.get("password")

        user = authenticate(request, username=username, password=password)

        if user is not None:
            login(request, user)

            if user.is_superuser:  # Redirect to Admin Dashboard
                return redirect("admin_dashboard")
            elif hasattr(user, "profile") and user.profile.is_seller:  # Redirect to Seller Dashboard
                return redirect("seller_dashboard")
            else:
                return redirect("index")  # Regular user homepage

        else:
            messages.error(request, "Invalid email or password.")

    return render(request, "registration/login.html")


@login_required
def seller_dashboard(request):
    """Display a dashboard of events created by the logged-in seller."""
    if not hasattr(request.user, "profile") or not request.user.profile.is_seller:
        messages.error(request, "Access denied. You are not a seller.")
        return redirect("index")

    events = Event.objects.filter(seller=request.user)
    return render(request, "events/seller_dashboard.html", {"events": events})


@login_required
def logout_view(request):
    """Logout the current user."""
    logout(request)
    messages.success(request, "You have been logged out.")
    return redirect("login")


# ------------------------------------------------------------------
# Admin Dashboard Views
# ------------------------------------------------------------------

def admin_required(view_func):
    """Decorator to restrict access to superusers (admin)."""
    return user_passes_test(lambda u: u.is_authenticated and u.is_superuser)(view_func)

def custom_admin_login(request):
    """Handle admin login with hardcoded credentials."""
    ADMIN_EMAIL = "admin@gmail.com"
    ADMIN_PASSWORD = "1234"

    if request.method == "POST":
        email = request.POST["username"]
        password = request.POST["password"]

        if email == ADMIN_EMAIL and password == ADMIN_PASSWORD:
            user = User.objects.filter(username="admin").first()
            if not user:
                user = User.objects.create_user("admin", ADMIN_EMAIL, ADMIN_PASSWORD)
                user.is_superuser = True
                user.is_staff = True
                user.save()

            user = authenticate(request, username="admin", password=ADMIN_PASSWORD)
            if user:
                login(request, user)
                return redirect("admin_dashboard")
            else:
                messages.error(request, "Authentication failed. Try resetting the admin password.")
        else:
            messages.error(request, "Invalid email or password.")
    
    return render(request, "events/admin_login.html")

@admin_required



def admin_dashboard(request):
    if not request.user.is_staff:
        return redirect('login')

    if request.method == "POST":
        action = request.POST.get("action")

        # ✅ Handling Adding a Seller
        if action == "add_seller":
            name = request.POST.get("name")
            email = request.POST.get("email")
            phone = request.POST.get("phone")
            password = request.POST.get("password")
            address = request.POST.get("address")

            # Check if user already exists
            if User.objects.filter(email=email).exists():
                messages.error(request, "Email already registered!")
            else:
                user = User.objects.create(
                    username=email,
                    first_name=name,
                    email=email,
                    password=make_password(password)
                )
                Seller.objects.create(user=user)
                messages.success(request, "Seller added successfully.")

        # ✅ Handling Removing a Seller
        elif action == "remove_seller":
            seller_id = request.POST.get("seller_id")
            seller = get_object_or_404(Seller, id=seller_id)
            seller.user.delete()
            seller.delete()
            messages.success(request, "Seller removed successfully.")

        # ✅ Handling Removing a User
        elif action == "remove_user":
            user_id = request.POST.get("user_id")
            user = get_object_or_404(User, id=user_id)

            if user.is_staff:
                messages.error(request, "Cannot remove admin users!")
            else:
                user.delete()
                messages.success(request, "User removed successfully.")

        return redirect('admin_dashboard')

    # ✅ Fetch total numbers
    total_users = User.objects.filter(is_staff=False).exclude(id__in=Seller.objects.values_list('user_id', flat=True)).count()
    total_sellers = Seller.objects.count()

    # ✅ Exclude sellers from users list
    users = User.objects.filter(is_staff=False).exclude(id__in=Seller.objects.values_list('user_id', flat=True))

    # ✅ Get all sellers
    sellers = Seller.objects.all()

    return render(request, "events/admin_dashboard.html", {
        "total_users": total_users,
        "total_sellers": total_sellers,
        "users": users,
        "sellers": sellers,
    })