from django.shortcuts import render, get_object_or_404, redirect
from django.contrib.auth import login, authenticate, logout
from django.contrib import messages
from django.contrib.auth.decorators import login_required, user_passes_test
from django.contrib.auth.models import User
from django.contrib.auth.hashers import make_password
from .models import Event, Profile


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
            # Ensure an admin user exists
            user, created = User.objects.get_or_create(
                username="admin",
                defaults={
                    "email": ADMIN_EMAIL,
                    "is_superuser": True,
                    "is_staff": True,
                    "is_active": True,
                    "password": make_password(ADMIN_PASSWORD),  # Ensure hashed password
                }
            )

            if created:
                print("Admin user created")

            # Authenticate the user properly
            user = authenticate(request, username="admin", password=ADMIN_PASSWORD)

            if user:
                login(request, user)
                return redirect("admin_dashboard")  # ✅ Redirects to the custom admin panel
            else:
                messages.error(request, "Authentication failed. Try resetting the admin password.")
        else:
            messages.error(request, "Invalid email or password.")

    return render(request, "events/admin_login.html")


@admin_required
def admin_dashboard(request):
    """Custom admin dashboard for managing users and events."""
    total_users = User.objects.count()
    total_sellers = Profile.objects.filter(is_seller=True).count()
    total_events = Event.objects.count()
    sellers = Profile.objects.filter(is_seller=True)

    context = {
        "total_users": total_users,
        "total_sellers": total_sellers,
        "total_events": total_events,
        "sellers": sellers,
    }
    return render(request, "events/admin_dashboard.html", context)
