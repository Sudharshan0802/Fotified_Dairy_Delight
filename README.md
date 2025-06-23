# Fortified Dairy Delight

A secure e-commerce web application for selling dairy products, built with Flask.

## Features

- User registration and login with password hashing (bcrypt)
- Google reCAPTCHA for bot protection on login
- Admin and user roles (admin has access to dashboard and product management)
- Two-factor authentication (2FA) for admin login using TOTP
- Product catalog with image uploads
- Shopping cart functionality
- Order placement and order history
- Admin dashboard for managing products and viewing all orders

## Project Structure

```
app.py
requirements.txt
static/
    uploads/
        ...product images...
    you-are-totally-wrong-the-legend.gif
templates/
    add_product.html
    admin_2fa.html
    admin_dashboard.html
    admin_orders.html
    base.html
    checkout.html
    home.html
    login.html
    order_details.html
    register.html
    view_cart.html
instance/
    products.db
```

## Setup Instructions

1. **Clone the repository**

2. **Create a virtual environment and activate it**
   ```sh
   python -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   ```

3. **Install dependencies**
   ```sh
   pip install -r requirements.txt
   ```

4. **Run the application**
   ```sh
   python app.py
   ```

5. **Access the app**
   - Open your browser and go to [http://127.0.0.1:5000](http://127.0.0.1:5000)

## Default Admin

- Username: `admin`
- Password: `admin`
- On first login, you will be prompted for a 2FA code (TOTP).

## Security Features

- Passwords are hashed using bcrypt.
- Google reCAPTCHA is used on the login page to prevent bots.
- Admins must complete a TOTP-based 2FA challenge.
- All sensitive actions (add/delete products, view orders) require admin authentication.

## File Uploads

- Product images are uploaded to `static/uploads/`.
- Only image files (`png`, `jpg`, `jpeg`, `gif`) are allowed.

## Database

- Uses SQLite (`products.db` in the `instance/` folder).
- Models: User, Product, Cart, CartItem, Order, OrderDetails.

## Customization

- To change the reCAPTCHA keys, update them in [`app.py`](app.py).
- To change the TOTP secret for admin 2FA, update the secret in the `admin_2fa` route in [`app.py`](app.py).

## License

This project is for educational purposes.

---

**Developed with Flask, SQLAlchemy, Flask-Login, Flask-Bcrypt, pyotp, and
