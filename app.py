from flask import Flask, render_template, request, redirect, url_for, flash, session
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.utils import secure_filename
from flask.cli import with_appcontext
import click
import os
import requests
import pyotp
from flask_bcrypt import Bcrypt
from datetime import datetime
from flask import flash, redirect, render_template, url_for
from flask_login import login_required, current_user
from flask_login import UserMixin
# from susa import app, db
# from susa.models import Order, OrderDetails, Cart


app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///products.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = os.urandom(32)
app.config['UPLOAD_FOLDER'] = 'static/uploads'  # Folder to store uploaded images
app.config['ALLOWED_EXTENSIONS'] = {'png', 'jpg', 'jpeg', 'gif'}  # Define allowed file extensions for uploads
db = SQLAlchemy(app)


# User Authentication Setup
login_manager = LoginManager(app)
login_manager.login_view = 'login'

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    password = db.Column(db.String(50), nullable=False)
    is_admin = db.Column(db.Boolean, default=False)
    carts = db.relationship('Cart', backref='user', lazy=True)
    orders = db.relationship('Order', backref='customer', lazy=True)




@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Product Model
class Product(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(255), nullable=False)
    description = db.Column(db.Text)
    price = db.Column(db.Float)
    image = db.Column(db.String(255))  # Image file path
    carts = db.relationship('Cart', backref='product', lazy=True)


# Add this to your models section
class Cart(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    product_id = db.Column(db.Integer, db.ForeignKey('product.id'), nullable=False)
    quantity = db.Column(db.Integer, default=1)

# Add this to your models section
class CartItem(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    quantity = db.Column(db.Integer, default=1)
    product_id = db.Column(db.Integer, db.ForeignKey('product.id'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

    # Define a relationship to the Product model
    product = db.relationship('Product', backref=db.backref('cart_items', lazy=True))

class Order(db.Model):
    __tablename__ = 'order'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    total_amount = db.Column(db.Float, nullable=False)
    name = db.Column(db.String(255))  # Add this line for the "name" column
    shipping_address = db.Column(db.String(255))
    card_number = db.Column(db.String(16))
    expiry_date = db.Column(db.String(5))
    cvv = db.Column(db.String(3))
    order_date = db.Column(db.DateTime, default=datetime.utcnow)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    order_items = db.relationship('OrderDetails', back_populates='order', lazy=True)

    
class OrderDetails(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    order_id = db.Column(db.Integer, db.ForeignKey('order.id'), nullable=False)
    product_id = db.Column(db.Integer, db.ForeignKey('product.id'), nullable=False)
    product_name = db.Column(db.String(255), nullable=False)
    quantity = db.Column(db.Integer, nullable=False)
    price = db.Column(db.Float, nullable=False)
    order = db.relationship('Order', back_populates='order_items')

    # Define any other necessary columns and relationships




# Database Creation
with app.app_context():
    db.create_all()

    admin_user = User.query.filter_by(username='admin').first()
    if not admin_user:
        admin_user = User(username='admin', password='admin', is_admin=True)
        db.session.add(admin_user)
        db.session.commit()

# ... (your other imports and configurations)

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in app.config['ALLOWED_EXTENSIONS']

# ... (rest of your code)

# Initialize Bcrypt for password hashing
bcrypt = Bcrypt(app)

# Function to hash passwords for existing users
def hash_existing_user_passwords():
    users = User.query.all()

    for user in users:
        if user.password is not None and not user.password.startswith('$2b$'):
            # Hash the password only if it's not already hashed
            hashed_password = bcrypt.generate_password_hash(user.password).decode('utf-8')
            user.password = hashed_password

    db.session.commit()

# Call the function to hash passwords
with app.app_context():
    hash_existing_user_passwords()



# # Route to display the user's cart
# @app.route('/cart')
# @login_required
# def view_cart():
#     # Assuming you have a relationship between User and Cart models
#     user_cart = current_user.cart
#     return render_template('view_cart.html', cart=user_cart)


# Admin Dashboard
@app.route('/admin/dashboard')
@login_required
def admin_dashboard():
    if current_user.is_admin:
        products = Product.query.all()
        return render_template('admin_dashboard.html', products=products)
    else:
        return "Permission Denied"
    

def verify_recaptcha(recaptcha_response):
    secret_key = "6LddK48oAAAAAOTdkykCV11V2uz_LP1if2jelHCK"
    data = {
        'secret': secret_key,
        'response': recaptcha_response
    }
    response = requests.post('https://www.google.com/recaptcha/api/siteverify', data=data)
    result = response.json()
    return result.get('success', False)


# Home Page
# ... (existing code)

# Update the 'home' route to include orders and related data
@app.route('/')
def home():
    if current_user.is_authenticated:
        # If the user is already logged in, check if they are an admin and redirect accordingly
        if current_user.is_admin:
            return redirect(url_for('admin_dashboard'))
        else:
            # # Redirect to the 'admin_2fa' route for authenticated non-admin users who are not yet verified
            # if 'is_admin' in session and session['is_admin']:
            #     return redirect(url_for('admin_2fa'))
            # else:
                products = Product.query.all()
                orders = Order.query.filter_by(user_id=current_user.id).all()  # Fetch orders for the current user
                order_details = OrderDetails.query.all()

                return render_template('home.html', products=products, orders=orders, order_details=order_details)

    products = Product.query.all()
    cart_items = Cart.query.filter_by(user_id=current_user.id).all() if current_user.is_authenticated else []

    return render_template('home.html', products=products, cart_items=cart_items)


# @app.route('/place_order', methods=['POST'])
# @login_required
# def place_order():
#     # Get the user's cart items
#     cart_items = CartItem.query.filter_by(user_id=current_user.id).all()

#     # Calculate the total order amount
#     total = sum(item.product.price * item.quantity for item in cart_items)

#     # Get user's shipping information from the form
#     name = request.form['name']
#     shipping_address = request.form['shipping_address']
#     card_number = request.form['card_number']
#     expiry_date = request.form['expiry_date']
#     cvv = request.form['cvv']

#     # Perform additional validation and processing of payment details (in a real system, use a payment gateway)

#     # Create a new order
#     new_order = Order(user_id=current_user.id, total_amount=total, name=name, shipping_address=shipping_address,
#                       card_number=card_number, expiry_date=expiry_date, cvv=cvv)
#     db.session.add(new_order)
#     db.session.commit()

#     # Clear the user's cart after placing the order
#     for item in cart_items:
#         db.session.delete(item)

#     db.session.commit()

#     flash('Order placed successfully! Thank you for shopping!', 'success')
#     return redirect(url_for('home'))  


# Add this route for adding items to the cart
@app.route('/add_to_cart/<int:product_id>', methods=['POST'])
@login_required
def add_to_cart(product_id):
    product = Product.query.get_or_404(product_id)

    # Check if the item is already in the cart
    cart_item = Cart.query.filter_by(user_id=current_user.id, product_id=product.id).first()

    if cart_item:
        # If the item is already in the cart, increment the quantity
        cart_item.quantity += 1
    else:
        # If the item is not in the cart, create a new cart item
        cart_item = Cart(user_id=current_user.id, product_id=product.id, quantity=1)

    db.session.add(cart_item)
    db.session.commit()

    flash('Item added to cart successfully!', 'success')
    return redirect(url_for('home'))

# Add this route for viewing the cart
@app.route('/view_cart')
@login_required
def view_cart():
    cart_items = Cart.query.filter_by(user_id=current_user.id).all()
    return render_template('view_cart.html', cart_items=cart_items)

@app.route('/your_cart_route')
def your_cart_route():
    # Fetch cart items and calculate total price
    cart_items = view_cart()  # Replace with your actual function to fetch cart items
    total_price = sum(item.product.price * item.quantity for item in cart_items)

    # Pass variables to the template
    return render_template('view_cart.html', cart_items=cart_items, total_price=total_price)

# Add this route for updating the cart
@app.route('/update_cart', methods=['POST'])
@login_required
def update_cart():
    if request.method == 'POST':
        item_id = request.form.get('item_id')
        new_quantity = int(request.form.get('quantity', 1))

        # Find the cart item by ID
        cart_item = Cart.query.get_or_404(item_id)

        # Update the quantity
        cart_item.quantity = new_quantity

        db.session.commit()
        flash('Cart updated successfully!', 'success')

    return redirect(url_for('view_cart'))


@app.route('/remove_from_cart/<int:item_id>')
@login_required
def remove_from_cart(item_id):
    cart_item = Cart.query.get_or_404(item_id)
    
    # Remove the item from the database
    db.session.delete(cart_item)
    db.session.commit()

    flash('Item removed from cart successfully!', 'success')
    return redirect(url_for('view_cart'))


@app.route('/admin_2fa', methods=['GET', 'POST'])
def admin_2fa():
    if request.method == 'POST':
        otp = request.form['otp']

        topt = pyotp.TOTP('ZZNIRYUFMDP5CY2LHSCLDGHO3TAMB7Y2')
        current_otp = topt.now()

        if otp != current_otp:
            flash('Incorrect OTP. Please try again.', category='error')
            return render_template('admin_2fa.html')  # Return the template in case of incorrect OTP
        else:
            session['is_admin'] = True
            return redirect(url_for('home'))  # Redirect to home after successful 2FA

    return render_template('admin_2fa.html')  # Return the template for GET requests
        
# Login Page
# Login Page
@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        # If the user is already logged in, check if they are an admin and redirect to the admin dashboard
        if current_user.is_admin:
            return redirect(url_for('admin_dashboard'))
        else:
            return redirect(url_for('home'))

    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        recaptcha_response = request.form.get('g-recaptcha-response')

        if not verify_recaptcha(recaptcha_response):
            flash('reCAPTCHA verification failed. Please try again.', category='error')
            return redirect(url_for('login'))

        user = User.query.filter_by(username=username).first()
        if user and bcrypt.check_password_hash(user.password, password):
            login_user(user)
            flash('Login successful!', 'success')

            # Check if the user is an admin
            if user.is_admin:
                return redirect(url_for('admin_2fa'))
            else:
                return redirect(url_for('home'))
        else:
            flash('Login failed. Check your username and password.', 'error')

    return render_template('login.html')


# Registration Page
# Registration Page
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        # Check if the username is already taken
        if User.query.filter_by(username=username).first():
            flash('Username is already taken. Please choose another.', 'error')
        else:
            # Use bcrypt to hash the password before storing it
            hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
            
            new_user = User(username=username, password=hashed_password)
            db.session.add(new_user)
            db.session.commit()
            
            flash('Registration successful! You can now log in.', 'success')
            return redirect(url_for('login'))

    return render_template('register.html')



@app.route('/admin/orders')
@login_required
def admin_orders():
    if not current_user.is_admin:
        return "Permission Denied"

    # Fetch all orders
    orders = Order.query.all()
    order_details = OrderDetails.query.all()

    return render_template('admin_orders.html', orders=orders, order_details=order_details)



from datetime import datetime  # Add this import

@app.route('/place_order', methods=['POST'])
@login_required
def place_order():
    # Get the user's cart items
    cart_items = Cart.query.filter_by(user_id=current_user.id).all()

    # Calculate the total order amount
    total = sum(item.product.price * item.quantity for item in cart_items)

    # Get user's shipping information from the form
    name = request.form['name']
    shipping_address = request.form['shipping_address']
    card_number = request.form['card_number']
    expiry_date = request.form['expiry_date']
    cvv = request.form['cvv']

    # Create a new order
    new_order = Order(user_id=current_user.id, total_amount=total, name=name, shipping_address=shipping_address,
                      card_number=card_number, expiry_date=expiry_date, cvv=cvv)
                      
    db.session.add(new_order)
    db.session.commit()

    # Create entries in OrderDetails for each item in the cart
    for item in cart_items:
        order_detail = OrderDetails(order_id=new_order.id, product_id=item.product.id,
                                    product_name=item.product.name, quantity=item.quantity,
                                    price=item.product.price * item.quantity)
        db.session.add(order_detail)

    db.session.commit()

    # Clear the user's cart after placing the order
    for item in cart_items:
        db.session.delete(item)

    db.session.commit()

    flash('Order placed successfully! Thank you for shopping!', 'success')
    return redirect(url_for('home'))



# Add a route to handle product addition by the admin
@app.route('/admin/add_product', methods=['GET', 'POST'])
@login_required
def add_product():
    if not current_user.is_admin:
        return "Permission Denied"

    if request.method == 'POST':
        name = request.form['name']
        description = request.form['description']
        price = float(request.form['price'])

        # Handle file upload
        if 'image' in request.files:
            file = request.files['image']
            if file.filename != '':
                if file and allowed_file(file.filename):
                    filename = secure_filename(file.filename)
                    file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
                else:
                    flash('Invalid file type. Please upload an image.', 'error')
                    return redirect(url_for('add_product'))
            else:
                flash('No file selected. Please choose an image.', 'error')
                return redirect(url_for('add_product'))
        else:
            flash('Image is required. Please choose an image.', 'error')
            return redirect(url_for('add_product'))

        # Create a new product
        new_product = Product(name=name, description=description, price=price, image=filename)
        db.session.add(new_product)
        db.session.commit()

        flash('Product added successfully!', 'success')
        return redirect(url_for('admin_dashboard'))

    return render_template('add_product.html')


# ... (your existing imports and configurations)

# Add this route for deleting a product
@app.route('/admin/delete_product/<int:product_id>', methods=['POST', 'GET'])
@login_required
def delete_product(product_id):
    # Check if the current user is an admin
    if not current_user.is_admin:
        return "Permission Denied"

    # Fetch all products for display in the admin dashboard
    products = Product.query.all()

    # Check if the product_id exists
    product = Product.query.get_or_404(product_id)

    if request.method == 'POST':
        try:
            print(f'Deleting product {product.id}: {product.name}')  # Debugging statement

            # Perform the deletion logic here
            db.session.delete(product)
            db.session.commit()

            flash('Product deleted successfully!', 'success')

            # Fetch updated product list after deletion
            products = Product.query.all()

            return render_template('admin_dashboard.html', products=products)
        except Exception as e:
            # Handle exceptions, e.g., if the product is associated with other records
            flash(f'Error deleting product: {str(e)}', 'error')
            return redirect(url_for('admin_dashboard'))

    # If the method is not POST, you might want to handle this case (e.g., redirect to admin_dashboard or show an error)

    return render_template('admin_dashboard.html', products=products)


# Logout
@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('Logout successful!', 'success')
    return redirect(url_for('home'))

if __name__ == '__main__':
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port, debug=True)
