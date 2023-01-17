from flask import Flask, render_template, flash, redirect, url_for, abort, request, session
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import relationship
from flask_bootstrap import Bootstrap
from flask_login import UserMixin, LoginManager, login_user, logout_user, login_required, current_user
from flask_gravatar import Gravatar
from flask_ckeditor import CKEditor
from flask_wtf import csrf
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps
import stripe
import datetime
import os
import forms
from notification_manager import NotificationManager
from dotenv import load_dotenv

load_dotenv()

POPULAR_THRESHOLD = 3
stripe.api_key = os.getenv("STRIPE_API_KEY")
messaging_bot = NotificationManager()

app = Flask(__name__)
with app.app_context():
    app.config['SECRET_KEY'] = os.getenv("FLASK_SECRET_KEY")
    Bootstrap(app)
    ckeditor = CKEditor(app)
    login_manager = LoginManager(app)
    gravatar = Gravatar(app,
                        size=30,
                        rating='g',
                        default='identicon',
                        force_default=False,
                        force_lower=False,
                        use_ssl=False,
                        base_url=None)

    # Connect to DB
    uri = os.getenv("DATABASE_URL")
    if uri.startswith("postgres://"):
        uri = uri.replace("postgres://", "postgresql://")
    app.config['SQLALCHEMY_DATABASE_URI'] = uri
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
    db = SQLAlchemy(app)


    ## CONFIGURE TABLES
    class Product(db.Model):
        __tablename__ = "products"
        id = db.Column(db.Integer, primary_key=True)
        product_name = db.Column(db.String, nullable=False, unique=True)
        quantity = db.Column(db.Integer, nullable=False)
        old_price = db.Column(db.Float)
        new_price = db.Column(db.Float, nullable=False)
        description = db.Column(db.String, nullable=False)
        picture = db.Column(db.String, nullable=False)
        sale_flag = db.Column(db.String)
        popular_flag = db.Column(db.String)
        likes = relationship("Like", back_populates="product_like_is_for")
        comments = relationship("Comment", back_populates="product_comment_is_for")
        checkouts = relationship("ForCheckout", back_populates="product_for_checkout")
        purchases = relationship("PurchaseReceipt", back_populates="product_relationship")


    class User(UserMixin, db.Model):
        __tablename__ = "users"
        id = db.Column(db.Integer, primary_key=True)
        user_name = db.Column(db.String, nullable=False)
        admin_flag = db.Column(db.String)
        email = db.Column(db.String, unique=True, nullable=False)
        password = db.Column(db.String, nullable=False)
        card_number = db.Column(db.String)
        address = db.Column(db.String)
        comments = relationship("Comment", back_populates="comment_author")
        likes = relationship("Like", back_populates="like_author")
        checkout_products = relationship("ForCheckout", back_populates="user_purchasing")


    class Comment(db.Model):
        __tablename__ = "comments"
        id = db.Column(db.Integer, primary_key=True)
        author_id = db.Column(db.Integer, db.ForeignKey("users.id"))
        comment_author = relationship("User", back_populates="comments")
        product_id = db.Column(db.Integer, db.ForeignKey("products.id"))
        product_comment_is_for = relationship("Product", back_populates="comments")
        text = db.Column(db.Text, nullable=False)
        date = db.Column(db.String, nullable=False)


    class Like(db.Model):
        __tablename__ = "likes"
        id = db.Column(db.Integer, primary_key=True)
        like_flag = db.Column(db.Integer, nullable=False)
        product_id = db.Column(db.Integer, db.ForeignKey("products.id"))
        author_id = db.Column(db.Integer, db.ForeignKey("users.id"))
        product_like_is_for = relationship("Product", back_populates="likes")
        like_author = relationship("User", back_populates="likes")


    class ForCheckout(db.Model):
        __tablename__ = "cart"
        id = db.Column(db.Integer, primary_key=True)
        prod_id = db.Column(db.Integer, db.ForeignKey("products.id"))
        product_for_checkout = relationship("Product", back_populates="checkouts")
        quantity_for_checkout = db.Column(db.Integer, nullable=False)
        adjusted_quantity = db.Column(db.Integer, nullable=False)
        user_id = db.Column(db.Integer, db.ForeignKey("users.id"))
        user_purchasing = relationship("User", back_populates="checkout_products")
        stripe_checkout_session_id = db.Column(db.String)


    class Payment(db.Model):
        __tablename__ = "payments"
        id = db.Column(db.Integer, primary_key=True)
        datetime_of_payment = db.Column(db.DateTime, nullable=False)
        client_email = db.Column(db.String, nullable=False)
        stripe_checkout_session_id = db.Column(db.String, nullable=False)
        total_amount = db.Column(db.Float, nullable=False)
        purchase_relationship = relationship("PurchaseReceipt", back_populates="payment_relationship")


    class PurchaseReceipt(db.Model):
        __tablename__ = "purchases_made"
        id = db.Column(db.Integer, primary_key=True)
        payment_relationship = relationship("Payment", back_populates="purchase_relationship")
        payment_id = db.Column(db.Integer, db.ForeignKey("payments.id"))
        product_relationship = relationship("Product", back_populates="purchases")
        product_purchased = db.Column(db.String, db.ForeignKey("products.product_name"))
        quantity_purchased = db.Column(db.Integer, nullable=False)
        price = db.Column(db.Float, nullable=False)
        amount = db.Column(db.Float, db.CheckConstraint("amount = price * quantity_purchased"))


    db.create_all()


    # END OF TABLES CONFIGURATION

    # Login_manager initialisation
    @login_manager.user_loader
    def load_user(user_id):
        return User.query.get(int(user_id))


    ## -------- ADDITIONAL FUNCTIONS SETUP BELOW -------- ##

    # Admin decorator function
    def admin_only(func):
        @wraps(func)
        def wrapper_func(*args, **kwargs):
            try:
                if current_user.admin_flag == "admin":
                    return func(*args, **kwargs)
                return abort(403)
            except AttributeError:
                return abort(403)

        return wrapper_func


    # Popular product identifier and mapper function
    def popular_mapping():
        all_products = Product.query.all()
        dict_of_likes_per_product = {product.id: len(product.likes) for product in all_products}
        for prod_id, likes in dict_of_likes_per_product.items():
            if likes >= POPULAR_THRESHOLD:
                product = Product.query.get(prod_id)
                if product.popular_flag == "popular":
                    continue
                else:
                    product.popular_flag = "popular"
                    db.session.commit()
            else:
                product = Product.query.get(prod_id)
                if product.popular_flag is None:
                    continue
                else:
                    product.popular_flag = None
                    db.session.commit()


    # Function to adjust product quantity in the stock and for checkout
    # once stripe checkout session is canceled or succeeded
    def adjust_product_quantity():
        global for_checkout
        get_products_for_checkout()
        try:
            saved_session_id = for_checkout[:1][0].stripe_checkout_session_id
        except IndexError:
            return
        else:
            if saved_session_id is None:
                return
            print(stripe.checkout.Session.retrieve(saved_session_id))
            session_list_items = stripe.checkout.Session.list_line_items(saved_session_id)["data"]
            list_of_items_names = [item.description for item in session_list_items]
            url_ending = request.url.split("/")[-1]
            for product in session_list_items:
                product_from_stock = Product.query.filter_by(product_name=product.description).first()
                for_checkout_per_db = ForCheckout.query.filter_by(prod_id=product_from_stock.id,
                                                                  user_id=for_checkout[:1][0].user_id).all()
                for prod in for_checkout_per_db:
                    prod.adjusted_quantity = prod.quantity_for_checkout - product.quantity
                    prod.quantity_for_checkout -= prod.adjusted_quantity
            prods_with_session_flags = ForCheckout.query.filter_by(user_id=for_checkout[:1][0].user_id).all()
            for item in prods_with_session_flags:
                product_to_update = Product.query.get(item.prod_id)
                if product_to_update.product_name not in list_of_items_names:
                    item.adjusted_quantity = item.quantity_for_checkout
                    item.quantity_for_checkout = 0
                product_to_update.quantity += item.adjusted_quantity
                item.adjusted_quantity = 0
                item.stripe_checkout_session_id = None
                if url_ending == "success":
                    db.session.delete(item)
                elif item.quantity_for_checkout == 0:
                    db.session.delete(item)
            db.session.commit()
        get_products_for_checkout()


    # If no user is authenticated the function uses current session's csrf_token
    # to uniquely identify anonymous user and add him/her to a db, so the user can make purchases
    def anonymous_user_adder():
        if not current_user.is_authenticated:
            try:
                csrf_token = session["csrf_token"]
            except KeyError:
                csrf.generate_csrf()
                csrf_token = session["csrf_token"]
            token_in_db = User.query.filter_by(user_name=csrf_token).first()
            if token_in_db is None:
                try:
                    last_user_id = User.query.order_by(User.id.desc()).first().id
                except AttributeError:
                    last_user_id = 0
                new_anonymous_user = User(id=last_user_id + 1, user_name=csrf_token, email=last_user_id + 1,
                                          password=last_user_id + 1)
                db.session.add(new_anonymous_user)
                db.session.commit()


    # Function that returns a list of product objects ready for check-out per user
    for_checkout = None


    def get_products_for_checkout():
        global for_checkout
        if current_user.is_authenticated:
            for_checkout = ForCheckout.query.filter_by(user_id=current_user.get_id()).all()
        else:
            csrf_token = session["csrf_token"]
            token_user = User.query.filter_by(user_name=csrf_token).first()
            for_checkout = ForCheckout.query.filter_by(user_id=token_user.id).all()
        return for_checkout


    ## -------- END OF ADDITIONAL FUNCTIONS SETUP -------- ##

    @app.route("/")
    def homepage():
        global for_checkout
        anonymous_user_adder()
        adjust_product_quantity()
        popular_mapping()
        popular_flag = request.args.get("popular")
        sale_flag = request.args.get("sale")
        total_quantity_for_checkout = sum([prod.quantity_for_checkout for prod in for_checkout])
        if popular_flag is not None:
            products = Product.query.filter_by(popular_flag=popular_flag).all()
        elif sale_flag is not None:
            products = Product.query.filter_by(sale_flag=sale_flag).all()
        else:
            products = Product.query.all()
        return render_template("index.html", products=products, logged_in=current_user.is_authenticated,
                               user=current_user, total_for_checkout=total_quantity_for_checkout)


    @app.route("/product<int:prod_id>", methods=["GET", "POST"])
    def get_product_page(prod_id):
        global for_checkout
        anonymous_user_adder()
        adjust_product_quantity()
        popular_mapping()
        requested_product = Product.query.get(prod_id)
        list_of_product_likes = [like_i.author_id for like_i in requested_product.likes]
        form = forms.ReviewForm()
        total_quantity_for_checkout = sum([prod.quantity_for_checkout for prod in for_checkout])
        if form.validate_on_submit():
            if not current_user.is_authenticated:
                flash("You need to login or register to leave reviews.")
                return redirect(url_for("login"))
            try:
                last_comment_id = Comment.query.order_by(Comment.id.desc()).first().id
            except AttributeError:
                last_comment_id = 0
            comment = Comment(id=last_comment_id + 1, text=form.text.data,
                              date=datetime.date.today().strftime("%d-%b-%Y"),
                              comment_author=current_user, product_comment_is_for=requested_product)
            db.session.add(comment)
            db.session.commit()
            return redirect(url_for("get_product_page", prod_id=prod_id, for_checkout=for_checkout))
        return render_template("product.html", product=requested_product, form=form,
                               logged_in=current_user.is_authenticated, user=current_user,
                               likes_list=list_of_product_likes, total_for_checkout=total_quantity_for_checkout)


    @app.route("/product<int:prod_id>/like")
    @login_required
    def like_func(prod_id):
        product = Product.query.get(prod_id)
        list_of_user_ids_with_likes = [like_obj.author_id for like_obj in product.likes]
        if int(current_user.get_id()) in list_of_user_ids_with_likes:
            like_obj_to_delete = Like.query.filter_by(author_id=current_user.get_id()).first()
            db.session.delete(like_obj_to_delete)
            db.session.commit()
        else:
            author = User.query.get(current_user.get_id())
            try:
                last_like_id = Like.query.order_by(Like.id.desc()).first().id
            except AttributeError:
                last_like_id = 0
            like_obj_to_create = Like(id=last_like_id + 1, like_flag=1, product_like_is_for=product, like_author=author)
            db.session.add(like_obj_to_create)
            db.session.commit()
        return "", 204


    @app.route("/about")
    def about():
        global for_checkout
        adjust_product_quantity()
        total_quantity_for_checkout = sum([prod.quantity_for_checkout for prod in for_checkout])
        return render_template('about.html', logged_in=current_user.is_authenticated, user=current_user,
                               total_for_checkout=total_quantity_for_checkout)


    @admin_only
    @app.route("/add-new-product", methods=["GET", "POST"])
    def add_product():
        form = forms.ProductForm()
        if form.validate_on_submit():
            product_details = {key: value.data for key, value in form._fields.items() if
                               key not in ["submit", "csrf_token"]}
            product_details_additional = {key: value.data for key, value in form._fields.items() if
                                          key not in ["submit", "csrf_token"]}
            for key in product_details_additional:
                if len(str(product_details_additional[key]).strip()) == 0:
                    product_details.pop(key)
            try:
                last_prod_id = Product.query.order_by(Product.id.desc()).first().id
            except AttributeError:
                last_prod_id = 0
            product_details["id"] = last_prod_id + 1
            new_product = Product(**product_details)
            db.session.add(new_product)
            db.session.commit()
            flash("Product added successfully. Add another product if needed.")
            return redirect(url_for("add_product"))
        return render_template("add-product.html", form=form, user=current_user,
                               logged_in=current_user.is_authenticated)


    @admin_only
    @app.route("/edit-product<int:prod_id>", methods=["GET", "POST"])
    def edit_product(prod_id):
        product = Product.query.get(prod_id)
        product_details = {str(key): getattr(product, key) for key in product.__table__.columns.keys()}
        form = forms.ProductForm(**product_details)
        if form.validate_on_submit():
            for key in product.__table__.columns.keys():
                if key == "id":
                    continue
                elif len(str(form[key].data).strip()) > 0:
                    setattr(product, key, form[key].data)
            db.session.commit()
            return redirect(url_for("get_product_page", prod_id=prod_id))
        return render_template("add-product.html", form=form, is_edit=True, user=current_user,
                               logged_in=current_user.is_authenticated)


    @admin_only
    @app.route("/delete-product<int:prod_id>", methods=["GET", "POST"])
    def delete_product(prod_id):
        to_delete = Product.query.get(prod_id)
        db.session.delete(to_delete)
        db.session.commit()
        return redirect(url_for("homepage"))


    @app.route("/register", methods=["GET", "POST"])
    def register():
        global for_checkout
        form = forms.RegisterForm()
        adjust_product_quantity()
        total_quantity_for_checkout = sum([prod.quantity_for_checkout for prod in for_checkout])
        if form.validate_on_submit():
            user = User.query.filter_by(email=form.email.data).first()
            if user is not None:
                flash("A user with this email already exists. Please use another email or go to login page")
                return redirect(url_for("register"))
            new_user_details = {key: value.data for key, value in form._fields.items()
                                if key not in ["submit", "csrf_token", "password", "repeat_password"]}
            salted_password = generate_password_hash(
                password=form.password.data, method="pbkdf2:sha256", salt_length=16)
            new_user_details["password"] = salted_password
            new_user_details["email"] = new_user_details["email"].lower()
            csrf_token = session["csrf_token"]
            token_user = User.query.filter_by(user_name=csrf_token).first()
            if token_user is not None:
                for key in token_user.__table__.columns.keys():
                    try:
                        setattr(token_user, key, new_user_details[key])
                    except KeyError:
                        continue
                db.session.commit()
                login_user(token_user)
            else:
                try:
                    last_user_id = User.query.order_by(User.id.desc()).first().id
                except AttributeError:
                    last_user_id = 0
                new_user_details["id"] = last_user_id + 1
                new_user = User(**new_user_details)
                db.session.add(new_user)
                db.session.commit()
                login_user(new_user)
            return redirect(url_for("homepage"))
        return render_template("register.html", form=form, logged_in=current_user.is_authenticated,
                               user=current_user, total_for_checkout=total_quantity_for_checkout)


    @app.route("/login", methods=["GET", "POST"])
    def login():
        global for_checkout
        form = forms.LoginForm()
        adjust_product_quantity()
        total_quantity_for_checkout = sum([prod.quantity_for_checkout for prod in for_checkout])
        if form.validate_on_submit():
            user = User.query.filter_by(email=form.email.data.lower()).first()
            if user is None:
                flash("The email you entered does not exist, please try again.")
                return redirect(url_for("login"))
            password_checked = check_password_hash(pwhash=user.password, password=form.password.data)
            if password_checked:
                csrf_token = session["csrf_token"]
                token_user_in_db = User.query.filter_by(user_name=csrf_token).first()
                if token_user_in_db is not None:
                    token_user_id = token_user_in_db.id
                    for_checkout = ForCheckout.query.filter_by(user_id=token_user_id).all()
                    for product in for_checkout:
                        setattr(product, "user_purchasing", user)
                    db.session.delete(token_user_in_db)
                    db.session.commit()
                login_user(user)
                return redirect(url_for("homepage"))
            flash("The password you entered is not correct, please try again.")
            return redirect(url_for("login"))
        return render_template("login.html", form=form, logged_in=current_user.is_authenticated, user=current_user,
                               total_for_checkout=total_quantity_for_checkout)


    @app.route("/logout")
    def logout():
        logout_user()
        return redirect(url_for("homepage"))


    @app.route("/", methods=["GET", "POST"])
    def add_to_cart():
        quantity = int(request.form.get("quantity"))
        prod_id = request.form.get("prod_id")
        prod_for_checkout = Product.query.get(prod_id)
        if prod_for_checkout.quantity < quantity:
            flash(
                f"Not enough items of this product at the stock. Current quantity is {prod_for_checkout.quantity} items.")
            return redirect(url_for("get_product_page", prod_id=prod_for_checkout.id))
        if current_user.is_authenticated:
            user_purchasing = current_user
        else:
            user_purchasing = User.query.filter_by(user_name=session["csrf_token"]).first()
        is_already_added = ForCheckout.query.filter_by(prod_id=prod_id, user_id=user_purchasing.id).first()
        if is_already_added:
            is_already_added.quantity_for_checkout += quantity
            prod_for_checkout.quantity -= quantity
            db.session.commit()
        else:
            try:
                last_cart_entry_id = ForCheckout.query.order_by(ForCheckout.id.desc()).first().id
            except AttributeError:
                last_cart_entry_id = 0
            new_checkout = ForCheckout(
                id=last_cart_entry_id + 1,
                quantity_for_checkout=quantity,
                product_for_checkout=prod_for_checkout,
                user_purchasing=user_purchasing,
                adjusted_quantity=0,
            )
            db.session.add(new_checkout)
            prod_for_checkout.quantity -= quantity
            db.session.commit()
        return redirect(request.referrer)


    @app.route('/checkout-session', methods=["GET", 'POST'])
    def checkout_session():
        global for_checkout
        success_url = "/".join(request.referrer.split("/")[:-1])
        get_products_for_checkout()
        amounts = [str(product.product_for_checkout.new_price).split(".") for product in for_checkout]
        for amount in amounts:
            if len(amount[1]) != 2:
                amount[1] += "0"
        amounts_for_checkout = ["".join(amount) for amount in amounts]
        checkout_session = stripe.checkout.Session.create(
            line_items=[{
                'price_data': {
                    'currency': 'usd',
                    'product_data': {
                        'name': product.product_for_checkout.product_name,
                        'images': [product.product_for_checkout.picture],
                    },
                    'unit_amount': amounts_for_checkout[for_checkout.index(product)],
                },
                'adjustable_quantity': {
                    'enabled': True,
                    'maximum': product.product_for_checkout.quantity + product.quantity_for_checkout,
                },
                'quantity': product.quantity_for_checkout,
            } for product in for_checkout],
            mode='payment',
            success_url=success_url + "/success",
            cancel_url=request.referrer,
            customer_email=current_user.email if current_user.is_authenticated else None,
        )
        session_id_to_save = checkout_session["id"]
        for prod in for_checkout:
            prod.stripe_checkout_session_id = session_id_to_save
        db.session.commit()
        return redirect(checkout_session.url, 303)


    @app.route('/success')
    def success():
        global for_checkout
        get_products_for_checkout()
        saved_session_id = for_checkout[:1][0].stripe_checkout_session_id
        adjust_product_quantity()
        total_quantity_for_checkout = sum([prod.quantity_for_checkout for prod in for_checkout])
        try:
            last_payment_id = Payment.query.order_by(Payment.id.desc()).first().id
        except AttributeError:
            last_payment_id = 0
        total_amount = str(stripe.checkout.Session.retrieve(saved_session_id)["amount_total"])[:-2] + "." \
                       + str(stripe.checkout.Session.retrieve(saved_session_id)["amount_total"])[-2]
        new_payment_made = Payment(id=last_payment_id + 1,
                                   datetime_of_payment=datetime.datetime.now(),
                                   client_email=stripe.checkout.Session.retrieve(saved_session_id)["customer_details"][
                                       "email"],
                                   stripe_checkout_session_id=saved_session_id,
                                   total_amount=float(total_amount))
        db.session.add(new_payment_made)
        session_line_items = stripe.checkout.Session.list_line_items(saved_session_id)["data"]
        for item in session_line_items:
            price = item.price.unit_amount_decimal[:-2] + "." + item.price.unit_amount_decimal[-2]
            amount_total = str(item.amount_total)[:-2] + "." + str(item.amount_total)[-2]
            try:
                last_id_entry = PurchaseReceipt.query.order_by(PurchaseReceipt.id.desc()).first().id
            except AttributeError:
                last_id_entry = 0
            product_purchased = PurchaseReceipt(
                id=last_id_entry + 1,
                payment_relationship=new_payment_made,
                product_relationship=Product.query.filter_by(product_name=item.description).first(),
                quantity_purchased=item.quantity,
                price=float(price),
                amount=float(amount_total)
            )
            db.session.add(product_purchased)
        db.session.commit()
        order_entry = Payment.query.filter_by(stripe_checkout_session_id=saved_session_id).first()
        products_purchased = PurchaseReceipt.query.filter_by(payment_id=order_entry.id).all()
        messaging_bot.list_of_products = [f"{prod.quantity_purchased}x {prod.product_purchased} " + \
                                          "{:.2f}".format(prod.price) + "USD - " + \
                                          "Subtotal: " + "{:.2f}".format(prod.amount) + "USD" for prod in products_purchased]
        messaging_bot.create_msg(order_entry)
        messaging_bot.send_msg(order_entry)
        return render_template("success.html", logged_in=current_user.is_authenticated, user=current_user,
                               total_for_checkout=total_quantity_for_checkout, order_id=last_payment_id + 1)


    if __name__ == "__main__":
        app.run(host="0.0.0.0", debug=True, port=5000)
