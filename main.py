from flask import Flask, render_template, flash, redirect, url_for, abort, request
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import relationship
from flask_bootstrap import Bootstrap
from flask_login import UserMixin, LoginManager, login_user, logout_user, login_required, current_user
from flask_gravatar import Gravatar
from flask_ckeditor import CKEditor
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps
import stripe
import datetime
import os
import forms
from dotenv import load_dotenv

load_dotenv()

POPULAR_THRESHOLD = 3
stripe.api_key = os.getenv("STRIPE_API_KEY")

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
        __tablename__ = "checkout_products_per_user"
        id = db.Column(db.Integer, primary_key=True)
        prod_id = db.Column(db.Integer, db.ForeignKey("products.id"))
        product_for_checkout = relationship("Product", back_populates="checkouts")
        quantity_for_checkout = db.Column(db.Integer, nullable=False)
        adjusted_quantity = db.Column(db.Integer, nullable=False)
        user_id = db.Column(db.Integer, db.ForeignKey("users.id"))
        user_purchasing = relationship("User", back_populates="checkout_products")
        stripe_checkout_session_id = db.Column(db.String)
    # END OF TABLES CONFIGURATION

    # Login_manager initialisation
    @login_manager.user_loader
    def load_user(user_id):
        return User.query.get(int(user_id))


    ## ADDITIONAL FUNCTIONS SETUP BELOW
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
        try:
            try:
                saved_session = ForCheckout.query.filter_by(user_id=current_user.id).first()
            except AttributeError:
                result = ForCheckout.query.all()
                if len(result) != 0:
                    for i in result:
                        product_in_stock = Product.query.get(i.prod_id)
                        product_in_stock.quantity += i.quantity_for_checkout
                    ForCheckout.query.delete()
                    db.session.commit()
                return
            saved_session_id = saved_session.stripe_checkout_session_id
        except AttributeError:
            return
        else:
            if saved_session_id is None:
                return
            session_list_items = stripe.checkout.Session.list_line_items(saved_session_id)["data"]
            list_of_items_names = [item.description for item in session_list_items]
            url_ending = request.url.split("/")[-1]
            for product in session_list_items:
                product_from_stock = Product.query.filter_by(product_name=product.description).first()
                for_checkout_per_db = ForCheckout.query.filter_by(prod_id=product_from_stock.id,
                                                                  user_id=current_user.id).all()
                for prod in for_checkout_per_db:
                    prod.adjusted_quantity = prod.quantity_for_checkout - product.quantity
                    prod.quantity_for_checkout -= prod.adjusted_quantity
            prods_with_session_flags = ForCheckout.query.filter_by(user_id=current_user.id).all()
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
    ## END OF ADDIOTIONAL FUNCTIONS SETUP

    @app.route("/")
    def homepage():
        adjust_product_quantity()
        popular_mapping()
        popular_flag = request.args.get("popular")
        sale_flag = request.args.get("sale")
        for_checkout = ForCheckout.query.filter_by(user_id=current_user.get_id()).all()
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
        adjust_product_quantity()
        popular_mapping()
        requested_product = Product.query.get(prod_id)
        list_of_product_likes = [like_i.author_id for like_i in requested_product.likes]
        form = forms.ReviewForm()
        for_checkout = ForCheckout.query.filter_by(user_id=current_user.get_id()).all()
        total_quantity_for_checkout = sum([prod.quantity_for_checkout for prod in for_checkout])
        if form.validate_on_submit():
            if not current_user.is_authenticated:
                flash("You need to login or register to leave reviews.")
                return redirect(url_for("login"))
            comment = Comment(text=form.text.data, date=datetime.date.today().strftime("%d-%b-%Y"),
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
            like_obj_to_create = Like(like_flag=1, product_like_is_for=product, like_author=author)
            db.session.add(like_obj_to_create)
            db.session.commit()
        return "", 204


    @app.route("/about")
    def about():
        adjust_product_quantity()
        for_checkout = ForCheckout.query.filter_by(user_id=current_user.get_id()).all()
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
        form = forms.RegisterForm()
        if form.validate_on_submit():
            user = User.query.filter_by(email=form.email.data).first()
            if user is not None:
                flash("A user with this email already exists. Please use another email or go to login page")
                return redirect(url_for("register"))
            new_user_details = {key: value.data for key, value in form._fields.items()
                                if key not in ["submit", "csrf_token", "password"]}
            salted_password = generate_password_hash(
                password=form.password.data, method="pbkdf2:sha256", salt_length=16)
            new_user_details["password"] = salted_password
            new_user_details["email"] = new_user_details["email"].lower()
            new_user = User(**new_user_details)
            db.session.add(new_user)
            db.session.commit()
            login_user(new_user)
            return redirect(url_for("homepage"))
        return render_template("register.html", form=form, logged_in=current_user.is_authenticated,
                               user=current_user)


    @app.route("/login", methods=["GET", "POST"])
    def login():
        form = forms.LoginForm()
        if form.validate_on_submit():
            user = User.query.filter_by(email=form.email.data.lower()).first()
            if user is None:
                flash("The email you entered does not exist, please try again.")
                return redirect(url_for("login"))
            password_checked = check_password_hash(pwhash=user.password, password=form.password.data)
            if password_checked:
                login_user(user)
                return redirect(url_for("homepage"))
            flash("The password you entered is not correct, please try again.")
            return redirect(url_for("login"))
        return render_template("login.html", form=form, logged_in=current_user.is_authenticated, user=current_user)


    @app.route("/logout")
    def logout():
        logout_user()
        return redirect(url_for("homepage"))


    @app.route("/", methods=["GET", "POST"])
    @login_required
    def add_to_cart():
        quantity = int(request.form.get("quantity"))
        prod_id = request.form.get("prod_id")
        prod_for_checkout = Product.query.get(prod_id)
        if prod_for_checkout.quantity < quantity:
            flash(
                f"Not enough items of this product at the stock. Current quantity is {prod_for_checkout.quantity} items.")
            return redirect(url_for("get_product_page", prod_id=prod_for_checkout.id))
        for_checkout = {prod_id: quantity}
        is_already_added = ForCheckout.query.filter_by(prod_id=prod_id, user_id=current_user.id).first()
        if is_already_added:
            is_already_added.quantity_for_checkout += quantity
            prod_for_checkout.quantity -= quantity
            db.session.commit()
        else:
            new_checkout = ForCheckout(
                quantity_for_checkout=for_checkout[prod_id],
                product_for_checkout=prod_for_checkout,
                user_purchasing=current_user,
                adjusted_quantity=0,
            )
            db.session.add(new_checkout)
            updated_quantity = prod_for_checkout.quantity - quantity
            prod_for_checkout.quantity = updated_quantity
            db.session.commit()
        return redirect(request.referrer)


    @app.route('/checkout-session', methods=["GET", 'POST'])
    def checkout_session():
        success_url = "/".join(request.referrer.split("/")[:-1])
        for_checkout = ForCheckout.query.filter_by(user_id=current_user.get_id()).all()
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
            customer_email=current_user.email,
        )
        session_id_to_save = checkout_session["id"]
        products_for_checkout_per_user = ForCheckout.query.filter_by(user_id=current_user.id).all()
        for prod in products_for_checkout_per_user:
            prod.stripe_checkout_session_id = session_id_to_save
        db.session.commit()
        return redirect(checkout_session.url, 303)


    @app.route('/success')
    @login_required
    def success():
        adjust_product_quantity()
        for_checkout = ForCheckout.query.filter_by(user_id=current_user.get_id()).all()
        total_quantity_for_checkout = sum([prod.quantity_for_checkout for prod in for_checkout])
        return render_template("success.html", logged_in=current_user.is_authenticated, user=current_user,
                               total_for_checkout=total_quantity_for_checkout)


    if __name__ == "__main__":
        app.run(host="0.0.0.0", debug=True, port=5000)
