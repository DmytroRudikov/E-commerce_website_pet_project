from flask_wtf import FlaskForm
from flask_ckeditor import CKEditorField
from wtforms import StringField, SubmitField, PasswordField, FloatField, IntegerField, ValidationError
from wtforms.validators import DataRequired, Email, URL, AnyOf, EqualTo, Length
from markupsafe import Markup
import email_validator


# WTForms
class RegisterForm(FlaskForm):
    email = StringField(label="Email", validators=[DataRequired(Markup("<span style='color: red'>This field is required</span>")), Email(Markup("<span style='color: red'>Invalid email address</span>"))])
    password = PasswordField(label="Password", validators=[DataRequired(Markup("<span style='color: red'>This field is required</span>")), Length(5, message=Markup("<span style='color: red'>A password needs to be at least 5 signs long.</span>"))])
    repeat_password = PasswordField("Repeat Your Password", validators=[DataRequired(Markup("<span style='color: red'>This field is required</span>")), EqualTo("password", Markup("<span style='color: red'>Passwords do not match. Make sure you have provided the same password for both fields.</span>"))])
    user_name = StringField(label="Your Name", validators=[DataRequired(Markup("<span style='color: red'>This field is required</span>"))], description="&nbsp;")
    submit = SubmitField(label="Ready to Shop!")


class LoginForm(FlaskForm):
    email = StringField(label="Email", validators=[DataRequired(Markup("<span style='color: red'>This field is required</span>")), Email(Markup("<span style='color: red'>Invalid email address</span>"))])
    password = PasswordField(label="Password", validators=[DataRequired(Markup("<span style='color: red'>This field is required</span>"))], description="&nbsp;")
    submit = SubmitField(label="Log in")


# Custom Validators for the ProductForm below
def sale_validator(form, field):
    message = Markup("<span style='color: red'>If data is entered into one of the fields ('Product's old price' or "
                     "'Sale flag') another field has to be filled in as well.</span>")
    if field.name == "sale_flag":
        if field.data == "":
            if form.old_price.data != "":
                raise ValidationError(message)
    elif field.name == "old_price":
        if field.data == "":
            if form.sale_flag.data != "":
                raise ValidationError(message)


def float_price_validator(form, field):
    if field.name == "old_price":
        if field.data == "":
            return
        try:
            float(field.data)
        except ValueError:
            raise ValidationError(Markup("<span style='color: red'>Incorrect Decimal input. "
                                         "Only numbers accepted (0-9) and a '.' sign as a separator.</span>"))
# Customization end


class ProductForm(FlaskForm):
    product_name = StringField(label="Product's Name", validators=[DataRequired(Markup("<span style='color: red'>This field is required</span>"))])
    quantity = IntegerField(label="Quantity of the product available", validators=[DataRequired(Markup("<span style='color: red'>This field is required</span>"))])
    old_price = StringField(
        label="Product's old price (Optional field, unless you plan to store a product with a discount)",
        validators=[sale_validator, float_price_validator])
    new_price = FloatField(label="Product's new price", validators=[DataRequired(Markup("<span style='color: red'>This field is required</span>"))])
    description = CKEditorField(label="Product's description", validators=[DataRequired(Markup("<span style='color: red'>This field is required</span>"))])
    picture = StringField(label="Product's image", description="A valid link to product's image",
                          validators=[DataRequired(Markup("<span style='color: red'>This field is required</span>")), URL(message=Markup("<span style='color: red'>Invalid URL</span>"))])
    sale_flag = StringField(label="Sale flag",
                            description='Type "sale" if product has a discount, otherwise leave empty (Optional field, unless you plan to store a product with a discount)',
                            validators=[sale_validator,
                                        AnyOf(values=["", "sale"],
                                              message=Markup('<span style="color: red">Incorrect input provided. '
                                                      'Type "sale" only, if you wish to mark a product with a '
                                                      'discount.</span>'))])
    submit = SubmitField(label="Submit")


class ReviewForm(FlaskForm):
    text = CKEditorField(label="We highly value your opinion! Please leave your review or share any thoughts/comments.",
                         validators=[DataRequired(Markup("<span style='color: red'>To submit a review please write it in the field provided above</span>"))])
    submit = SubmitField(label="Submit Review")
