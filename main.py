from functools import wraps

from flask import Flask, render_template, redirect, url_for, flash, request
from flask_bootstrap import Bootstrap
from flask_ckeditor import CKEditor
from datetime import datetime
from pytz import timezone
import pytz
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import relationship
from flask_login import UserMixin, login_user, LoginManager, login_required, current_user, logout_user
from forms import CreatePostForm, RegisterForm, LoginForm, CommentForm
from flask_gravatar import Gravatar
from sqlalchemy import Table, Column, Integer, ForeignKey
from sqlalchemy.orm import relationship
from sqlalchemy.ext.declarative import declarative_base
import smtplib
import requests

import re
import os

email_regex = re.compile(r"[^@]+@[^@]+\.[^@]+")

MY_EMAIL = os.environ.get('EMAIL')
PASSWORD = os.environ.get('PASSWORD')

app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET')
ckeditor = CKEditor(app)
Bootstrap(app)

gravatar = Gravatar(app,
                    size=100,
                    rating='g',
                    default='retro',
                    force_default=False,
                    force_lower=False,
                    use_ssl=False,
                    base_url=None)

##CONNECT TO DB
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL', 'sqlite:///blog.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

Base = declarative_base()


##CONFIGURE TABLES

class Users(UserMixin, db.Model):
    __tablename__ = "users"
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(250), nullable=False)
    email = db.Column(db.String(250), nullable=False, unique=True)
    password = db.Column(db.String(250), nullable=False)
    # This will act like a List of BlogPost objects attached to each User.
    # The "author" refers to the author property in the BlogPost class.
    posts = relationship("BlogPost", back_populates="author")
    comments = relationship("Comment", back_populates="comment_author")


class BlogPost(db.Model):
    __tablename__ = "blog_posts"
    id = db.Column(db.Integer, primary_key=True)

    # Create Foreign Key, "users.id" the users refers to the tablename of User.
    author_id = db.Column(db.Integer, db.ForeignKey("users.id"))
    # Create reference to the User object, the "posts" refers to the posts property in the User class.
    author = relationship("Users", back_populates="posts")

    title = db.Column(db.String(250), unique=True, nullable=False)
    subtitle = db.Column(db.String(250), nullable=False)
    date = db.Column(db.String(250), nullable=False)
    body = db.Column(db.Text, nullable=False)
    img_url = db.Column(db.String(250), nullable=False)
    comments = relationship("Comment", back_populates="blog_post")


class Comment(db.Model):
    __tablename__ = "comments"
    id = db.Column(db.Integer, primary_key=True)
    text = db.Column(db.Text, nullable=False)
    date_time = db.Column(db.String(300), nullable=False)
    # Create Foreign Key, "users.id" the users refers to the tablename of User.
    author_id = db.Column(db.Integer, db.ForeignKey("users.id"))
    # Create Foreign Key, "blog_posts.id" the blog_posts refers to the tablename of BlogPost.
    post_id = db.Column(db.Integer, db.ForeignKey("blog_posts.id"))
    # Create reference to the User object, the "comments" refers to the comments property in the User class.
    comment_author = relationship("Users", back_populates="comments")
    # Create reference to the BlogPost object, the "comments" refers to the comments property in the BlogPost class.
    blog_post = relationship("BlogPost", back_populates="comments")


# Create database
# db.create_all()
#etereesffs
login_manager = LoginManager()
login_manager.init_app(app)


@login_manager.user_loader
def load_user(user_id):
    return Users.query.get(user_id)


def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if current_user.is_anonymous or current_user.id != 1:
            return render_template("403.html"), 403
        return f(*args, **kwargs)

    return decorated_function


@app.route('/')
def get_all_posts():
    # quote_data = response.json()
    # quote = quote_data[0]["q"]
    # author = quote_data[0]["a"]
    quote="sdkfn dfn nfdn dsn nfdsnfdsn nf ndnfdsnf"
    author="dfndj"
    posts = BlogPost.query.all()
    return render_template("index.html", all_posts=posts, current_user=current_user, now=datetime.utcnow(), q=quote,
                           a=author)


@app.route("/register", methods=["GET", "POST"])
def register():
    form = RegisterForm()
    if form.validate_on_submit():
        user_email = request.form.get("email")
        user_password = request.form.get("password")
        user_name = request.form.get("name").title()
        user_confirm_password = request.form.get("confirm_password")
        user = db.session.query(Users).filter_by(email=user_email).first()

        if not user:
            # check if address is valid in email form
            if email_regex.match(user_email):
                # print("address is valid")
                # check if email really exist
                response = requests.get(
                    "https://isitarealemail.com/api/email/validate",
                    params={'email': user_email})
                status = response.json()['status']
                if status == "valid":
                    print("email is valid")
                    if user_password == user_confirm_password:
                        hashed_and_salted_password = generate_password_hash(user_password, method='pbkdf2:sha256',
                                                                            salt_length=8)
                        new_user = Users(email=user_email,
                                         password=hashed_and_salted_password,
                                         name=user_name)
                        db.session.add(new_user)
                        db.session.commit()

                        # logs in and authenticate user
                        login_user(new_user)
                        return redirect(url_for("get_all_posts"))
                    else:
                        flash("Password doesn't match. Please try again")
                        return redirect(url_for("register"))
                elif status == "invalid":
                    flash("Oops! looks like the email address entered was invalid. Please try again.")
                    return redirect(url_for("register"))
                else:
                    flash("Please enter a valid email address.")
                    return redirect(url_for("register"))
            else:
                flash("Please enter a valid email address")
                return redirect(url_for("register"))
        else:
            flash("You've already signed up with that email, login instead.")
            return redirect(url_for("login"))
    return render_template("register.html", form=form, current_user=current_user, now=datetime.utcnow())


@app.route('/login', methods=["GET", "POST"])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user_email = request.form.get("email")
        user_password = request.form.get("password")

        # find user by email entered
        user = db.session.query(Users).filter_by(email=user_email).first()

        # checks whether user is present or not in the database
        if user:
            # Checks the user password against the typed password
            if check_password_hash(user.password, user_password):
                login_user(user)
                return redirect(url_for("get_all_posts"))
            else:
                flash("Password incorrect, please try again.")
                return redirect(url_for("login"))
        else:
            flash("That email does not exist, please try again.")
            return redirect(url_for("login"))

    return render_template("login.html", form=form, current_user=current_user, now=datetime.utcnow())


@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('get_all_posts', current_user=current_user, now=datetime.utcnow()))


@app.route("/post/<int:post_id>", methods=["GET", "POST"])
def show_post(post_id):
    form = CommentForm()
    requested_post = BlogPost.query.get(post_id)
    if form.validate_on_submit():
        if not current_user.is_authenticated:
            flash("Login or register to comment.")
            return redirect(url_for('login'))

        new_comment = Comment(text=form.comment_text.data,
                              comment_author=current_user,
                              blog_post=requested_post,
                              date_time=f"On{datetime.now().strftime(' %a, %b %d, %Y')} At {datetime.now().strftime('%I:%M %p')} "
                              )
        db.session.add(new_comment)
        db.session.commit()

    return render_template("post.html", post=requested_post, current_user=current_user, form=form,
                           gravatar=gravatar,
                           now=datetime.utcnow())


@app.route("/about")
def about():
    return render_template("about.html", current_user=current_user, now=datetime.utcnow())


@app.route("/contact", methods=["GET", "POST"])
def contact():
    if request.method == "POST":
        if current_user.is_anonymous:
            flash("You need to login or register to contact.")
            return redirect(url_for('login'))
        name = request.form["username"]
        email = request.form["email"]
        phone_number = request.form["phone_number"]
        message = request.form["message"]
        if phone_number == "":
            phone_number = "Not Provided"
        msg = f"Name: {name}\n" \
              f"Email: {email}\n" \
              f"Phone: {phone_number}\n" \
              f"Message: {message}"
        with smtplib.SMTP("smtp.gmail.com", port=587) as connection:
            connection.starttls()
            connection.login(user=MY_EMAIL, password=PASSWORD)
            connection.sendmail(from_addr=MY_EMAIL, to_addrs="ayushnegi352@gmail.com", msg=f"Subject: New Message\n\n{msg}")
        url = "https://ayush-blog.herokuapp.com/"
        msg1 = f"Your message has been received successfully at {url}. We'll get back to you as soon as possible."
        with smtplib.SMTP("smtp.gmail.com", port=587) as connection:
            connection.starttls()
            connection.login(user=MY_EMAIL, password=PASSWORD)
            connection.sendmail(from_addr=MY_EMAIL, to_addrs=email, msg=f"Subject: Thanks!\n\n{msg1}")
        return render_template("contact.html", msg=True, current_user=current_user, now=datetime.utcnow())
    return render_template("contact.html", current_user=current_user, msg=False, now=datetime.utcnow())


@app.route("/new-post", methods=["GET", "POST"])
def add_new_post():
    if current_user.is_anonymous:
        flash("Login or register to create a post.")
        return redirect(url_for("login"))
    form = CreatePostForm()
    if form.validate_on_submit():
        if db.session.query(BlogPost).filter_by(title=form.title.data).first():
            flash("A blog post with that title already exist. Please think about a different topic.")
            return redirect(url_for("add_new_post"))
        new_post = BlogPost(
            title=form.title.data,
            subtitle=form.subtitle.data,
            body=form.body.data,
            img_url=form.img_url.data,
            author=current_user,
            date=datetime.now().strftime("%B %d, %Y")
        )
        db.session.add(new_post)
        db.session.commit()
        return redirect(url_for("get_all_posts"))
    return render_template("make-post.html", form=form, current_user=current_user, now=datetime.utcnow())


@app.route("/edit-post/<int:post_id>", methods=["GET", "POST"])
def edit_post(post_id):
    post = BlogPost.query.get(post_id)
    edit_form = CreatePostForm(
        title=post.title,
        subtitle=post.subtitle,
        img_url=post.img_url,
        body=post.body
    )
    if edit_form.validate_on_submit():
        post.title = edit_form.title.data
        post.subtitle = edit_form.subtitle.data
        post.img_url = edit_form.img_url.data
        post.body = edit_form.body.data
        db.session.commit()
        return redirect(url_for("show_post", post_id=post.id))

    return render_template("make-post.html", form=edit_form, current_user=current_user, is_edit=True,
                           now=datetime.utcnow())


@app.route("/delete/<int:post_id>")
@admin_required
def delete_post(post_id):
    post_to_delete = BlogPost.query.get(post_id)
    db.session.delete(post_to_delete)
    db.session.commit()
    return redirect(url_for('get_all_posts'))


if __name__ == "__main__":
    app.run(debug=True, port=5000)
