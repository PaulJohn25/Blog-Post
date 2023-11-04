from datetime import date
from flask import Flask, redirect, render_template, url_for, flash, abort
from flask_bootstrap import Bootstrap5
from flask_ckeditor import CKEditor
from flask_gravatar import Gravatar
from flask_login import LoginManager, login_user, logout_user, UserMixin, current_user, login_required
from flask_sqlalchemy import SQLAlchemy
from functools import wraps
from werkzeug.security import generate_password_hash, check_password_hash
from sqlalchemy.orm import relationship
from forms import CreatePostForm, RegisterForm, LogInForm, CommentForm
import os


app = Flask(__name__)
app.config["SECRET_KEY"] = os.environ.get("secret_key")


ckeditor = CKEditor()
ckeditor.init_app(app)

bootstrap5 = Bootstrap5()
bootstrap5.init_app(app)

app.config["SQLALCHEMY_DATABASE_URI"] = os.environ.get("DB_URI", "sqlite:///C:/Users/imper/Blog/post.db")
db = SQLAlchemy()
db.init_app(app)

login_manager = LoginManager()
login_manager.init_app(app)


gravatar = Gravatar(
    app,
    size=100,
    rating='g',
    default='retro',
    force_default=False,
    force_lower=False,
    use_ssl=False,
    base_url=None,
)


# CONFIGURE TABLES
class User(UserMixin, db.Model):
    __tablename__ = "user"

    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    email = db.Column(db.String(50), nullable=False)
    password = db.Column(db.String(50), nullable=False)
    name = db.Column(db.String(50), nullable=False)

    # One-to-Many relationship: One user can have multiple blog posts and comments
    posts = relationship("BlogPost", back_populates="author")
    comments = relationship("Comment", back_populates="commenter")


class BlogPost(db.Model):
    __tablename__ = "blog_post"

    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    author_id = db.Column(db.Integer, db.ForeignKey("user.id"))
    title = db.Column(db.String(200), nullable=False)
    subtitle = db.Column(db.String(200), nullable=False)
    body = db.Column(db.Text, nullable=False)
    date = db.Column(db.String(30), nullable=False)
    img_url = db.Column(db.String(200), nullable=False)

    # Many-to-One relationship: Many blog posts can belong to one user
    author = relationship("User", back_populates="posts")

    # One-to-Many relationship: One blog post can have multiple comments
    comments = relationship("Comment", back_populates="parent_post")


class Comment(db.Model):
    __tablename__ = "comment"

    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    text = db.Column(db.Text, nullable=False)

    author_id = db.Column(db.Integer, db.ForeignKey("user.id"))
    post_id = db.Column(db.Integer, db.ForeignKey("blog_post.id"))

    # Many-to-One relationship: Many comments can belong to one user
    commenter = relationship("User", back_populates="comments")

    # Many-to-One relationship: Many comments can belong to one blog post
    parent_post = relationship("BlogPost", back_populates="comments")


# Create Table Schema
with app.app_context():
    db.create_all()


def admin_only(func):
    @wraps(func)
    def wrapped_function(*args, **kwargs):

        if not current_user.is_authenticated:
            return abort(404)
        elif current_user.get_id() != "1":  # Admin ID
            return abort(403)

        return func(*args, **kwargs)

    return wrapped_function


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(user_id)


@app.route("/register", methods=["GET", "POST"])
def register():
    form = RegisterForm()

    email = form.email.data
    result = db.session.execute(db.select(User).where(User.email == email))
    user = result.scalar()

    if form.validate_on_submit():
        if user:
            flash("The email you provided is already associated with an existing account. Please log in with your "
                  "existing account or use a different email address to sign up.")
            return redirect(url_for("login"))
        else:
            hashed_password = generate_password_hash(
                password=form.password.data,
                salt_length=8
            )

            with app.app_context():
                new_user = User(
                    email=form.email.data,
                    password=hashed_password,
                    name=form.name.data,
                )
                db.session.add(new_user)
                db.session.commit()

                login_user(user=new_user)

                return redirect(url_for("get_all_posts"))  # Redirect new user to homepage

    return render_template(
        "register.html",
        form=form,
        logged_in=current_user.is_authenticated
    )


@app.route("/login", methods=["GET", "POST"])
def login():

    form = LogInForm()

    if form.validate_on_submit():

        email = form.email.data
        password = form.password.data

        result = db.session.execute(db.select(User).where(User.email == email))
        user = result.scalar()

        if user is None:
            flash("The email you provided does not exist. Register if you don't have an account.")
            return redirect(url_for('login'))
        elif not check_password_hash(user.password, password):
            flash("Password is incorrect, please try again.")
            return redirect(url_for('login'))
        else:
            login_user(user)
            return redirect(url_for("get_all_posts"))

    return render_template(
        "login.html",
        form=form,
        logged_in=current_user.is_authenticated
    )


@app.route("/")
def get_all_posts():
    posts = db.session.query(BlogPost).all()

    return render_template(
        "index.html",
        posts=posts,
        logged_in=current_user.is_authenticated,
        current_user_id=current_user.get_id()
    )


@app.route("/logout")
def logout():
    logout_user()

    return redirect(url_for('get_all_posts'))


@app.route("/post/<int:post_id>", methods=["GET", "POST"])
def show_post(post_id):
    form = CommentForm()

    requested_post = BlogPost.query.get(post_id)

    if form.validate_on_submit():
        comment = form.comment.data.strip()

        requested_post = db.get_or_404(BlogPost, post_id)
        new_comment = Comment(
            text=comment,
            parent_post=requested_post,
            commenter=current_user
        )
        # Add the new comment to the database.
        db.session.add(new_comment)
        # Commit changes to the database.
        db.session.commit()
        form.comment.data = ""  # Clear comment form after submission

    return render_template(
        "post.html",
        post=requested_post,
        logged_in=current_user.is_authenticated,
        current_user_id=current_user.get_id(),
        form=form
    )


@app.route("/add-new-post", methods=["GET", "POST"])
@admin_only
def add_new_post():
    form = CreatePostForm()

    if form.validate_on_submit():
        with app.app_context():
            new_post = BlogPost(
                title=form.title.data,
                subtitle=form.subtitle.data,
                author=current_user,
                body=form.body.data,
                date=date.today().strftime("%B %d, %Y"),
                img_url=form.img_url.data
            )

            db.session.add(new_post)
            db.session.commit()

            return redirect(url_for("get_all_posts"))

    return render_template(
        "make-post.html",
        form=form,
        logged_in=current_user.is_authenticated
    )


@app.route("/edit-post/<int:post_id>", methods=["GET", "POST"])
@admin_only
def edit_post(post_id):
    post = db.get_or_404(BlogPost, post_id)
    # Pre-populate form with post-data.
    form = CreatePostForm(obj=post)

    if form.validate_on_submit():
        with app.app_context():
            post = BlogPost.query.get(post_id)
            # Update the BlogPost object with the form data.
            form.populate_obj(post)
            # Commit changes to the database
            db.session.commit()
        return redirect(url_for("get_all_posts"))

    return render_template("make-post.html", form=form,
                           is_edit=True,
                           logged_in=current_user.is_authenticated
                           )


@app.route("/delete/<int:post_id>")
@admin_only
def delete_post(post_id):
    """
    Deletes a blog post with the given post_id.
    :param post_id: Blog post UNIQUE ID
    :return: Redirects to homepage
    """
    with app.app_context():
        post_to_delete = BlogPost.query.get(post_id)
        db.session.delete(post_to_delete)
        db.session.commit()

    return redirect(url_for("get_all_posts"))


@app.route("/delete-comment/<int:comment_id>")
@login_required
def delete_comment(comment_id):

    with app.app_context():
        comment = Comment.query.get(comment_id)
        db.session.delete(comment)
        db.session.commit()
        return redirect(url_for("show_post", post_id=comment.post_id))


@app.route("/about")
def about():
    return render_template("about.html", logged_in=current_user.is_authenticated)


@app.route("/contact")
def contact():
    return render_template("contact.html", logged_in=current_user.is_authenticated)


if __name__ == "__main__":
    app.run(debug=False)
