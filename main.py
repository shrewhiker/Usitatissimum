from flask import Flask, render_template, redirect, url_for, flash, request
from flask_bootstrap import Bootstrap
from flask_ckeditor import CKEditor
from datetime import date
from functools import wraps
from flask import abort
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import relationship
from flask_login import UserMixin, login_user, LoginManager, login_required, current_user, logout_user
from forms import CreatePostForm, RegisterForm, LoginForm, CommentForm
from flask_gravatar import Gravatar
from datetime import datetime
import os

app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY')
ckeditor = CKEditor(app)
Bootstrap(app)
gravatar = Gravatar(
    app,
    size=100,
    rating='g',
    default='retro',
    force_default=False,
    force_lower=False,
    use_ssl=False,
    base_url=None
)

##CONNECT TO DB
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL', 'sqlite:///blog.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.init_app(app)

##CONFIGURE TABLES
class User(UserMixin, db.Model):
    __tablename__ = 'user'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(1000))
    email = db.Column(db.String(100), unique=True)
    password = db.Column(db.String(100))

    #Relationships
    posts = relationship('BlogPost', back_populates='author')
    comments = relationship('Comment', back_populates='comment_author')
db.create_all()
#fa-stack-1x fa-inverse
# fa-stack-1x fa-inverse
#
#<i class="fas fa-circle fa-stack-2x"></i>

class BlogPost(db.Model):
    __tablename__ = "blog_posts"
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(250), unique=True, nullable=False)
    subtitle = db.Column(db.String(250), nullable=False)
    date = db.Column(db.String(250), nullable=False)
    body = db.Column(db.Text, nullable=False)
    img_url = db.Column(db.String(250), nullable=False)

    #User (author) relationship
    author_id = db.Column(db.Integer, db.ForeignKey("user.id"))
    author = relationship("User", back_populates="posts")

    # Children
    comments = relationship('Comment', back_populates='parent_post')
db.create_all()

class Comment(db.Model):
    __tablename__ = 'comment'
    id = db.Column(db.Integer, primary_key=True)
    text = db.Column(db.String(250))

    #author relationship
    author_id = db.Column(db.Integer, db.ForeignKey("user.id"))
    comment_author = relationship('User', back_populates='comments')

    # Parent
    post_id = db.Column(db.Integer, db.ForeignKey("blog_posts.id"))
    parent_post = relationship('BlogPost', back_populates='comments')
db.create_all()

def admin_only(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if current_user.id != 3:
            return abort(403)
        return f(*args, **kwargs)
    return decorated_function


@app.errorhandler(404)
def page_not_found(e):
    # note that we set the 404 status explicitly
    return render_template('404.html'), 404

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@app.route('/')
def get_all_posts():
    posts = BlogPost.query.all()
    return render_template("index.html", all_posts=posts, current_user=current_user, year=datetime.now().year)


@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegisterForm()
    if form.validate_on_submit():
        # HAD TO PUT .first() TO GET IT TO WORK, OTHERWISE ALL EMAILS WOULD TRIGGER THIS IF STATEMENT
        if User.query.filter_by(email=form.email.data).first():
            flash('there is already an account associated with this email')
            print(User.query.filter_by(email=form.email.data))
            return redirect(url_for('register'))
        password = form.password.data
        hash = generate_password_hash(password, method='pbkdf2:sha256', salt_length=8)
        new_user = User(
            name=form.name.data,
            email=form.email.data,
            password=hash
        )
        db.session.add(new_user)
        db.session.commit()
        login_user(new_user)
        return redirect(url_for('get_all_posts'))
    return render_template("register.html", form=form, current_user=current_user, year=datetime.now().year)


@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        email = form.email.data
        password = form.password.data
        user = User.query.filter_by(email=email).first()
        if not user:
            flash('No user with that email')
            return redirect(url_for('login'))
        if user and not check_password_hash(user.password, password):
            flash('Password is incorrect')
            return redirect(url_for('login'))
        if user and check_password_hash(user.password, password):
            if user.id == 3:
                admin = True
                print(admin)
                print(user.posts)
                login_user(user)
                return redirect(url_for('get_all_posts', admin=admin))
            else:
                login_user(user)
                return redirect(url_for('get_all_posts'))

    return render_template("login.html", form=form, current_user=current_user, year=datetime.now().year)


@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('get_all_posts', current_user=current_user))


@app.route("/post/<int:post_id>", methods=['GET', 'POST'])
def show_post(post_id):
    requested_post = BlogPost.query.get(post_id)
    comment = CommentForm()
    all_comments = requested_post.comments
    if request.method == 'POST':
        if not current_user.is_authenticated:
            flash('You must first login to comment')
            return redirect(url_for('login'))

        comment_form_data = comment.comments.data
        new_comment = Comment(
            text=comment_form_data,
            comment_author=current_user,
            parent_post=requested_post
        )
        db.session.add(new_comment)
        db.session.commit()



    return render_template("post.html", post=requested_post, form=comment, comments=all_comments, current_user=current_user, year=datetime.now().year)


@app.route("/about")
def about():
    return render_template("about.html", current_user=current_user, year=datetime.now().year)


@app.route("/contact")
def contact():
    return render_template("contact.html", current_user=current_user, year=datetime.now().year)


@app.route("/new-post", methods=['GET', 'POST'])
@admin_only
def add_new_post():
    form = CreatePostForm()
    if form.validate_on_submit():
        new_post = BlogPost(
            title=form.title.data,
            subtitle=form.subtitle.data,
            body=form.body.data,
            img_url=form.img_url.data,
            author=current_user,
            date=date.today().strftime("%B %d, %Y")
        )
        db.session.add(new_post)
        db.session.commit()
        return redirect(url_for("get_all_posts"))
    return render_template("make-post.html", form=form, current_user=current_user, year=datetime.now().year)


@app.route("/edit-post/<int:post_id>", methods=['GET', 'POST'])
@admin_only
def edit_post(post_id):
    post = BlogPost.query.get(post_id)
    edit_form = CreatePostForm(
        title=post.title,
        subtitle=post.subtitle,
        img_url=post.img_url,
        author=post.author,
        body=post.body
    )
    if edit_form.validate_on_submit():
        post.title = edit_form.title.data
        post.subtitle = edit_form.subtitle.data
        post.img_url = edit_form.img_url.data
        post.author = edit_form.author.data
        post.body = edit_form.body.data
        db.session.commit()
        return redirect(url_for("show_post", post_id=post.id, current_user=current_user, year=datetime.now().year))

    return render_template("make-post.html", form=edit_form, current_user=current_user, edit=True, year=datetime.now().year)



@app.route("/delete/<int:post_id>")
@admin_only
def delete_post(post_id):
    post_to_delete = BlogPost.query.get(post_id)
    db.session.delete(post_to_delete)
    db.session.commit()
    return redirect(url_for('get_all_posts', current_user=current_user, admin=True, year=datetime.now().year))

if __name__ == "__main__":
    app.run(debug=True)
