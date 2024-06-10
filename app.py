from flask import Flask, render_template, make_response,flash ,redirect,url_for
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, BooleanField, SubmitField, PasswordField, EmailField,TextAreaField
from wtforms.validators import DataRequired, Email, Length

from flask_sqlalchemy import SQLAlchemy
from datetime import datetime
from flask_migrate import Migrate
from wtforms.widgets import TextArea
from flask_ckeditor import CKEditor, CKEditorField
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user


db = SQLAlchemy()
migrate = Migrate()
ckeditor = CKEditor()

def create_app():
    print("Before Flask app definition")
    app = Flask(__name__)
    app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.sqlite3'
    app.config['SECRET_KEY'] = "MY FORM SECRET_KEY"
    ckeditor.init_app(app)
    
    db.init_app(app)
    
    with app.app_context():
        db.create_all()
        print("created database")

    return app
print("After SQLAlchemy definition")
print("program is running")

class Posts(db.Model):
    id=db.Column(db.Integer, primary_key=True)
    title=db.Column(db.String(200),nullable=False)
    content=db.Column(db.Text,nullable=False)
    author=db.Column(db.String(200),nullable=False)
    date_posted=db.Column(db.DateTime,default=datetime.utcnow)
    slug=db.Column(db.String(200))
    author_id=db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    comment = db.relationship('Comment', backref='comm', lazy=True)

class Comment(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    text = db.Column(db.Text, nullable=False)
    user_id=db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    post_id = db.Column(db.Integer, db.ForeignKey('posts.id'), nullable=False)

class Users(db.Model, UserMixin):
    id=db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(30),nullable=False,unique=True)
    name=db.Column(db.String(200),nullable=False)
    db_password = db.Column("password", db.String)
    email=db.Column(db.String(120),nullable=False,unique=True)
    date_added=db.Column(db.DateTime,default=datetime.utcnow)
    posts=db.relationship('Posts',backref='authr',lazy=True)
    comment = db.relationship('Comment',backref='comu',lazy=True)

    @property
    def password(self):
        raise AttributeError('password is not a readable attribute')
    
    @password.setter
    def password(self, password):
        self.db_password = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.db_password, password)
      

def __repr__(self):
    return '<Name: %r>' % self.name

 
#create form class
class SigninForm(FlaskForm):
    username = StringField("Username",validators=[DataRequired()])
    name=StringField("Name",validators=[DataRequired()])
    email = EmailField('Email', [Email()])
    password=PasswordField('Password', [
        DataRequired(message='Password is required.'),
        Length(message='Password must be at least 6 characters long.', min=6)
    ])
    submit=SubmitField("Submit")

class PostsForm(FlaskForm):
    title=StringField("Title",validators=[DataRequired()])
    #content=StringField("Content",validators=[DataRequired()],widget=TextArea())
    content=CKEditorField("Content",validators=[DataRequired()])
    author=StringField("Author")
    slug=StringField("Slug",validators=[DataRequired()])
    submit=SubmitField("Submit")
class CommentForm(FlaskForm):
    comment_text = TextAreaField('Comment', validators=[DataRequired()])
    submit = SubmitField('Submit')

class LoginForm(FlaskForm):
    username = StringField("Username",validators=[DataRequired()])
    password = PasswordField("Password",validators=[DataRequired()])
    submit=SubmitField("Submit")

class SearchForm(FlaskForm):
    searched = StringField("Searched",validators=[DataRequired()])
    submit=SubmitField("Submit")


                                        
app = create_app()



login_manager=LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

@login_manager.user_loader
def load_user(user_id):
    return Users.query.get(int(user_id))

@app.context_processor
def base():
    form = SearchForm()
    return dict(form=form)

@app.route('/posts/<int:id>')
def post(id):
    post = Posts.query.get_or_404(id)
    form = CommentForm() 
    comments = Comment.query.filter_by(post_id=id).all()
    return render_template('post.html',post=post,comments=comments,form=form)

@app.route('/search',methods=["POST"])
def search():
    form = SearchForm()
    posts = Posts.query
    searched_data = form.searched.data
    if form.validate_on_submit():
        
        
        posts = posts.filter(Posts.content.like('%'+searched_data+'%'))
        posts = posts.order_by(Posts.title.desc).all()
        
    else:
        print("failed here")
    return render_template('search.html', 
                               form=form,
                                 searched=searched_data,
                                 posts=posts)


@app.route('/delete-post/<int:id>',methods=['GET','POST'])
@login_required
def delete_post(id):
    post = Posts.query.get_or_404(id)
    id = current_user.id
    if id == post.author_id:
        db.session.delete(post)
        db.session.commit()
        flash("Post has been deleted")
        return redirect(url_for('posts'))
    else:
        flash("You are not authorized to delete this post")
        return redirect(url_for('posts'))


@app.route('/login',methods=['GET','POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = Users.query.filter_by(username=form.username.data).first()
        if user:
            if user.check_password(form.password.data):
                login_user(user)
                flash("You have been logged in")
                return redirect(url_for('dashboard'))
            else:
                flash("Incorrect password")
        else:
            flash("User does not exist")
    return render_template('login.html',form=form)

@app.route('/post/<int:id>', methods=['GET', 'POST'])
def postc(id):
    post = Posts.query.get_or_404(id)
    form = CommentForm()
    comments = Comment.query.filter_by(post_id=id).all()
    if form.validate_on_submit():
        comments = Comment(text=form.comment_text.data, post_id=id, user_id=current_user.id)
        db.session.add(comments)
        db.session.commit()
        return redirect(url_for('postc', id=id))
    return render_template('post.html', post=post,comments=comments,form=form)

@app.route('/logout', methods=['GET', 'POST'])
@login_required
def logout():
    logout_user()
    flash("You have been logged out")
    return redirect(url_for('home'))


@app.route('/dashboard',methods=['GET','POST'])
@login_required
def dashboard():
    return render_template('dashboard.html')

@app.route("/posts/edit/<int:id>",methods=['GET','POST'])
@login_required
def edit_post(id):
    post = Posts.query.get_or_404(id)
    form=PostsForm()
    id = current_user.id
    
    if form.validate_on_submit():
        
            post.title = form.title.data
            post.slug = form.slug.data
            post.author = current_user.name
            post.content = form.content.data
            db.session.add(post)
            db.session.commit()
            flash("Post has been updated")
            return redirect(url_for('post',id=post.id))
            
    if id == post.author_id:
        form.title.data =post.title
        form.slug.data = post.slug
        form.content.data = post.content
        return render_template('edit_post.html',form=form)
    else:
        flash("You are not authorized to edit this post")
        return redirect(url_for('posts'))
    
@app.route('/add-post',methods=['GET','POST'])
@login_required
def add_post():
    form = PostsForm()
    if form.validate_on_submit():
        author = current_user.id
        post = Posts(title=form.title.data,content=form.content.data,author_id=author,author=current_user.name,slug=form.slug.data)
        db.session.add(post)
        db.session.commit()
        flash("Post added successfully")
        form.title.data = ''
        form.content.data = ''
        form.author.data = ''
        form.slug.data = ' '


    our_posts = Posts.query.order_by(Posts.date_posted)
    return render_template('add-post.html',
    form=form,
    our_posts=our_posts
    )

@app.route('/posts')
def posts():
    our_posts = Posts.query.order_by(Posts.date_posted)
    
    return render_template('posts.html',
    our_posts=our_posts
    )

@app.route('/')
def home():
    # Fetch featured posts (for simplicity, we'll just get the most recent ones)
    featured_posts = Posts.query.order_by(Posts.date_posted.desc()).limit(3).all()
    
    # Fetch latest posts
    latest_posts = Posts.query.order_by(Posts.date_posted.desc()).limit(6).all()
    
    # Render the template with the fetched posts
    response = make_response(render_template('index.html', featured_posts=featured_posts, latest_posts=latest_posts))
    return response
  

@app.route('/signin',methods=['GET', 'POST'])
def signin():
    name = None
    form =SigninForm()
    if form.validate_on_submit():
        user = Users.query.filter_by(email=form.email.data).first()
        if user is None:
            print(form.password.data)
            hashed_pw = generate_password_hash(form.password.data)
            user = Users(username=form.username.data,name=form.name.data,email=form.email.data,db_password=hashed_pw)
            db.session.add(user)
            db.session.commit()
        name = form.name.data
        email = form.email.data
        password = form.password.data
        form.name.data = ''
        flash("Sign in successfully")
    our_users = Users.query.order_by(Users.date_added)
    return render_template('signin.html',
    name=name,
    form=form,
    our_users=our_users
    )


