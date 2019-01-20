# coding:utf-8
from flask import Flask, render_template, redirect, url_for
from flask_bootstrap import Bootstrap
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, BooleanField
from wtforms.validators import InputRequired, Email, Length
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask_debugtoolbar import DebugToolbarExtension

app = Flask(__name__)
app.debug = True
app.config['SECRET_KEY'] = 'secret_key'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.sqlite3'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = True
app.config['DEBUG_TB_INTERCEPT_REDIRECTS'] = False
bootstrap = Bootstrap(app)
db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.init_app(app)
toolbar = DebugToolbarExtension(app)

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(8), unique=True, nullable=False)
    userid = db.Column(db.String(8), unique=True, nullable=False)
    email = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(12), nullable=False)

def __init__(self, name, userid, email, password):
   self.name = name
   self.userid = userid
   self.email = email
   self.password = password

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


class LoginForm(FlaskForm):
    userid = StringField('ユーザーID', validators=[InputRequired(), Length(min=4, max=15)])
    password = PasswordField('パスワード', validators=[InputRequired(), Length(min=4, max=80)])
    remember = BooleanField('remember me')


class RegisterForm(FlaskForm):
    userid = StringField('ユーザーID', validators=[InputRequired(), Length(min=4, max=15)])
    email = StringField('メールアドレス', validators=[InputRequired(), Email(message='Invalid email'), Length(max=50)])
    name = StringField('名前', validators=[InputRequired(), Length(min=4, max=15)])
    password = PasswordField('パスワード', validators=[InputRequired(), Length(min=4, max=80)])


@app.route('/')
def index():
    return render_template('index.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()

    if form.validate_on_submit():
        user = User.query.filter_by(userid=form.userid.data).first()
        if user:
            if check_password_hash(user.password, form.password.data):
                login_user(user, remember=form.remember.data)
                return redirect(url_for('users'))

        return '<h1>Invalid name or password</h1>'

    return render_template('login.html', form=form)


@app.route('/signup', methods=['GET', 'POST'])
def signup():
    form = RegisterForm()

    if form.validate_on_submit():
        hashed_password = generate_password_hash(form.password.data, method='sha256')
        new_user = User(userid=form.userid.data, name=form.name.data, email=form.email.data, password=hashed_password)
        db.session.add(new_user)
        db.session.commit()


        return redirect(url_for('users'))

    return render_template('signup.html', form=form)


@app.route('/users')
@login_required
def users():
    return render_template('users.html', user = User.query.all() )


@app.route('/users/:id')
@login_required
def show():
    return render_template('show.html', user = User.query.all() )


@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))

if __name__ == '__main__':
    app.run(debug=True)
