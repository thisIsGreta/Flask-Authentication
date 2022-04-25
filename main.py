from flask import Flask, render_template, request, url_for, redirect, flash, send_from_directory, abort, current_app
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin, login_user, LoginManager, login_required, current_user, logout_user
from werkzeug.security import generate_password_hash, check_password_hash
from urllib.parse import urljoin, urlparse

app = Flask(__name__)

app.config['SECRET_KEY'] = ''
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

##CREATE TABLE IN DB
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(100), unique=True)
    password = db.Column(db.String(100))
    name = db.Column(db.String(1000))
#Line below only required once, when creating DB. 
# db.create_all()


@app.route('/')
def home():
    return render_template("index.html")


@app.route('/register', methods=["GET", "POST"])
def register():
    if request.method == "POST":
        user_email = request.form['email']
        user_name = request.form['name']
        password = request.form['password']
        user_password = generate_password_hash(password, method='pbkdf2:sha256', salt_length=8)
        new_user = User(email=user_email, password=user_password, name=user_name)
        db.session.add(new_user)
        db.session.commit()
        return render_template('login.html')
    return render_template("register.html")


#Flask-Login
# The most important part of an application that uses Flask-Login is the LoginManager class.
login_manager = LoginManager()
login_manager.init_app(app)


def is_safe_url(target):
    ref_url = urlparse(request.host_url)
    test_url = urlparse(urljoin(request.host_url, target))
    return test_url.scheme in ('http', 'https') and \
           ref_url.netloc == test_url.netloc


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(user_id)


@app.route('/login', methods=["POST", "GET"])
def login():
    if request.method == "POST":
        user_email = request.form['email']
        user_password = request.form['password']
        user = User.query.filter_by(email=user_email).first()
        if not user:
            flash("The email is not found. Please try again.")
            return redirect(url_for("login"))
        elif not check_password_hash(pwhash= user.password, password=user_password):
            flash("Password incorrect, please try again.")
            return redirect(url_for("login"))
        else:
            login_user(user)
            next = request.args.get('next')
            if not is_safe_url(next):
                return abort(400)
            return redirect(next or url_for('secrets', name=user.name))
    return render_template("login.html")


@app.route('/secrets/<name>')
@login_required
def secrets(name):
    if not current_user.is_authenticated:
        return current_app.login_manager.unauthorized()
    else:
        return render_template("secrets.html", name=name)


@app.route('/download')
@login_required
def download_file():
    return send_from_directory('static/files','cheat_sheet.pdf', as_attachment=False)


@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('home'))


if __name__ == "__main__":
    app.run(debug=True)
