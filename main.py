from flask import Flask, render_template, request, url_for, redirect, flash, send_from_directory
from flask_login import UserMixin, login_user, LoginManager, login_required, current_user, logout_user
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)

app.config['SECRET_KEY'] = 'sef45sefk3s6eoifhnoebf82sdf'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)
login_manager = LoginManager()

db.init_app(app)
login_manager.init_app(app)


# CREATE TABLE IN DB
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(100), unique=True)
    password = db.Column(db.String(100))
    name = db.Column(db.String(1000))


with app.app_context():
    db.create_all()


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


@app.route('/')
def home():
    return render_template("index.html", logged_in=current_user.is_authenticated)


@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        if User.query.filter_by(email=request.form['email']).first() is None:
            new_user = User(  # ~ IGNORE UNEXPECTED ARGUMENT FLAGS *BUG* ~ #
                name=request.form['name'],
                email=request.form['email'],
                password=generate_password_hash(request.form['password'], "pbkdf2:sha256", 8)
            )
            db.session.add(new_user)
            db.session.commit()
            login_user(User.query.filter_by(email=request.form['email']).first())
            return redirect(url_for('secrets'))
        else:
            flash("You've already registered with that email! Log in instead.")
            return redirect(url_for('login'))
    return render_template("register.html", logged_in=current_user.is_authenticated)


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        user = User.query.filter_by(email=request.form['email']).first()
        if user is not None and check_password_hash(user.password, request.form['password']):
            login_user(user)
            return redirect(url_for('secrets'))
        elif user is None:
            flash("No email found. You need to register, first.")
            return redirect(url_for('login'))
        else:
            flash("Incorrect password, try again.")
            return redirect(url_for('login'))
    return render_template("login.html", logged_in=current_user.is_authenticated)


@app.route('/secrets')
@login_required
def secrets():
    return render_template("secrets.html", name=current_user.name, logged_in=current_user.is_authenticated)


@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('home'))


@app.route('/download')
@login_required
def download():
    return send_from_directory("static", "files/cheat_sheet.pdf")


if __name__ == "__main__":
    app.run(debug=True)
