from flask import Flask, render_template, url_for, request, redirect, flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin, login_user, LoginManager, current_user, logout_user, login_required

from werkzeug.security \
import generate_password_hash, check_password_hash

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
app.config['SECRET_KEY'] = "das46a4d6as4d6as4d6as4d6"

db = SQLAlchemy(app)

login_manager = LoginManager()
login_manager.init_app(app)

# db.init_app(app)


# db class which will store the user data
class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), nullable=False)
    password = db.Column(db.String(80), nullable=False)
    admin = db.Column(db.Boolean, default=False)
    staff = db.Column(db.Boolean, default=False)

    def __init__(self, username, password="", admin=False, staff=False):
        self.username = username
        self.password = password
        self.admin = admin
        self.staff = staff

@login_manager.user_loader
def load_user(id):
    u = User.query.get(id)
    return User(username=u.username,admin=u.admin, staff=u.staff)


with app.app_context():
    db.create_all()
    # db.drop_all()
    db.session.commit()
    #
    db.session.add(User('admin', 'admin@123', True, False))
    db.session.add(User('guest', 'guest@123', False, False))
    users = User.query.all()

    for i in users:
        print("===>>>> i ", i.username, i.password  )
app.app_context().push()

@app.route('/')
def home():
    return render_template("index.html", data={"username": current_user.username})

@app.route('/profile')
def profile():
    return render_template("profile.html")

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST']) # define login page path
def login(): # define login page fucntion
    if request.method=='GET': # if the request is a GET we return the login page
        return render_template('login.html')
    else: # if the request is POST the we check if the user exist
          # and with te right password
        username = request.form.get('username')
        password = request.form.get('password')
        user = User.query.filter_by(username=username).first()
        # check if the user actually exists
        # take the user-supplied password, hash it, and compare it
        # to the hashed password in the database
        if not user:
            return redirect(url_for('register'))
        elif not check_password_hash(user.password, password):
            return redirect(url_for('home')) # if the user
               #doesn't exist or password is wrong, reload the page
        # if the above check passes, then we know the user has the
        # right credentials
        login_user(user)
        return redirect(url_for('home'))


@app.route('/register', methods=['GET', 'POST'])# we define the sign
def register(): # define the sign up function
    if request.method=='GET': # If the request is GET we return the
                              # sign up page and forms
        return render_template('register.html')
    else: # if the request is POST, then we check if the email
          # doesn't already exist and then we save data
        email = request.form.get('email')
        username = request.form.get('username')
        password = request.form.get('password')
        print("==>>>> usernmae ", username)
        print("==>>>> password ", password)
        radio = request.form.get('admin')
        print("====>>>>> radio : ", radio)
        user = User.query.filter_by(username=username).first() # if this
                              # returns a user, then the email
                              # already exists in database
        if user: # if a user is found, we want to redirect back to
                 # signup page so user can try again
            flash('username already exists')
            return redirect(url_for('login'))
        # create a new user with the form data. Hash the password so
        # the plaintext version isn't saved.
        new_user = User(username=username, \
                        password=generate_password_hash(password, \
                        method='sha256'))#add the new user to the db

        load_user(new_user.id)
        db.session.add(new_user)
        db.session.commit()
        return redirect(url_for('login'))


@app.route('/admin_dashboard', methods=['GET'])
def admin_dashboard():
    if current_user and current_user.admin == True:
        return redirect()



if __name__ == '__main__':
    app.run(debug=True)
