from flask import Flask, render_template, redirect, url_for, request, flash
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from datetime import datetime, timedelta

app = Flask(__name__)
app.config['SECRET_KEY'] = 'mysecretkey'  # Update this for security
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///quitter.db'
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

# Predefined list of habits to quit
PREDEFINED_QUITS = [
    'Social Media', 'Procrastination', 'Not Exercising', 'Eating Poorly', 'Not Having a Sleep Routine',
    'Alcohol', 'Porn', 'Weed', 'Nicotine', 'Gambling'
]

# User model
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(150), nullable=False)
    quit_habits = db.relationship('Quit', backref='owner', lazy=True)

# Quit model
class Quit(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    habit = db.Column(db.String(80), nullable=False)
    quit_date = db.Column(db.DateTime, nullable=False)
    days_quit = db.Column(db.Integer, nullable=False)
    why_quit = db.Column(db.String(300), nullable=False)
    goal_quit = db.Column(db.String(300), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    
    last_checked = db.Column(db.DateTime, nullable=True)  # Last check-in
    login_streak = db.Column(db.Integer, default=0)  # Streak of consecutive logins
    consistency_30_days = db.Column(db.Float, default=0.0)  # 30-day consistency

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Route for homepage
@app.route('/')
def home():
    return render_template('home.html')

# Route for user registration
@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        hashed_pw = bcrypt.generate_password_hash(password).decode('utf-8')

        user = User(username=username, password=hashed_pw)
        db.session.add(user)
        db.session.commit()

        flash('Account created! You can now log in.', 'success')
        return redirect(url_for('login'))
    return render_template('signup.html')

# Route for user login
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()

        if user and bcrypt.check_password_hash(user.password, password):
            login_user(user)
            flash('Login successful!', 'success')
            return redirect(url_for('dashboard'))
        else:
            flash('Login failed. Please check your credentials.', 'danger')
    return render_template('login.html')

# Route for user logout
@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('You have been logged out!', 'info')
    return redirect(url_for('login'))

# Dashboard route with a limit of 3 active quits
@app.route('/dashboard', methods=['GET', 'POST'])
@login_required
def dashboard():
    user_quits = Quit.query.filter_by(user_id=current_user.id).all()
    if len(user_quits) >= 3:
        flash("You've reached the limit of 3 active quit categories.", "info")
        return render_template('dashboard.html', quits=user_quits, habits=PREDEFINED_QUITS)

    if request.method == 'POST':
        habit = request.form['habit']
        quit_date = request.form['quit_date']
        why_quit = request.form['why_quit']
        goal_quit = request.form['goal_quit']
        days_quit = (datetime.now() - datetime.strptime(quit_date, "%Y-%m-%d")).days

        new_quit = Quit(
            habit=habit, 
            quit_date=datetime.strptime(quit_date, "%Y-%m-%d"),
            days_quit=days_quit, 
            why_quit=why_quit, 
            goal_quit=goal_quit, 
            user_id=current_user.id
        )
        db.session.add(new_quit)
        db.session.commit()

        flash('Your quit has been added!', 'success')
        return redirect(url_for('dashboard'))

    return render_template('dashboard.html', quits=user_quits, habits=PREDEFINED_QUITS)

# Leaderboard route
@app.route('/leaderboard')
@login_required
def leaderboard():
    all_quits = Quit.query.order_by(Quit.login_streak.desc(), Quit.days_quit.desc()).all()
    return render_template('leaderboard.html', quits=all_quits)

if __name__ == '__main__':
    app.run(debug=True)
