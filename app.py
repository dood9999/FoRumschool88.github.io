from flask import Flask, render_template, request, redirect, url_for, flash, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your_secret_key_here'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///forum.db'
db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(120), nullable=False)
    role = db.Column(db.String(20), nullable=False)

class Post(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(100), nullable=False)
    content = db.Column(db.Text, nullable=False)
    author = db.Column(db.String(80), nullable=False)
    date = db.Column(db.Date, nullable=False)
    time = db.Column(db.Time, nullable=False)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@app.route('/')
def index():
    posts = Post.query.order_by(Post.date.desc(), Post.time.desc()).all()
    return render_template('index.html', posts=posts)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        role = request.form['role']
        user = User.query.filter_by(username=username, role=role).first()
        if user and check_password_hash(user.password, password):
            login_user(user)
            flash('Logged in successfully.', 'success')
            return redirect(url_for('index'))
        else:
            flash('Invalid credentials.', 'error')
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('Logged out successfully.', 'success')
    return redirect(url_for('index'))

@app.route('/create_post', methods=['GET', 'POST'])
@login_required
def create_post():
    if current_user.role not in ['public', 'publisher']:
        flash('You do not have permission to create posts.', 'error')
        return redirect(url_for('index'))
    
    if request.method == 'POST':
        title = request.form['title']
        content = request.form['content']
        now = datetime.now()
        new_post = Post(title=title, content=content, author=current_user.username,
                        date=now.date(), time=now.time())
        db.session.add(new_post)
        db.session.commit()
        flash('Post created successfully!', 'success')
        return redirect(url_for('index'))
    return render_template('create_post.html')

@app.route('/developer_console', methods=['GET', 'POST'])
@login_required
def developer_console():
    if current_user.role != 'developer':
        flash('You do not have permission to access the developer console.', 'error')
        return redirect(url_for('index'))
    
    if request.method == 'POST':
        command = request.form['command'].split()
        if len(command) >= 2:
            action = command[0].upper()
            if action == 'USERPUBLIK':
                subaction = command[1].upper()
                if subaction == 'CREATE' and len(command) == 4:
                    username, password = command[2], command[3]
                    if User.query.filter_by(username=username).first():
                        flash(f'User {username} already exists.', 'error')
                    else:
                        new_user = User(username=username, password=generate_password_hash(password), role='public')
                        db.session.add(new_user)
                        db.session.commit()
                        flash(f'User {username} created successfully.', 'success')
                elif subaction == 'DEL' and len(command) == 3:
                    username = command[2]
                    user = User.query.filter_by(username=username, role='public').first()
                    if user:
                        db.session.delete(user)
                        db.session.commit()
                        flash(f'User {username} deleted successfully.', 'success')
                    else:
                        flash(f'Public user {username} not found.', 'error')
                else:
                    flash('Invalid USERPUBLIK command. Use CREATE or DEL.', 'error')
            elif action == 'DELETEPOST' and len(command) == 2:
                post_id = command[1]
                post = Post.query.get(post_id)
                if post:
                    db.session.delete(post)
                    db.session.commit()
                    flash(f'Post with ID {post_id} deleted successfully.', 'success')
                else:
                    flash(f'Post with ID {post_id} not found.', 'error')
            else:
                flash('Unknown command.', 'error')
        else:
            flash('Invalid command format.', 'error')
    return render_template('developer_console.html')

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
        if not User.query.filter_by(username='marlen').first():
            developer = User(username='marlen', password=generate_password_hash('mar@@2011SA'), role='developer')
            publisher = User(username='publisher1', password=generate_password_hash('pub123'), role='publisher')
            db.session.add(developer)
            db.session.add(publisher)
            db.session.commit()
    app.run(debug=True)