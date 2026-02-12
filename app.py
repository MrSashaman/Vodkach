from flask import Flask, render_template, request, redirect, url_for, flash
from flask_login import LoginManager, login_user, login_required, logout_user
from werkzeug.security import generate_password_hash, check_password_hash
from models import db, User
from models import db, User, Message
from flask_login import current_user
from flask import jsonify

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = 'supersecretkey'

db.init_app(app)

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

with app.app_context():
    db.create_all()


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))



@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')

        if not username or not password:
            flash("Заполните все поля")
            return redirect(url_for('register'))

        if User.query.filter_by(username=username).first():
            flash("Пользователь уже существует")
            return redirect(url_for('register'))

        hashed_password = generate_password_hash(password)

        new_user = User(
            username=username,
            password_hash=hashed_password
        )

        db.session.add(new_user)
        db.session.commit()

        flash("Регистрация успешна")
        return redirect(url_for('login'))

    return render_template('register.html')



@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')

        user = User.query.filter_by(username=username).first()

        if user and check_password_hash(user.password_hash, password):
            login_user(user)
            return redirect(url_for('index'))

        flash("Неверный логин или пароль")

    return render_template('login.html')


@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))


@app.route('/')
@login_required
def index():
    return render_template('index.html')


@app.route('/get_messages')
@login_required
def get_messages():
    messages = Message.query.order_by(Message.timestamp.asc()).all()

    data = []
    for msg in messages:
        data.append({
            "username": msg.user.username,
            "text": msg.text,
            "time": msg.timestamp.strftime("%H:%M")
        })

    return jsonify(data)


@app.route('/chat', methods=['GET', 'POST'])
@login_required
def chat():
    if request.method == 'POST':
        text = request.form.get('message')

        if text:
            new_message = Message(
                text=text,
                user_id=current_user.id
            )
            db.session.add(new_message)
            db.session.commit()

        return redirect(url_for('chat'))

    messages = Message.query.order_by(Message.timestamp.asc()).all()
    return render_template('chat.html', messages=messages)



@app.route('/profile/<username>')
@login_required
def profile(username):
    user = User.query.filter_by(username=username).first_or_404()
    return render_template('profile.html', user=user)



if __name__ == '__main__':
    app.run(debug=True)
