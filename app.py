from flask import Flask, render_template, request, redirect, url_for, flash
from flask_login import LoginManager, login_user, login_required, logout_user
from werkzeug.security import generate_password_hash, check_password_hash
from models import db, User
from models import db, User, Message
from flask_login import current_user
from flask import jsonify
from models import PrivateMessage
import os
from werkzeug.utils import secure_filename
from models import Block


app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = 'supersecretkey'
app.config['AVATAR_FOLDER'] = os.path.join('static', 'avatars')

db.init_app(app)

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

with app.app_context():
    db.create_all()
os.makedirs(app.config['AVATAR_FOLDER'], exist_ok=True)


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@app.route('/update_bio', methods=['POST'])
@login_required
def update_bio():
    bio = request.form.get("bio")
    current_user.bio = bio
    db.session.commit()
    return redirect(url_for('profile', username=current_user.username))


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



@app.route('/upload_avatar', methods=['POST'])
@login_required
def upload_avatar():
    file = request.files.get('avatar')

    if file and file.filename != "":
        filename = secure_filename(file.filename)
        filepath = os.path.join(app.config['AVATAR_FOLDER'], filename)
        file.save(filepath)

        current_user.avatar = filename
        db.session.commit()

    return redirect(url_for('profile', username=current_user.username))


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')

        user = User.query.filter_by(username=username).first()

        if user and check_password_hash(user.password_hash, password):
            login_user(user)
            return redirect(url_for('chat'))

        flash("Неверный логин или пароль")

    return render_template('login.html')


@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))


def get_dialog_users():
    sent = PrivateMessage.query.filter_by(sender_id=current_user.id).all()
    received = PrivateMessage.query.filter_by(receiver_id=current_user.id).all()

    users = set()

    for msg in sent:
        users.add(msg.receiver)

    for msg in received:
        users.add(msg.sender)

    return users


@app.route('/')
def index():
    if current_user.is_authenticated:
        return redirect(url_for('chat'))
    return render_template('index.html')



@app.route('/get_messages')
@login_required
def get_messages():
    messages = Message.query.order_by(Message.timestamp.asc()).all()

    data = []
    for msg in messages:
        avatar = msg.user.avatar if msg.user.avatar and msg.user.avatar.strip() != "" else "default_avatar.png"

        data.append({
            "username": msg.user.username,
            "text": msg.text,
            "time": msg.timestamp.strftime("%H:%M"),
            "avatar_url": url_for('static', filename='avatars/' + avatar)
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
    return render_template(
        'chat.html',
        dialog_users=get_dialog_users()
    )


@app.route('/profile/<username>')
@login_required
def profile(username):
    user = User.query.filter_by(username=username).first_or_404()
    return render_template('profile.html', user=user)



def is_blocked(user1_id, user2_id):
    return Block.query.filter(
        ((Block.blocker_id == user1_id) & (Block.blocked_id == user2_id)) |
        ((Block.blocker_id == user2_id) & (Block.blocked_id == user1_id))
    ).first() is not None


@app.route('/dialog/<username>', methods=['GET', 'POST'])
@login_required
def dialog(username):
    other_user = User.query.filter_by(username=username).first_or_404()

    if request.method == 'POST':
        text = request.form.get('message')

        if text:
            new_message = PrivateMessage(
                text=text,
                sender_id=current_user.id,
                receiver_id=other_user.id
            )
            db.session.add(new_message)
            db.session.commit()

        return redirect(url_for('dialog', username=username))

    messages = PrivateMessage.query.filter(
        ((PrivateMessage.sender_id == current_user.id) &
         (PrivateMessage.receiver_id == other_user.id)) |
        ((PrivateMessage.sender_id == other_user.id) &
         (PrivateMessage.receiver_id == current_user.id))
    ).order_by(PrivateMessage.timestamp.asc()).all()

    blocked = is_blocked(current_user.id, other_user.id)

    if request.method == 'POST' and not blocked:
        text = request.form.get('message')

        if text:
            new_message = PrivateMessage(
                text=text,
                sender_id=current_user.id,
                receiver_id=other_user.id
            )
            db.session.add(new_message)
            db.session.commit()

        return redirect(url_for('dialog', username=username))

    return render_template(
        "dialog.html",
        messages=messages,
        other_user=other_user,
        blocked=blocked,
        dialog_users=get_dialog_users()
    )


@app.route('/block/<username>')
@login_required
def block_user(username):
    other_user = User.query.filter_by(username=username).first_or_404()

    if not is_blocked(current_user.id, other_user.id):
        block = Block(
            blocker_id=current_user.id,
            blocked_id=other_user.id
        )
        db.session.add(block)
        db.session.commit()

    return redirect(url_for('dialog', username=username))

@app.route('/dialogs')
@login_required
def dialogs():
    sent = PrivateMessage.query.filter_by(sender_id=current_user.id).all()
    received = PrivateMessage.query.filter_by(receiver_id=current_user.id).all()

    users = set()

    for msg in sent:
        users.add(msg.receiver)

    for msg in received:
        users.add(msg.sender)

    return render_template("dialogs.html", users=users)


if __name__ == '__main__':
    app.run(debug=True)
