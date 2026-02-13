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
from flask_socketio import SocketIO, emit, join_room
from models import db, User, Message, PrivateMessage, Block, Badge



app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = 'supersecretkey'
app.config['AVATAR_FOLDER'] = os.path.join('static', 'avatars')
app.config['ADMIN_PANEL_PASSWORD'] = "superadmin123"

db.init_app(app)

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

with app.app_context():
    db.create_all()
os.makedirs(app.config['AVATAR_FOLDER'], exist_ok=True)
socketio = SocketIO(app, cors_allowed_origins="*")


@socketio.on('join_private')
def handle_join_private(data):
    room = data['room']
    join_room(room)

@socketio.on('join_global')
def handle_join_global():
    join_room("global_chat")


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


@app.route('/admin/create_badge', methods=['POST'])
@login_required
def create_badge():
    if not current_user.is_admin:
        return redirect(url_for('chat'))

    name = request.form.get("name")
    color = request.form.get("color")

    if name:
        badge = Badge(name=name, color=color)
        db.session.add(badge)
        db.session.commit()

    return redirect(url_for('admin_panel'))


@app.route('/admin/give_badge/<int:user_id>/<int:badge_id>')
@login_required
def give_badge(user_id, badge_id):
    if not current_user.is_admin:
        return redirect(url_for('chat'))

    user = User.query.get_or_404(user_id)
    badge = Badge.query.get_or_404(badge_id)

    if badge not in user.badges:
        user.badges.append(badge)
        db.session.commit()

    return redirect(url_for('admin_panel'))


@app.route('/admin/remove_badge/<int:user_id>/<int:badge_id>')
@login_required
def remove_badge(user_id, badge_id):
    if not current_user.is_admin:
        return redirect(url_for('chat'))

    user = User.query.get_or_404(user_id)
    badge = Badge.query.get_or_404(badge_id)

    if badge in user.badges:
        user.badges.remove(badge)
        db.session.commit()

    return redirect(url_for('admin_panel'))


@app.route('/shop')
@login_required
def shop():
    return render_template(
        "shop.html",
        dialog_users=get_dialog_users()
    )


@app.route('/get_private_messages/<username>')
@login_required
def get_private_messages(username):
    other_user = User.query.filter_by(username=username).first_or_404()

    messages = PrivateMessage.query.filter(
        ((PrivateMessage.sender_id == current_user.id) &
         (PrivateMessage.receiver_id == other_user.id)) |
        ((PrivateMessage.sender_id == other_user.id) &
         (PrivateMessage.receiver_id == current_user.id))
    ).order_by(PrivateMessage.timestamp.asc()).all()

    data = []
    for msg in messages:
        avatar = msg.sender.avatar if msg.sender.avatar and msg.sender.avatar.strip() != "" else "default_avatar.png"

        data.append({
            "username": msg.sender.username,
            "text": msg.text,
            "time": msg.timestamp.strftime("%H:%M"),
            "avatar_url": url_for('static', filename='avatars/' + avatar),
            "is_verified": msg.sender.is_verified
        })

    return jsonify(data)



@app.before_request
def check_if_banned():
    if current_user.is_authenticated and current_user.is_banned:
        if request.endpoint not in ('logout', 'blocked'):
            return redirect(url_for('blocked'))


@app.route('/blocked')
@login_required
def blocked():
    return render_template('blocked.html')

@app.route('/admin/ban/<int:user_id>', methods=['POST'])
@login_required
def ban_user(user_id):
    if not current_user.is_admin:
        return redirect(url_for('chat'))

    user = User.query.get_or_404(user_id)

    user.is_banned = True
    user.ban_reason = request.form.get("reason")

    db.session.commit()
    return redirect(url_for('admin_panel'))


@app.route('/admin/unban/<int:user_id>')
@login_required
def unban_user(user_id):
    if not current_user.is_admin:
        return redirect(url_for('chat'))

    user = User.query.get_or_404(user_id)
    user.is_banned = False
    user.ban_reason = None
    db.session.commit()

    return redirect(url_for('admin_panel'))



@app.route('/admin/set_rank/<int:user_id>/<rank>')
@login_required
def set_rank(user_id, rank):
    if not current_user.is_admin:
        return redirect(url_for('chat'))

    user = User.query.get_or_404(user_id)

    if rank == "none":
        user.rank = None
    else:
        user.rank = rank

    db.session.commit()
    return redirect(url_for('admin_panel'))


@app.route('/admin', methods=['GET', 'POST'])
@login_required
def admin_panel():

    if not current_user.is_admin:
        password = request.form.get("admin_password")
        if request.method == "POST":
            if password == app.config['ADMIN_PANEL_PASSWORD']:
                current_user.is_admin = True
                db.session.commit()
            else:
                flash("Неверный пароль администратора")
                return redirect(url_for('admin_panel'))

        if not current_user.is_admin:
            return render_template("admin_login.html")

    users = User.query.all()
    badges = Badge.query.all()

    return render_template("admin_panel.html",
                           users=users,
                           badges=badges)




@app.route('/admin/toggle_admin/<int:user_id>')
@login_required
def toggle_admin(user_id):
    if not current_user.is_admin:
        return redirect(url_for('chat'))

    user = User.query.get_or_404(user_id)
    user.is_admin = not user.is_admin
    db.session.commit()

    return redirect(url_for('admin_panel'))


@app.route('/admin/toggle_verified/<int:user_id>')
@login_required
def toggle_verified(user_id):
    if not current_user.is_admin:
        return redirect(url_for('chat'))

    user = User.query.get_or_404(user_id)
    user.is_verified = not user.is_verified
    db.session.commit()

    return redirect(url_for('admin_panel'))


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




@app.route('/update_extra', methods=['POST'])
@login_required
def update_extra():
    current_user.marital_status = request.form.get("marital_status")
    current_user.gender = request.form.get("gender")
    current_user.address = request.form.get("address")
    current_user.telegram = request.form.get("telegram")
    current_user.discord = request.form.get("discord")
    current_user.email = request.form.get("email")

    db.session.commit()
    return redirect(url_for('profile', username=current_user.username))


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
            "avatar_url": url_for('static', filename='avatars/' + avatar),
            "is_verified": msg.user.is_verified,
            "rank": msg.user.rank
        })

    return jsonify(data)



@app.route('/chat', methods=['GET', 'POST'])
@login_required
def chat():

    if request.method == 'POST':
        text = request.form.get('message')

        if text and text.strip() != "":
            new_message = Message(
                text=text,
                user_id=current_user.id
            )
            db.session.add(new_message)
            db.session.commit()

            avatar = current_user.avatar if current_user.avatar else "default_avatar.png"

            socketio.emit('receive_global_message', {
                "id": new_message.id,  # ВАЖНО
                "username": current_user.username,
                "text": text,
                "time": new_message.timestamp.strftime("%H:%M"),
                "avatar_url": url_for('static', filename='avatars/' + avatar),
                "is_verified": current_user.is_verified,
                "is_pinned": new_message.is_pinned,
                "rank": current_user.rank

            }, room="global_chat")

        return "", 204

    messages = Message.query.order_by(Message.timestamp.asc()).all()

    return render_template(
        "chat.html",
        messages=messages,
        dialog_users=get_dialog_users()
    )



@app.route('/delete_message/<int:message_id>', methods=['POST'])
@login_required
def delete_message(message_id):
    message = Message.query.get_or_404(message_id)

    if message.user_id != current_user.id and not current_user.is_admin:
        return "", 403

    db.session.delete(message)
    db.session.commit()

    socketio.emit('message_deleted', {"id": message_id}, room="global_chat")

    return "", 204




@app.route('/pin_message/<int:message_id>', methods=['POST'])
@login_required
def pin_message(message_id):
    message = Message.query.get_or_404(message_id)

    if not current_user.is_admin:
        return "", 403

    message.is_pinned = not message.is_pinned
    db.session.commit()

    socketio.emit('message_pinned', {
        "id": message_id,
        "pinned": message.is_pinned
    }, room="global_chat")

    return "", 204


@app.route('/profile/<username>')
@login_required
def profile(username):
    user = User.query.filter_by(username=username).first_or_404()

    if user.is_banned:
        return "Упс, похоже данный пользователь был заблокирован на нашем сайте :/"

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

    blocked = is_blocked(current_user.id, other_user.id)

    if request.method == 'POST' and not blocked:
        text = request.form.get('message')

        if text and text.strip() != "":
            new_message = PrivateMessage(
                text=text,
                sender_id=current_user.id,
                receiver_id=other_user.id
            )
            db.session.add(new_message)
            db.session.commit()

            # ---- REALTIME ----
            room = f"private_{min(current_user.id, other_user.id)}_{max(current_user.id, other_user.id)}"

            avatar = current_user.avatar if current_user.avatar else "default_avatar.png"

            socketio.emit('receive_private_message', {
                "username": current_user.username,
                "text": text,
                "time": new_message.timestamp.strftime("%H:%M"),
                "avatar_url": url_for('static', filename='avatars/' + avatar),
                "is_verified": current_user.is_verified
            }, room=room)

        # Не делаем redirect — WebSocket сам добавит сообщение
        return "", 204

    # GET запрос
    messages = PrivateMessage.query.filter(
        ((PrivateMessage.sender_id == current_user.id) &
         (PrivateMessage.receiver_id == other_user.id)) |
        ((PrivateMessage.sender_id == other_user.id) &
         (PrivateMessage.receiver_id == current_user.id))
    ).order_by(PrivateMessage.timestamp.asc()).all()

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
    socketio.run(app, debug=True)

