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
from models import db, User, Message, PrivateMessage, Block, Badge, Server, ServerMessage, ServerInvite, Channel, ChannelMessage, Reaction

from flask_socketio import join_room, leave_room, emit
import re
import os
import re
from markupsafe import Markup


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


def format_message(text):
    return parse_emojis(text)



def parse_emojis(text):
    pattern = r":emoji:(.*?):"

    def replace(match):
        filename = match.group(1)

        if filename not in get_emojis():
            return ""

        return f'<img src="/static/emojis/{filename}" class="chat-emoji">'

    return Markup(re.sub(pattern, replace, text))




def get_emojis():
    emoji_folder = os.path.join("static", "emojis")

    if not os.path.exists(emoji_folder):
        return []

    files = [
        f for f in os.listdir(emoji_folder)
        if f.lower().endswith((".png", ".jpg", ".jpeg", ".gif", ".webp"))
    ]

    return sorted(files)



@app.context_processor
def inject_emojis():
    return dict(all_emojis=get_emojis())


@socketio.on('join_private')
def handle_join_private(data):
    room = data['room']
    join_room(room)

@socketio.on('join_global')
def handle_join_global():
    join_room("global_chat")


@socketio.on('join_server')
def handle_join_server(data):
    server_id = data['server_id']
    join_room(f"server_{server_id}")

@app.route('/set_status', methods=['POST'])
@login_required
def set_status():
    status = request.form.get("status")

    if status not in ["online", "dnd", "invisible"]:
        return "", 400

    current_user.status = status
    db.session.commit()

    socketio.emit("status_updated", {
        "user_id": current_user.id,
        "status": status
    })

    return "", 204



@socketio.on('join_channel')
def handle_join_channel(data):
    channel_id = data['channel_id']
    join_room(f"channel_{channel_id}")


@socketio.on('send_channel_message')
def handle_channel_message(data):

    if not current_user.is_authenticated:
        return

    channel_id = data['channel_id']
    text = data['text']

    channel = Channel.query.get(channel_id)

    if not channel:
        return

    if current_user not in channel.server.members:
        return

    msg = ChannelMessage(
        text=text,
        user_id=current_user.id,
        channel_id=channel_id
    )

    db.session.add(msg)
    db.session.commit()

    emit('receive_channel_message', {
        "username": current_user.username,
        "text": parse_emojis(text),
        "time": msg.timestamp.strftime("%H:%M"),
        "avatar": current_user.avatar
    }, room=f"channel_{channel_id}")



@app.context_processor
def inject_invites():
    if current_user.is_authenticated:
        invites = ServerInvite.query.filter_by(
            invited_id=current_user.id
        ).all()
    else:
        invites = []

    return dict(current_user_invites=invites)



@app.route("/invite/<int:invite_id>/accept")
@login_required
def accept_invite(invite_id):

    invite = ServerInvite.query.get_or_404(invite_id)

    if invite.invited_id != current_user.id:
        return "Нет доступа", 403

    server = invite.server

    if current_user not in server.members:
        server.members.append(current_user)

    db.session.delete(invite)
    db.session.commit()

    return redirect(url_for("server_chat", server_id=server.id))



@app.route("/invite/<int:invite_id>/decline")
@login_required
def decline_invite(invite_id):

    invite = ServerInvite.query.get_or_404(invite_id)

    if invite.invited_id != current_user.id:
        return "Нет доступа", 403

    db.session.delete(invite)
    db.session.commit()

    return redirect(url_for("chat"))


@socketio.on('send_server_message')
def handle_server_message(data):

    server_id = data['server_id']
    text = data['text']

    if not current_user.is_authenticated:
        return

    server = Server.query.get(server_id)

    if current_user not in server.members:
        return

    msg = ServerMessage(
        text=text,
        user_id=current_user.id,
        server_id=server_id
    )

    db.session.add(msg)
    db.session.commit()

    emit('receive_server_message', {
        "username": current_user.username,
        "text": parse_emojis(text),
        "time": msg.timestamp.strftime("%H:%M"),
        "avatar": current_user.avatar
    }, room=f"server_{server_id}")


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



@app.route('/create_server', methods=['GET', 'POST'])
@login_required
def create_server():
    if request.method == 'POST':
        name = request.form.get("name")
        file = request.files.get("avatar")

        limit = 10

        if current_user.rank == "WINE":
            limit = 20
        elif current_user.rank == "LIQUOR":
            limit = 30

        if len(current_user.servers) >= limit:
            return "Лимит серверов достигнут", 403

        avatar_filename = None
        if file and file.filename != "":
            filename = secure_filename(file.filename)
            filepath = os.path.join("static/servers", filename)
            os.makedirs("static/servers", exist_ok=True)
            file.save(filepath)
            avatar_filename = filename

        server = Server(
            name=name,
            avatar=avatar_filename,
            owner_id=current_user.id
        )

        server.members.append(current_user)
        db.session.add(server)
        db.session.commit()

        # создаём канал general
        general = Channel(name="general", server_id=server.id)
        db.session.add(general)
        db.session.commit()

        return redirect(url_for('server_chat', server_id=server.id))

    return render_template("create_server.html")


@app.route('/channel/<int:channel_id>')
@login_required
def channel_chat(channel_id):

    channel = Channel.query.get_or_404(channel_id)
    server = channel.server

    if current_user not in server.members:
        return "Нет доступа", 403

    messages = ChannelMessage.query.filter_by(
        channel_id=channel.id
    ).order_by(ChannelMessage.timestamp.asc()).all()

    return render_template(
        "channel_chat.html",
        channel=channel,
        server=server,
        messages=messages,
        dialog_users=get_dialog_users()
    )


@app.route("/server/<int:server_id>/kick/<int:user_id>")
@login_required
def kick_user(server_id, user_id):

    server = Server.query.get_or_404(server_id)

    if current_user.id != server.owner_id:
        return "Нет прав", 403

    user = User.query.get_or_404(user_id)

    if user in server.members:
        server.members.remove(user)
        db.session.commit()

    return redirect(url_for("server_chat", server_id=server.id))




@app.route("/server/<int:server_id>/create_channel", methods=["POST"])
@login_required
def create_channel(server_id):

    server = Server.query.get_or_404(server_id)

    if current_user.id != server.owner_id:
        return "Нет прав", 403

    name = request.form.get("name")

    if not name:
        return redirect(url_for("server_chat", server_id=server.id))

    channel = Channel(
        name=name,
        server_id=server.id
    )

    db.session.add(channel)
    db.session.commit()

    return redirect(url_for("server_chat", server_id=server.id))


@app.route('/server/<int:server_id>', methods=['GET', 'POST'])
@login_required
def server_chat(server_id):

    server = Server.query.get_or_404(server_id)

    if current_user not in server.members:
        return "Нет доступа", 403

    if request.method == "POST":
        text = request.form.get("message")

        if text:
            msg = ServerMessage(
                text=text,
                user_id=current_user.id,
                server_id=server.id
            )
            db.session.add(msg)
            db.session.commit()

        return "", 204

    messages = ServerMessage.query.filter_by(
        server_id=server.id
    ).order_by(ServerMessage.timestamp.asc()).all()

    return render_template(
        "server_chat.html",
        server=server,
        messages=messages,
        dialog_users=get_dialog_users()
    )



@app.route('/unblock/<username>')
@login_required
def unblock_user(username):
    other_user = User.query.filter_by(username=username).first_or_404()

    block = Block.query.filter_by(
        blocker_id=current_user.id,
        blocked_id=other_user.id
    ).first()

    if block:
        db.session.delete(block)
        db.session.commit()

    return redirect(url_for('dialog', username=username))



@app.route('/edit_message/<int:message_id>', methods=['POST'])
@login_required
def edit_message(message_id):
    message = Message.query.get_or_404(message_id)

    if message.user_id != current_user.id and not current_user.is_admin:
        return "", 403

    new_text = request.form.get("text")

    if not new_text or new_text.strip() == "":
        return "", 400

    message.text = new_text
    db.session.commit()

    socketio.emit('message_edited', {
        "id": message.id,
        "text": parse_emojis(new_text)
    }, room="global_chat")

    return "", 204



@app.route('/react/<int:message_id>', methods=['POST'])
@login_required
def react(message_id):

    message = Message.query.get_or_404(message_id)
    emoji = request.form.get("emoji")

    if not emoji:
        return "", 400

    # Проверяем — есть ли уже такая реакция от пользователя
    existing = Reaction.query.filter_by(
        user_id=current_user.id,
        message_id=message_id,
        emoji=emoji
    ).first()

    # Если есть — удаляем (toggle)
    if existing:
        db.session.delete(existing)
    else:
        new_reaction = Reaction(
            emoji=emoji,
            user_id=current_user.id,
            message_id=message_id
        )
        db.session.add(new_reaction)

    db.session.commit()

    # ---- Считаем реакции ----
    reactions = Reaction.query.filter_by(
        message_id=message_id
    ).all()

    counts = {}
    user_reacted = {}

    for r in reactions:
        counts[r.emoji] = counts.get(r.emoji, 0) + 1

        # Отмечаем какие реакции поставил текущий пользователь
        if r.user_id == current_user.id:
            user_reacted[r.emoji] = True

    # ---- Отправляем обновление ----
    socketio.emit("reaction_updated", {
        "message_id": message_id,
        "reactions": counts,
        "user_reacted": user_reacted
    }, room="global_chat")

    return "", 204



@app.route('/invite/<int:server_id>/<username>')
@login_required
def invite_user(server_id, username):

    server = Server.query.get_or_404(server_id)

    if server.owner_id != current_user.id:
        return "Только владелец может приглашать", 403

    user = User.query.filter_by(username=username).first_or_404()

    if user not in server.members:
        server.members.append(user)
        db.session.commit()

    return redirect(url_for('server_chat', server_id=server.id))




@app.route("/server/<int:server_id>/invite", methods=["POST"])
@login_required
def send_invite(server_id):

    server = Server.query.get_or_404(server_id)

    if current_user.id != server.owner_id:
        return "Нет прав", 403

    username = request.form.get("username")
    user = User.query.filter_by(username=username).first_or_404()

    invite = ServerInvite(
        server_id=server.id,
        inviter_id=current_user.id,
        invited_id=user.id
    )

    db.session.add(invite)
    db.session.commit()

    return redirect(url_for("server_chat", server_id=server.id))



@app.route('/leave_server/<int:server_id>')
@login_required
def leave_server(server_id):

    server = Server.query.get_or_404(server_id)

    if current_user in server.members:
        server.members.remove(current_user)
        db.session.commit()

    return redirect(url_for('chat'))


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





@app.route('/agreement')
def agree():
    return render_template("agreement.html")


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

    for m in messages:
        m.text = parse_emojis(m.text)

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
                "text": parse_emojis(text),
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
                "text": parse_emojis(text),
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

