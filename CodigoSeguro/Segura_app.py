from flask import Flask, request, render_template_string, session, redirect, url_for, abort
import sqlite3
import os
import secrets
import bcrypt
from markupsafe import escape

app = Flask(__name__)
app.secret_key = os.urandom(24)


def get_db_connection():
    conn = sqlite3.connect('example.db')
    conn.row_factory = sqlite3.Row
    return conn


# --- 4.4 Almacenamiento seguro de contraseñas (bcrypt) ---
def hash_password(password):
    salt = bcrypt.gensalt()
    return bcrypt.hashpw(password.encode('utf-8'), salt).decode('utf-8')


def check_password(password, hashed):
    return bcrypt.checkpw(password.encode('utf-8'), hashed.encode('utf-8'))


# --- 4.3 Protección CSRF ---
def generate_csrf_token():
    if '_csrf_token' not in session:
        session['_csrf_token'] = secrets.token_hex(32)
    return session['_csrf_token']


def validate_csrf_token():
    token_form = request.form.get('csrf_token')
    token_session = session.get('_csrf_token')
    if not token_form or not token_session or not secrets.compare_digest(token_form, token_session):
        abort(400, description="Token CSRF inválido o ausente")


@app.context_processor
def inject_csrf_token():
    return {'csrf_token': generate_csrf_token}


@app.route('/')
def index():
    return render_template_string('''
        <!doctype html>
        <html lang="en">
        <head>
            <meta charset="utf-8">
            <meta name="viewport" content="width=device-width, initial-scale=1, shrink-to-fit=no">
            <link href="https://maxcdn.bootstrapcdn.com/bootstrap/4.0.0/css/bootstrap.min.css" rel="stylesheet">
            <title>Welcome</title>
        </head>
        <body>
            <div class="container">
                <h1 class="mt-5">Welcome to the Example Application!</h1>
                <p class="lead">This is the home page. Please <a href="/login">login</a>.</p>
            </div>
        </body>
        </html>
    ''')


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        # --- 4.3 Validación CSRF ---
        validate_csrf_token()

        username = request.form['username']
        password = request.form['password']

        conn = get_db_connection()

        # --- 4.1 Corrección de Inyección SQL: siempre consulta parametrizada ---
        query = "SELECT * FROM users WHERE username = ?"
        user = conn.execute(query, (username,)).fetchone()
        conn.close()

        # --- 4.4 Verificación con bcrypt ---
        if user and check_password(password, user['password']):
            session['user_id'] = user['id']
            session['role'] = user['role']
            return redirect(url_for('dashboard'))
        else:
            return render_template_string('''
                <!doctype html>
                <html lang="en">
                <head>
                    <meta charset="utf-8">
                    <meta name="viewport" content="width=device-width, initial-scale=1, shrink-to-fit=no">
                    <link href="https://maxcdn.bootstrapcdn.com/bootstrap/4.0.0/css/bootstrap.min.css" rel="stylesheet">
                    <title>Login</title>
                </head>
                <body>
                    <div class="container">
                        <h1 class="mt-5">Login</h1>
                        <div class="alert alert-danger" role="alert">Invalid credentials!</div>
                        <form method="post">
                            <input type="hidden" name="csrf_token" value="{{ csrf_token() }}">
                            <div class="form-group">
                                <label for="username">Username</label>
                                <input type="text" class="form-control" id="username" name="username">
                            </div>
                            <div class="form-group">
                                <label for="password">Password</label>
                                <input type="password" class="form-control" id="password" name="password">
                            </div>
                            <button type="submit" class="btn btn-primary">Login</button>
                        </form>
                    </div>
                </body>
                </html>
            ''')
    return render_template_string('''
        <!doctype html>
        <html lang="en">
        <head>
            <meta charset="utf-8">
            <meta name="viewport" content="width=device-width, initial-scale=1, shrink-to-fit=no">
            <link href="https://maxcdn.bootstrapcdn.com/bootstrap/4.0.0/css/bootstrap.min.css" rel="stylesheet">
            <title>Login</title>
        </head>
        <body>
            <div class="container">
                <h1 class="mt-5">Login</h1>
                <form method="post">
                    <input type="hidden" name="csrf_token" value="{{ csrf_token() }}">
                    <div class="form-group">
                        <label for="username">Username</label>
                        <input type="text" class="form-control" id="username" name="username">
                    </div>
                    <div class="form-group">
                        <label for="password">Password</label>
                        <input type="password" class="form-control" id="password" name="password">
                    </div>
                    <button type="submit" class="btn btn-primary">Login</button>
                </form>
            </div>
        </body>
        </html>
    ''')


@app.route('/dashboard')
def dashboard():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    user_id = session['user_id']
    conn = get_db_connection()
    comments = conn.execute(
        "SELECT comment FROM comments WHERE user_id = ?", (user_id,)).fetchall()
    conn.close()

    return render_template_string('''
        <!doctype html>
        <html lang="en">
        <head>
            <meta charset="utf-8">
            <meta name="viewport" content="width=device-width, initial-scale=1, shrink-to-fit=no">
            <link href="https://maxcdn.bootstrapcdn.com/bootstrap/4.0.0/css/bootstrap.min.css" rel="stylesheet">
            <title>Dashboard</title>
        </head>
        <body>
            <div class="container">
                <h1 class="mt-5">Welcome, user {{ user_id }}!</h1>
                <form action="/submit_comment" method="post">
                    <input type="hidden" name="csrf_token" value="{{ csrf_token() }}">
                    <div class="form-group">
                        <label for="comment">Comment</label>
                        <textarea class="form-control" id="comment" name="comment" rows="3"></textarea>
                    </div>
                    <button type="submit" class="btn btn-primary">Submit Comment</button>
                </form>
                <h2 class="mt-5">Your Comments</h2>
                <ul class="list-group">
                    {% for comment in comments %}
                        <li class="list-group-item">{{ comment['comment'] }}</li>
                    {% endfor %}
                </ul>
            </div>
        </body>
        </html>
    ''', user_id=user_id, comments=comments)


@app.route('/submit_comment', methods=['POST'])
def submit_comment():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    # --- 4.3 Validación CSRF ---
    validate_csrf_token()

    # --- 4.2 Corrección de XSS: escapar el comentario antes de almacenarlo ---
    comment = str(escape(request.form['comment']))
    user_id = session['user_id']

    conn = get_db_connection()
    conn.execute(
        "INSERT INTO comments (user_id, comment) VALUES (?, ?)", (user_id, comment))
    conn.commit()
    conn.close()

    return redirect(url_for('dashboard'))


@app.route('/admin')
def admin():
    if 'user_id' not in session or session.get('role') != 'admin':
        return redirect(url_for('login'))

    return render_template_string('''
        <!doctype html>
        <html lang="en">
        <head>
            <meta charset="utf-8">
            <meta name="viewport" content="width=device-width, initial-scale=1, shrink-to-fit=no">
            <link href="https://maxcdn.bootstrapcdn.com/bootstrap/4.0.0/css/bootstrap.min.css" rel="stylesheet">
            <title>Admin Panel</title>
        </head>
        <body>
            <div class="container">
                <h1 class="mt-5">Welcome to the admin panel!</h1>
            </div>
        </body>
        </html>
    ''')


# --- 4.5 Configuración segura de producción ---
if __name__ == '__main__':
    debug_mode = os.environ.get('FLASK_DEBUG', 'False') == 'True'
    app.run(debug=debug_mode, host='0.0.0.0', port=5000)
