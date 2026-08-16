import os
from flask import Flask, render_template, request, redirect, url_for, session, flash
from supabase import create_client, Client
from dotenv import load_dotenv
from werkzeug.middleware.proxy_fix import ProxyFix

load_dotenv()

app = Flask(__name__)
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1, x_prefix=1)
app.secret_key = os.environ.get('FLASK_SECRET_KEY', 'default_super_secret_key')

SUPABASE_URL = os.environ.get("SUPABASE_URL", "https://xyzcompany.supabase.co")
SUPABASE_KEY = os.environ.get("SUPABASE_ANON_KEY", "public-anon-key")

supabase: Client = create_client(SUPABASE_URL, SUPABASE_KEY)

@app.route('/')
def index():
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        action = request.form.get('action')
        email = request.form.get('email')
        password = request.form.get('password')

        if action == 'login':
            try:
                response = supabase.auth.sign_in_with_password({"email": email, "password": password})
                session_token = response.session.access_token
                return redirect(f"melodify://auth?sessionCode={session_token}")
            except Exception as e:
                flash(f"Login failed: {str(e)}", "error")
        elif action == 'signup':
            try:
                response = supabase.auth.sign_up({"email": email, "password": password})
                session_token = response.session.access_token if response.session else None
                if session_token:
                    return redirect(f"melodify://auth?sessionCode={session_token}")
                else:
                    flash("Signup successful! Please check your email to verify.", "success")
            except Exception as e:
                flash(f"Signup failed: {str(e)}", "error")

    return render_template('login.html')

@app.route('/auth/google')
def google_auth():
    # Redirects to Supabase Google OAuth
    res = supabase.auth.sign_in_with_oauth(
        {
            "provider": 'google',
            "options": {
                "redirect_to": request.host_url + url_for('google_callback')
            }
        }
    )
    return redirect(res.url)

@app.route('/auth/callback')
def google_callback():
    # Typically supabase handles the redirect on the client side for OAuth (hash fragment)
    # However, if using server side or standard auth code:
    code = request.args.get('code')
    if code:
        try:
            # exchange code for session if applicable, but usually in PKCE flow the client does it.
            # For simplicity, if we get an access_token in the callback (fragment), we'd need JS to pass it, 
            # but let's assume we somehow get the session code here or prompt the user.
            pass
        except Exception as e:
            flash(f"Google Auth failed: {str(e)}", "error")
            return redirect(url_for('login'))
            
    # Assuming we have session from somewhere, or redirecting to Android via a JS script that parses hash.
    # A cleaner way is a template that parses the hash and redirects to the melodify scheme.
    return render_template('oauth_callback.html')

@app.route('/profile', methods=['GET', 'POST'])
def profile():
    # This expects the user to be somewhat authenticated in the web session, which requires handling
    # Supabase session cookies or similar, or just accepting a token via URL/header.
    # For a simple web view:
    token = request.args.get('token')
    if not token and 'access_token' in session:
        token = session['access_token']
    
    if not token:
        return redirect(url_for('login'))

    # Set auth for this client instance (not thread safe for global client, better to create a new one or pass header)
    supabase.postgrest.auth(token)
    
    if request.method == 'POST':
        username = request.form.get('username')
        avatar_url = request.form.get('avatar_url')
        new_password = request.form.get('new_password')
        
        try:
            update_data = {}
            if username or avatar_url:
                user_data = {}
                if username: user_data['username'] = username
                if avatar_url: user_data['avatar_url'] = avatar_url
                supabase.auth.update_user({"data": user_data})
                
            if new_password:
                supabase.auth.update_user({"password": new_password})
                
            flash("Profile updated successfully!", "success")
        except Exception as e:
            flash(f"Failed to update profile: {str(e)}", "error")

    try:
        user_resp = supabase.auth.get_user(token)
        user = user_resp.user
    except Exception as e:
        flash("Session expired.", "error")
        return redirect(url_for('login'))

    return render_template('profile.html', user=user, token=token)

if __name__ == '__main__':
    app.run(debug=True, port=5000)
