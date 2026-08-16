import os
import re
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
        email = request.form.get('email')
        password = request.form.get('password')

        try:
            response = supabase.auth.sign_in_with_password({"email": email, "password": password})
            session_token = response.session.access_token
            return redirect(f"melodify://auth?sessionCode={session_token}")
        except Exception as e:
            flash(f"Login failed: {str(e)}", "error")
            return render_template('login.html', supabase_url=SUPABASE_URL, supabase_key=SUPABASE_KEY, email=email, error_fields=['email', 'password'])

    return render_template('login.html', supabase_url=SUPABASE_URL, supabase_key=SUPABASE_KEY)

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        email = request.form.get('email')
        username = request.form.get('username')
        password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')

        # Validation
        if password != confirm_password:
            flash("Passwords do not match.", "error")
            return render_template('signup.html', email=email, username=username, error_fields=['password', 'confirm_password'])
            
        if not re.match(r'^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[^a-zA-Z0-9]).{8,}$', password):
            flash("Password must contain at least 8 characters, one uppercase letter, one lowercase letter, one number, and one special character.", "error")
            return render_template('signup.html', email=email, username=username, error_fields=['password'])

        # Check unique username
        try:
            user_check = supabase.table("profiles").select("username").eq("username", username).execute()
            if len(user_check.data) > 0:
                flash("Username already exists. Please choose a different one.", "error")
                return render_template('signup.html', email=email, error_fields=['username'])
        except Exception as e:
            # Table might not exist or permissions issue; log it or proceed
            pass

        try:
            response = supabase.auth.sign_up({"email": email, "password": password})
            session_token = response.session.access_token if response.session else None
            
            if session_token:
                # Update user metadata
                supabase.auth.update_user({"data": {"username": username}})
                
                # Attempt to insert into profiles manually in case the user doesn't have the SQL trigger
                try:
                    user_resp = supabase.auth.get_user(session_token)
                    supabase.table("profiles").insert({
                        "id": user_resp.user.id,
                        "email": email,
                        "username": username,
                        "avatar_url": ""
                    }).execute()
                except Exception as e:
                    print("Manual profile insertion skipped (possibly already inserted by trigger):", e)

                session['access_token'] = session_token
                return redirect(url_for('profile', token=session_token, new_user='true'))
            else:
                flash("Signup successful! Please check your email to verify your account.", "success")
                return redirect(url_for('login'))
        except Exception as e:
            flash(f"Signup failed: {str(e)}", "error")
            return render_template('signup.html', email=email, username=username)

    return render_template('signup.html')


@app.route('/auth/callback')
def google_callback():
    return render_template('oauth_callback.html', supabase_url=SUPABASE_URL, supabase_key=SUPABASE_KEY)

@app.route('/profile', methods=['GET', 'POST'])
def profile():
    token = request.args.get('token')
    new_user = request.args.get('new_user') == 'true'
    
    if not token and 'access_token' in session:
        token = session['access_token']
    
    if not token:
        return redirect(url_for('login'))

    # Set auth for this request
    client = create_client(SUPABASE_URL, SUPABASE_KEY)
    client.postgrest.auth(token)
    
    if request.method == 'POST':
        username = request.form.get('username')
        avatar_url = request.form.get('avatar_url')
        new_password = request.form.get('new_password')
        
        # Handle file upload for avatar
        avatar_file = request.files.get('avatar')
        if avatar_file and avatar_file.filename:
            try:
                user_id = client.auth.get_user(token).user.id
                file_ext = os.path.splitext(avatar_file.filename)[1]
                file_path = f"{user_id}/profile{file_ext}"
                file_bytes = avatar_file.read()
                
                # Upload to Supabase Storage (requires a public 'avatars' bucket)
                client.storage.from_("avatars").upload(
                    file_path,
                    file_bytes,
                    {"content-type": avatar_file.content_type, "upsert": "true"}
                )
                
                avatar_url = f"{SUPABASE_URL}/storage/v1/object/public/avatars/{file_path}"
            except Exception as e:
                flash(f"Failed to upload profile picture: {str(e)}", "error")
        
        try:
            update_data = {}
            if username or avatar_url:
                profile_update = {}
                if username: profile_update['username'] = username
                if avatar_url: profile_update['avatar_url'] = avatar_url
                
                if profile_update:
                    try:
                        user_resp = client.auth.get_user(token)
                        client.table("profiles").update(profile_update).eq("id", user_resp.user.id).execute()
                    except Exception as db_e:
                        print("Could not update profile table:", db_e)
                
            flash("Profile updated successfully!", "success")
        except Exception as e:
            flash(f"Failed to update profile: {str(e)}", "error")

    try:
        user_resp = client.auth.get_user(token)
        user = user_resp.user
        
        # Override user_metadata with data from profiles table for display
        try:
            profile_data = client.table("profiles").select("*").eq("id", user.id).execute()
            if profile_data.data and len(profile_data.data) > 0:
                user.user_metadata = profile_data.data[0]
        except Exception as e:
            print("Could not fetch profile table data:", e)
            
    except Exception as e:
        flash("Session expired.", "error")
        return redirect(url_for('login'))

    return render_template('profile.html', user=user, token=token, new_user=new_user)

if __name__ == '__main__':
    app.run(debug=True, port=5000)
