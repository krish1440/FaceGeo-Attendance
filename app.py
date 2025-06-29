import os
import logging
from flask import Flask, render_template, request, redirect, send_file, url_for, session, jsonify, Response
from supabase import create_client, Client
from werkzeug.utils import secure_filename
from flask_compress import Compress
import io
import csv
from datetime import datetime, date, timedelta
from dotenv import load_dotenv
import cloudinary
import cloudinary.uploader
import cloudinary.api
import json
from math import radians, sin, cos, sqrt, atan2
import uuid
import pytz
from PIL import Image
import base64
from io import BytesIO

# Configure logging
logging.basicConfig(
    level=os.getenv('LOG_LEVEL', 'INFO'),  # Default to INFO in production
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('app.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

load_dotenv()



app = Flask(__name__, static_folder=None)  # Disable static file serving
app.config['SESSION_COOKIE_SECURE'] = True  # Only send cookies over HTTPS
app.config['SESSION_COOKIE_HTTPONLY'] = True  # Prevent JavaScript access to cookies
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'  # Protect against CSRF
Compress(app)

app.secret_key = os.getenv('FLASK_SECRET_KEY')

# Supabase configuration
SUPABASE_URL = os.getenv('SUPABASE_URL')
SUPABASE_ANON_KEY = os.getenv('SUPABASE_ANON_KEY')
supabase: Client = create_client(SUPABASE_URL, SUPABASE_ANON_KEY)

# Cloudinary configuration
cloudinary.config(
    cloud_name=os.getenv('CLOUDINARY_CLOUD_NAME'),
    api_key=os.getenv('CLOUDINARY_API_KEY'),
    api_secret=os.getenv('CLOUDINARY_API_SECRET')
)

# Allowed extensions for image uploads
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg'}

def allowed_file(filename):
    """Check if the file extension is allowed."""
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def upload_to_cloudinary(image_bytes, public_id):
    from cloudinary.uploader import upload
    try:
        result = upload(image_bytes, public_id=public_id, resource_type="image")
        return result['secure_url']
    except Exception as e:
        logger.error(f"Cloudinary upload failed: {str(e)}")
        raise Exception(f"Failed to upload to Cloudinary: {str(e)}")

def delete_from_cloudinary(file_url: str) -> None:
    """Delete a file from Cloudinary using its public URL."""
    try:
        public_id = "attendance_system/images/" + file_url.split('/')[-1].split('.')[0]
        cloudinary.uploader.destroy(public_id, resource_type="image")
    except Exception as e:
        logger.error(f"Cloudinary delete failed: {str(e)}")
        raise Exception(f"Failed to delete from Cloudinary: {str(e)}")

def is_within_geofence(lat1: float, lon1: float, lat2: float, lon2: float, radius: float) -> bool:
    """Check if a location (lat1, lon1) is within a geofence (lat2, lon2, radius in meters)."""
    R = 6371000  # Earth's radius in meters
    lat1, lon1, lat2, lon2 = map(radians, [lat1, lon1, lat2, lon2])
    dlat = lat2 - lat1
    dlon = lon2 - lon1
    a = sin(dlat / 2)**2 + cos(lat1) * cos(lat2) * sin(dlon / 2)**2
    c = 2 * atan2(sqrt(a), sqrt(1 - a))
    distance = R * c
    return distance <= radius

def validate_face_descriptor(new_descriptor: list, stored_descriptor: list) -> bool:
    """Validate if two face descriptors match using Euclidean distance."""
    distance = sqrt(sum((a - b) ** 2 for a, b in zip(new_descriptor, stored_descriptor)))
    return distance < 0.6  # Threshold for face match

def get_current_date(timezone=None):
    if not timezone:
        timezone = os.getenv('APP_TIMEZONE', 'UTC')  # Default to UTC if not set
    tz = pytz.timezone(timezone)
    return datetime.now(tz).date().isoformat()

def calculate_attendance_percentage(records, start_date=None, end_date=None):
    """Calculate attendance percentage based on ACCEPTED records."""
    if not records:
        return 0.0
    accepted_count = sum(1 for record in records if record['status'] == 'ACCEPTED')
    total_count = len(records)
    if start_date and end_date:
        start = datetime.strptime(start_date, '%Y-%m-%d').date()
        end = datetime.strptime(end_date, '%Y-%m-%d').date()
        total_days = (end - start).days + 1
        total_count = max(total_count, total_days)  # Use max to account for days with no records
    if total_count == 0:
        return 0.0
    percentage = (accepted_count / total_count) * 100
    return round(percentage, 2)

@app.route('/')
def home():
    return render_template('home.html')

@app.route('/org_signup', methods=['GET', 'POST'])
def org_signup():
    if request.method == 'POST':
        name = request.form.get('name')
        username = request.form.get('username')  # Email ID
        password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')
        
        # Validate input fields
        if not all([name, username, password, confirm_password]):
            logger.warning("Missing required fields in org_signup")
            return render_template('org_signup.html', error='All fields are required')
        
        if password != confirm_password:
            logger.warning("Password mismatch in org_signup")
            return render_template('org_signup.html', error='Passwords do not match')
        
        # Validate email format
        if '@' not in username or '.' not in username:
            logger.warning(f"Invalid email format: {username}")
            return render_template('org_signup.html', error='Invalid email format')
        
        try:
            # Check if username (email) already exists
            existing_org = supabase.table('organizations').select('username').eq('username', username).execute().data
            if existing_org:
                logger.warning(f"Email already exists: {username}")
                return render_template('org_signup.html', error='Email already exists')
            
            # Generate org_id
            org_id = str(uuid.uuid4())
            
            # Send OTP using Supabase Auth
            response = supabase.auth.sign_up({
                'email': username,
                'password': password,
                'options': {
                    'data': {'name': name},
                    'email_redirect_to': url_for('verify_otp', _external=True)
                }
            })
            
            logger.debug(f"Sign-up response for {username}: user_id={getattr(response.user, 'id', None)}, email={getattr(response.user, 'email', None)}")
            
            # Store signup data in session for verification
            session['signup_data'] = {
                'name': name,
                'username': username,
                'password': password,  # Store plaintext as per schema
                'org_id': org_id
            }
            session['pending_verification'] = username
            
            logger.info(f"OTP sent to {username} for organization signup")
            return jsonify({'success': True, 'redirect': url_for('verify_otp')})
        except Exception as e:
            logger.error(f"Org signup failed for {username}: {str(e)}")
            return jsonify({'success': False, 'error': f"Signup failed: {str(e)}"}), 400
    
    return render_template('org_signup.html')

@app.route('/verify_otp', methods=['GET', 'POST'])
def verify_otp():
    if 'pending_verification' not in session:
        logger.warning("No pending_verification in session")
        return redirect(url_for('org_signup'))
    
    email = session['pending_verification']
    
    if request.method == 'POST':
        otp = request.form.get('otp')
        
        if not otp:
            logger.warning("Missing OTP in verify_otp")
            return render_template('verify_otp.html', email=email, error='OTP is required')
        
        try:
            # Verify OTP
            response = supabase.auth.verify_otp({
                'email': email,
                'token': otp,
                'type': 'signup'
            })
            
            logger.debug(f"OTP verification for {email}: user_id={getattr(response.user, 'id', None)}, session={response.session}")
            
            # Retrieve signup data
            signup_data = session.get('signup_data')
            if not signup_data:
                logger.error(f"No signup data found for {email}")
                return render_template('verify_otp.html', email=email, error='Session expired. Please try signing up again.')
            
            # Insert into organizations table
            org_data = {
                'id': signup_data['org_id'],
                'name': signup_data['name'],
                'username': signup_data['username'],
                'password': signup_data['password']  # Plaintext as per schema
            }
            supabase.table('organizations').insert(org_data).execute()
            
            logger.info(f"Organization created: {signup_data['username']}, org_id: {signup_data['org_id']}")
            
            # Clear session data
            session.pop('signup_data', None)
            session.pop('pending_verification', None)
            
            return redirect(url_for('org_login'))
        except Exception as e:
            logger.error(f"OTP verification failed for {email}: {str(e)}")
            return render_template('verify_otp.html', email=email, error=f"Invalid OTP or verification failed: {str(e)}")
    
    return render_template('verify_otp.html', email=email)

@app.route('/resend_otp', methods=['GET'])
def resend_otp():
    if 'pending_verification' not in session or 'signup_data' not in session:
        logger.warning("No pending_verification or signup_data in session for resend_otp")
        return redirect(url_for('org_signup'))
    
    email = session['pending_verification']
    signup_data = session['signup_data']
    
    try:
        # Resend OTP
        response = supabase.auth.resend({
            'type': 'signup',
            'email': email,
            'options': {
                'data': {'name': signup_data['name']},
                'email_redirect_to': url_for('verify_otp', _external=True)
            }
        })
        logger.debug(f"Resend OTP response for {email}: response={response}")
        return render_template('verify_otp.html', email=email, message='A new OTP has been sent to your email.')
    except Exception as e:
        logger.error(f"Failed to resend OTP for {email}: {str(e)}")
        return render_template('verify_otp.html', email=email, error=f"Failed to resend OTP: {str(e)}")
@app.route('/user_signup', methods=['GET', 'POST'])
def user_signup():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')
        
        if not all([email, password, confirm_password]):
            return render_template('user_signup.html', error='All fields are required')
        
        if password != confirm_password:
            return render_template('user_signup.html', error='Passwords do not match')
        
        try:
            user = supabase.table('users').select('email, org_id').eq('email', email).execute().data
            if not user:
                return render_template('user_signup.html', error='Email does not exist. Contact your organization.')
            
            supabase.table('users').update({'password': password}).eq('email', email).eq('org_id', user[0]['org_id']).execute()
            logger.info(f"User signed up with email: {email}, org_id: {user[0]['org_id']}")
            return redirect(url_for('user_login'))
        except Exception as e:
            logger.error(f"User signup failed for email {email}: {str(e)}")
            return render_template('user_signup.html', error=f"Signup failed: {str(e)}")
    return render_template('user_signup.html')

@app.route('/org_login', methods=['GET', 'POST'])
def org_login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        if not all([username, password]):
            return redirect(url_for('org_login'))
        
        try:
            org = supabase.table('organizations').select('id, password').eq('username', username).execute().data
            if not org or org[0]['password'] != password:
                return redirect(url_for('org_login'))
            
            session['org_id'] = org[0]['id']
            session['user_type'] = 'organization'
            logger.info(f"Organization logged in: {username}, org_id: {org[0]['id']}")
            return redirect(url_for('org_dashboard'))
        except Exception as e:
            logger.error(f"Org login failed for {username}: {str(e)}")
            return render_template('org_login.html', error=f"Login failed: {str(e)}")
    return render_template('org_login.html')

@app.route('/user_login', methods=['GET', 'POST'])
def user_login():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        
        if not all([email, password]):
            return redirect(url_for('user_login'))
        
        try:
            user = supabase.table('users').select('email, password, user_id, org_id').eq('email', email).execute().data
            if not user or user[0]['password'] != password:
                return redirect(url_for('user_login'))
            
            session['user_id'] = user[0]['user_id']
            session['org_id'] = user[0]['org_id']
            session['user_type'] = 'user'
            session['custom_user_id'] = email
            logger.info(f"User logged in: {email}, user_id: {user[0]['user_id']}, org_id: {user[0]['org_id']}")
            return redirect(url_for('user_dashboard'))
        except Exception as e:
            logger.error(f"User login failed for {email}: {str(e)}")
            return render_template('user_login.html', error=f"Login failed: {str(e)}")
    return render_template('user_login.html')

@app.route('/org_dashboard')
def org_dashboard():
    if session.get('user_type') != 'organization':
        return redirect(url_for('org_login'))
    return render_template('org_dashboard.html')

@app.route('/user_dashboard')
def user_dashboard():
    if session.get('user_type') != 'user':
        return redirect(url_for('user_login'))
    email = session.get('custom_user_id')
    try:
        user = supabase.table('users').select('*').eq('email', email).eq('org_id', session['org_id']).execute().data[0]
        return render_template('user_dashboard.html', user=user)
    except Exception as e:
        logger.error(f"User dashboard failed for {email}: {str(e)}")
        return render_template('user_dashboard.html', error=f"Failed to load user data: {str(e)}")

@app.route('/add_user', methods=['GET', 'POST'])
def add_user():
    if session.get('user_type') != 'organization':
        return redirect(url_for('org_login'))
    if 'org_id' not in session:
        logger.error("No org_id in session")
        return render_template('add_user.html', error='Organization session not found. Please log in again.')
    
    if request.method == 'POST':
        user_id = request.form.get('user_id')
        name = request.form.get('name')
        mobile = request.form.get('mobile')
        email = request.form.get('email')
        role = request.form.get('role')
        department = request.form.get('department')
        picture = request.files.get('picture')
        
        if not all([user_id, name, mobile, email, role, department]):
            logger.warning(f"Missing required fields: user_id={user_id}, name={name}, mobile={mobile}, email={email}, role={role}, department={department}")
            return render_template('add_user.html', error='All fields except profile picture are required')
        
        try:
            user_id = int(user_id)  # Ensure user_id is numeric
        except ValueError:
            logger.warning(f"Invalid user_id format: {user_id}")
            return render_template('add_user.html', error='User ID must be numeric')
        
        if picture and not allowed_file(picture.filename):
            logger.warning(f"Invalid file format for picture: {picture.filename}")
            return render_template('add_user.html', error='Invalid file format. Only PNG, JPG, JPEG allowed.')
        
        try:
            # Validate org_id exists
            org_check = supabase.table('organizations').select('id').eq('id', session['org_id']).execute().data
            if not org_check:
                logger.error(f"Invalid org_id in session: {session['org_id']}")
                return render_template('add_user.html', error='Invalid organization. Please log in again.')
            
            # Check if user_id or email exists for this organization
            existing_user = supabase.table('users').select('user_id').eq('user_id', user_id).eq('org_id', session['org_id']).execute().data
            existing_email = supabase.table('users').select('email').eq('email', email).eq('org_id', session['org_id']).execute().data
            if existing_user:
                logger.warning(f"User ID {user_id} already exists for org_id={session['org_id']}")
                return render_template('add_user.html', error=f"User ID {user_id} already exists for this organization")
            if existing_email:
                logger.warning(f"Email {email} already exists for org_id={session['org_id']}")
                return render_template('add_user.html', error=f"Email {email} already exists for this organization")
            
            # Upload picture to Cloudinary
            picture_url = None
            if picture:
                if picture.content_length > 5 * 1024 * 1024:
                    logger.warning(f"File size too large: {picture.filename}")
                    return render_template('add_user.html', error='File size must be less than 5MB')
                picture_url = upload_to_cloudinary(picture, f"user_{user_id}_{session['org_id']}")
                logger.info(f"Uploaded picture to Cloudinary: {picture_url}")
            
            # Insert user
            user_data = {
                'user_id': user_id,
                'org_id': session['org_id'],
                'name': name,
                'mobile': mobile,
                'email': email,
                'role': role,
                'department': department,
                'picture_url': picture_url,
                'face_descriptor': None,  # Not provided in form
                'password': None  # Set during user_signup
            }
            logger.debug(f"Inserting user data: {user_data}")
            response = supabase.table('users').insert(user_data).execute()
            logger.info(f"User added successfully: user_id={user_id}, email={email}, org_id={session['org_id']}, response={response}")
            return redirect(url_for('org_dashboard'))
        except Exception as e:
            logger.error(f"Failed to add user: user_id={user_id}, email={email}, org_id={session['org_id']}, error={str(e)}")
            return render_template('add_user.html', error=f"Failed to add user: {str(e)}")
    return render_template('add_user.html')

@app.route('/edit_user', methods=['GET', 'POST'])
def edit_user():
    if session.get('user_type') != 'organization':
        return jsonify({'error': 'Unauthorized'}), 401

    if request.method == 'POST':
        action = request.form.get('action')

        if action == 'fetch':
            user_id = request.form.get('user_id')
            if not user_id:
                return jsonify({'error': 'User ID is required'}), 400
            try:
                user_id = int(user_id)
                user = supabase.table('users').select('*').eq('user_id', user_id).eq('org_id', session['org_id']).execute().data
                if not user:
                    return jsonify({'error': 'User ID not found or not associated with your organization'}), 404
                logger.info(f"Fetched user: user_id={user_id}, org_id={session['org_id']}")
                return jsonify(user[0])
            except ValueError:
                return jsonify({'error': 'User ID must be numeric'}), 400
            except Exception as e:
                logger.error(f"Error fetching user_id={user_id}: {str(e)}")
                return jsonify({'error': f"Fetch failed: {str(e)}"}), 500

        elif action == 'update':
            user_id = request.form.get('user_id')  # Get user_id from form
            if not user_id:
                logger.error("No user_id provided in update request")
                return jsonify({'error': 'User ID is required'}), 400

            name = request.form.get('name')
            mobile = request.form.get('mobile')
            email = request.form.get('email')
            role = request.form.get('role')
            department = request.form.get('department')
            picture = request.files.get('picture')

            try:
                user_id = int(user_id)
            except ValueError:
                logger.error(f"Invalid user_id format: {user_id}")
                return jsonify({'error': 'User ID must be numeric'}), 400

            if not all([name, mobile, email, role, department]):
                logger.warning(f"Missing required fields: name={name}, mobile={mobile}, email={email}, role={role}, department={department}")
                return jsonify({'error': 'All fields except profile picture are required'}), 400

            try:
                user = supabase.table('users').select('picture_url, email').eq('user_id', user_id).eq('org_id', session['org_id']).execute().data
                if not user:
                    logger.warning(f"User not found: user_id={user_id}, org_id={session['org_id']}")
                    return jsonify({'error': 'User not found'}), 404

                if email != user[0]['email']:
                    existing_email = supabase.table('users').select('email').eq('email', email).eq('org_id', session['org_id']).execute().data
                    if existing_email:
                        logger.warning(f"Email already exists: {email}, org_id={session['org_id']}")
                        return jsonify({'error': f"Email {email} already exists for this organization"}), 400

                update_data = {
                    'name': name,
                    'mobile': mobile,
                    'email': email,
                    'role': role,
                    'department': department
                }

                if picture and allowed_file(picture.filename):
                    if picture.content_length > 5 * 1024 * 1024:
                        logger.warning(f"Picture file too large: {picture.filename}")
                        return jsonify({'error': 'File size must be less than 5MB'}), 400
                    if user[0]['picture_url']:
                        delete_from_cloudinary(user[0]['picture_url'])
                    picture_url = upload_to_cloudinary(picture, f"user_{user_id}_{session['org_id']}")
                    update_data['picture_url'] = picture_url

                supabase.table('users').update(update_data).eq('user_id', user_id).eq('org_id', session['org_id']).execute()
                logger.info(f"User updated: user_id={user_id}, email={email}, org_id={session['org_id']}")
                return jsonify({'success': 'User updated successfully'}), 200
            except Exception as e:
                logger.error(f"Update user failed for user_id={user_id}: {str(e)}")
                return jsonify({'error': f"Update failed: {str(e)}"}), 500

    return render_template('edit_user.html')

@app.route('/delete_user', methods=['GET', 'POST'])
def delete_user():
    if session.get('user_type') != 'organization':
        logger.error(f"Unauthorized access to /delete_user by user_type={session.get('user_type')}")
        return redirect(url_for('org_login'))
    
    if request.method == 'POST':
        action = request.form.get('action')
        user_id = request.form.get('user_id')
        
        try:
            user_id = int(user_id)
        except ValueError:
            logger.warning(f"Invalid user_id format: {user_id}")
            return jsonify({'error': 'User ID must be numeric'}), 400
        
        if action == 'fetch':
            try:
                user = supabase.table('users').select('user_id, name, email').eq('user_id', user_id).eq('org_id', session['org_id']).execute().data
                if not user:
                    logger.warning(f"User not found: user_id={user_id}, org_id={session['org_id']}")
                    return jsonify({'error': 'User ID not found or not associated with your organization'}), 404
                logger.info(f"Fetched user: user_id={user_id}, org_id={session['org_id']}")
                return jsonify(user[0])
            except Exception as e:
                logger.error(f"Fetch user failed for user_id={user_id}, org_id={session['org_id']}: {str(e)}")
                return jsonify({'error': f"Fetch failed: {str(e)}"}), 500
        
        elif action == 'delete':
            try:
                user = supabase.table('users').select('picture_url').eq('user_id', user_id).eq('org_id', session['org_id']).execute().data
                if not user:
                    logger.warning(f"User not found: user_id={user_id}, org_id={session['org_id']}")
                    return jsonify({'error': 'User not found'}), 404
                
                if user[0]['picture_url']:
                    delete_from_cloudinary(user[0]['picture_url'])
                attendance_records = supabase.table('attendance').select('selfie_image').eq('user_id', user_id).eq('org_id', session['org_id']).execute().data
                for record in attendance_records:
                    if record['selfie_image']:
                        delete_from_cloudinary(record['selfie_image'])
                supabase.table('users').delete().eq('user_id', user_id).eq('org_id', session['org_id']).execute()
                supabase.table('attendance').delete().eq('user_id', user_id).eq('org_id', session['org_id']).execute()
                supabase.table('manual_requests').delete().eq('user_id', user_id).eq('org_id', session['org_id']).execute()
                logger.info(f"User deleted: user_id={user_id}, org_id={session['org_id']}")
                return '', 200
            except Exception as e:
                logger.error(f"Delete user failed for user_id={user_id}, org_id={session['org_id']}: {str(e)}")
                return jsonify({'error': f"Delete failed: {str(e)}"}), 500
    
    return render_template('delete_user.html')

@app.route('/geofence_setup', methods=['GET', 'POST'])
def geofence_setup():
    if session.get('user_type') != 'organization':
        logger.error(f"Unauthorized access to /geofence_setup by user_type={session.get('user_type')}")
        return redirect(url_for('org_login'))
    
    org_id = session.get('org_id')
    if not org_id:
        logger.error("Missing org_id in session")
        return render_template('geofence_setup.html', error='Invalid session'), 400
    
    if request.method == 'POST':
        latitude = request.form.get('latitude')
        longitude = request.form.get('longitude')
        radius = request.form.get('radius')
        
        try:
            # Validate inputs
            if not all([latitude, longitude, radius]):
                logger.warning(f"Missing geofence parameters for org_id={org_id}")
                return render_template('geofence_setup.html', error='All fields are required'), 400
            
            latitude = float(latitude)
            longitude = float(longitude)
            radius = float(radius)
            
            if not (-90 <= latitude <= 90):
                logger.warning(f"Invalid latitude {latitude} for org_id={org_id}")
                return render_template('geofence_setup.html', error='Latitude must be between -90 and 90'), 400
            if not (-180 <= longitude <= 180):
                logger.warning(f"Invalid longitude {longitude} for org_id={org_id}")
                return render_template('geofence_setup.html', error='Longitude must be between -180 and 180'), 400
            if radius <= 0:
                logger.warning(f"Invalid radius {radius} for org_id={org_id}")
                return render_template('geofence_setup.html', error='Radius must be positive'), 400
            
            # Upsert geofence
            geofence_data = {
                'org_id': org_id,
                'latitude': latitude,
                'longitude': longitude,
                'radius': radius
            }
            logger.debug(f"Upserting geofence: {geofence_data}")
            try:
                response = supabase.table('geofences').upsert(geofence_data, on_conflict=['org_id']).execute()
            except Exception as e:
                logger.error(f"Geofence upsert failed for org_id={org_id}: {str(e)}")
                return render_template('geofence_setup.html', error=f'Geofence setup failed: {str(e)}'), 500
            
            logger.info(f"Geofence set for org_id={org_id}")
            return redirect(url_for('org_dashboard'))
        except ValueError:
            logger.warning(f"Invalid numeric values for org_id={org_id}: lat={latitude}, lon={longitude}, radius={radius}")
            return render_template('geofence_setup.html', error='Invalid numeric values'), 400
        except Exception as e:
            logger.error(f"Geofence setup failed for org_id={org_id}: {str(e)}")
            return render_template('geofence_setup.html', error=f'Geofence setup failed: {str(e)}'), 500
    
    return render_template('geofence_setup.html')

@app.route('/manual_requests', methods=['GET', 'POST'])
def manual_requests():
    if session.get('user_type') != 'organization' or not session.get('org_id'):
        logger.error(f"Invalid session: user_type={session.get('user_type')}, org_id={session.get('org_id')}")
        return redirect(url_for('org_login', error='Session expired, please log in again'))
    
    if request.method == 'POST':
        request_id = request.form.get('request_id')
        status = request.form.get('status')
        logger.debug(f"Processing manual request: request_id={request_id}, status={status}, org_id={session['org_id']}")
        try:
            if not request_id or not status:
                logger.error(f"Missing request_id or status: request_id={request_id}, status={status}")
                return jsonify({'error': 'Missing request_id or status'}), 400

            request_data = supabase.table('manual_requests').select('user_id, org_id, created_at').eq('id', request_id).eq('org_id', session['org_id']).execute().data
            if not request_data:
                logger.error(f"Request not found: request_id={request_id}, org_id={session['org_id']}")
                return jsonify({'error': f'Request ID {request_id} not found for this organization'}), 404

            request_record = request_data[0]
            supabase.table('manual_requests').update({'status': status}).eq('id', request_id).eq('org_id', session['org_id']).execute()
            logger.info(f"Manual request updated: request_id={request_id}, status={status}")

            if status == 'ACCEPTED':
                request_date = request_record['created_at'].split('T')[0]
                logger.debug(f"Parsed request_date: {request_date}")
                existing_attendance = supabase.table('attendance').select('id').eq('user_id', request_record['user_id']).eq('org_id', request_record['org_id']).eq('data', request_date).execute().data
                if existing_attendance:
                    logger.warning(f"Attendance already exists for user_id={request_record['user_id']}, date={request_date}")
                    return jsonify({'error': 'Attendance already marked for this date'}), 400
                
                attendance_data = {
                    'user_id': request_record['user_id'],
                    'org_id': request_record['org_id'],
                    'data': request_date,
                    'status': 'ACCEPTED',
                    'location': None,
                    'selfie_image': None
                }
                logger.debug(f"Inserting attendance: {attendance_data}")
                attendance_response = supabase.table('attendance').insert(attendance_data).execute()
                if not attendance_response.data:
                    logger.error(f"Attendance insert failed for request_id={request_id}: {attendance_response}")
                    return jsonify({'error': 'Failed to mark attendance'}), 500
                logger.info(f"Attendance marked for user_id={request_record['user_id']}, date={request_date}")

            return '', 200
        except Exception as e:
            logger.error(f"Manual request update failed for request_id={request_id}: {str(e)}")
            return jsonify({'error': f'Failed to update request: {str(e)}'}), 500
    
    try:
        requests = supabase.table('manual_requests').select('*').eq('org_id', session['org_id']).execute().data
        return render_template('manual_requests.html', requests=requests)
    except Exception as e:
        logger.error(f"Fetch manual requests failed for org_id={session['org_id']}: {str(e)}")
        return render_template('manual_requests.html', error=f"Fetch failed: {str(e)}")

@app.route('/get_users', methods=['GET'])
def get_users():
    if session.get('user_type') != 'organization':
        logger.warning(f"Unauthorized access to /get_users by user_type={session.get('user_type')}")
        return jsonify({'error': 'Unauthorized access. Please log in as an organization.'}), 401
    
    try:
        users = supabase.table('users').select('user_id, name').eq('org_id', session['org_id']).execute().data
        if not users:
            logger.info(f"No users found for org_id={session['org_id']}")
            return jsonify([]), 200  # Return empty list if no users
        logger.info(f"Fetched {len(users)} users for org_id={session['org_id']}")
        return jsonify(users), 200
    except Exception as e:
        logger.error(f"Failed to fetch users for org_id={session['org_id']}: {str(e)}")
        return jsonify({'error': 'Something went wrong. Please try again later.'}), 500

@app.route('/attendance_summary', methods=['GET', 'POST'])
def attendance_summary():
    if session.get('user_type') != 'organization':
        logger.warning(f"Unauthorized access to /attendance_summary by user_type={session.get('user_type')}")
        return redirect(url_for('org_login'))
    
    if request.method == 'POST':
        user_id = request.form.get('user_id')
        start_date = request.form.get('start_date')
        end_date = request.form.get('end_date')
        department = request.form.get('department')
        action = request.form.get('action')
        
        try:
            # Fetch all users for name lookup
            users = supabase.table('users').select('user_id, name').eq('org_id', session['org_id'])
            if department:
                users = users.eq('department', department)
            users_data = users.execute().data
            user_map = {user['user_id']: user['name'] for user in users_data}
            
            # Build base query for attendance
            query = supabase.table('attendance').select('user_id, data, status, location, users!inner(department)')\
                .eq('org_id', session['org_id'])
            
            # Apply filters
            if user_id:
                try:
                    user_id = int(user_id)  # Ensure user_id is numeric
                    query = query.eq('user_id', user_id)
                except ValueError:
                    logger.warning(f"Invalid user_id format: {user_id}")
                    return jsonify({'error': 'User ID must be numeric'}), 400
            
            if start_date and end_date:
                try:
                    datetime.strptime(start_date, '%Y-%m-%d')
                    datetime.strptime(end_date, '%Y-%m-%d')
                    query = query.gte('data', start_date).lte('data', end_date)
                except ValueError:
                    logger.warning(f"Invalid date format: start_date={start_date}, end_date={end_date}")
                    return jsonify({'error': 'Invalid date format'}), 400
            
            if department:
                query = query.eq('users.department', department)
            
            # Execute query
            records = query.execute().data
            logger.info(f"Fetched {len(records)} attendance records for org_id={session['org_id']}")
            
            if action == 'fetch':
                # Group records by user_id
                user_records = {}
                for record in records:
                    uid = record['user_id']
                    if uid not in user_records:
                        user_records[uid] = []
                    user_records[uid].append(record)
                
                # Prepare response with summary and details
                summary = []
                for uid, recs in user_records.items():
                    percentage = calculate_attendance_percentage(recs, start_date, end_date)
                    name = user_map.get(uid, 'Unknown')
                    summary.append({
                        'user_id': uid,
                        'name': name,
                        'percentage': percentage,
                        'details': recs
                    })
                return jsonify(summary), 200
            
            # Generate CSV
            output = io.StringIO()
            writer = csv.writer(output)
            writer.writerow(['User ID', 'Name', 'Attendance Percentage'])
            for user_id, name in user_map.items():
                user_recs = [r for r in records if r['user_id'] == user_id]
                percentage = calculate_attendance_percentage(user_recs, start_date, end_date)
                writer.writerow([user_id, name, f"{percentage}%"])
            output.seek(0)
            
            logger.info(f"Generated CSV for org_id={session['org_id']}")
            return send_file(
                io.BytesIO(output.getvalue().encode('utf-8')),
                mimetype='text/csv',
                as_attachment=True,
                download_name='attendance_summary.csv'
            )
        except Exception as e:
            logger.error(f"Attendance summary failed for org_id={session['org_id']}: {str(e)}")
            if action == 'fetch':
                return jsonify({'error': 'Something went wrong. Please try again later.'}), 500
            return render_template('attendance_summary.html', error='Something went wrong. Please try again later.'), 500
    
    return render_template('attendance_summary.html')

@app.route('/mark_absent_users', methods=['POST'])
def mark_absent_users():
    if session.get('user_type') != 'organization':
        logger.warning(f"Unauthorized access to /mark_absent_users by user_type={session.get('user_type')}")
        return jsonify({'error': 'Unauthorized access. Please log in as an organization.'}), 401
    
    org_id = session.get('org_id')
    if not org_id:
        logger.error("Missing org_id in session")
        return jsonify({'error': 'Invalid session'}), 400
    
    date_input = request.form.get('date', get_current_date(timezone='UTC'))
    
    try:
        # Validate date format
        datetime.strptime(date_input, '%Y-%m-%d')
    except ValueError:
        logger.warning(f"Invalid date format: {date_input}")
        return jsonify({'error': 'Invalid date format. Use YYYY-MM-DD.'}), 400
    
    try:
        # Fetch all users for the organization
        users = supabase.table('users').select('user_id, name').eq('org_id', org_id).execute().data
        if not users:
            logger.info(f"No users found for org_id={org_id}")
            return jsonify({'message': 'No users found for the organization'}), 200
        
        # Fetch attendance records for the given date
        attendance_records = supabase.table('attendance').select('user_id').eq('org_id', org_id).eq('data', date_input).execute().data
        present_user_ids = {record['user_id'] for record in attendance_records}
        
        # Identify absent users
        absent_users = [user for user in users if user['user_id'] not in present_user_ids]
        if not absent_users:
            logger.info(f"All users have attendance records for org_id={org_id}, date={date_input}")
            return jsonify({'message': 'All users have attendance records for the selected date'}), 200
        
        # Insert ABSENT records
        absent_records = [
            {
                'user_id': user['user_id'],
                'org_id': org_id,
                'data': date_input,
                'status': 'ABSENT',
                'location': None,
                'selfie_image': None
            } for user in absent_users
        ]
        
        # Batch insert absent records
        supabase.table('attendance').insert(absent_records).execute()
        logger.info(f"Marked {len(absent_users)} users as ABSENT for org_id={org_id}, date={date_input}")
        
        # Prepare response with marked users
        response = {
            'message': f"Successfully marked {len(absent_users)} users as ABSENT for {date_input}",
            'marked_users': [{'user_id': user['user_id'], 'name': user['name']} for user in absent_users]
        }
        return jsonify(response), 200
    except Exception as e:
        logger.error(f"Failed to mark absent users for org_id={org_id}, date={date_input}: {str(e)}")
        return jsonify({'error': f"Failed to mark absent users: {str(e)}"}), 500

@app.route('/delete_org', methods=['GET', 'POST'])
def delete_org():
    if session.get('user_type') != 'organization':
        return redirect(url_for('org_login'))
    
    org_id = session.get('org_id')
    if not org_id:
        logger.error("Missing org_id in session")
        return render_template('delete_org.html', error='Invalid session'), 400
    
    if request.method == 'POST':
        try:
            # Delete Cloudinary images for users
            users = supabase.table('users').select('picture_url').eq('org_id', org_id).execute().data
            for user in users:
                if user.get('picture_url'):
                    delete_from_cloudinary(user['picture_url'])
            
            # Delete Cloudinary images for attendance records
            attendance_records = supabase.table('attendance').select('selfie_image').eq('org_id', org_id).execute().data
            for record in attendance_records:
                if record['selfie_image']:
                    delete_from_cloudinary(record['selfie_image'])
            
            # Delete dependent records first to avoid foreign key constraints
            supabase.table('manual_requests').delete().eq('org_id', org_id).execute()
            supabase.table('attendance').delete().eq('org_id', org_id).execute()
            supabase.table('users').delete().eq('org_id', org_id).execute()
            supabase.table('geofences').delete().eq('org_id', org_id).execute()
            supabase.table('organizations').delete().eq('id', org_id).execute()
            
            logger.info(f"Organization deleted: org_id={org_id}")
            session.clear()
            return redirect(url_for('home'))
        except Exception as e:
            logger.error(f"Delete org failed for org_id={org_id}: {str(e)}")
            return render_template('delete_org.html', error=f"Delete failed: {str(e)}")
    
    # For GET requests, render the confirmation page
    return render_template('delete_org.html')

@app.route('/get_user_picture', methods=['GET'])
def get_user_picture():
    if not session.get('user_type') == 'user':
        logger.error("Unauthorized access to /get_user_picture")
        return jsonify({'error': 'Unauthorized'}), 401
    email = session.get('custom_user_id')
    org_id = session.get('org_id')
    if not email or not org_id:
        logger.error(f"Missing session data: email={email}, org_id={org_id}")
        return jsonify({'error': 'Invalid session'}), 400
    try:
        logger.debug(f"Querying user picture for email={email}, org_id={org_id}")
        user = supabase.table('users').select('picture_url, email, org_id').execute().data
        if not user:
            logger.error(f"No user found for email={email}, org_id={org_id}")
            return jsonify({'error': 'User not found'}), 404
        if not user[0]['picture_url']:
            logger.error(f"No picture_url for email={email}, org_id={org_id}")
            return jsonify({'error': 'No picture found'}), 404
        logger.info(f"Picture fetched for email={email}: {user[0]['picture_url']}")
        return jsonify({'picture_url': user[0]['picture_url']})
    except Exception as e:
        logger.error(f"Fetch picture failed for email={email}, org_id={org_id}: {str(e)}")
        return jsonify({'error': f'Server error: {str(e)}'}), 500

@app.route('/mark_attendance', methods=['GET', 'POST'])
def mark_attendance():
    if not session.get('user_type') == 'user':
        logger.error("Unauthorized access to /mark_attendance")
        return jsonify({'error': 'Unauthorized access. Please log in as a user.'}), 401
    
    if request.method == 'GET':
        return render_template('mark_attendance.html')
    
    email = session.get('custom_user_id')
    org_id = session.get('org_id')
    if not email or not org_id:
        logger.error(f"Missing session data: email={email}, org_id={org_id}")
        return jsonify({'error': 'Invalid session. Please log in again.'}), 400
    
    selfie_data = request.form.get('selfie_data')
    latitude = request.form.get('latitude')
    longitude = request.form.get('longitude')
    
    try:
        # Validate inputs
        if not selfie_data:
            logger.warning(f"Missing selfie for email={email}")
            return jsonify({'error': 'Selfie required'}), 400
        if not latitude or not longitude:
            logger.warning(f"Missing location for email={email}")
            return jsonify({'error': 'Location required'}), 400
        
        latitude = float(latitude)
        longitude = float(longitude)
        
        # Get current date in organization’s timezone (default UTC)
        current_date = get_current_date(timezone='UTC')  # Adjust timezone as needed
        user_response = supabase.table('users').select('user_id, org_id').eq('email', email).eq('org_id', org_id).execute()
        if not user_response.data:
            logger.error(f"User not found: email={email}, org_id={org_id}")
            return jsonify({'error': 'User not found'}), 404
        user = user_response.data[0]
        
        # Check for existing attendance
        existing_attendance = supabase.table('attendance').select('id')\
            .eq('user_id', user['user_id'])\
            .eq('org_id', user['org_id'])\
            .eq('data', current_date).execute().data
        if existing_attendance:
            logger.warning(f"Attendance already marked for user_id={user['user_id']}, date={current_date}")
            return jsonify({'error': 'Attendance already marked for today'}), 400
        
        # Decode base64
        selfie_data = selfie_data.split(',')[1]
        selfie_bytes = base64.b64decode(selfie_data)
        selfie_image = Image.open(BytesIO(selfie_bytes))
        logger.debug(f"Selfie decoded, size={len(selfie_bytes)} bytes")
        
        # Check selfie size
        if len(selfie_bytes) > 5 * 1024 * 1024:
            logger.warning(f"Selfie too large for email={email}")
            return jsonify({'error': 'Selfie must be less than 5MB'}), 400
        
        # Fetch geofence
        geofence_response = supabase.table('geofences').select('*').eq('org_id', user['org_id']).execute()
        if not geofence_response.data:
            logger.error(f"No geofence found for org_id={user['org_id']}")
            return jsonify({'error': 'Geofence not configured'}), 400
        geofence = geofence_response.data[0]
        
        # Validate geofence
        radius = geofence.get('radius', 0)
        if radius <= 0:
            logger.error(f"Invalid or missing geofence radius for org_id={user['org_id']}: {radius}")
            return jsonify({'error': 'Geofence radius is invalid or not set. Please contact your organization.'}), 400

        in_geofence = is_within_geofence(latitude, longitude, geofence['latitude'], geofence['longitude'], radius)
        if not in_geofence:
            logger.warning(f"Outside geofence for email={email}, user_location=({latitude}, {longitude}), geofence_center=({geofence['latitude']}, {geofence['longitude']}), radius={radius}")
            return jsonify({'error': 'You are outside the geofence. Please move to the designated location.'}), 400
            
        # Upload to Cloudinary
        selfie_url = upload_to_cloudinary(selfie_bytes, f"selfie_{user['user_id']}_{user['org_id']}_{current_date}")
        logger.debug(f"Selfie uploaded: {selfie_url}")
        
        # Insert attendance
        attendance_data = {
            'user_id': user['user_id'],
            'org_id': user['org_id'],
            'data': current_date,
            'status': 'ACCEPTED',
            'location': f'{latitude},{longitude}',
            'selfie_image': selfie_url
        }
        logger.debug(f"Inserting attendance: {attendance_data}")
        try:
            insert_response = supabase.table('attendance').insert(attendance_data).execute()
            if not insert_response.data:
                logger.error(f"Attendance insert failed for email={email}, response: {insert_response}")
                return jsonify({'error': 'Failed to mark attendance'}), 500
            
            logger.info(f"Attendance marked: user_id={user['user_id']}, email={email}, org_id={user['org_id']}")
            return jsonify({'success': 'Attendance marked successfully'}), 200
        except Exception as e:
            if 'duplicate key value violates unique constraint' in str(e).lower():
                logger.warning(f"Attendance already marked for user_id={user['user_id']}, date={current_date}")
                return jsonify({'error': 'Attendance already marked for today'}), 400
            logger.error(f"Attendance insert failed for email={email}: {str(e)}")
            return jsonify({'error': f'Failed to mark attendance: {str(e)}'}), 500
    except ValueError as ve:
        logger.error(f"Invalid data for email={email}: {ve}")
        return jsonify({'error': f'Invalid data: {str(ve)}'}), 400
    except Exception as e:
        logger.error(f"Attendance failed for email={email}: {str(e)}")
        return jsonify({'error': f'Failed to mark attendance: {str(e)}'}), 500

@app.route('/manual_attendance', methods=['GET', 'POST'])
def manual_attendance():
    if session.get('user_type') != 'user':
        return redirect(url_for('user_login'))
    if request.method == 'POST':
        reason = request.form.get('reason')
        email = session.get('custom_user_id')
        
        if not reason:
            return 'Reason is required', 400
        
        try:
            user = supabase.table('users').select('user_id, org_id').eq('email', email).eq('org_id', session['org_id']).execute().data[0]
            data = {
                'user_id': user['user_id'],
                'org_id': user['org_id'],
                'reason': reason,
                'status': 'pending',
                'created_at': datetime.now().isoformat()
            }
            supabase.table('manual_requests').insert(data).execute()
            logger.info(f"Manual attendance requested for user_id={user['user_id']}, email={email}")
            return redirect(url_for('user_dashboard'))
        except Exception as e:
            logger.error(f"Manual attendance failed for {email}: {str(e)}")
            return render_template('manual_attendance.html', error=f"Request failed: {str(e)}")
    
    return render_template('manual_attendance.html')

@app.route('/view_attendance', methods=['GET', 'POST'])
def view_attendance():
    if session.get('user_type') != 'user':
        return redirect(url_for('user_login'))
    email = session.get('custom_user_id')
    
    try:
        user = supabase.table('users').select('user_id, org_id').eq('email', email).eq('org_id', session['org_id']).execute().data[0]
    except Exception as e:
        logger.error(f"View attendance failed for {email}: {str(e)}")
        return render_template('view_attendance.html', error=f"Failed to fetch user: {str(e)}")
    
    if request.method == 'POST':
        start_date = request.form.get('start_date')
        end_date = request.form.get('end_date')
        action = request.form.get('action')
        
        query = supabase.table('attendance').select('data, status, location').eq('user_id', user['user_id']).eq('org_id', user['org_id'])
        if start_date and end_date:
            query = query.gte('data', start_date).lte('data', end_date)
        
        try:
            records = query.order('data', desc=True).execute().data
            percentage = calculate_attendance_percentage(records, start_date, end_date)
            if action == 'fetch':
                return jsonify({'records': records, 'percentage': percentage})
            
            output = io.StringIO()
            writer = csv.writer(output)
            writer.writerow(['Date', 'Status', 'Location', 'Attendance Percentage'])
            for record in records:
                writer.writerow([record['data'], record['status'], record['location'] or 'N/A', f"{percentage}%"])
            output.seek(0)
            return send_file(
                io.BytesIO(output.getvalue().encode('utf-8')),
                mimetype='text/csv',
                as_attachment=True,
                download_name='attendance_history.csv'
            )
        except Exception as e:
            logger.error(f"View attendance failed for {email}: {str(e)}")
            return render_template('view_attendance.html', error=f"Fetch failed: {str(e)}")
    
    return render_template('view_attendance.html')

@app.route('/download_user_attendance', methods=['POST'])
def download_user_attendance():
    if session.get('user_type') != 'organization':
        logger.warning(f"Unauthorized access to /download_user_attendance by user_type={session.get('user_type')}")
        return Response("Unauthorized access. Please log in as an organization.", status=401, mimetype='text/plain')
    
    org_id = session.get('org_id')
    if not org_id:
        logger.error("Missing org_id in session")
        return Response("Invalid session", status=400, mimetype='text/plain')
    
    user_id = request.form.get('user_id')
    start_date = request.form.get('start_date')
    end_date = request.form.get('end_date')
    
    try:
        # Validate inputs
        if not user_id:
            logger.warning("Missing user_id in request")
            return Response("User ID is required", status=400, mimetype='text/plain')
        
        user_id = int(user_id)  # Ensure user_id is numeric
        
        # Fetch user for name
        user = supabase.table('users').select('user_id, name').eq('user_id', user_id).eq('org_id', org_id).execute().data
        if not user:
            logger.warning(f"User not found: user_id={user_id}, org_id={org_id}")
            return Response(f"User ID {user_id} not found for this organization", status=404, mimetype='text/plain')
        
        name = user[0]['name']
        
        # Build query for attendance records
        query = supabase.table('attendance').select('user_id, data, status, location').eq('user_id', user_id).eq('org_id', org_id)
        if start_date and end_date:
            try:
                datetime.strptime(start_date, '%Y-%m-%d')
                datetime.strptime(end_date, '%Y-%m-%d')
                query = query.gte('data', start_date).lte('data', end_date)
            except ValueError:
                logger.warning(f"Invalid date format: start_date={start_date}, end_date={end_date}")
                return Response("Invalid date format", status=400, mimetype='text/plain')
        
        # Execute query
        records = query.execute().data
        logger.info(f"Fetched {len(records)} attendance records for user_id={user_id}, org_id={org_id}")
        
        # Calculate attendance percentage
        percentage = calculate_attendance_percentage(records, start_date, end_date)
        
        # Generate CSV
        output = io.StringIO()
        writer = csv.writer(output)
        writer.writerow(['User ID', 'Name', 'Date', 'Status', 'Location', 'Attendance Percentage'])
        for record in records:
            writer.writerow([
                record['user_id'],
                name,
                record['data'] or 'N/A',
                record['status'] or 'N/A',
                record['location'] or 'N/A',
                f"{percentage}%"
            ])
        output.seek(0)
        
        logger.info(f"Generated CSV for user_id={user_id}, org_id={org_id}")
        return send_file(
            io.BytesIO(output.getvalue().encode('utf-8')),
            mimetype='text/csv',
            as_attachment=True,
            download_name=f'user_attendance_{user_id}.csv'
        )
    except ValueError:
        logger.warning(f"Invalid user_id format: {user_id}")
        return Response("User ID must be numeric", status=400, mimetype='text/plain')
    except Exception as e:
        logger.error(f"Download user attendance failed for user_id={user_id}, org_id={org_id}: {str(e)}")
        return Response(f"Failed to download user CSV: {str(e)}", status=500, mimetype='text/plain')

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('home'))

if __name__ == '__main__':
    app.run()