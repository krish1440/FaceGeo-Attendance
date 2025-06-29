
to do 
     
     -- for one day only one present
     ====== apsent if not present that day   
     -- cal % of attendace 
    


Backend: Flask (Python) for API endpoints and routing.
Frontend: HTML with embedded CSS and JavaScript (using face-api.js for face recognition and Leaflet.js for maps).
Database: Supabase for authentication, user data, attendance records, and geofencing.
Assumptions: Supabase handles user/organization authentication and storage; face recognition and geofencing validation are processed via backend API calls.

Directory Structure
attendance-system/
|- static/
|  |-model/
|    |- face-api 
|
├── templates/
│   ├── base.html               # Base HTML template with common layout, CSS, JS
│   ├── home.html               # Home page with login/signup links
│   ├── org_signup.html         # Organization signup page
│   ├── user_signup.html        # User signup page
│   ├── org_login.html          # Organization login page
│   ├── user_login.html         # User login page
│   ├── org_dashboard.html      # Organization dashboard
│   ├── user_dashboard.html     # User dashboard
│   ├── add_user.html           # Add user page
│   ├── edit_user.html          # Edit user page
│   ├── geofence_setup.html     # Geofencing setup page
│   ├── manual_requests.html    # Manual attendance requests page
│   ├── attendance_summary.html # Attendance summary page
│   ├── delete_org.html         # Delete organization page
│   ├── mark_attendance.html    # Mark attendance page
│   ├── manual_attendance.html  # Manual attendance request page
│   └── view_attendance.html    # View attendance page
├── app.py                      # Main Flask application
├── requirements.txt            # Python dependencies
└── README.md                   # Project documentation

File Functionality

base.html: Base template with common layout (header, footer, navigation), embedded CSS for global styling (e.g., layout, buttons, forms), and JavaScript for shared functionality (e.g., Supabase client initialization).
CSS: Defines styles for body, header, footer, forms, buttons, and cards.
JS: Initializes Supabase client, includes CDN links for face-api.js and Leaflet.js.

home.html: Landing page with links to organization/user login and signup.
CSS: Styles for welcome message and buttons.
JS: None specific.

org_signup.html: Form for organization signup (name, username, password, confirm password).
CSS: Form styling.
JS: Validates password match, sends signup data to Supabase via Flask endpoint.

user_signup.html: Form for user signup (user ID if assigned, password, confirm password).
CSS: Form styling.
JS: Validates password match, sends signup data to Supabase.

org_login.html: Organization login form (username, password).
CSS: Form styling.
JS: Sends login credentials to Supabase via Flask.

user_login.html: User login form (user ID, password).
CSS: Form styling.
JS: Sends login credentials to Supabase.

org_dashboard.html: Organization dashboard with options: add user, delete user, edit user, set geofencing, view manual requests, download attendance summary, delete organization, logout.
CSS: Grid layout for options, button styling.
JS: Handles navigation to other pages.

user_dashboard.html: User dashboard displaying user details (ID, name, mobile, email, role, department) and options: mark attendance, request manual attendance, view attendance, logout.
CSS: Card layout for user details, button styling.
JS: Fetches user details from Supabase.

add_user.html: Form to add users (user ID, name, mobile, email, role, department, picture upload).
CSS: Form styling, file input styling.
JS: Handles file upload, sends data to Supabase.

edit_user.html: Form to edit user details, including replacing picture (removes old picture).
CSS: Form styling.
JS: Fetches current user data, handles updates and file upload.

geofence_setup.html: Form for geofencing (latitude, longitude, radius) with Leaflet map preview.
CSS: Map container styling, form styling.
JS: Initializes Leaflet map, updates map based on input, sends geofence data to Supabase.

manual_requests.html: Displays manual attendance requests with buttons to mark present/absent.
CSS: Table styling for requests, button styling.
JS: Fetches requests from Supabase, sends approval/rejection to Supabase.

attendance_summary.html: Interface to download attendance summaries with filters (user, date range, department).
CSS: Form and table styling.
JS: Fetches filtered data from Supabase, generates CSV for download.

delete_org.html: Confirmation page to delete organization and all data.
CSS: Confirmation button styling.
JS: Sends delete request to Supabase via Flask.

mark_attendance.html: Interface for users to capture selfie and verify location.
CSS: Video feed styling, button styling.
JS: Accesses webcam, captures selfie using face-api.js, gets location, sends data to Flask for validation.

manual_attendance.html: Form for manual attendance requests with reason.
CSS: Form styling.
JS: Sends request data to Supabase.

view_attendance.html: Displays attendance history with date range filters and CSV download.
CSS: Table styling, form styling.
JS: Fetches attendance data from Supabase, generates CSV.

Root Files
app.py: Main Flask application defining routes and Supabase integration.
Supabase Setup: Initializes Supabase client using project URL and API key.
Routes:
/: Renders home page.
/org_signup, /user_signup: Handles signup, stores data in Supabase tables (organizations, users).
/org_login, /user_login: Authenticates via Supabase auth.
/org_dashboard, /user_dashboard: Protected routes rendering dashboards.
/add_user, /edit_user/<id>, /delete_user/<id>: CRUD operations on users table.
/geofence_setup: Stores geofence data in geofences table.
/manual_requests: Fetches and updates manual_requests table.
/attendance_summary: Queries attendance table, generates CSV.
/delete_org: Deletes organization and related data from Supabase.
/mark_attendance: Validates face (via API) and geofence, updates attendance table.
/manual_attendance: Inserts into manual_requests table.
/view_attendance: Queries attendance table for user.
/logout: Clears session.


requirements.txt: Lists dependencies (flask, supabase-py, requests).flask==2.3.2
supabase-py==1.0.3
requests==2.31.0


Supabase Schema (Assumed)

Tables:
organizations: id, name, username, created_at
users: id, user_id, name, mobile, email, role, department, picture_url, org_id (foreign key)
geofences: id, org_id, latitude, longitude, radius
attendance: id, user_id, date, status (present/absent), location, selfie_url
manual_requests: id, user_id, reason, status (pending/approved/rejected), created_at
