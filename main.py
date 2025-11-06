from multiprocessing import connection
import os
from traceback import print_list
from dotenv import load_dotenv
from flask import Flask, render_template, request, redirect, send_file, send_from_directory, url_for, session, flash, jsonify
from flask_moment import Moment
from werkzeug.utils import secure_filename
import pyodbc
import pandas as pd
from datetime import date, datetime, time
from typing import List, Tuple, Optional
from dateutil.parser import parse
import requests
from requests_oauthlib import OAuth2Session
import secrets
from datetime import datetime, date, time
from flask_socketio import SocketIO, emit, join_room, leave_room
import json
from PIL import Image
import uuid
from datetime import datetime
from werkzeug.utils import secure_filename
from flask_socketio import emit, join_room, leave_room
import mimetypes
import numpy as np
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from flask import jsonify  
import json


# Email Configuration
SMTP_HOST = os.getenv('SMTP_HOST', 'smtp.gmail.com')
SMTP_PORT = int(os.getenv('SMTP_PORT', '587'))
SMTP_USER = os.getenv('SMTP_USER')
SMTP_PASSWORD = os.getenv('SMTP_PASSWORD')
SMTP_FROM_EMAIL = os.getenv('SMTP_FROM_EMAIL')

def send_email(to_email, subject, text_content):
    """Send email notification - Plain text version"""
    try:
        if not SMTP_USER or not SMTP_PASSWORD:
            print("Email configuration missing. Skipping email notification.")
            return False
            
        msg = MIMEMultipart()
        msg['From'] = SMTP_FROM_EMAIL or SMTP_USER
        msg['To'] = to_email
        msg['Subject'] = subject

        # Change from 'html' to 'plain'
        msg.attach(MIMEText(text_content, 'plain'))

        with smtplib.SMTP(SMTP_HOST, SMTP_PORT) as server:
            server.starttls()
            server.login(SMTP_USER, SMTP_PASSWORD)
            server.send_message(msg)

        print(f" Email sent to {to_email} with subject '{subject}'")
        return True

    except Exception as e:
        print(f" Failed to send email to {to_email}: {e}")
        return False

def get_user_email(username):
    """Get user email from database"""
    df = run_query("SELECT email FROM users WHERE username = ?", (username,))
    if not df.empty:
        return df.iloc[0]['email']
    return None



load_dotenv()

# Set OAuth environment variable
os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = os.getenv('OAUTHLIB_INSECURE_TRANSPORT', '1')

# --------------------
# CONFIG - Load from environment variables
# --------------------
SQL_DRIVER = os.getenv('SQL_DRIVER', 'ODBC Driver 17 for SQL Server')
SQL_SERVER = os.getenv('SQL_SERVER')
SQL_PORT = os.getenv('SQL_PORT', '1433')
SQL_DATABASE = os.getenv('SQL_DATABASE')
SQL_USERNAME = os.getenv('SQL_USERNAME')
SQL_PASSWORD = os.getenv('SQL_PASSWORD')

UPLOAD_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'Uploads')
os.makedirs(UPLOAD_DIR, exist_ok=True)
print(f" Upload directory: {UPLOAD_DIR}")
APP_TITLE = os.getenv('APP_TITLE', 'Timesheet & Leave System')

CLIENT_ID = os.getenv('CLIENT_ID')
CLIENT_SECRET = os.getenv('CLIENT_SECRET')
TENANT_ID = os.getenv('TENANT_ID')

# Validate required environment variables
required_vars = [
    'SQL_SERVER', 'SQL_DATABASE', 'SQL_USERNAME', 'SQL_PASSWORD',
    'CLIENT_ID', 'CLIENT_SECRET', 'TENANT_ID'
]

missing_vars = [var for var in required_vars if not os.getenv(var)]
if missing_vars:
    raise ValueError(f"Missing required environment variables: {', '.join(missing_vars)}")

# Change this based on your deployment
USE_NGROK = os.getenv('USE_NGROK', 'False').lower() == 'true'
NGROK_URL = os.getenv('NGROK_URL')

if USE_NGROK and NGROK_URL:
    REDIRECT_URI = f"{NGROK_URL}/callback"
else:
    REDIRECT_URI = "https://nexus.chervicaon.com/callback"


# Azure OAuth2 URLs
AUTH_URL = f"https://login.microsoftonline.com/{TENANT_ID}/oauth2/v2.0/authorize"
TOKEN_URL = f"https://login.microsoftonline.com/{TENANT_ID}/oauth2/v2.0/token"
SCOPES = ["openid", "profile", "email", "User.Read"]

# Configuration for different user roles and privileges
MANAGER_ROLES = ['Manager']
HR_FINANCE_ROLES = ['Hr & Finance Controller']
LEAD_ROLES = ['Lead', 'Finance Manager']
ADMIN_ROLES = ['Admin Manager', 'Lead Staffing Specialist']
EMPLOYEE_ROLES = ['Employee', 'Rm', 'Lead', 'Product Owner', 'BDE Manager', 'SAP Consultant', 'Contractor']
INTERN_ROLES = ['Intern']

# Special privilege users (configure these as needed)
SUPER_ADMIN_USERS = []  # Add usernames that should have super admin privileges
TOP_LEVEL_MANAGERS = []  # Add usernames that are top-level managers
HR_CONTROLLERS = []  # Add usernames that are HR controllers

app = Flask(__name__)
app.secret_key = os.getenv('SECRET_KEY', secrets.token_hex(16))
app.config['UPLOAD_FOLDER'] = UPLOAD_DIR

moment = Moment(app)
socketio = SocketIO(app, cors_allowed_origins="*")

app.config['TEMPLATES_AUTO_RELOAD'] = True
app.config['SEND_FILE_MAX_AGE_DEFAULT'] = 0
app.jinja_env.auto_reload = True
app.debug = os.getenv('FLASK_DEBUG', 'True').lower() == 'true'

# --------------------
# DB helpers
# --------------------
def get_connection():
    conn_str = (
        f"DRIVER={{{SQL_DRIVER}}};"
        f"SERVER={SQL_SERVER},{SQL_PORT};"
        f"DATABASE={SQL_DATABASE};"
        f"UID={SQL_USERNAME};"
        f"PWD={SQL_PASSWORD};"
        "Encrypt=no;"
    )
    return pyodbc.connect(conn_str, autocommit=False)


def run_query(sql: str, params: Tuple = ()):
    try:
        conn = get_connection()
        df = pd.read_sql(sql, conn, params=params if params else None)
        conn.close()
        return df
    except Exception as e:
        flash(f"DB query error: {e}")
        return pd.DataFrame()

def run_exec(sql: str, params: Tuple = ()):
    try:
        conn = get_connection()
        cur = conn.cursor()
        cur.execute(sql, params)
        conn.commit()
        conn.close()
        return True
    except Exception as e:
        try:
            conn.rollback()
            conn.close()
        except:
            pass
        flash(f"DB exec error: {e}")
        return False

# --------------------
# User privilege helpers
# --------------------
def is_super_admin(username: str) -> bool:
    """Check if user has super admin privileges"""
    return username in SUPER_ADMIN_USERS or has_role(username, ADMIN_ROLES)

def is_top_level_manager(username: str) -> bool:
    """Check if user is a top-level manager"""
    return username in TOP_LEVEL_MANAGERS or has_role(username, MANAGER_ROLES)

def is_hr_controller(username: str) -> bool:
    """Check if user has HR controller privileges"""
    return username in HR_CONTROLLERS or has_role(username, HR_FINANCE_ROLES)

def has_role(username: str, roles: List[str]) -> bool:
    """Check if user has any of the specified roles"""
    user_df = run_query("SELECT role FROM users WHERE username = ?", (username,))
    if not user_df.empty:
        user_role = user_df.iloc[0]['role']
        return user_role in roles
    return False

def get_user_role(username: str) -> str:
    """Get user's role from database"""
    user_df = run_query("SELECT role FROM users WHERE username = ?", (username,))
    if not user_df.empty:
        return user_df.iloc[0]['role']
    return None

# --------------------
# Leave balance helpers
# --------------------
def _apply_leave_balance(username: str, leave_type: str, days: int, sign: int = +1):
    """Apply leave balance change. sign +1 to consume, -1 to revert"""
    
    leave_balance_mapping = {
        'Sick': 'sick_used',
        'Vacation': 'paid_used',
        'Personal': 'paid_used',
        'Casual': 'casual_used',
        'Other': 'casual_used'
    }
    
    col_used = leave_balance_mapping.get(leave_type, 'casual_used')
    
    sql = f"UPDATE leave_balances SET {col_used} = COALESCE({col_used}, 0) + ? WHERE username = ?"
    run_exec(sql, (sign * days, username))

def _get_remaining_balances(username: str):
    """Get remaining balances for all leave types"""
    df = run_query("""
        SELECT 
            COALESCE(sick_total, 12) - COALESCE(sick_used, 0) AS sick_rem,
            COALESCE(paid_total, 18) - COALESCE(paid_used, 0) AS paid_rem,
            COALESCE(casual_total, 6) - COALESCE(casual_used, 0) AS casual_rem
        FROM [timesheet_db].[dbo].[leave_balances] WHERE username = ?
    """, (username,))
    
    if df.empty:
        run_exec("""
            IF NOT EXISTS (SELECT 1 FROM leave_balances WHERE username = ?)
            INSERT INTO [timesheet_db].[dbo].[leave_balances] (username, total_leaves, sick_total, paid_total, casual_total, sick_used, paid_used, casual_used)
            VALUES (?, 36, 12, 18, 6, 0, 0, 0)
        """, (username, username))
        return {'sick': 12, 'paid': 18, 'casual': 6}
    
    r = df.iloc[0]
    return {
        'sick': max(0, int(r['sick_rem'])),
        'paid': max(0, int(r['paid_rem'])),
        'casual': max(0, int(r['casual_rem']))
    }
# Organizational hierarchy helpers - CORRECTED VERSION
def get_direct_reports(rm_username: str) -> List[str]:
    """Get direct reports for a manager - RM ONLY"""
    df = run_query("SELECT username FROM report WHERE rm = ?", (rm_username,))
    if df.empty:
        return []
    return df["username"].astype(str).tolist()

def get_all_reports_recursive(supervisor: str) -> List[str]:
    """Get all reports recursively (including sub-reports) - RM ONLY"""
    try:
        recursive_df = run_query("""
            WITH RecursiveHierarchy AS (
                -- Base case: direct reports (RM ONLY)
                SELECT username 
                FROM report 
                WHERE rm = ?
                
                UNION ALL
                
                -- Recursive case: reports of reports (RM ONLY)
                SELECT r.username
                FROM report r
                INNER JOIN RecursiveHierarchy rh ON r.rm = rh.username
            )
            SELECT DISTINCT username FROM RecursiveHierarchy
        """, (supervisor,))
        
        if not recursive_df.empty:
            return recursive_df["username"].astype(str).tolist()
        else:
            return []
        
    except Exception as e:
        print(f"Error getting recursive reports: {e}")
        return get_direct_reports(supervisor)

def can_assign_work_to_user(assigner: str, assignee: str) -> bool:
    """ASSIGNMENT: Hierarchical assignment allowed (direct + indirect reports)"""
    team_members = get_all_reports_recursive(assigner)
    return assignee in team_members

def get_direct_reports(rm_username: str) -> List[str]:
    """Get direct reports for ANY user who acts as RM - including Admin Manager and Lead Staffing Specialist"""
    try:
        # Query the report table to find users where rm = current_user
        df = run_query("SELECT username FROM report WHERE rm = ?", (rm_username,))
        
        if df.empty:
            print(f" DEBUG: No direct reports found for {rm_username} in reports table")
            return []
        
        direct_reports = df["username"].astype(str).tolist()
        print(f" DEBUG: Direct reports for {rm_username}: {direct_reports}")
        return direct_reports
        
    except Exception as e:
        print(f" Error getting direct reports for {rm_username}: {e}")
        return []

def get_work_assignable_employees(rm_username: str) -> List[str]:
    """Get employees to whom this user can assign work - based on reports table RM relationship"""
    try:
        # Same logic as get_direct_reports - anyone can be an RM regardless of their role
        assignable_df = run_query("SELECT username FROM report WHERE rm = ?", (rm_username,))
        
        if not assignable_df.empty:
            assignable = assignable_df["username"].astype(str).tolist()
            print(f" DEBUG: {rm_username} can assign work to: {assignable}")
            return assignable
        
        print(f"⚠ DEBUG: No assignable employees found for {rm_username}")
        return []
        
    except Exception as e:
        print(f" Error getting assignable employees for {rm_username}: {e}")
        return []

def get_rm_for_employee(employee_username: str) -> str:
    """Get the DIRECT RM for an employee from report table - UPDATED VERSION"""
    try:
        # Get direct RM from report table
        rm_query = run_query("SELECT rm FROM report WHERE username = ?", (employee_username,))
        
        if not rm_query.empty:
            rm = rm_query.iloc[0]['rm']
            print(f" DEBUG: Employee {employee_username} -> RM: {rm}")
            return rm
        
        # If no direct RM found, log it
        print(f"⚠ WARNING: No RM found for employee {employee_username} in report table")
        return None
        
    except Exception as e:
        print(f" Error getting RM for {employee_username}: {e}")
        return None

def get_manager_for_employee(employee_username: str) -> str:
    """Get the manager for an employee (different from RM)"""
    try:
        manager_query = run_query("SELECT manager FROM report WHERE username = ?", (employee_username,))
        if not manager_query.empty:
            return manager_query.iloc[0]['manager']
        return None
    except Exception as e:
        print(f"Error getting manager for {employee_username}: {e}")
        return None

def can_approve_timesheet(approver: str, employee: str) -> bool:
    """Check if approver can approve timesheet - ONLY RM can approve"""
    try:
        rm_query = run_query("SELECT rm FROM report WHERE username = ?", (employee,))
        if not rm_query.empty:
            assigned_rm = rm_query.iloc[0]['rm']
            return approver == assigned_rm  # Only direct RM can approve
        return False
    except:
        return False

def can_approve_leave(approver: str, employee: str) -> bool:
    """Check if approver can approve leave - ONLY RM can approve"""
    try:
        rm_query = run_query("SELECT rm FROM report WHERE username = ?", (employee,))
        if not rm_query.empty:
            assigned_rm = rm_query.iloc[0]['rm']
            return approver == assigned_rm  # Only direct RM can approve
        return False
    except:
        return False

def can_view_employee_data(viewer: str, employee: str) -> bool:
    """Check if viewer can see employee data - Both RM and Manager can view"""
    try:
        report_query = run_query("SELECT rm, manager FROM report WHERE username = ?", (employee,))
        if not report_query.empty:
            assigned_rm = report_query.iloc[0]['rm']
            assigned_manager = report_query.iloc[0]['manager']
            return viewer == assigned_rm or viewer == assigned_manager
        return False
    except:
        return False
def get_pending_approvals_for_rm(rm_username: str):
    """Get pending approvals for RM - ONLY direct RM assignments - FIXED"""
    
    # Get employees where this user is the DIRECT RM (not manager)
    rm_employees = run_query("SELECT username FROM report WHERE rm = ?", (rm_username,))
    
    if rm_employees.empty:
        print(f"DEBUG: No direct reports found for RM {rm_username}")
        return pd.DataFrame(), pd.DataFrame()
    
    employee_list = rm_employees['username'].tolist()
    print(f"DEBUG: RM {rm_username} can approve for employees: {employee_list}")
    
    placeholders = ",".join(["?"] * len(employee_list))
    
    # Get pending timesheets - ONLY where this user is the assigned RM approver
    pending_timesheets = run_query(f"""
        SELECT t.id, t.username, t.work_date, t.project_name, t.work_desc, t.hours, t.break_hours,
               u.name as employee_name
        FROM timesheets t
        JOIN users u ON t.username = u.username
        JOIN report r ON t.username = r.username  
        WHERE t.username IN ({placeholders}) 
        AND t.rm_status = 'Pending' 
        AND r.rm = ?
        ORDER BY t.work_date ASC
    """, tuple(employee_list + [rm_username]))
    
    # Get pending leaves - ONLY where this user is the assigned RM approver
    pending_leaves = run_query(f"""
        SELECT l.id, l.username, l.start_date, l.end_date, l.leave_type, l.description,
               l.health_document,
               CASE WHEN l.health_document IS NOT NULL THEN 1 ELSE 0 END as has_document,
               u.role as employee_role, u.name as employee_name,
               DATEDIFF(day, l.start_date, l.end_date) + 1 as duration_days
        FROM leaves l
        JOIN users u ON l.username = u.username
        JOIN report r ON l.username = r.username
        WHERE l.username IN ({placeholders}) 
        AND l.rm_status = 'Pending' 
        AND r.rm = ?
        ORDER BY l.start_date ASC
    """, tuple(employee_list + [rm_username]))
    
    print(f"DEBUG: Found {len(pending_timesheets)} pending timesheets and {len(pending_leaves)} pending leaves for RM {rm_username}")
    
    return pending_timesheets, pending_leaves

def fix_approver_columns():
    """Ensure approver columns exist and are populated"""
    try:
        # Add rm_approver column if it doesn't exist
        run_exec("""
            IF NOT EXISTS (SELECT * FROM sys.columns WHERE object_id = OBJECT_ID('timesheets') AND name = 'rm_approver')
            ALTER TABLE timesheets ADD rm_approver NVARCHAR(100)
        """)
        
        run_exec("""
            IF NOT EXISTS (SELECT * FROM sys.columns WHERE object_id = OBJECT_ID('leaves') AND name = 'rm_approver')
            ALTER TABLE leaves ADD rm_approver NVARCHAR(100)
        """)
        
        # Update existing records without approvers
        run_exec("""
            UPDATE t SET t.rm_approver = r.rm
            FROM timesheets t
            INNER JOIN report r ON t.username = r.username
            WHERE t.rm_approver IS NULL AND t.rm_status = 'Pending'
        """)
        
        run_exec("""
            UPDATE l SET l.rm_approver = r.rm
            FROM leaves l
            INNER JOIN report r ON l.username = r.username
            WHERE l.rm_approver IS NULL AND l.rm_status = 'Pending'
        """)
        
        print(" Approver columns fixed successfully")
        
    except Exception as e:
        print(f" Error fixing approver columns: {e}")

# Call this function when your app starts
fix_approver_columns()

# --------------------
# Role-based Helper Functions (NO NAMES)
# --------------------
def is_top_level_manager(username: str) -> bool:
    """Check if user is a top-level manager based on hierarchy"""
    try:
        # Check if user reports to themselves (top of hierarchy)
        self_reporting = run_query("SELECT rm FROM report WHERE username = ? AND rm = ?", (username, username))
        
        # Check if user has many subordinates
        subordinate_count = len(get_all_reports_recursive(username))
        
        return not self_reporting.empty or subordinate_count >= 5
    except:
        return False

def has_company_wide_access(username: str) -> bool:
    """Check if user has company-wide access based on role and hierarchy"""
    user_role = get_user_role(username)
    
    # Role-based access
    if user_role in ['Manager', 'Admin Manager', 'Hr & Finance Controller']:
        return True
    
    # Hierarchy-based access
    return is_top_level_manager(username)

def get_approver_for_user(username: str) -> str:
    """Get the approver for any user based on reporting structure"""
    try:
        rm_query = run_query("SELECT rm FROM report WHERE username = ?", (username,))
        if not rm_query.empty:
            return rm_query.iloc[0]['rm']
        
        # If no direct RM, find a manager
        manager_query = run_query("""
            SELECT username FROM users 
            WHERE role IN ('Manager', 'Admin Manager', 'Hr & Finance Controller') 
            AND status = 'Active' 
            LIMIT 1
        """)
        
        if not manager_query.empty:
            return manager_query.iloc[0]['username']
        
        return None
    except:
        return None
    # Template filters
# --------------------
@app.template_filter('dateformat')
def dateformat(value, fmt='%Y-%m-%d'):
    """Convert date objects to strings safely"""
    if isinstance(value, (datetime, date)):
        return value.strftime(fmt)
    elif isinstance(value, pd.Timestamp):
        return value.strftime(fmt)
    return str(value) if value else ''

@app.template_filter('strptime')
def strptime_filter(date_string, format='%Y-%m-%d'):
    """Parse date string using strptime"""
    try:
        if isinstance(date_string, (datetime, date)):
            return date_string
        elif isinstance(date_string, pd.Timestamp):
            return date_string.to_pydatetime()
        return datetime.strptime(str(date_string), format)
    except (ValueError, TypeError):
        return datetime.now()

@app.template_filter('days_between')
def days_between_filter(start_date, end_date):
    """Calculate days between two dates"""
    try:
        if isinstance(start_date, str):
            start_date = datetime.strptime(start_date, '%Y-%m-%d')
        elif isinstance(start_date, pd.Timestamp):
            start_date = start_date.to_pydatetime()
            
        if isinstance(end_date, str):
            end_date = datetime.strptime(end_date, '%Y-%m-%d')
        elif isinstance(end_date, pd.Timestamp):
            end_date = end_date.to_pydatetime()
        
        return (end_date - start_date).days + 1
    except (ValueError, TypeError, AttributeError):
        return 0

@app.template_filter('zfill')
def zfill_filter(value, width=2):
    """Zero-fill a number to specified width"""
    try:
        return str(int(value)).zfill(width)
    except (ValueError, TypeError):
        return str(value).zfill(width)

@app.template_filter('safe_sum')
def safe_sum_filter(iterable, attribute=None):
    """Safely sum numeric values, ignoring None values"""
    total = 0.0
    for item in iterable:
        if attribute:
            val = item.get(attribute, 0) if hasattr(item, 'get') else getattr(item, attribute, 0)
        else:
            val = item
        
        if val is not None:
            try:
                total += float(val)
            except (ValueError, TypeError):
                continue
    return total

@app.template_filter('format_currency')
def format_currency_filter(value):
    """Format number as currency"""
    try:
        return f"₹{float(value):,.2f}"
    except (ValueError, TypeError):
        return "₹0.00"

@app.template_filter('calculate_duration')
def calculate_duration_filter(start_date, end_date):
    """Calculate duration between two dates in days"""
    try:
        if not start_date or not end_date:
            return 0
            
        if isinstance(start_date, str):
            start_date = datetime.strptime(start_date, '%Y-%m-%d').date()
        elif isinstance(start_date, datetime):
            start_date = start_date.date()
        elif isinstance(start_date, pd.Timestamp):
            start_date = start_date.date()
            
        if isinstance(end_date, str):
            end_date = datetime.strptime(end_date, '%Y-%m-%d').date()
        elif isinstance(end_date, datetime):
            end_date = end_date.date()
        elif isinstance(end_date, pd.Timestamp):
            end_date = end_date.date()
            
        return (end_date - start_date).days + 1
    except:
        return 0

# Add template globals
def min_value(a, b):
    return min(a, b)

def max_value(a, b):
    return max(a, b)

app.jinja_env.filters['min_value'] = min_value
app.jinja_env.filters['max_value'] = max_value

@app.template_global()
def moment():
    class MomentMock:
        def format(self, format_string):
            return datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    return MomentMock()

# --------------------
# Helper functions
# --------------------
def calc_hours(start_t: Optional[time], end_t: Optional[time], break_hours: float = 0.0) -> float:
    if not start_t or not end_t:
        return 0.0
    start_dt = datetime.combine(date.today(), start_t)
    end_dt = datetime.combine(date.today(), end_t)
    if end_dt < start_dt:
        end_dt = end_dt.replace(day=end_dt.day + 1)
    total = (end_dt - start_dt).total_seconds() / 3600.0
    result = max(0.0, total - float(break_hours))
    return round(result, 2)

def calculate_leave_duration(leave_records):
    """Calculate duration for leave records and ensure dates are strings"""
    for record in leave_records:
        try:
            if 'start_date' in record and 'end_date' in record:
                start_date_str = record['start_date']
                end_date_str = record['end_date']
                
                if hasattr(start_date_str, 'strftime'):
                    start_date_str = start_date_str.strftime('%Y-%m-%d')
                    record['start_date'] = start_date_str
                    
                if hasattr(end_date_str, 'strftime'):
                    end_date_str = end_date_str.strftime('%Y-%m-%d')
                    record['end_date'] = end_date_str
                
                start_date = datetime.strptime(str(start_date_str), '%Y-%m-%d')
                end_date = datetime.strptime(str(end_date_str), '%Y-%m-%d')
                record['duration_days'] = (end_date - start_date).days + 1
            else:
                record['duration_days'] = 0
        except Exception:
            record['duration_days'] = 0
    return leave_records

# --------------------
# Authentication Routes
# --------------------
@app.route('/')
def index():
    """Main entry point - redirect to login"""
    print(" Accessing index route")
    if 'username' in session:
        print(f" User already logged in: {session.get('username')}")
        return redirect(url_for('dashboard'))
    print(" Redirecting to login_sso")
    return redirect(url_for('login_sso'))

@app.route('/login_sso')
def login_sso():
    """Show login page with SSO option"""
    print(" Accessing login_sso route")
    if 'username' in session:
        return redirect(url_for('dashboard'))
    
    return render_template('login_sso.html', title=APP_TITLE)

@app.route('/login', methods=['GET', 'POST'])
def login():
    """Redirect to SSO login"""
    print(" Accessing legacy login route, redirecting to login_sso")
    return redirect(url_for('login_sso'))

@app.route('/auth/microsoft')
def auth_microsoft():
    """Initiate Microsoft SSO login"""
    try:
        print(f" Starting Microsoft auth with CLIENT_ID: {CLIENT_ID}")
        print(f" Redirect URI: {REDIRECT_URI}")
        
        if not CLIENT_ID or not CLIENT_SECRET or not TENANT_ID:
            print(" Missing OAuth configuration")
            flash("OAuth configuration incomplete. Please check CLIENT_ID, CLIENT_SECRET, and TENANT_ID.")
            return redirect(url_for('login_sso'))
        
        oauth_session = OAuth2Session(
            CLIENT_ID,
            redirect_uri=REDIRECT_URI,
            scope=SCOPES
        )
        authorization_url, state = oauth_session.authorization_url(AUTH_URL)
        session['oauth_state'] = state
        
        print(f" Authorization URL generated: {authorization_url[:100]}...")
        print(f" OAuth state stored: {state}")
        return redirect(authorization_url)
    except Exception as e:
        print(f" Microsoft auth error: {str(e)}")
        flash(f"SSO authentication error: {str(e)}")
        return redirect(url_for('login_sso'))

@app.route('/callback')
def auth_callback():
    """Handle Microsoft SSO callback with enhanced debugging"""
    try:
        print(" CALLBACK ROUTE ACCESSED!")
        print(f" Full callback URL: {request.url}")
        print(f" Request args: {dict(request.args)}")
        print(f" Session keys: {list(session.keys())}")
        print(f" REDIRECT_URI configured: {REDIRECT_URI}")
        
        # Check for errors first
        error = request.args.get('error')
        if error:
            error_description = request.args.get('error_description', 'Unknown error')
            print(f" OAuth error: {error} - {error_description}")
            flash(f"Authentication failed: {error_description}")
            return redirect(url_for('login_sso'))
        
        # Check for authorization code
        code = request.args.get('code')
        if not code:
            print(" No authorization code received")
            flash("No authorization code received from Microsoft.")
            return redirect(url_for('login_sso'))
        
        print(f" Received authorization code: {code[:20]}...")
        
        oauth_session = OAuth2Session(
            CLIENT_ID,
            redirect_uri=REDIRECT_URI,
            scope=SCOPES
        )

        print(" Fetching token...")
        token = oauth_session.fetch_token(
            TOKEN_URL,
            client_id=CLIENT_ID,
            client_secret=CLIENT_SECRET,
            authorization_response=request.url
        )

        access_token = token.get("access_token")
        print(f" Got access token: {access_token[:20] if access_token else 'None'}...")

        if not access_token:
            print(" No access token received")
            flash("Failed to get access token from Microsoft.")
            return redirect(url_for('login_sso'))

        # Get user profile from Microsoft Graph
        print(" Calling Microsoft Graph API...")
        graph_resp = requests.get(
            "https://graph.microsoft.com/v1.0/me",
            headers={"Authorization": f"Bearer {access_token}"}
        )
        
        print(f" Graph API status: {graph_resp.status_code}")
        
        if graph_resp.status_code != 200:
            print(f" Graph API error: {graph_resp.text}")
            flash("Failed to get user information from Microsoft.")
            return redirect(url_for('login_sso'))

        user_info = graph_resp.json()
        email = user_info.get("mail") or user_info.get("userPrincipalName")
        display_name = user_info.get("displayName", "")
        
        print(f" User info - Email: {email}, Name: {display_name}")

        if not email:
            print(" No email in user info")
            flash("Could not retrieve email from Microsoft account.")
            return redirect(url_for('login_sso'))

        # Check if user exists in your database
        print(f" Checking database for email: {email}")
        
        try:
            user_df = run_query("SELECT username, role, name FROM users WHERE email = ? AND status = 'Active'", (email,))
            print(f" Email lookup result: {len(user_df)} users found")
        except Exception as db_error:
            print(f" Database email lookup failed: {db_error}")
            username_part = email.split('@')[0]
            print(f" Trying username fallback: {username_part}")
            user_df = run_query("SELECT username, role, name FROM users WHERE username = ? AND status = 'Active'", (username_part,))
            print(f" Username lookup result: {len(user_df)} users found")
        
        if user_df.empty:
            print(f" No user found for email: {email}")
            flash(f"Access denied. Email {email} is not registered in the system. Please contact your administrator.")
            return redirect(url_for('login_sso'))

        # User exists, log them in
        user_record = user_df.iloc[0]
        session['username'] = user_record['username']
        session['role'] = user_record['role']
        session['user_email'] = email
        session['user_display_name'] = display_name
        session['user_info'] = user_info
        session['access_token'] = access_token

        print(f" Login successful for: {user_record['username']} ({user_record['role']})")
        flash(f"Welcome {display_name} ({user_record['role']})")
        return redirect(url_for('dashboard'))

    except Exception as e:
        print(f" Callback error: {str(e)}")
        import traceback
        print(f" Full traceback: {traceback.format_exc()}")
        flash(f"Authentication error: {str(e)}")
        return redirect(url_for('login_sso'))

@app.route('/auth/manual', methods=['POST'])
def auth_manual():
    """Handle manual login (fallback)"""
    print(" Manual login attempt")
    username = request.form.get('username')
    password = request.form.get('password')
    
    if not username or not password:
        flash("Username and password are required.")
        return redirect(url_for('login_sso'))

    df = run_query("SELECT role, email, name FROM users WHERE username = ? AND password = ? AND status = 'Active'", (username, password))
    
    if not df.empty:
        session['username'] = username
        session['role'] = df.iloc[0]['role']
        session['user_email'] = df.iloc[0].get('email', '')
        session['user_display_name'] = df.iloc[0].get('name', username)
        flash(f"Welcome {username} ({session['role']})")
        return redirect(url_for('dashboard'))
    else:
        flash("Invalid credentials or account is inactive.")
        return redirect(url_for('login_sso'))

@app.route('/logout')
def logout():
    """Logout and clear session"""
    session.clear()
    flash("You have been logged out successfully.")
    return redirect(url_for('login_sso'))

# Debug routes for testing
@app.route('/debug/test')
def debug_test():
    """Test route to verify Flask is working"""
    return f"""
    <h1> Flask App is Working!</h1>
    <p><strong>App Title:</strong> {APP_TITLE}</p>
    <p><strong>Current Time:</strong> {datetime.now()}</p>
    <p><strong>Redirect URI:</strong> {REDIRECT_URI}</p>
    <p><strong>Client ID:</strong> {CLIENT_ID[:10] if CLIENT_ID else 'NOT SET'}...</p>
    <p><a href="/login_sso">Go to Login</a></p>
    <p><a href="/debug/routes">View All Routes</a></p>
    """

@app.route('/debug/routes')
def debug_routes():
    """Debug: Show all available routes"""
    routes = []
    for rule in app.url_map.iter_rules():
        routes.append(f"<li><strong>{rule.endpoint}</strong>: {rule.rule} [{','.join(rule.methods)}]</li>")
    return f"<h2>Available Routes:</h2><ul>{''.join(routes)}</ul>"

@app.route('/reset_password', methods=['POST'])
def reset_password():
    """Self-service password reset - user can reset their own password"""
    try:
        username = request.form.get('username', '').strip()
        new_password = request.form.get('new_password', '').strip()
        
        if not username or not new_password:
            return jsonify({'success': False, 'message': 'Username and new password are required.'})
        
        if len(new_password) < 6:
            return jsonify({'success': False, 'message': 'Password must be at least 6 characters long.'})
        
        # Check if user exists and is active
        user_check = run_query("""
            SELECT username, name, email, status FROM users 
            WHERE username = ? AND status = 'Active'
        """, (username,))
        
        if user_check.empty:
            return jsonify({'success': False, 'message': 'Username not found or account is inactive.'})
        
        # Update the password
        ok = run_exec("""
            UPDATE users 
            SET password = ? 
            WHERE username = ? AND status = 'Active'
        """, (new_password, username))
        
        if ok:
            print(f" Password reset successful for user: {username}")
            return jsonify({'success': True, 'message': 'Password reset successfully!'})
        else:
            return jsonify({'success': False, 'message': 'Failed to update password. Please try again.'})
            
    except Exception as e:
        print(f" Password reset error: {str(e)}")
        return jsonify({'success': False, 'message': 'An error occurred during password reset.'})



# --------------------
# Dashboard Route
# --------------------
# In your dashboard route, find this section and update it:
 
@app.route('/dashboard', methods=['GET', 'POST'])
def dashboard():
    if 'username' not in session:
        return redirect(url_for('login_sso'))
    user = session['username']
    role = session['role']
    # Check if user is an RM regardless of their primary role
    direct_reports = get_direct_reports(user)
    is_rm = len(direct_reports) > 0
    # ENHANCED routing logic
    if role == 'Manager':
        return view_manager(user)
    elif role == 'Hr & Finance Controller':
        return view_hr_finance(user)
    elif role == 'Finance Manager':
        return view_lead(user)
    elif role in ('Rm', 'Employee'):
        return view_employee(user)
    # UPDATED: Include HR Intern with regular Intern
    elif role in ('Intern', 'HR Intern'):
        print(f"DEBUG: {role} {user} getting intern view")
        return view_intern(user)
    elif role in ('Admin Manager', 'Lead Staffing Specialist'):
        return view_admin_manager(user)
    elif role == 'Lead':
        return view_lead(user)
    elif role == 'SAP Consultant':
        if is_rm:
            return view_employee(user)
        else:
            return view_employee(user)
    elif role == 'BDE Manager':
        if is_rm:
            print(f"DEBUG: BDE Manager {user} has {len(direct_reports)} direct reports - giving RM view")
            return view_employee(user)
        else:
            print(f"DEBUG: BDE Manager {user} has no direct reports - giving employee view")
            return view_employee(user)
    elif role in ('Product Owner', 'Contractor'):
        return view_employee(user)
    # NEW: Handle Jr HR Executive
    elif role == 'Jr HR Executive':
        print(f"DEBUG: Jr HR Executive {user} getting employee view with HR context")
        return view_employee(user)  # Could create special HR employee view later
    else:
        flash(f"Role '{role}' not specifically mapped, showing employee view.")
        return view_employee(user)


    

    # Manager View Function - COMPLETE
# --------------------
def view_manager(user):
    """Manager dashboard view - ROLE BASED with REAL-TIME BUDGET UPDATES"""
    
    # Get user role and permissions
    user_role = session.get('role', '')
    has_company_access = has_company_wide_access(user)
    is_senior_manager = user_role in ['Manager', 'Admin Manager']
    
    # REAL-TIME BUDGET CALCULATIONS (same as HR Finance view)
    try:
        total_budget_df = run_query("SELECT total_budget FROM company_budget WHERE id = 1")
        if not total_budget_df.empty and len(total_budget_df) > 0:
            total_company_budget = float(total_budget_df['total_budget'].iloc[0])
        else:
            total_company_budget = 50000000.0
    except Exception as e:
        print(f" Budget retrieval error: {e}")
        total_company_budget = 50000000.0

    # Calculate ONLY PROJECT allocations (exclude salary/asset projects)
    try:
        project_allocated_df = run_query("""
            SELECT COALESCE(SUM(CAST(budget_amount AS DECIMAL(18,2))), 0) as allocated 
            FROM projects 
            WHERE hr_approval_status = 'Approved' 
            AND budget_amount IS NOT NULL
            AND CAST(budget_amount AS DECIMAL(18,2)) > 0
            AND project_name NOT LIKE 'Salary%'
            AND project_name NOT LIKE 'Asset Purchase%'
        """)
        
        project_allocated = float(project_allocated_df['allocated'].iloc[0]) if not project_allocated_df.empty else 0.0
        
    except Exception as e:
        print(f" Project allocation calculation error: {e}")
        project_allocated = 0.0

    # Calculate PAYROLL & ASSET allocations separately
    try:
        # Current payroll costs
        payroll_df = run_query("""
            SELECT COALESCE(SUM(CAST(yearly_salary AS DECIMAL(18,2))), 0) as total_payroll
            FROM users 
            WHERE status = 'Active' AND yearly_salary IS NOT NULL
        """)
        current_payroll = float(payroll_df['total_payroll'].iloc[0]) if not payroll_df.empty else 0.0

        # Asset purchases (approved asset requests)  
        asset_allocated_df = run_query("""
            SELECT COALESCE(SUM(CAST(amount AS DECIMAL(18,2))), 0) as asset_total
            FROM asset_requests 
            WHERE status = 'Approved'
        """)
        asset_allocated = float(asset_allocated_df['asset_total'].iloc[0]) if not asset_allocated_df.empty else 0.0

        # Total payroll & asset allocation
        payroll_asset_allocated = current_payroll + asset_allocated
        
    except Exception as e:
        print(f" Payroll & Asset calculation error: {e}")
        current_payroll = 0.0
        asset_allocated = 0.0
        payroll_asset_allocated = 0.0

    # Calculate remaining budget CORRECTLY (SAME AS HR FINANCE)
    remaining_company_budget = total_company_budget - project_allocated - payroll_asset_allocated
    
    print(f" MANAGER VIEW BUDGET CALCULATION:")
    print(f"   Total Budget: ₹{total_company_budget:,.2f}")
    print(f"   Project Allocations: ₹{project_allocated:,.2f}")
    print(f"   Payroll & Asset Allocations: ₹{payroll_asset_allocated:,.2f}")
    print(f"   Remaining Available: ₹{remaining_company_budget:,.2f}")

    # Get form filters
    if request.method == 'POST':
        team_start = request.form.get('team_start', '')
        team_end = request.form.get('team_end', '')
        team_user = request.form.get('team_user', '')
        team_proj = request.form.get('team_proj', '')
        team_desc = request.form.get('team_desc', '')
        
        leave_start = request.form.get('leave_start', '')
        leave_end = request.form.get('leave_end', '')
        leave_user = request.form.get('leave_user', '')
        leave_type = request.form.get('leave_type', '')
        leave_desc = request.form.get('leave_desc', '')
    else:
        team_start = request.args.get('team_start', '')
        team_end = request.args.get('team_end', '')
        team_user = request.args.get('team_user', '')
        team_proj = request.args.get('team_proj', '')
        team_desc = request.args.get('team_desc', '')
        
        leave_start = request.args.get('leave_start', '')
        leave_end = request.args.get('leave_end', '')
        leave_user = request.args.get('leave_user', '')
        leave_type = request.args.get('leave_type', '')
        leave_desc = request.args.get('leave_desc', '')

    # Get team members
    direct_team = get_direct_reports(user)
    all_team = get_all_reports_recursive(user)
    is_rm = len(direct_team) > 0 or has_company_access

    # Get manager's projects (EXCLUDING SALARY/ASSET PROJECTS)
    my_projects = run_query("""
        SELECT project_id, project_name, description, created_on, end_date, status, 
               cost_center, budget_amount, hr_approval_status, created_by
        FROM projects 
        WHERE (created_by = ? OR hr_approval_status = 'Approved')
        AND project_name NOT LIKE 'Salary Increase%'
        AND project_name NOT LIKE 'Asset Purchase%'
        ORDER BY created_on DESC
    """, (user,))

    # Get all employees for project assignment
    all_employees = run_query("""
            SELECT username, role, name FROM users 
            WHERE status = 'Active'
            ORDER BY role, COALESCE(name, username)
        """)

    # Get approved projects (EXCLUDING SALARY/ASSET PROJECTS)
    all_projects = run_query("""
    SELECT project_id, project_name, created_by, cost_center, description, 
           hr_approval_status, budget_amount, end_date, created_on
    FROM projects
    WHERE project_name NOT LIKE 'Salary%'
    AND project_name NOT LIKE 'Asset Purchase%'
    ORDER BY created_on DESC
    """)

    # Get expenses (EXCLUDING SALARY/ASSET EXPENSES)
    # In view_manager function, update expenses query:
    expenses = run_query("""
    SELECT id, spent_by, project_name, category, 
           COALESCE(CAST(amount AS DECIMAL(18,2)), 0) as amount, 
           description, date, document_path
    FROM expenses
    WHERE spent_by = ? OR project_name IN (
        SELECT project_name FROM projects 
        WHERE (created_by = ? OR hr_approval_status = 'Approved')
        AND project_name NOT LIKE 'Salary Increase%'
        AND project_name NOT LIKE 'Asset Purchase%'
    )
    ORDER BY date DESC
""", (user, user))

# In view_hr_finance function, update expense queries similarly

    # Get budget data (EXCLUDING SALARY/ASSET PROJECTS)
    budgets_from_sabitha = run_query("""
        SELECT 
            p.project_name as budget_name,
            p.project_name,
            COALESCE(p.cost_center, 'General') as category,
            COALESCE(CAST(p.budget_amount AS DECIMAL(18,2)), 0) as amount,
            p.created_on as start_date,
            p.end_date as end_date,
            p.created_by,
            p.hr_approval_status as status,
            p.project_id
        FROM projects p
        WHERE p.hr_approval_status = 'Approved'
        AND COALESCE(CAST(p.budget_amount AS DECIMAL(18,2)), 0) > 0
        AND p.project_name NOT LIKE 'Salary Increase%'
        AND p.project_name NOT LIKE 'Asset Purchase%'
        ORDER BY p.created_on DESC
    """)

    # Get payroll history
    payroll_history = run_query("""
        SELECT u.username, u.name, u.role, 
               COALESCE(CAST(u.monthly_salary AS DECIMAL(18,2)), 0) as monthly_salary, 
               COALESCE(CAST(u.yearly_salary AS DECIMAL(18,2)), 0) as yearly_salary,
               COALESCE(ed.employment_type, 'Full-Time') as employment_type
        FROM users u
        LEFT JOIN employee_details ed ON u.username = ed.username
        WHERE u.status = 'Active'
        ORDER BY u.monthly_salary DESC
    """)

    # Initialize team-related variables
    pending_timesheets = pd.DataFrame()
    pending_leaves = pd.DataFrame()
    pending_rm_assignments = pd.DataFrame()
    approved_assets = pd.DataFrame()
    team_work_history = pd.DataFrame()
    team_leave_history = pd.DataFrame()
    all_employee_work_history = pd.DataFrame()
    all_employee_leave_history = pd.DataFrame()

    # Complete Budget Overview for company access users
    complete_budget_overview = {
        'projects': budgets_from_sabitha.to_dict('records') if not budgets_from_sabitha.empty else [],
        'payroll_total': current_payroll
    }

    # FOR COMPANY-WIDE ACCESS (Senior Managers)
    if has_company_access:
        # Get pending RM assignments for company-wide approval
        pending_rm_assignments = run_query("""
            SELECT id, assigned_by, assigned_to, project_name, task_desc, start_date, 
                due_date, assigned_on, manager_status, manager_approver,
                COALESCE(rm_rejection_reason, '') as rejection_reason
            FROM assigned_work 
            WHERE manager_status IN ('Pending', 'Approved', 'Rejected')
            ORDER BY assigned_on DESC
        """)


        # Get ALL asset requests
        approved_assets = run_query("""
    SELECT id, asset_type, quantity, amount, for_employee, description, 
           requested_by, requested_date, status, approved_by, approved_date, rejection_reason, document_path
    FROM asset_requests 
    WHERE status IN ('Approved', 'Rejected')
    ORDER BY 
        CASE WHEN status = 'Approved' THEN 1 ELSE 2 END,
        approved_date DESC, requested_date DESC
""")

        # Get ALL employee work history with filters
        all_work_query = """
            SELECT TOP 500 t.username, t.work_date, t.project_name, t.work_desc, t.hours, 
                   COALESCE(t.break_hours, 0) as break_hours,
                   CASE WHEN t.hours > 8 THEN t.hours - 8 ELSE 0 END AS overtime_hours,
                   t.rm_status, t.rm_rejection_reason, t.rm_approver,
                   t.start_time, t.end_time
            FROM timesheets t
            WHERE 1=1
        """
        all_work_params = []

        if team_start:
            all_work_query += " AND t.work_date >= ?"
            all_work_params.append(team_start)
        if team_end:
            all_work_query += " AND t.work_date <= ?"
            all_work_params.append(team_end)
        if team_user:
            all_work_query += " AND t.username LIKE ?"
            all_work_params.append(f"%{team_user}%")
        if team_proj:
            all_work_query += " AND t.project_name LIKE ?"
            all_work_params.append(f"%{team_proj}%")
        if team_desc:
            all_work_query += " AND t.work_desc LIKE ?"
            all_work_params.append(f"%{team_desc}%")

        all_work_query += " ORDER BY t.work_date DESC, t.id DESC"
        all_employee_work_history = run_query(all_work_query, tuple(all_work_params))

        # Get ALL employee leave history with filters
        all_leave_query = """
            SELECT TOP 500 l.username, l.start_date, l.end_date, l.leave_type, l.description, 
                   l.rm_status, l.rm_rejection_reason, l.rm_approver, 
                   l.cancellation_requested, l.cancellation_status,
                   DATEDIFF(day, l.start_date, l.end_date) + 1 as duration_days
            FROM leaves l
            WHERE 1=1
        """
        all_leave_params = []

        if leave_start:
            all_leave_query += " AND l.start_date >= ?"
            all_leave_params.append(leave_start)
        if leave_end:
            all_leave_query += " AND l.end_date <= ?"
            all_leave_params.append(leave_end)
        if leave_user:
            all_leave_query += " AND l.username LIKE ?"
            all_leave_params.append(f"%{leave_user}%")
        if leave_type:
            all_leave_query += " AND l.leave_type LIKE ?"
            all_leave_params.append(f"%{leave_type}%")
        if leave_desc:
            all_leave_query += " AND l.description LIKE ?"
            all_leave_params.append(f"%{leave_desc}%")

        all_leave_query += " ORDER BY l.start_date DESC"
        all_employee_leave_history = run_query(all_leave_query, tuple(all_leave_params))

    # FOR REGULAR TEAM MANAGERS
    if is_rm and direct_team:
        placeholders = ",".join(["?"] * len(direct_team))

        # Get pending approvals for direct team
        pending_timesheets = run_query(f"""
            SELECT id, username, work_date, project_name, work_desc, hours, break_hours
            FROM timesheets
            WHERE username IN ({placeholders}) AND rm_status = 'Pending'
            ORDER BY work_date ASC
        """, tuple(direct_team))


        pending_leaves = run_query(f"""
    SELECT l.id, l.username, l.start_date, l.end_date, l.leave_type, l.description, 
           l.rm_status, l.health_document,
           CASE WHEN l.health_document IS NOT NULL THEN 1 ELSE 0 END as has_document,
           DATEDIFF(day, l.start_date, l.end_date) + 1 as duration_days,
           u.name as employee_name
    FROM leaves l
    JOIN users u ON l.username = u.username
    WHERE l.username IN ({placeholders}) AND l.rm_status = 'Pending'
    ORDER BY l.start_date ASC
""", tuple(direct_team))

        # Get team history with filters
        work_query = f"""
            SELECT TOP 500 t.username, t.work_date, t.project_name, t.work_desc, t.hours, 
                   COALESCE(t.break_hours, 0) as break_hours,
                   CASE WHEN t.hours > 8 THEN t.hours - 8 ELSE 0 END AS overtime_hours,
                   t.rm_status, t.rm_rejection_reason, t.rm_approver,
                   t.start_time, t.end_time
            FROM timesheets t
            WHERE t.username IN ({placeholders})
        """
        work_params = list(direct_team)

        if team_start:
            work_query += " AND t.work_date >= ?"
            work_params.append(team_start)
        if team_end:
            work_query += " AND t.work_date <= ?"
            work_params.append(team_end)
        if team_user:
            work_query += " AND t.username LIKE ?"
            work_params.append(f"%{team_user}%")
        if team_proj:
            work_query += " AND t.project_name LIKE ?"
            work_params.append(f"%{team_proj}%")
        if team_desc:
            work_query += " AND t.work_desc LIKE ?"
            work_params.append(f"%{team_desc}%")

        work_query += " ORDER BY t.work_date DESC"
        team_work_history = run_query(work_query, tuple(work_params))

        # Team leave history with filters
        leave_query = f"""
            SELECT TOP 500 l.username, l.start_date, l.end_date, l.leave_type, l.description, 
                   l.rm_status, l.rm_rejection_reason, l.rm_approver,
                   l.cancellation_requested, l.cancellation_status,
                   DATEDIFF(day, l.start_date, l.end_date) + 1 as duration_days
            FROM leaves l
            WHERE l.username IN ({placeholders})
        """
        leave_params = list(direct_team)

        if leave_start:
            leave_query += " AND l.start_date >= ?"
            leave_params.append(leave_start)
        if leave_end:
            leave_query += " AND l.end_date <= ?"
            leave_params.append(leave_end)
        if leave_user:
            leave_query += " AND l.username LIKE ?"
            leave_params.append(f"%{leave_user}%")
        if leave_type:
            leave_query += " AND l.leave_type LIKE ?"
            leave_params.append(f"%{leave_type}%")
        if leave_desc:
            leave_query += " AND l.description LIKE ?"
            leave_params.append(f"%{leave_desc}%")

        leave_query += " ORDER BY l.start_date DESC"
        team_leave_history = run_query(leave_query, tuple(leave_params))

    # Calculate leave duration
    leave_records = pending_leaves.to_dict('records') if not pending_leaves.empty else []
    leave_records = calculate_leave_duration(leave_records)

    team_leave_records = team_leave_history.to_dict('records') if not team_leave_history.empty else []
    team_leave_records = calculate_leave_duration(team_leave_records)

    all_leave_records = all_employee_leave_history.to_dict('records') if not all_employee_leave_history.empty else []
    all_leave_records = calculate_leave_duration(all_leave_records)

    # Return template with ALL variables INCLUDING REAL-TIME BUDGET DATA
    return render_template('manager_dashboard.html',
        user=user,
        role=session['role'],
        today=date.today().isoformat(),
        has_company_access=has_company_access,
        is_senior_manager=is_senior_manager,
        is_rm=is_rm,
        
        # REAL-TIME BUDGET DATA (same as HR Finance)
        total_budget=float(total_company_budget),
        project_allocated=float(project_allocated),
        payroll_asset_allocated=float(payroll_asset_allocated),
        remaining_allocation=float(remaining_company_budget),  
        current_payroll=float(current_payroll),
        asset_allocated=float(asset_allocated),

        my_projects=my_projects.to_dict('records') if not my_projects.empty else [],
        all_employees=all_employees.to_dict('records') if not all_employees.empty else [],
        all_projects=all_projects.to_dict('records') if not all_projects.empty else [],
        expenses=expenses.to_dict('records') if not expenses.empty else [],
        budgets_from_sabitha=budgets_from_sabitha.to_dict('records') if not budgets_from_sabitha.empty else [],
        pending_timesheets=pending_timesheets.to_dict('records') if not pending_timesheets.empty else [],
        pending_leaves=leave_records,
        pending_rm_assignments=pending_rm_assignments.to_dict('records') if not pending_rm_assignments.empty else [],
        approved_assets=approved_assets.to_dict('records') if not approved_assets.empty else [],
        team_work_history=team_work_history.to_dict('records') if not team_work_history.empty else [],
        team_leave_history=team_leave_records,
        payroll_history=payroll_history.to_dict('records') if not payroll_history.empty else [],
        can_view_all_history=has_company_access,
        all_employee_work_history=all_employee_work_history.to_dict('records') if not all_employee_work_history.empty else [],
        all_employee_leave_history=all_leave_records,
        total_company_budget=float(total_company_budget),
        remaining_company_budget=float(remaining_company_budget),
        remaining_budget=float(remaining_company_budget),
        complete_budget_overview=complete_budget_overview,
        team_start=team_start,
        team_end=team_end,
        team_user=team_user,
        team_proj=team_proj,
        team_desc=team_desc,
        leave_start=leave_start,
        leave_end=leave_end,
        leave_user=leave_user,
        leave_type=leave_type,
        leave_desc=leave_desc
    )

# HR Finance View Function - COMPLETE
# --------------------
def view_hr_finance(user):
    """HR & Finance dashboard view with SEPARATED project and payroll/asset tracking"""
    try:
        # ========== GET ALL COMPANY EXPENSES ==========
        expenses = run_query("""
        SELECT 
            id, 
            spent_by, 
            project_name, 
            category, 
            COALESCE(CAST(amount AS DECIMAL(18,2)), 0) as amount, 
            description, 
            date, 
            document_path
        FROM expenses 
        ORDER BY date DESC, id DESC
        """)
        
        print(f"✅ HR Finance: Loaded {len(expenses)} total company expenses")
    except Exception as e:
            print(f"❌ Error loading expenses: {e}")
            expenses = pd.DataFrame()
    # STEP 1: Get total budget
    try:
        total_budget_df = run_query("SELECT total_budget FROM company_budget WHERE id = 1")
        if not total_budget_df.empty and len(total_budget_df) > 0:
            total_budget = float(total_budget_df['total_budget'].iloc[0])
        else:
            run_exec("""
                IF NOT EXISTS (SELECT * FROM company_budget WHERE id = 1)
                INSERT INTO [timesheet_db].[dbo]. [company_budget] (id, total_budget, updated_by, updated_on, reason)
                VALUES (1, 50000000, 'system', GETDATE(), 'Initial budget setup')
            """)
            total_budget = 50000000.0
    except Exception as e:
        print(f" Budget retrieval error: {e}")
        total_budget = 50000000.0

    # STEP 2: Calculate ONLY PROJECT allocations (exclude salary/asset projects)
    try:
        project_allocated_df = run_query("""
            SELECT COALESCE(SUM(CAST(budget_amount AS DECIMAL(18,2))), 0) as allocated 
            FROM projects 
            WHERE hr_approval_status = 'Approved' 
            AND budget_amount IS NOT NULL
            AND CAST(budget_amount AS DECIMAL(18,2)) > 0
            AND project_name NOT LIKE 'Salary%'
            AND project_name NOT LIKE 'Asset Purchase%'
        """)
        
        project_allocated = float(project_allocated_df['allocated'].iloc[0]) if not project_allocated_df.empty else 0.0
        
    except Exception as e:
        print(f" Project allocation calculation error: {e}")
        project_allocated = 0.0

    # STEP 3: Calculate PAYROLL & ASSET allocations separately
    try:
        # Current payroll costs
        payroll_df = run_query("""
            SELECT COALESCE(SUM(CAST(yearly_salary AS DECIMAL(18,2))), 0) as total_payroll
            FROM users 
            WHERE status = 'Active' AND yearly_salary IS NOT NULL
        """)
        current_payroll = float(payroll_df['total_payroll'].iloc[0]) if not payroll_df.empty else 0.0

        # Asset purchases (approved asset requests)  
        asset_allocated_df = run_query("""
            SELECT COALESCE(SUM(CAST(amount AS DECIMAL(18,2))), 0) as asset_total
            FROM asset_requests 
            WHERE status = 'Approved'
        """)
        asset_allocated = float(asset_allocated_df['asset_total'].iloc[0]) if not asset_allocated_df.empty else 0.0

        # Total payroll & asset allocation
        payroll_asset_allocated = current_payroll + asset_allocated
        
    except Exception as e:
        print(f" Payroll & Asset calculation error: {e}")
        current_payroll = 0.0
        asset_allocated = 0.0
        payroll_asset_allocated = 0.0

    # STEP 4: Calculate remaining budget CORRECTLY
    remaining_allocation = total_budget - project_allocated - payroll_asset_allocated
    
    print(f" HR FINANCE BUDGET CALCULATION:")
    print(f"   Total Budget: ₹{total_budget:,.2f}")
    print(f"   Project Allocations: ₹{project_allocated:,.2f}")
    print(f"   Payroll & Asset Allocations: ₹{payroll_asset_allocated:,.2f}")
    print(f"   Remaining Available: ₹{remaining_allocation:,.2f}")


    
    # CORRECTED Budget Summary query - ONLY actual projects
    try:
        budget_summary = run_query("""
            SELECT 
                p.project_name, 
                p.created_by,
                p.cost_center,
                p.created_on,
                CAST(p.budget_amount AS DECIMAL(18,2)) as total_budget,
                COALESCE(SUM(CAST(e.amount AS DECIMAL(18,2))), 0) as used_amount,
                CAST(p.budget_amount AS DECIMAL(18,2)) - COALESCE(SUM(CAST(e.amount AS DECIMAL(18,2))), 0) as remaining
            FROM projects p
            LEFT JOIN expenses e ON p.project_name = e.project_name
            WHERE p.hr_approval_status = 'Approved' 
            AND p.budget_amount IS NOT NULL
            AND CAST(p.budget_amount AS DECIMAL(18,2)) > 0
            AND p.project_name NOT LIKE 'Salary%'
            AND p.project_name NOT LIKE 'Asset Purchase%'
            GROUP BY p.project_name, p.created_by, p.cost_center, p.budget_amount, p.created_on
            ORDER BY p.created_on DESC
        """)
    except Exception as e:
        print(f"Budget summary error: {e}")
        budget_summary = pd.DataFrame()

    # All Expenses
    try:
        expense_summary = run_query("""
            SELECT TOP 100 id, spent_by, project_name, category, 
                COALESCE(CAST(amount AS DECIMAL(18,2)), 0) as amount, 
                description, date, document_path
            FROM expenses
            ORDER BY date DESC
        """)
    except Exception as e:
        expense_summary = pd.DataFrame()

    # Projects needing budget allocation (already approved)
    try:
        projects_needing_budget = run_query("""
            SELECT project_id, project_name, created_by, description, created_on, end_date, cost_center
            FROM projects
            WHERE hr_approval_status = 'Approved'
            AND (budget_amount IS NULL OR budget_amount = 0)
            AND project_name NOT LIKE 'Salary%'
            AND project_name NOT LIKE 'Asset Purchase%'
            ORDER BY created_on DESC
        """)
    except Exception as e:
        projects_needing_budget = pd.DataFrame()

    # Projects pending HR approval
    try:
        pending_projects = run_query("""
            SELECT project_id, project_name, created_by, description, created_on, end_date, cost_center
            FROM projects
            WHERE hr_approval_status = 'Pending'
            AND project_name NOT LIKE 'Salary%'
            AND project_name NOT LIKE 'Asset Purchase%'
            ORDER BY created_on DESC
        """)
    except Exception as e:
        pending_projects = pd.DataFrame()

    # All Projects (ONLY real projects for management view)
    try:
        all_projects = run_query("""
            SELECT project_id, project_name, created_by, cost_center, description, 
                   hr_approval_status, budget_amount, end_date, created_on
            FROM projects
            WHERE project_name NOT LIKE 'Salary%'
            AND project_name NOT LIKE 'Asset Purchase%'
            ORDER BY created_on DESC
        """)
    except Exception as e:
        all_projects = pd.DataFrame()

    # Employee Salary Information
    try:
        employee_salaries = run_query("""
            SELECT username, name, role,
                   CAST(COALESCE(monthly_salary, 0) AS DECIMAL(18,2)) as monthly_salary, 
                   CAST(COALESCE(yearly_salary, 0) AS DECIMAL(18,2)) as yearly_salary
            FROM users
            WHERE status = 'Active'
            ORDER BY yearly_salary DESC
        """)
        
        total_monthly_payroll = sum(float(s['monthly_salary'] or 0) for s in employee_salaries.to_dict('records'))
        total_annual_payroll = sum(float(s['yearly_salary'] or 0) for s in employee_salaries.to_dict('records'))
    except Exception as e:
        employee_salaries = pd.DataFrame()
        total_monthly_payroll = 0.0
        total_annual_payroll = 0.0

    # Employee Work Records
    try:
     employee_timesheets = run_query("""
        SELECT TOP 1000 id, username, work_date, project_name, work_desc, hours, 
               COALESCE(break_hours, 0) as break_hours, rm_status,
               CASE WHEN hours > 8 THEN hours - 8 ELSE 0 END as overtime_hours,
               MONTH(work_date) as work_month, YEAR(work_date) as work_year,
               start_time, end_time
        FROM timesheets
        ORDER BY work_date DESC
    """)

    except Exception as e:
        employee_timesheets = pd.DataFrame()

    # Employee Leave Records
    try:
        employee_leaves = run_query("""
            SELECT TOP 1000 id, username, start_date, end_date, leave_type, description, rm_status,
                   COALESCE(cancellation_requested, 0) as cancellation_requested, 
                   cancellation_status,
                   MONTH(start_date) as leave_month, YEAR(start_date) as leave_year
            FROM leaves
            ORDER BY start_date DESC
        """)
    except Exception as e:
        employee_leaves = pd.DataFrame()

    # Asset Requests
    try:
        asset_requests_raw = run_query("""
                  SELECT id, asset_type, quantity, 
                CAST(COALESCE(amount, 0) AS DECIMAL(18,2)) as amount, 
                for_employee, description, requested_by, requested_date, status, 
                rejection_reason, approved_by, approved_date, document_path
            FROM asset_requests
            ORDER BY 
                CASE 
                    WHEN status = 'Pending' THEN 1 
                    WHEN status = 'Approved' THEN 2 
                    ELSE 3 
                END,
                requested_date DESC
        """)
        
        if not asset_requests_raw.empty:
            asset_records = asset_requests_raw.to_dict('records')
            for record in asset_records:
                try:
                    record['amount'] = float(record['amount']) if record['amount'] is not None else 0.0
                except (ValueError, TypeError):
                    record['amount'] = 0.0
            asset_requests = pd.DataFrame(asset_records)
        else:
            asset_requests = pd.DataFrame()
            
    except Exception as e:
        print(f"Asset requests error: {e}")
        asset_requests = pd.DataFrame()

    # Team Approvals - FIXED: Only show team members' work/leave
    try:
        # Get direct reports for HR Finance Controller
        team_members = get_direct_reports(user)
        
        # If no direct reports found, try alternative methods to find team
        if not team_members:
            # Try alternative method: Check report table with different column names
            team_query = run_query("""
                SELECT username FROM report WHERE rm = ? OR manager = ?
            """, (user, user))
            
            if not team_query.empty:
                team_members = team_query['username'].tolist()
                print(f"DEBUG: Alternative method found team members: {team_members}")
        
        # Initialize empty DataFrames
        pending_team_work = pd.DataFrame()
        pending_team_leaves = pd.DataFrame()
        
        # ONLY get pending items IF there are actual team members
        if team_members:
            placeholders = ",".join(["?"] * len(team_members))
            
            # Get pending work for team members ONLY
            pending_team_work = run_query(f"""
                SELECT id, username, work_date, project_name, work_desc, hours, 
                    COALESCE(break_hours, 0) as break_hours
                FROM timesheets 
                WHERE username IN ({placeholders}) AND rm_status = 'Pending'
                ORDER BY work_date ASC
            """, tuple(team_members))
            
            # Get pending leave for team members ONLY
            pending_team_leaves = run_query(f"""
                SELECT l.id, l.username, l.start_date, l.end_date, l.leave_type, l.description, 
                    l.rm_status, l.health_document,
                    CASE WHEN l.health_document IS NOT NULL THEN 1 ELSE 0 END as has_document,
                    DATEDIFF(day, l.start_date, l.end_date) + 1 as duration_days,
                    u.name as employee_name
                FROM leaves l
                JOIN users u ON l.username = u.username
                WHERE l.username IN ({placeholders}) AND l.rm_status = 'Pending'
                ORDER BY l.start_date ASC
            """, tuple(team_members))
            print(f"DEBUG: Found {len(pending_team_work)} pending work items and {len(pending_team_leaves)} pending leave items for team: {team_members}")
        else:
            print(f"DEBUG: HR Finance user {user} has no team members reporting to them")

    except Exception as e:
        print(f"Team approvals error: {e}")
        pending_team_work = pd.DataFrame()
        pending_team_leaves = pd.DataFrame()
        team_members = []
    # NEW: Get all employees for work assignment
    try:
        all_employees = run_query("""
            SELECT username, role, name FROM users 
            WHERE status = 'Active'
            ORDER BY username
        """)
    except Exception as e:
        all_employees = pd.DataFrame()

    # NEW: Get all work assignments
    try:
        # Update the work_assignments query
        work_assignments = run_query("""
            SELECT TOP 500 assigned_by, assigned_to, project_name, task_desc as work_description, 
                start_date, due_date, manager_status as status
            FROM assigned_work
            ORDER BY due_date ASC, start_date ASC
        """)

    except Exception as e:
        work_assignments = pd.DataFrame()
    
    
    return render_template('hr_finance.html',
        user=user,
        role=session['role'],
        today=date.today().isoformat(),
        
        # UPDATED Financial Overview with separated allocations
        total_budget=float(total_budget),
        project_allocated=float(project_allocated),  # Only real projects
        payroll_asset_allocated=float(payroll_asset_allocated),  # Payroll + Assets
        remaining_allocation=float(remaining_allocation),
        current_payroll=float(current_payroll),
        asset_allocated=float(asset_allocated),
        expenses=expenses.to_dict('records') if not expenses.empty else [],
        expensesummary=expenses.to_dict('records') if not expenses.empty else [],
        
        # Data for tables (ONLY real projects)
        budget_summary=budget_summary.to_dict('records') if not budget_summary.empty else [],
        expense_summary=expense_summary.to_dict('records') if not expense_summary.empty else [],
        pending_projects=pending_projects.to_dict('records') if not pending_projects.empty else [],
        all_projects=all_projects.to_dict('records') if not all_projects.empty else [],
        
        # Payroll data
        employee_salaries=employee_salaries.to_dict('records') if not employee_salaries.empty else [],
        total_monthly_payroll=float(total_monthly_payroll),
        total_annual_payroll=float(total_annual_payroll),
        
        # Employee records
        employee_timesheets=employee_timesheets.to_dict('records') if not employee_timesheets.empty else [],
        employee_leaves=employee_leaves.to_dict('records') if not employee_leaves.empty else [],
        projects_needing_budget=projects_needing_budget.to_dict('records') if not projects_needing_budget.empty else [],
        
        # Asset requests and team approvals
        asset_requests=asset_requests.to_dict('records') if not asset_requests.empty else [],
        pending_team_work=pending_team_work.to_dict('records') if not pending_team_work.empty else [],
        pending_team_leaves=pending_team_leaves.to_dict('records') if not pending_team_leaves.empty else [],
        has_team=len(team_members) > 0,
        team_members=team_members,
        
        # NEW: Work assignment data
        all_employees=all_employees.to_dict('records') if not all_employees.empty else [],
        work_assignments=work_assignments.to_dict('records') if not work_assignments.empty else [],
       
    )

# Lead View Function - COMPLETE
# --------------------
def view_lead(user):
    """Lead dashboard with complete oversight of all company data - ENHANCED"""
    
    # STEP 1: Get total budget (same as HR Finance)
    try:
        total_budget_df = run_query("SELECT total_budget FROM company_budget WHERE id = 1")
        if not total_budget_df.empty and len(total_budget_df) > 0:
            total_company_budget = float(total_budget_df['total_budget'].iloc[0])
        else:
            run_exec("""
                IF NOT EXISTS (SELECT * FROM company_budget WHERE id = 1)
                INSERT INTO [timesheet_db].[dbo]. [company_budget] (id, total_budget, updated_by, updated_on, reason)
                VALUES (1, 50000000, 'system', GETDATE(), 'Initial budget setup')
            """)
            total_company_budget = 50000000.0
    except Exception as e:
        print(f" Budget retrieval error: {e}")
        total_company_budget = 50000000.0

    # STEP 2: Calculate ONLY PROJECT allocations (exclude salary/asset projects)
    try:
        project_allocated_df = run_query("""
            SELECT COALESCE(SUM(CAST(budget_amount AS DECIMAL(18,2))), 0) as allocated 
            FROM projects 
            WHERE hr_approval_status = 'Approved' 
            AND budget_amount IS NOT NULL
            AND CAST(budget_amount AS DECIMAL(18,2)) > 0
            AND project_name NOT LIKE 'Salary%'
            AND project_name NOT LIKE 'Asset Purchase%'
        """)
        
        project_allocated = float(project_allocated_df['allocated'].iloc[0]) if not project_allocated_df.empty else 0.0
        
    except Exception as e:
        print(f" Project allocation calculation error: {e}")
        project_allocated = 0.0

    # STEP 3: Calculate PAYROLL & ASSET allocations separately
    try:
        # Current payroll costs
        payroll_df = run_query("""
            SELECT COALESCE(SUM(CAST(yearly_salary AS DECIMAL(18,2))), 0) as total_payroll
            FROM users 
            WHERE status = 'Active' AND yearly_salary IS NOT NULL
        """)
        current_payroll = float(payroll_df['total_payroll'].iloc[0]) if not payroll_df.empty else 0.0

        # Asset purchases (approved asset requests)  
        asset_allocated_df = run_query("""
            SELECT COALESCE(SUM(CAST(amount AS DECIMAL(18,2))), 0) as asset_total
            FROM asset_requests 
            WHERE status = 'Approved'
        """)
        asset_allocated = float(asset_allocated_df['asset_total'].iloc[0]) if not asset_allocated_df.empty else 0.0

        # Total payroll & asset allocation
        payroll_asset_allocated = current_payroll + asset_allocated
        
    except Exception as e:
        print(f" Payroll & Asset calculation error: {e}")
        current_payroll = 0.0
        asset_allocated = 0.0
        payroll_asset_allocated = 0.0

    # STEP 4: Calculate remaining budget CORRECTLY
    remaining_company_budget = total_company_budget - project_allocated - payroll_asset_allocated
    
    print(f" LEAD VIEW BUDGET CALCULATION:")
    print(f"   Total Budget: ₹{total_company_budget:,.2f}")
    print(f"   Project Allocations: ₹{project_allocated:,.2f}")
    print(f"   Payroll & Asset Allocations: ₹{payroll_asset_allocated:,.2f}")
    print(f"   Remaining Available: ₹{remaining_company_budget:,.2f}")
    
    # Get form filters for work history
    work_start = request.args.get('work_start', '').strip()
    work_end = request.args.get('work_end', '').strip()
    work_user = request.args.get('work_user', '').strip()
    work_project = request.args.get('work_project', '').strip()
    work_status = request.args.get('work_status', '').strip()
    
    # Get form filters for leave history
    leave_start = request.args.get('leave_start', '').strip()
    leave_end = request.args.get('leave_end', '').strip()
    leave_user = request.args.get('leave_user', '').strip()
    leave_type = request.args.get('leave_type', '').strip()
    leave_status = request.args.get('leave_status', '').strip()
    
    # Get all projects with budget allocations (EXCLUDE SALARY PROJECTS)
    my_projects = run_query("""
        SELECT p.project_id, p.project_name, p.description, p.created_by, p.created_on, p.end_date,
               p.hr_approval_status, p.cost_center, 
               COALESCE(CAST(p.budget_amount AS DECIMAL(18,2)), 0) as budget_amount, p.status,
               COALESCE(e.spent_amount, 0) as spent_amount,
               (COALESCE(CAST(p.budget_amount AS DECIMAL(18,2)), 0) - COALESCE(e.spent_amount, 0)) as remaining_amount
        FROM projects p
        LEFT JOIN (
            SELECT project_name, SUM(CAST(amount AS DECIMAL(18,2))) as spent_amount
            FROM expenses
            GROUP BY project_name
        ) e ON p.project_name = e.project_name
        WHERE p.project_name NOT LIKE 'Salary%'
        AND p.project_name NOT LIKE '%Salary%'
        AND p.project_name NOT LIKE 'Asset Purchase%'
        ORDER BY p.created_on DESC
    """)
    
    # Get budget summary for all approved projects (EXCLUDE SALARY)
    budget_summary = run_query("""
        SELECT p.project_name, p.cost_center, p.created_by,
               COALESCE(CAST(p.budget_amount AS DECIMAL(18,2)), 0) as total_budget,
               COALESCE(e.used_amount, 0) as used_amount,
               (COALESCE(CAST(p.budget_amount AS DECIMAL(18,2)), 0) - COALESCE(e.used_amount, 0)) as remaining
        FROM projects p
        LEFT JOIN (
            SELECT project_name, SUM(CAST(amount AS DECIMAL(18,2))) as used_amount
            FROM expenses
            GROUP BY project_name
        ) e ON p.project_name = e.project_name
        WHERE p.hr_approval_status = 'Approved'
        AND p.project_name NOT LIKE 'Salary%'
        AND p.project_name NOT LIKE '%Salary%'
        AND p.project_name NOT LIKE 'Asset Purchase%'
        AND COALESCE(CAST(p.budget_amount AS DECIMAL(18,2)), 0) > 0
        ORDER BY p.project_name
    """)
    
    # Get ALL expenses (EXCLUDE SALARY-RELATED)
    # In view_manager function, update expenses query:
    expenses = run_query("""
SELECT id, spent_by, project_name, category, 
       COALESCE(CAST(amount AS DECIMAL(18,2)), 0) as amount, 
       description, date, document_path
FROM expenses
WHERE (spent_by = ? OR project_name IN (
    SELECT project_name FROM projects 
    WHERE hr_approval_status = 'Approved'
    AND project_name NOT LIKE 'Salary Increase%'
    AND project_name NOT LIKE 'Asset Purchase%'
) OR project_name IS NULL OR project_name = '(non-project)')
ORDER BY date DESC
""", (user,))
    # Get ALL employee payroll data (monthly and yearly salaries)
    payment_rate_cards = run_query("""
        SELECT u.username, u.name, u.role, 
            COALESCE(CAST(u.monthly_salary AS DECIMAL(18,2)), 0) as monthly_salary, 
            COALESCE(CAST(u.yearly_salary AS DECIMAL(18,2)), 0) as yearly_salary
        FROM users u
        WHERE u.status = 'Active'
        ORDER BY u.monthly_salary DESC
    """)

    # Get ALL employee work history with filters
    work_base_query = """
        SELECT username, work_date, project_name, work_desc, hours, break_hours,
               CASE WHEN hours > 8 THEN hours - 8 ELSE 0 END AS overtime_hours,
               rm_status, rm_rejection_reason, rm_approver
        FROM timesheets 
        WHERE 1=1
    """
    work_params = []
    
    if work_start:
        work_base_query += " AND work_date >= ?"
        work_params.append(work_start)
    if work_end:
        work_base_query += " AND work_date <= ?"
        work_params.append(work_end)
    if work_user:
        work_base_query += " AND username LIKE ?"
        work_params.append(f"%{work_user}%")
    if work_project:
        work_base_query += " AND project_name LIKE ?"
        work_params.append(f"%{work_project}%")
    if work_status:
        work_base_query += " AND rm_status = ?"
        work_params.append(work_status)
    
    work_base_query += " ORDER BY work_date DESC"
    
    all_employee_work_history = run_query(work_base_query, tuple(work_params))
    
    # Get ALL employee leave history with filters
    leave_base_query = """
        SELECT username, start_date, end_date, leave_type, description, 
               rm_status, rm_rejection_reason, rm_approver, 
               cancellation_requested, cancellation_status,
               DATEDIFF(day, start_date, end_date) + 1 as duration_days
        FROM leaves 
        WHERE 1=1
    """
    leave_params = []
    
    if leave_start:
        leave_base_query += " AND start_date >= ?"
        leave_params.append(leave_start)
    if leave_end:
        leave_base_query += " AND end_date <= ?"
        leave_params.append(leave_end)
    if leave_user:
        leave_base_query += " AND username LIKE ?"
        leave_params.append(f"%{leave_user}%")
    if leave_type:
        leave_base_query += " AND leave_type = ?"
        leave_params.append(leave_type)
    if leave_status:
        leave_base_query += " AND rm_status = ?"
        leave_params.append(leave_status)
    
    leave_base_query += " ORDER BY start_date DESC"
    
    all_employee_leave_history = run_query(leave_base_query, tuple(leave_params))
    
    # Add this query to get all employees for work assignment
    try:
        all_employees = run_query("""
            SELECT username, role, name FROM users 
            WHERE status = 'Active'
            ORDER BY role, COALESCE(name, username)
        """)
    except Exception as e:
        print(f"All employees query error: {e}")
        all_employees = pd.DataFrame()

    # Get ALL work assignments
    work_assignments = run_query("""
        SELECT TOP 500 id, assigned_by, assigned_to, project_name, task_desc, 
               start_date, due_date, assigned_on, manager_status, rm_status,
               COALESCE(rm_rejection_reason, '') as rejection_reason
        FROM assigned_work
        ORDER BY assigned_on DESC
    """)
    
    # Get ALL asset requests
    asset_requests = run_query("""
    SELECT id, asset_type, quantity, 
           CAST(COALESCE(amount, 0) AS DECIMAL(18,2)) as amount, 
           for_employee, description, requested_by, requested_date, 
           status, approved_by, approved_date, rejection_reason, document_path
    FROM asset_requests
    ORDER BY 
        CASE 
            WHEN status = 'Pending' THEN 1 
            WHEN status = 'Approved' THEN 2 
            ELSE 3 
        END,
        requested_date DESC
""")
    # Get system requests
    system_requests = run_query("""
        SELECT TOP 50 id, requested_by, item, CAST(amount AS DECIMAL(18,2)) as amount, 
               description, date, status, reason
        FROM requests
        ORDER BY date DESC
    """)
    
    # Get pending leaves for subordinates (if any)
    direct_reports = get_direct_reports(user)
    pending_timesheets = pd.DataFrame()
    pending_leaves = pd.DataFrame()
    
    if direct_reports:
        placeholders = ",".join(["?"] * len(direct_reports))
        
        # Get pending work approvals for direct reports
        pending_timesheets = run_query(f"""
            SELECT t.id, t.username, t.work_date, t.project_name, t.work_desc, t.hours, 
                COALESCE(t.break_hours, 0) as break_hours, t.start_time, t.end_time,
                u.name as employee_name
            FROM timesheets t
            JOIN users u ON t.username = u.username
            WHERE t.username IN ({placeholders}) AND t.rm_status = 'Pending' AND t.rm_approver = ?
            ORDER BY t.work_date ASC
        """, tuple(direct_reports + [user]))
        
        # Get pending leave approvals for direct reports with document info
        pending_leaves = run_query(f"""
            SELECT l.id, l.username, l.start_date, l.end_date, l.leave_type, l.description, 
                l.rm_status, l.health_document,
                DATEDIFF(day, l.start_date, l.end_date) + 1 as duration_days,
                u.name as employee_name,
                CASE WHEN l.health_document IS NOT NULL THEN 1 ELSE 0 END as has_document
            FROM leaves l
            JOIN users u ON l.username = u.username
            WHERE l.username IN ({placeholders}) AND l.rm_status = 'Pending' AND l.rm_approver = ?
            ORDER BY l.start_date ASC
        """, tuple(direct_reports + [user]))

    
    # Calculate leave duration
    pending_leave_records = pending_leaves.to_dict('records') if not pending_leaves.empty else []
    pending_leave_records = calculate_leave_duration(pending_leave_records)

    leave_records = pending_leaves.to_dict('records') if not pending_leaves.empty else []
    leave_records = calculate_leave_duration(leave_records)
    
    all_leave_records = all_employee_leave_history.to_dict('records') if not all_employee_leave_history.empty else []
    all_leave_records = calculate_leave_duration(all_leave_records)
    
    # Calculate financial metrics (EXCLUDE SALARY PROJECTS)
    budget_records = budget_summary.to_dict('records') if not budget_summary.empty else []
    total_allocated_budget = sum(float(row.get('total_budget', 0) or 0) for row in budget_records)
    total_used_budget = sum(float(row.get('used_amount', 0) or 0) for row in budget_records)
    
    # Calculate payroll totals
    payroll_records = payment_rate_cards.to_dict('records') if not payment_rate_cards.empty else []
    total_monthly_payroll = sum(float(row.get('monthly_salary', 0) or 0) for row in payroll_records)
    total_yearly_payroll = sum(float(row.get('yearly_salary', 0) or 0) for row in payroll_records)
    
    # Generate budget alerts
    budget_alerts = []
    for project in budget_records:
        if project.get('total_budget') and project.get('used_amount'):
            usage_percent = (project['used_amount'] / project['total_budget']) * 100
            if usage_percent >= 80:
                budget_alerts.append({
                    'project': project['project_name'],
                    'usage_percent': usage_percent,
                    'remaining': project['remaining']
                })
    
    return render_template('lead.html',
        user=user,
        role=session['role'],
        all_employees=all_employees.to_dict('records') if not all_employees.empty else [],  
        today=date.today().isoformat(),
        
        # ENHANCED Financial Overview (same as HR Finance)
        total_budget=float(total_company_budget),
        project_allocated=float(project_allocated),
        payroll_asset_allocated=float(payroll_asset_allocated),
        remaining_allocation=float(remaining_company_budget),
        current_payroll=float(current_payroll),
        asset_allocated=float(asset_allocated),
        allocated=float(total_allocated_budget),
        
        # Project & Budget Data (NO SALARY PROJECTS)
        my_projects=my_projects.to_dict('records') if not my_projects.empty else [],
        budget_summary=budget_records,
        budget_alerts=budget_alerts,
        
        # Expense Data (EXCLUDING SALARY)
        expenses=expenses.to_dict('records') if not expenses.empty else [],
        
        # Payroll Data (ALL employees' monthly and yearly salaries)
        payment_rate_cards=payroll_records,
        total_monthly_payroll=float(total_monthly_payroll),
        total_yearly_payroll=float(total_yearly_payroll),
        
        # ALL Employee Work & Leave History with Filters
        all_employee_work_history=all_employee_work_history.to_dict('records') if not all_employee_work_history.empty else [],
        all_employee_leave_history=all_leave_records,
        
        # Work Assignments and Assets
        work_assignments=work_assignments.to_dict('records') if not work_assignments.empty else [],
        asset_requests=asset_requests.to_dict('records') if not asset_requests.empty else [],
        
        # System Data
        system_requests=system_requests.to_dict('records') if not system_requests.empty else [],
        
        # Pending approvals (if Lead has subordinates)
        direct_reports=direct_reports,
        has_team=len(direct_reports) > 0,
        pending_timesheets=pending_timesheets.to_dict('records') if not pending_timesheets.empty else [],
        pending_leaves=pending_leave_records,
        #pending_leaves=leave_records,
        
        # Filter values
        work_start=work_start,
        work_end=work_end,
        work_user=work_user,
        work_project=work_project,
        work_status=work_status,
        leave_start=leave_start,
        leave_end=leave_end,
        leave_user=leave_user,
        leave_type=leave_type,
        leave_status=leave_status
    )

# Update the view_employee function to fix team history filters
def view_employee(user):
    """Employee dashboard view - FIXED with proper team history filters and document access"""

  
    
    # Check if user is an RM
    direct_reports = get_direct_reports(user)
    all_team = get_all_reports_recursive(user)
    is_rm = len(direct_reports) > 0 or len(all_team) > 0

    # Get projects list
    projects_df = run_query("""
        SELECT project_name FROM projects 
        WHERE hr_approval_status = 'Approved' 
        AND project_name NOT LIKE 'Salary%'
        AND project_name NOT LIKE 'Asset Purchase%'
        ORDER BY project_name
    """)
    proj_list = ["(non-project)"] + projects_df["project_name"].astype(str).tolist() if not projects_df.empty else ["(non-project)"]
    
    # Get work assigned TO this user
    assigned_work_df = pd.DataFrame()
    try:
        assigned_work_df = run_query("""
            SELECT aw.id, aw.assigned_by, aw.project_name, aw.task_desc, aw.start_date, aw.due_date, 
                   aw.assigned_on, aw.rm_status,
                   CASE 
                       WHEN aw.due_date < GETDATE() AND aw.rm_status != 'Completed' THEN 'Overdue'
                       WHEN aw.due_date <= DATEADD(day, 3, GETDATE()) AND aw.rm_status != 'Completed' THEN 'Due Soon'
                       ELSE 'Active'
                   END as urgency_status,
                   u.name as assigned_by_name
            FROM assigned_work aw 
            LEFT JOIN users u ON aw.assigned_by = u.username
            WHERE aw.assigned_to = ? 
            ORDER BY 
                CASE WHEN aw.due_date < GETDATE() THEN 1 ELSE 2 END,
                aw.due_date ASC, aw.assigned_on DESC
        """, (user,))
    except Exception as e:
        print(f"Error fetching assigned work: {e}")
        assigned_work_df = pd.DataFrame()

    # Get work assigned BY this user (if RM)
    my_assigned_work_df = pd.DataFrame()
    if is_rm:
        try:
            my_assigned_work_df = run_query("""
                SELECT 
                    aw.id, aw.assigned_to, aw.task_desc, aw.project_name, aw.start_date, aw.due_date,
                    aw.assigned_on, aw.rm_status,
                    u.name as assigned_to_name,
                    CASE 
                        WHEN aw.due_date < GETDATE() AND aw.rm_status != 'Completed' THEN 'Overdue'
                        WHEN aw.due_date <= DATEADD(day, 3, GETDATE()) AND aw.rm_status != 'Completed' THEN 'Due Soon'
                        ELSE 'Active'
                    END as urgency_status
                FROM assigned_work aw
                LEFT JOIN users u ON aw.assigned_to = u.username
                WHERE aw.assigned_by = ?
                ORDER BY aw.assigned_on DESC, aw.due_date ASC
            """, (user,))
        except Exception as e:
            print(f"Error fetching my assigned work: {e}")
            my_assigned_work_df = pd.DataFrame()

    # Get personal work history
    work_history_df = run_query("""
        SELECT id, work_date, project_name, work_desc, hours, break_hours, start_time, end_time,
               CASE WHEN hours > 8 THEN hours - 8 ELSE 0 END AS overtime_hours,
               rm_status, rm_rejection_reason, rm_approver
        FROM timesheets 
        WHERE username = ? 
        ORDER BY work_date DESC, id DESC
    """, (user,))
    
    # Get personal leave history
    leaves_df = run_query("""
        SELECT id, start_date, end_date, leave_type, description, rm_status, rm_rejection_reason, 
               rm_approver, cancellation_requested, cancellation_status, health_document,
               CASE WHEN health_document IS NOT NULL THEN 1 ELSE 0 END as has_document,
               DATEDIFF(day, start_date, end_date) + 1 as duration_days
        FROM leaves 
        WHERE username = ? 
        ORDER BY start_date DESC
    """, (user,))
    
    # Get remaining leave balances
    remaining_leaves = _get_remaining_balances(user)
    
    # Get employees for work assignment (if user is RM)
    employees_df = pd.DataFrame()
    if is_rm and all_team:
        try:
            placeholders = ",".join(["?"] * len(all_team))
            employees_df = run_query(f"""
                SELECT u.username, u.role, u.name 
                FROM users u 
                WHERE u.username IN ({placeholders}) 
                AND u.status = 'Active' 
                ORDER BY u.name, u.username
            """, tuple(all_team))
        except Exception as e:
            print(f"Error fetching team members: {e}")
    
    # Get pending approvals (if user is RM) - FIXED to only show direct reports
    pending_timesheets = pd.DataFrame()
    pending_leaves = pd.DataFrame()
    
    if is_rm and direct_reports:  # Only direct reports, not all team
        try:
            placeholders = ",".join(["?"] * len(direct_reports))
            
            # Get pending timesheet approvals - ONLY where current user is the ASSIGNED RM
            pending_timesheets = run_query(f"""
                SELECT t.id, t.username, t.work_date, t.project_name, t.work_desc, t.hours, 
                       COALESCE(t.break_hours, 0) as break_hours, t.start_time, t.end_time,
                       u.name as employee_name
                FROM timesheets t
                JOIN users u ON t.username = u.username
                JOIN report r ON t.username = r.username
                WHERE t.username IN ({placeholders}) 
                AND t.rm_status = 'Pending' 
                AND r.rm = ?
                ORDER BY t.work_date ASC
            """, tuple(direct_reports + [user]))

            # Get pending leave approvals - ONLY where current user is the ASSIGNED RM
            pending_leaves = run_query(f"""
                SELECT l.id, l.username, l.start_date, l.end_date, l.leave_type, l.description, 
                       l.rm_status, l.health_document,
                       DATEDIFF(day, l.start_date, l.end_date) + 1 as duration_days,
                       u.name as employee_name,
                       CASE WHEN l.health_document IS NOT NULL THEN 1 ELSE 0 END as has_document
                FROM leaves l
                JOIN users u ON l.username = u.username
                JOIN report r ON l.username = r.username
                WHERE l.username IN ({placeholders}) 
                AND l.rm_status = 'Pending' 
                AND r.rm = ?
                ORDER BY l.start_date ASC
            """, tuple(direct_reports + [user]))
        except Exception as e:
            print(f"Error fetching pending approvals: {e}")
    
    # Get team history with filters (if RM) - ENHANCED FILTERING
    team_work_history = pd.DataFrame()
    team_leaves = pd.DataFrame()
    
    if is_rm and all_team:
        try:
            # Get filter parameters from request
            team_work_start = request.args.get('team_work_start', '').strip()
            team_work_end = request.args.get('team_work_end', '').strip()
            team_work_emp = request.args.get('team_work_emp', '').strip()
            team_work_proj = request.args.get('team_work_proj', '').strip()
            team_work_desc = request.args.get('team_work_desc', '').strip()
            team_work_status = request.args.get('team_work_status', '').strip()
            
            # Build dynamic query for team work history with ENHANCED filters
            placeholders = ",".join(["?"] * len(all_team))
            work_base_query = f"""
                SELECT TOP 500 t.id, t.username, t.project_name, t.work_date, t.work_desc, 
                       t.hours, COALESCE(t.break_hours, 0) as break_hours, 
                       t.start_time, t.end_time,
                       CASE WHEN t.hours > 8 THEN t.hours - 8 ELSE 0 END AS overtime_hours, 
                       t.rm_status, t.rm_rejection_reason, t.rm_approver,
                       u.name as employee_name
                FROM timesheets t
                JOIN users u ON t.username = u.username
                WHERE t.username IN ({placeholders})
            """
            work_params = list(all_team)

           

            # Apply ALL filters
            if team_work_start:
                work_base_query += " AND t.work_date >= ?"
                work_params.append(team_work_start)
            if team_work_end:
                work_base_query += " AND t.work_date <= ?"
                work_params.append(team_work_end)
            if team_work_emp:
                work_base_query += " AND t.username = ?"
                work_params.append(team_work_emp)
            if team_work_proj:
                work_base_query += " AND t.project_name LIKE ?"
                work_params.append(f"%{team_work_proj}%")
            if team_work_desc:
                work_base_query += " AND t.work_desc LIKE ?"
                work_params.append(f"%{team_work_desc}%")
            if team_work_status:
                work_base_query += " AND t.rm_status = ?"
                work_params.append(team_work_status)
                
            work_base_query += " ORDER BY t.work_date DESC, t.username"
            team_work_history = run_query(work_base_query, tuple(work_params))

            # Team leave history with ENHANCED filters
            team_leave_start = request.args.get('team_leave_start', '').strip()
            team_leave_end = request.args.get('team_leave_end', '').strip()
            team_leave_emp = request.args.get('team_leave_emp', '').strip()
            team_leave_type = request.args.get('team_leave_type', '').strip()
            team_leave_status = request.args.get('team_leave_status', '').strip()
            
            placeholders = ",".join(["?"] * len(all_team))
            leave_base_query = f"""
                SELECT TOP 500 l.id, l.username, l.start_date, l.end_date, l.leave_type, 
                       l.description, l.rm_status, l.rm_rejection_reason, l.rm_approver,
                       l.cancellation_requested, l.cancellation_status, l.health_document,
                       DATEDIFF(day, l.start_date, l.end_date) + 1 as duration_days,
                       u.name as employee_name,
                       CASE WHEN l.health_document IS NOT NULL THEN 1 ELSE 0 END as has_document
                FROM leaves l
                JOIN users u ON l.username = u.username
                WHERE l.username IN ({placeholders})
            """
            leave_params = list(all_team)

            # Apply ALL leave filters
            if team_leave_start:
                leave_base_query += " AND l.start_date >= ?"
                leave_params.append(team_leave_start)
            if team_leave_end:
                leave_base_query += " AND l.end_date <= ?"
                leave_params.append(team_leave_end)
            if team_leave_emp:
                leave_base_query += " AND l.username = ?"
                leave_params.append(team_leave_emp)
            if team_leave_type:
                leave_base_query += " AND l.leave_type = ?"
                leave_params.append(team_leave_type)
            if team_leave_status:
                leave_base_query += " AND l.rm_status = ?"
                leave_params.append(team_leave_status)

            leave_base_query += " ORDER BY l.start_date DESC, l.username"
            team_leaves = run_query(leave_base_query, tuple(leave_params))
        except Exception as e:
            print(f"Error fetching team history: {e}")
    
    # Calculate statistics
    work_stats = {
        'assigned_to_me': len(assigned_work_df.to_dict('records')) if not assigned_work_df.empty else 0,
        'my_assignments': len(my_assigned_work_df.to_dict('records')) if not my_assigned_work_df.empty else 0,
        'pending_approvals': len(pending_timesheets.to_dict('records')) + len(pending_leaves.to_dict('records')) if is_rm else 0,
        'overdue_assignments': len([w for w in assigned_work_df.to_dict('records') if w.get('urgency_status') == 'Overdue']) if not assigned_work_df.empty else 0
    }
    vacation_info = get_vacation_leave_info()
    project_options = get_assigned_projects_and_work(user)
    # Pass all data to template with ENHANCED filter values
    return render_template('employee.html',
        user=user,
        role=session['role'],
        is_rm=is_rm,
        today=date.today().isoformat(),
        
        # Project and assignment data
        proj_list=proj_list,
        assigned_work=assigned_work_df.to_dict('records') if not assigned_work_df.empty else [],
        my_assigned_work=my_assigned_work_df.to_dict('records') if not my_assigned_work_df.empty else [],
        
        # Personal work and leave data
        work_history_rows=work_history_df.to_dict('records') if not work_history_df.empty else [],
        work_history_cols=work_history_df.columns.tolist() if not work_history_df.empty else [],
        leave_rows=leaves_df.to_dict('records') if not leaves_df.empty else [],
        leave_cols=leaves_df.columns.tolist() if not leaves_df.empty else [],
        remaining_leaves=remaining_leaves,
        
        # RM-specific data
        employees=employees_df.to_dict('records') if not employees_df.empty else [],
        pending_timesheets=pending_timesheets.to_dict('records') if not pending_timesheets.empty else [],
        pending_leaves=pending_leaves.to_dict('records') if not pending_leaves.empty else [],
        
        # Team history data with ENHANCED filtering
        employee_history_rows=team_work_history.to_dict('records') if not team_work_history.empty else [],
        employee_history_cols=team_work_history.columns.tolist() if not team_work_history.empty else [],
        team_leaves=team_leaves.to_dict('records') if not team_leaves.empty else [],
        team_leaves_columns=team_leaves.columns.tolist() if not team_leaves.empty else [],
        
        # Statistics
        work_stats=work_stats,
        
        # Team info
        direct_reports=direct_reports,
        all_team=all_team,
        has_team=len(all_team) > 0,
        
        # ENHANCED Filter values - work history
        team_work_start=request.args.get('team_work_start', ''),
        team_work_end=request.args.get('team_work_end', ''),
        team_work_emp=request.args.get('team_work_emp', ''),
        team_work_proj=request.args.get('team_work_proj', ''),
        team_work_desc=request.args.get('team_work_desc', ''),
        team_work_status=request.args.get('team_work_status', ''),
        
        # ENHANCED Filter values - leave history
        team_leave_start=request.args.get('team_leave_start', ''),
        team_leave_end=request.args.get('team_leave_end', ''),
        team_leave_emp=request.args.get('team_leave_emp', ''),
        team_leave_type=request.args.get('team_leave_type', ''),
        team_leave_status=request.args.get('team_leave_status', ''),
        project_options=project_options,
        vacation_leave_info=vacation_info
    )

# Intern View Function - COMPLETE
# --------------------
def view_intern(user):
    """Intern dashboard view - FIXED to show assigned work properly"""
    
    # Get projects list
    projects_df = run_query("""
        SELECT project_name FROM projects 
        WHERE hr_approval_status = 'Approved' 
        AND project_name NOT LIKE 'Salary%'
        AND project_name NOT LIKE 'Asset Purchase%'
        ORDER BY project_name
    """)
    proj_list = ["(non-project)"] + projects_df["project_name"].astype(str).tolist() if not projects_df.empty else ["(non-project)"]
    
    # FIXED: Get ALL assigned work for this intern
    assigned_work_df = run_query("""
        SELECT aw.id, aw.assigned_by, aw.project_name, aw.task_desc, aw.start_date, aw.due_date,
               aw.assigned_on, aw.rm_status, aw.manager_status,
               u.name as assigned_by_name,
               CASE 
                   WHEN aw.due_date < GETDATE() AND aw.rm_status NOT IN ('Completed', 'Rejected') THEN 'Overdue'
                   WHEN aw.due_date <= DATEADD(day, 3, GETDATE()) AND aw.rm_status NOT IN ('Completed', 'Rejected') THEN 'Due Soon'
                   ELSE 'Active'
               END as urgency_status
        FROM assigned_work aw
        LEFT JOIN users u ON aw.assigned_by = u.username
        WHERE aw.assigned_to = ? 
        ORDER BY aw.assigned_on DESC, aw.due_date ASC
    """, (user,))
    
    # Get work history
    work_history_df = run_query("""
        SELECT id, work_date, project_name, work_desc, hours, break_hours, start_time, end_time,
               CASE WHEN hours > 8 THEN hours - 8 ELSE 0 END AS overtime_hours,
               rm_status, rm_rejection_reason, rm_approver
        FROM timesheets 
        WHERE username = ? 
        ORDER BY work_date DESC, id DESC
    """, (user,))
    
    # Get leaves with rejection reason
    leaves_df = run_query("""
        SELECT id, start_date, end_date, leave_type, description, 
               rm_status, rm_rejection_reason, rm_approver, 
               cancellation_requested, cancellation_status, health_document,
               CASE WHEN health_document IS NOT NULL THEN 1 ELSE 0 END as document_path,
               DATEDIFF(day, start_date, end_date) + 1 as duration_days
        FROM leaves 
        WHERE username = ? 
        ORDER BY id DESC
    """, (user,))
    
    # Calculate remaining leaves
    remaining_leaves = _get_remaining_balances(user)
    vacation_info = get_vacation_leave_info()
    # Convert DataFrames to dictionaries for template
    assigned_work = assigned_work_df.to_dict('records') if not assigned_work_df.empty else []
    work_history = work_history_df.to_dict('records') if not work_history_df.empty else []
    leaves = leaves_df.to_dict('records') if not leaves_df.empty else []
    project_options = get_assigned_projects_and_work(user)
    return render_template('intern_dashboard.html',
        user=user,
        role=session['role'],
        proj_list=proj_list,
        assigned_work=assigned_work,
        work_history=work_history,
        work_history_rows=work_history,
        work_history_cols=work_history_df.columns.tolist() if not work_history_df.empty else [],
        leaves=leaves,
        leave_rows=leaves,
        leave_cols=leaves_df.columns.tolist() if not leaves_df.empty else [],
        remaining_leaves=remaining_leaves,
        project_options=project_options,
        vacation_leave_info=vacation_info,
        today=date.today().isoformat()
    )
# Admin Manager View Function - COMPLETE WITH FIXED DATA
# --------------------
def view_admin_manager(user):
    """Admin Manager dashboard view with COMPLETE employee management, asset handling, and team management - UPDATED with proper data"""
    user_role = session.get('role', '')
    can_manage_payroll = user_role == 'Lead Staffing Specialist'
    is_admin_manager = user_role == 'Admin Manager'
    is_lead_staffing = user_role == 'Lead Staffing Specialist'
    
    # Get direct reports from reports table (where rm = current user)
    direct_reports_list = get_direct_reports(user)
    assignable_employees_list = get_work_assignable_employees(user)
    
    print(f" DEBUG view_admin_manager: User {user} ({user_role})")
    print(f" DEBUG: Direct reports: {direct_reports_list}")
    print(f" DEBUG: Assignable employees: {assignable_employees_list}")
    
    # Convert to proper format for template
    direct_reports_data = []
    if direct_reports_list:
        placeholders = ",".join(["?"] * len(direct_reports_list))
        direct_reports_query = run_query(f"""
            SELECT username, name, role FROM users 
            WHERE username IN ({placeholders}) AND status = 'Active'
            ORDER BY name, username
        """, tuple(direct_reports_list))
        
        if not direct_reports_query.empty:
            direct_reports_data = direct_reports_query.to_dict('records')
    
    # Get all employees with their reporting structure
    all_employees = run_query("""
        SELECT u.username, u.password, u.role, u.email, u.monthly_salary, u.yearly_salary, 
               u.name, u.status,
               ed.joining_date, ed.employment_type, ed.blood_group, ed.mobile_number,
               ed.emergency_contact, ed.id_card, ed.id_card_provided, ed.photo_url,
               ed.linkedin_url, ed.laptop_provided, ed.email_provided, ed.asset_details,
               ed.adhaar_number, ed.pan_number, ed.duration,ed.employmentid,
               r.rm, r.manager
        FROM users u
        LEFT JOIN employee_details ed ON u.username = ed.username
        LEFT JOIN report r ON u.username = r.username
        WHERE u.status IN ('Active')
        ORDER BY u.role, u.username
    """)
    
  # ✅ FULLY CORRECTED - All non-existent columns removed
    my_assigned_work = run_query("""
        SELECT 
        aw.id, 
        aw.assigned_by, 
        aw.assigned_to, 
        aw.task_desc, 
        aw.project_name, 
        aw.due_date, 
        aw.start_date,
        aw.assigned_on,
        aw.rm_status, 
        aw.manager_status,
        u.name as assigned_to_name, 
        u.role as assigned_to_role,
        CASE 
            WHEN aw.due_date < CAST(GETDATE() AS DATE) THEN 'Overdue'
            WHEN aw.due_date <= DATEADD(day, 3, CAST(GETDATE() AS DATE)) THEN 'Due Soon'
            ELSE 'On Track'
        END as urgency_status,
        CASE 
            WHEN aw.assigned_on > DATEADD(hour, -1, GETDATE()) THEN 1 
            ELSE 0 
        END as recently_updated
        FROM assigned_work aw
        LEFT JOIN users u ON aw.assigned_to = u.username
        WHERE aw.assigned_by = ?
        OR aw.assigned_to IN (
        SELECT username FROM users 
        WHERE username IN (
            SELECT username FROM report 
            WHERE rm = ? OR manager = ?
        )
    )
        ORDER BY aw.assigned_on DESC
        """, (user, user, user))



    # Get work assigned TO this admin manager
    work_assigned_to_me = run_query("""
        SELECT aw.id, aw.assigned_by, aw.task_desc, aw.project_name, 
            COALESCE(aw.start_date, aw.assigned_on) as startdate,
            aw.end_date, aw.due_date, aw.assigned_on, aw.rm_status, aw.manager_status, 
            aw.work_type, aw.rm_rejection_reason, u.name as assigned_by_name,
            CASE 
                WHEN aw.due_date < GETDATE() AND aw.rm_status != 'Completed' THEN 'Overdue'
                WHEN aw.due_date <= DATEADD(day, 3, GETDATE()) AND aw.rm_status != 'Completed' THEN 'Due Soon'
                ELSE 'Active'
            END as urgency_status
        FROM assigned_work aw 
        LEFT JOIN users u ON aw.assigned_by = u.username 
        WHERE aw.assigned_to = ?
        ORDER BY aw.assigned_on DESC, aw.due_date ASC
    """, (user,))

    # Get all managers for dropdown
    # Get all RMs from report table PLUS other managers - COMPREHENSIVE
    all_managers = run_query("""
    SELECT DISTINCT u.username, u.name, u.role 
    FROM (
        SELECT DISTINCT rm as username FROM report WHERE rm IS NOT NULL
        UNION
        SELECT username FROM users WHERE role IN ('Manager', 'Admin Manager', 'Lead Staffing Specialist') AND status = 'Active'
    ) AS combined
    JOIN users u ON combined.username = u.username
    WHERE u.status = 'Active'
    ORDER BY u.name
""")

    
    # Get resigned employees
    resigned_employees = run_query("""
    SELECT username, name, role, joining_date, resigned_date, resigned_by, resignation_reason
    FROM resigned_employees
    ORDER BY resigned_date DESC
""")
    
    # Get projects list for work assignments
    projects_df = run_query("""
        SELECT project_name FROM projects 
        WHERE hr_approval_status = 'Approved' 
        AND project_name NOT LIKE 'Salary%'
        AND project_name NOT LIKE 'Asset Purchase%'
        ORDER BY project_name
    """)
    proj_list = ["(non-project)"] + projects_df["project_name"].astype(str).tolist() if not projects_df.empty else ["(non-project)"]

    # Get ALL asset requests with proper schema alignment
    try:
        all_asset_requests = run_query("""
            SELECT id, asset_type, quantity, 
                   COALESCE(CAST(amount AS DECIMAL(18,2)), 0) as amount, 
                   for_employee, description, requested_by, requested_date, 
                   status, approved_by, approved_date, rejection_reason,document_path
            FROM asset_requests
            ORDER BY 
                CASE 
                    WHEN status = 'Pending' THEN 1 
                    WHEN status = 'Approved' THEN 2 
                    ELSE 3 
                END,
                requested_date DESC
        """)
        
        if not all_asset_requests.empty:
            asset_records = all_asset_requests.to_dict('records')
            for record in asset_records:
                try:
                    record['amount'] = float(record['amount']) if record['amount'] is not None else 0.0
                    record['rejection_reason'] = record['rejection_reason'] or ''
                    record['for_employee'] = record['for_employee'] or ''
                    # Format dates
                    if record.get('requested_date') and hasattr(record['requested_date'], 'strftime'):
                        record['requested_date'] = record['requested_date'].strftime('%Y-%m-%d')
                    if record.get('approved_date') and hasattr(record['approved_date'], 'strftime'):
                        record['approved_date'] = record['approved_date'].strftime('%Y-%m-%d')
                except (ValueError, TypeError):
                    record['amount'] = 0.0
                    record['rejection_reason'] = ''
                    record['documentpath'] = record.get('document_path', '')
            all_asset_requests_list = asset_records
        else:
            all_asset_requests_list = []
            
    except Exception as e:
        print(f"Asset requests error: {e}")
        all_asset_requests_list = []

    # Calculate asset request totals by status
    pending_asset_requests = [r for r in all_asset_requests_list if r['status'] == 'Pending']
    approved_asset_requests = [r for r in all_asset_requests_list if r['status'] == 'Approved']
    rejected_asset_requests = [r for r in all_asset_requests_list if r['status'] == 'Rejected']
    
    total_pending_cost = sum(r.get('amount', 0) for r in pending_asset_requests)
    total_approved_cost = sum(r.get('amount', 0) for r in approved_asset_requests)
    total_rejected_cost = sum(r.get('amount', 0) for r in rejected_asset_requests)

    # Get personal work history for this admin
    personal_work_history = run_query("""
        SELECT id, work_date, project_name, work_desc, hours, break_hours, start_time, end_time,
               CASE WHEN hours > 8 THEN hours - 8 ELSE 0 END AS overtime_hours,
               rm_status, rm_rejection_reason, rm_approver
        FROM timesheets 
        WHERE username = ? 
        ORDER BY work_date DESC, id DESC
    """, (user,))
    
    # Get personal leaves for this admin
    personal_leaves = run_query("""
        SELECT id, start_date, end_date, leave_type, description, 
               rm_status, rm_rejection_reason, rm_approver, 
               cancellation_requested, cancellation_status, health_document,
               CASE WHEN health_document IS NOT NULL THEN 1 ELSE 0 END as document_path,
               DATEDIFF(day, start_date, end_date) + 1 as duration_days
        FROM leaves 
        WHERE username = ? 
        ORDER BY id DESC
    """, (user,))
    
    # Get personal remaining leave balances
    personal_remaining_leaves = _get_remaining_balances(user)
    
    # Get assigned work for this admin
    personal_assigned_work = run_query("""
        SELECT id, assigned_by, project_name, task_desc, start_date, due_date,
               rm_status, assigned_on
        FROM assigned_work 
        WHERE assigned_to = ?
        ORDER BY assigned_on DESC
    """, (user,))
    
    # Get team members and their work/leave history
    team_work_history = pd.DataFrame()
    team_leave_history = pd.DataFrame()
    pending_work_approvals = pd.DataFrame()
    pending_leave_approvals = pd.DataFrame()
    
    if direct_reports_list:
        placeholders = ",".join(["?"] * len(direct_reports_list))
        
        # Team work history with filters
        work_start = request.args.get('team_work_start', '').strip()
        work_end = request.args.get('team_work_end', '').strip()
        work_user = request.args.get('team_work_emp', '').strip()
        work_proj = request.args.get('team_work_proj', '').strip()
        work_status = request.args.get('team_work_status', '').strip()
        
        work_query = f"""
            SELECT TOP 500 t.username, t.work_date, t.project_name, t.work_desc, t.hours, 
                   COALESCE(t.break_hours, 0) as break_hours,
                   CASE WHEN t.hours > 8 THEN t.hours - 8 ELSE 0 END AS overtime_hours,
                   t.rm_status, t.rm_rejection_reason, t.rm_approver,
                   u.name as employee_name
            FROM timesheets t
            JOIN users u ON t.username = u.username
            WHERE t.username IN ({placeholders})
        """
        work_params = list(direct_reports_list)
        
        if work_start:
            work_query += " AND t.work_date >= ?"
            work_params.append(work_start)
        if work_end:
            work_query += " AND t.work_date <= ?"
            work_params.append(work_end)
        if work_user:
            work_query += " AND t.username = ?"
            work_params.append(work_user)
        if work_proj:
            work_query += " AND t.project_name = ?"
            work_params.append(work_proj)
        if work_status:
            work_query += " AND t.rm_status = ?"
            work_params.append(work_status)
            
        work_query += " ORDER BY t.work_date DESC"
        team_work_history = run_query(work_query, tuple(work_params))
        
        # Team leave history with filters
        leave_start = request.args.get('team_leave_start', '').strip()
        leave_end = request.args.get('team_leave_end', '').strip()
        leave_user = request.args.get('team_leave_emp', '').strip()
        leave_type = request.args.get('team_leave_type', '').strip()
        leave_status = request.args.get('team_leave_status', '').strip()
        
        leave_query = f"""
            SELECT TOP 500 l.username, l.start_date, l.end_date, l.leave_type, l.description, 
                   l.rm_status, l.rm_rejection_reason, l.rm_approver,
                   l.cancellation_requested, l.cancellation_status,
                   DATEDIFF(day, l.start_date, l.end_date) + 1 as duration_days,
                   u.name as employee_name
            FROM leaves l
            JOIN users u ON l.username = u.username
            WHERE l.username IN ({placeholders})
        """
        leave_params = list(direct_reports_list)
        
        if leave_start:
            leave_query += " AND l.start_date >= ?"
            leave_params.append(leave_start)
        if leave_end:
            leave_query += " AND l.end_date <= ?"
            leave_params.append(leave_end)
        if leave_user:
            leave_query += " AND l.username = ?"
            leave_params.append(leave_user)
        if leave_type:
            leave_query += " AND l.leave_type = ?"
            leave_params.append(leave_type)
        if leave_status:
            leave_query += " AND l.rm_status = ?"
            leave_params.append(leave_status)
            
        leave_query += " ORDER BY l.start_date DESC"
        team_leave_history = run_query(leave_query, tuple(leave_params))

        # Pending approvals (only for direct reports where current user is RM)
        pending_work_approvals = run_query(f"""
            SELECT t.id, t.username, t.work_date, t.project_name, t.work_desc, t.hours, 
                   COALESCE(t.break_hours, 0) as break_hours, t.start_time, t.end_time,
                   u.name as employee_name
            FROM timesheets t
            JOIN users u ON t.username = u.username
            WHERE t.username IN ({placeholders}) AND t.rm_status = 'Pending' AND t.rm_approver = ?
            ORDER BY t.work_date ASC
        """, tuple(direct_reports_list + [user]))
        
        pending_leave_approvals = run_query(f"""
            SELECT l.id, l.username, l.start_date, l.end_date, l.leave_type, l.description, 
                   l.rm_status, l.health_document,
                   DATEDIFF(day, l.start_date, l.end_date) + 1 as duration_days,
                   u.name as employee_name,
                   CASE WHEN l.health_document IS NOT NULL THEN 1 ELSE 0 END as has_document
            FROM leaves l
            JOIN users u ON l.username = u.username
            WHERE l.username IN ({placeholders}) AND l.rm_status = 'Pending' AND l.rm_approver = ?
            ORDER BY l.start_date ASC
        """, tuple(direct_reports_list + [user]))
    
    # Calculate leave duration for team leaves
    team_leave_records = team_leave_history.to_dict('records') if not team_leave_history.empty else []
    team_leave_records = calculate_leave_duration(team_leave_records)
    
    pending_leave_records = pending_leave_approvals.to_dict('records') if not pending_leave_approvals.empty else []
    pending_leave_records = calculate_leave_duration(pending_leave_records)
    
    # Calculate statistics - FIXED
    active_employees_count = len([emp for emp in all_employees.to_dict('records') if emp.get('status') == 'Active'])
    inactive_employees_count = len([emp for emp in all_employees.to_dict('records') if emp.get('status') == 'Inactive'])
    suspended_employees_count = len([emp for emp in all_employees.to_dict('records') if emp.get('status') == 'Suspended'])
    
    # Calculate payroll totals - FIXED
    all_emp_records = all_employees.to_dict('records') if not all_employees.empty else []
    total_monthly_payroll = 0.0
    total_yearly_payroll = 0.0
    paid_employees_count = 0
    
    for emp in all_emp_records:
        if emp.get('status') == 'Active':
            monthly = float(emp.get('monthly_salary') or 0)
            yearly = float(emp.get('yearly_salary') or 0)
            total_monthly_payroll += monthly
            total_yearly_payroll += yearly
            if monthly > 0:
                paid_employees_count += 1
    
    # Get employee statistics by role
    employee_stats_by_role = {}
    for emp in all_emp_records:
        if emp.get('status') == 'Active':
            role = emp.get('role')
            if role:
                if role not in employee_stats_by_role:
                    employee_stats_by_role[role] = 0
                employee_stats_by_role[role] += 1
    
    # Get recent activities
    recent_hires = run_query("""
        SELECT TOP 10 u.username, u.name, u.role, ed.joining_date
        FROM users u
        LEFT JOIN employee_details ed ON u.username = ed.username
        WHERE u.status = 'Active' AND ed.joining_date >= DATEADD(day, -30, GETDATE())
        ORDER BY ed.joining_date DESC
    """)
    
    # Get work assignment statistics - FIXED
    my_assigned_work_records = my_assigned_work.to_dict('records') if not my_assigned_work.empty else []
    work_assigned_to_me_records = work_assigned_to_me.to_dict('records') if not work_assigned_to_me.empty else []
    
    assignment_stats = {
        'total_assignments': len(my_assigned_work_records),
        'pending_assignments': len([w for w in my_assigned_work_records if w.get('rm_status') == 'Pending']),
        'overdue_assignments': len([w for w in my_assigned_work_records if w.get('urgency_status') == 'Overdue']),
        'my_pending_work': len([w for w in work_assigned_to_me_records if w.get('rm_status') == 'Pending']),
    }
    
    # Get company performance metrics - FIXED
    try:
        monthly_metrics = run_query("""
            SELECT 
                (SELECT COUNT(*) FROM timesheets WHERE MONTH(work_date) = MONTH(GETDATE()) AND YEAR(work_date) = YEAR(GETDATE())) as monthly_timesheets,
                (SELECT COUNT(*) FROM leaves WHERE MONTH(start_date) = MONTH(GETDATE()) AND YEAR(start_date) = YEAR(GETDATE())) as monthly_leaves,
                (SELECT AVG(CAST(hours AS FLOAT)) FROM timesheets WHERE MONTH(work_date) = MONTH(GETDATE()) AND YEAR(work_date) = YEAR(GETDATE()) AND rm_status = 'Approved') as avg_hours
        """)
        
        company_metrics = {
            'total_employees': active_employees_count,
            'total_timesheets_this_month': 0,
            'total_leaves_this_month': 0,
            'avg_working_hours': 0.0,
            'employee_satisfaction': 85.0  # Default value
        }
        
        if not monthly_metrics.empty:
            metrics = monthly_metrics.iloc[0]
            company_metrics.update({
                'total_timesheets_this_month': int(metrics.get('monthly_timesheets', 0) or 0),
                'total_leaves_this_month': int(metrics.get('monthly_leaves', 0) or 0),
                'avg_working_hours': float(metrics.get('avg_hours', 0) or 0)
            })
    except Exception as e:
        print(f"Error calculating company metrics: {e}")
        company_metrics = {
            'total_employees': active_employees_count,
            'total_timesheets_this_month': 0,
            'total_leaves_this_month': 0,
            'avg_working_hours': 0.0,
            'employee_satisfaction': 85.0
        }
    
    # Get department-wise breakdown
    department_breakdown = []
    try:
        dept_stats = run_query("""
            SELECT role, 
                   COUNT(*) as total_count,
                   SUM(CASE WHEN status = 'Active' THEN 1 ELSE 0 END) as active_count,
                   AVG(CAST(COALESCE(monthly_salary, 0) AS FLOAT)) as avg_salary
            FROM users 
            WHERE role IS NOT NULL
            GROUP BY role
            ORDER BY total_count DESC
        """)
        
        if not dept_stats.empty:
            department_breakdown = dept_stats.to_dict('records')
    except Exception as e:
        print(f"Error calculating department breakdown: {e}")
    project_options = get_assigned_projects_and_work(user)
    vacation_info = get_vacation_leave_info()
    
    return render_template('admin_manager.html',
        user=user,
        role=session['role'],
        today=date.today().isoformat(),
        
        # Employee data - FIXED
        all_employees=all_emp_records,
        all_managers=all_managers.to_dict('records') if not all_managers.empty else [],
        resigned_employees=resigned_employees.to_dict('records') if not resigned_employees.empty else [],
        recent_hires=recent_hires.to_dict('records') if not recent_hires.empty else [],
        
        # Asset requests data - FIXED
        all_asset_requests=all_asset_requests_list,
        pending_asset_requests=pending_asset_requests,
        approved_asset_requests=approved_asset_requests,
        rejected_asset_requests=rejected_asset_requests,
        total_pending_asset_cost=float(total_pending_cost),
        total_approved_asset_cost=float(total_approved_cost),
        total_rejected_asset_cost=float(total_rejected_cost),

        # Work assignments - FIXED
        my_assigned_work=my_assigned_work_records,
        work_assigned_to_me=work_assigned_to_me_records,
        assignment_stats=assignment_stats,
        
        # Team history data - FIXED
        team_work_history=team_work_history.to_dict('records') if not team_work_history.empty else [],
        team_leave_history=team_leave_records,
        
        # Approval data (only for direct reports) - FIXED
        pending_work_approvals=pending_work_approvals.to_dict('records') if not pending_work_approvals.empty else [],
        pending_leave_approvals=pending_leave_records,
        
        # Statistics - ALL FIXED
        active_employees_count=int(active_employees_count),
        inactive_employees_count=int(inactive_employees_count),
        suspended_employees_count=int(suspended_employees_count),
        total_monthly_payroll=float(total_monthly_payroll),
        total_yearly_payroll=float(total_yearly_payroll),
        paid_employees_count=int(paid_employees_count),
        employee_stats_by_role=employee_stats_by_role,
        
        # Company performance metrics - FIXED
        company_metrics=company_metrics,
        department_breakdown=department_breakdown,
        
        # Permission flags
        can_manage_payroll=can_manage_payroll,
        is_admin_manager=is_admin_manager,
        is_lead_staffing=is_lead_staffing,
        
        # Team info - FIXED with proper data structure
        direct_reports=direct_reports_data,  # This is now a list of dictionaries with username, name, role
        assignable_employees=direct_reports_data,  # Same as direct_reports for template compatibility
        has_team=len(direct_reports_data) > 0,
        can_assign_work=len(direct_reports_data) > 0,
        proj_list=proj_list,
        
        # Personal admin data
        personal_assigned_work=personal_assigned_work.to_dict('records') if not personal_assigned_work.empty else [],
        personal_work_history=personal_work_history.to_dict('records') if not personal_work_history.empty else [],
        personal_leaves=personal_leaves.to_dict('records') if not personal_leaves.empty else [],
        personal_remaining_leaves=personal_remaining_leaves,
        
        # Filter values for team history
        work_start=request.args.get('team_work_start', ''),
        work_end=request.args.get('team_work_end', ''),
        work_user=request.args.get('team_work_emp', ''),
        work_proj=request.args.get('team_work_proj', ''),
        work_status=request.args.get('team_work_status', ''),
        leave_start=request.args.get('team_leave_start', ''),
        leave_end=request.args.get('team_leave_end', ''),
        leave_user=request.args.get('team_leave_emp', ''),
        leave_type=request.args.get('team_leave_type', ''),
        leave_status=request.args.get('team_leave_status', ''),
        
        # Additional admin features
        system_alerts=[],
        pending_system_actions=len(pending_asset_requests) + len(pending_work_approvals.to_dict('records') if not pending_work_approvals.empty else []),
        last_backup_date=datetime.now().strftime('%Y-%m-%d'),
        
        # Add missing variables that template expects
        my_work_assignments=my_assigned_work_records,  # Alternative name
        work_assigned_to_admin=work_assigned_to_me_records,
        project_options=project_options, 
        vacation_leave_info=vacation_info # Alternative name
    )




@app.route('/submit_timesheet', methods=['POST'])
def submit_timesheet_action():
    """Submit timesheet with assigned projects/work filter"""
    if 'username' not in session:
        return redirect(url_for('login_sso'))
    
    user = session['username']
    project = request.form.get('project')
    workdate = request.form.get('work_date')
    desc = request.form.get('desc')
    starttstr = request.form.get('start_t')
    endtstr = request.form.get('end_t')
    brk = request.form.get('brk', '0.0')
    
    if not project or not workdate or not desc or not starttstr or not endtstr:
        flash("All fields are required.")
        return redirect(url_for('dashboard'))
    
    try:
        start_t = time.fromisoformat(starttstr)
        end_t = time.fromisoformat(endtstr)
        hours = calc_hours(start_t, end_t, float(brk))
        
        # Handle project selection
        proj_val = "(non-project)" if project == "(non-project)" or not project else project
        cost_center = None
        
        # Get cost center if it's a real project - CORRECTED COLUMN NAME
        if proj_val and proj_val != "(non-project)":
            df = run_query("SELECT cost_center FROM projects WHERE project_name = ?", (proj_val,))
            if not df.empty:
                cost_center = df.iloc[0]['cost_center']
        
        # Convert time objects to strings for database storage
        start_time_str = start_t.strftime("%H:%M:%S")
        end_time_str = end_t.strftime("%H:%M:%S")
        
        # Get RM approver for the user
        rm_approver = get_rm_for_employee(user)
        
        # Insert timesheet record - CORRECTED COLUMN NAMES
        ok = run_exec("""
            INSERT INTO [timesheet_db].[dbo].[timesheets] 
            (username, work_date, project_name, work_desc, hours, start_time, end_time, break_hours, 
             rm_status, cost_center, rm_approver)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'pending', ?, ?)
        """, (user, workdate, proj_val, desc, int(round(hours)), 
              start_time_str, end_time_str, float(brk), cost_center, rm_approver))
        
        if ok:
            flash("Timesheet submitted successfully (awaiting RM approval).")
            
            # Send email notification to RM
            if rm_approver:
                rm_email = get_user_email(rm_approver)
                if rm_email:
                    subject = f"New Timesheet Pending Approval - {user}"
                    text_content = f"""Dear {rm_approver},

A new timesheet has been submitted by {user} and requires your approval.

Timesheet Details:
- Employee: {user}
- Date: {workdate}
- Project: {proj_val}
- Hours: {hours}
- Description: {desc[:100]}{'...' if len(desc) > 100 else ''}
- Status: Pending Approval

Please log in to the system to review and approve this timesheet.
https://nexus.chervicaon.com
This is an automated notification from the Timesheet & Leave Management System."""
                    send_email(rm_email, subject, text_content)
        else:
            flash("Failed to submit timesheet.")
    
    except ValueError as e:
        flash(f"Invalid time format: {str(e)}")
    except Exception as e:
        flash(f"Error submitting timesheet: {str(e)}")
    
    return redirect(url_for('dashboard'))


def get_assigned_projects_and_work(username):
    """Get ONLY projects and work assigned to user for timesheet dropdown with assignor info"""
    try:
        # CORRECTED: Use actual table name 'assigned_work' and include assigned_by info
        assigned_options = run_query("""
            SELECT DISTINCT p.project_name as name, 'Project' as type, p.created_by as assigned_by
            FROM projects p 
            INNER JOIN assigned_work aw ON p.project_name = aw.project_name 
            WHERE aw.assigned_to = ? AND p.hr_approval_status = 'approved'
            
            UNION
            
            SELECT DISTINCT aw.project_name as name, 'Work' as type, aw.assigned_by
            FROM assigned_work aw 
            WHERE aw.assigned_to = ? AND aw.rm_status IN ('pending', 'approved')
            
            ORDER BY type, name
        """, (username, username))
        
        # Create dropdown options with labels including assignor
        project_options = []
        
        # Always add non-project option first
        project_options.append({
            'value': '(non-project)',
            'label': '(Non-Project Work)'
        })
        
        # Add ONLY assigned projects and work with assignor info
        if not assigned_options.empty:
            for _, row in assigned_options.iterrows():
                if row['type'] == 'Project':
                    project_options.append({
                        'value': row['name'],
                        'label': f"{row['name']} (Project - Assigned by: {row['assigned_by']})"
                    })
                else:
                    project_options.append({
                        'value': row['name'], 
                        'label': f"{row['name']} (Work - Assigned by: {row['assigned_by']})"
                    })
        
        return project_options
        
    except Exception as e:
        print(f"Error fetching assigned projects: {e}")
        return [{'value': '(non-project)', 'label': '(Non-Project Work)'}]





@app.route('/request_leave', methods=['POST'])
def request_leave_action():
    if 'username' not in session:
        return redirect(url_for('login_sso'))
    
    user = session['username']
    leave_type = request.form.get('leave_type')
    start_d = request.form.get('start_d')
    end_d = request.form.get('end_d')
    description = request.form.get('description')
    
    if not all([leave_type, start_d, end_d, description]):
        flash(" All fields are required for leave request.")
        return redirect(url_for('dashboard'))
    
    valid_leave_types = ['Other', 'Casual', 'Personal', 'Sick', 'Vacation']
    
    if leave_type not in valid_leave_types:
        flash(f" Invalid leave type: '{leave_type}'. Must be one of: {', '.join(valid_leave_types)}")
        return redirect(url_for('dashboard'))
    
    try:
        start_date = datetime.strptime(start_d, '%Y-%m-%d').date()
        end_date = datetime.strptime(end_d, '%Y-%m-%d').date()
        
        if start_date > end_date:
            flash(" Start date cannot be after end date.")
            return redirect(url_for('dashboard'))
        
        if start_date < date.today():
            flash(" Cannot apply for leave in the past.")
            return redirect(url_for('dashboard'))
        
        # Vacation leave advance notice validation
        if leave_type == 'Vacation':
            days_in_advance = (start_date - date.today()).days
            if days_in_advance < 3:
                flash('Vacation leave must be requested at least 3 days in advance.')
                return redirect(url_for('dashboard'))
            
        days_requested = (end_date - start_date).days + 1
        remaining = _get_remaining_balances(user)
        
        leave_balance_mapping = {
            'Sick': 'sick',
            'Vacation': 'paid',
            'Personal': 'paid',
            'Casual': 'casual',
            'Other': 'casual'
        }
        
        balance_key = leave_balance_mapping.get(leave_type, 'casual')
        
        if remaining.get(balance_key, 0) < days_requested:
            flash(f" Insufficient {leave_type} leave balance. Available: {remaining.get(balance_key, 0)} days, Requested: {days_requested} days")
            return redirect(url_for('dashboard'))
        
        # Handle document upload for sick leave > 2 days
        doc_name = None
        need_doc = (leave_type == "Sick") and (days_requested > 2)
        
        if need_doc:
            if 'doc' in request.files and request.files['doc'].filename:
                file = request.files['doc']
                if file.filename != '':
                    allowed_extensions = {'pdf', 'jpg', 'jpeg', 'png', 'doc', 'docx'}
                    file_ext = file.filename.rsplit('.', 1)[1].lower() if '.' in file.filename else ''
                    
                    if file_ext not in allowed_extensions:
                        flash(" Invalid file type. Please upload PDF, JPG, PNG, DOC, or DOCX files only.")
                        return redirect(url_for('dashboard'))
                    
                    timestamp = int(datetime.now().timestamp())
                    doc_name = f"{user}_{timestamp}_{secure_filename(file.filename)}"
                    file.save(os.path.join(app.config['UPLOAD_FOLDER'], doc_name))
            else:
                flash(" Please upload the required medical certificate for sick leave > 2 days.")
                return redirect(url_for('dashboard'))
        
        #  CRITICAL FIX: Get the DIRECT RM for this user
        rm_approver = get_rm_for_employee(user)
        
        if not rm_approver:
            flash(" No reporting manager found. Please contact admin to set up reporting structure.")
            return redirect(url_for('dashboard'))
        
        print(f" DEBUG: Leave submission - User: {user} -> RM Approver: {rm_approver}")
        
        ok = run_exec("""
            INSERT INTO [timesheet_db].[dbo].[leaves] (username, start_date, end_date, leave_type, description, 
                              rm_status, rm_approver, health_document, cancellation_requested, 
                              cancellation_status)
            VALUES (?, ?, ?, ?, ?, 'Pending', ?, ?, 0, NULL)
        """, (user, start_d, end_d, leave_type, description, rm_approver, doc_name))
        
        if ok:
            rm_approver = get_rm_for_employee(user)
            rm_email = get_user_email(rm_approver)
            if rm_email:
                subject = f"New Leave Request - {user}"
                text_content = f"""Dear {rm_approver},

    {user} has submitted a leave request that requires your approval.

    Details:
    - Employee: {user}
    - Leave Type: {leave_type}
    - Duration: {start_d} to {end_d} ({days_requested} days)
    - Reason: {description}
    {f'- Medical Document: Attached' if doc_name else ''}

    Please log in to the system to review and approve this leave request.
    https://nexus.chervicaon.com
    This is an automated notification from the Timesheet & Leave Management System."""
                send_email(rm_email, subject, text_content)

            flash(f" {leave_type} leave request submitted successfully to RM: {rm_approver} for {days_requested} day(s) from {start_d} to {end_d}.")
            
            

        else:
            flash(" Failed to submit leave request.")
    
    except Exception as e:
        flash(f" Error submitting leave request: {str(e)}")
        print(f"Leave submission error: {e}")
    
    return redirect(url_for('dashboard'))


def get_vacation_leave_info():
    """Get vacation leave policy information for dashboard display"""
    return {
        'policy_message': '⚠️ Vacation Leave Policy: Must be requested at least 3 days in advance',
        'advance_days': 3,
        'leave_type': 'Vacation'
    }

# Add these missing document viewing routes with proper permission checks
@app.route('/view-leave-document/<int:leave_id>')
def view_leave_document(leave_id):
    """View leave document with proper permission checks"""
    if 'username' not in session:
        return redirect(url_for('login_sso'))
    
    user = session['username']
    
    # Get leave details
    leave_query = run_query("""
        SELECT l.username, l.health_document, r.rm, r.manager 
        FROM leaves l
        LEFT JOIN report r ON l.username = r.username
        WHERE l.id = ?
    """, (leave_id,))
    
    if leave_query.empty:
        flash("Document not found.")
        return redirect(url_for('dashboard'))
    
    leave_record = leave_query.iloc[0]
    document_owner = leave_record['username']
    assigned_rm = leave_record['rm']
    assigned_manager = leave_record['manager']
    document_path = leave_record['health_document']
    
    # Check permissions: user must be document owner, assigned RM, or assigned manager
    if user != document_owner and user != assigned_rm and user != assigned_manager:
        flash("Access denied. You don't have permission to view this document.")
        return redirect(url_for('dashboard'))
    
    if not document_path:
        flash("No document attached to this leave request.")
        return redirect(url_for('dashboard'))
    
    try:
        return send_file(os.path.join(app.config['UPLOAD_FOLDER'], document_path))
    except FileNotFoundError:
        flash("Document file not found on server.")
        return redirect(url_for('dashboard'))

@app.route('/download-leave-document/<int:leave_id>')
def download_leave_document(leave_id):
    """Download leave document with proper permission checks"""
    if 'username' not in session:
        return redirect(url_for('login_sso'))
    
    user = session['username']
    
    # Get leave details
    leave_query = run_query("""
        SELECT l.username, l.health_document, r.rm, r.manager 
        FROM leaves l
        LEFT JOIN report r ON l.username = r.username
        WHERE l.id = ?
    """, (leave_id,))
    
    if leave_query.empty:
        flash("Document not found.")
        return redirect(url_for('dashboard'))
    
    leave_record = leave_query.iloc[0]
    document_owner = leave_record['username']
    assigned_rm = leave_record['rm']
    assigned_manager = leave_record['manager']
    document_path = leave_record['health_document']
    
    # Check permissions
    if user != document_owner and user != assigned_rm and user != assigned_manager:
        flash("Access denied. You don't have permission to download this document.")
        return redirect(url_for('dashboard'))
    
    if not document_path:
        flash("No document attached to this leave request.")
        return redirect(url_for('dashboard'))
    
    try:
        return send_file(
            os.path.join(app.config['UPLOAD_FOLDER'], document_path),
            as_attachment=True
        )
    except FileNotFoundError:
        flash("Document file not found on server.")
        return redirect(url_for('dashboard'))
    
    
@app.route('/approve_timesheet', methods=['POST'])
def approve_timesheet_action():
    if 'username' not in session:
        return redirect(url_for('login_sso'))
    
    user = session['username']
    ts_id = request.form.get('id')
    
    if not ts_id:
        flash(" Timesheet ID is required.")
        return redirect(url_for('dashboard'))
    
    try:
        # Get timesheet and employee details
        timesheet_query = run_query("""
            SELECT t.username, t.rm_approver, r.rm, r.manager
            FROM timesheets t
            LEFT JOIN report r ON t.username = r.username
            WHERE t.id = ? AND t.rm_status = 'Pending'
        """, (int(ts_id),))
        
        if timesheet_query.empty:
            flash(" Timesheet not found or already processed.")
            return redirect(url_for('dashboard'))
        
        timesheet = timesheet_query.iloc[0]
        employee_username = timesheet['username']
        assigned_rm = timesheet['rm']  # From report table
        assigned_manager = timesheet['manager']  # From report table
        
        #  ONLY RM CAN APPROVE - Manager cannot approve
        if user != assigned_rm:
            if user == assigned_manager:
                flash(f" You are the manager for {employee_username}, but only the RM ({assigned_rm}) can approve timesheets.")
            else:
                flash(f" You cannot approve timesheet for {employee_username}. Only RM ({assigned_rm}) can approve.")
            return redirect(url_for('dashboard'))
        
        # Approve the timesheet
        ok = run_exec("""
            UPDATE timesheets 
            SET rm_status = 'Approved', rm_approver = ?
            WHERE id = ? AND rm_status = 'Pending'
        """, (user, int(ts_id)))
        
        if ok:
            flash(f" Timesheet approved for {employee_username}")
            user_email = get_user_email(employee_username)
            if user_email:
                subject = f"Timesheet Approved - {employee_username}"
                text_content = f"""Dear {employee_username},

        Your timesheet has been approved by your RM.

        You can view the updated status in your dashboard.
        https://nexus.chervicaon.com

        This is an automated notification from the Timesheet & Leave Management System."""
                send_email(user_email, subject, text_content)
        else:
            flash(" Failed to approve timesheet")
    
    except Exception as e:
        flash(f" Error approving timesheet: {str(e)}")
    
    return redirect(url_for('dashboard'))

@app.route('/approve_leave', methods=['POST'])
def approve_leave_action():
    if 'username' not in session:
        return redirect(url_for('login_sso'))
    
    user = session['username']
    leave_id = request.form.get('id')
    
    if not leave_id:
        flash(" Leave ID is required.")
        return redirect(url_for('dashboard'))
    
    try:
        # Get leave and employee details
        leave_query = run_query("""
            SELECT l.username, l.leave_type, l.start_date, l.end_date, r.rm, r.manager
            FROM leaves l
            LEFT JOIN report r ON l.username = r.username
            WHERE l.id = ? AND l.rm_status = 'Pending'
        """, (int(leave_id),))
        
        if leave_query.empty:
            flash(" Leave not found or already processed.")
            return redirect(url_for('dashboard'))
        
        leave_details = leave_query.iloc[0]
        employee_username = leave_details['username']
        assigned_rm = leave_details['rm']
        assigned_manager = leave_details['manager']
        
        #  ONLY RM CAN APPROVE - Manager cannot approve
        if user != assigned_rm:
            if user == assigned_manager:
                flash(f" You are the manager for {employee_username}, but only the RM ({assigned_rm}) can approve leaves.")
            else:
                flash(f" You cannot approve leave for {employee_username}. Only RM ({assigned_rm}) can approve.")
            return redirect(url_for('dashboard'))
        
        # Calculate leave days and apply balance
        leave_type = str(leave_details['leave_type'])
        start_date = parse(str(leave_details['start_date']))
        end_date = parse(str(leave_details['end_date']))
        leave_days = (end_date - start_date).days + 1
        
        # Apply leave balance deduction
        _apply_leave_balance(employee_username, leave_type, leave_days, +1)
        
        # Approve the leave
        ok = run_exec("""
            UPDATE leaves 
            SET rm_status = 'Approved', rm_approver = ?
            WHERE id = ? AND rm_status = 'Pending'
        """, (user, int(leave_id)))
        
        if ok:
            # Notify employee about approval
            user_email = get_user_email(employee_username)
            if user_email:
                subject = f"Leave Request Approved - {employee_username}"
                text_content = f"""Dear {employee_username},

    Your leave request has been approved by your RM.

    Details:
    - Leave Type: {leave_type}
    - Duration: {leave_days} days
    - Status: Approved

    You can view the updated status in your dashboard.
    https://nexus.chervicaon.com

    This is an automated notification from the Timesheet & Leave Management System."""
                send_email(user_email, subject, text_content)

            flash(f" Leave approved for {employee_username} ({leave_days} days)")
            
        else:
            flash(" Failed to approve leave")
    
    except Exception as e:
        flash(f" Error approving leave: {str(e)}")
    
    return redirect(url_for('dashboard'))

@app.route('/reject_timesheet', methods=['POST'])
def reject_timesheet_action():
    if 'username' not in session:
        return redirect(url_for('login_sso'))
    
    user = session['username']
    timesheet_id = request.form.get('id')
    reason = request.form.get('rejection_reason', 'Not specified')
    
    if not timesheet_id:
        flash(" Timesheet ID is required.")
        return redirect(url_for('dashboard'))
    
    #  CRITICAL FIX: Only reject if user is the ASSIGNED RM
    timesheet_check = run_query("""
        SELECT t.username, r.rm FROM timesheets t
        LEFT JOIN report r ON t.username = r.username
        WHERE t.id = ? AND r.rm = ? AND t.rm_status = 'Pending'
    """, (int(timesheet_id), user))
    
    if timesheet_check.empty:
        flash(" You can only reject timesheets where you are the assigned RM.")
        return redirect(url_for('dashboard'))
    
    employee_username = timesheet_check.iloc[0]['username']
    
    ok = run_exec("""
        UPDATE timesheets 
        SET rm_status = 'Rejected', rm_approver = ?, rm_rejection_reason = ? 
        WHERE id = ? AND rm_status = 'Pending'
    """, (user, reason, int(timesheet_id)))
    
    if ok:
        flash(f" Timesheet rejected for {employee_username} with reason: {reason}")
        user_email = get_user_email(employee_username)
        if user_email:
            subject = f"Timesheet Rejected - {employee_username}"
            text_content = f"""Dear {employee_username},

    Your timesheet has been rejected by your RM.

    Reason: {reason}

    Please contact your RM or resubmit your timesheet with corrections.
    https://nexus.chervicaon.com

    This is an automated notification from the Timesheet & Leave Management System."""
            send_email(user_email, subject, text_content)

            
        
    else:
        flash(" Failed to reject timesheet.")
    
    return redirect(url_for('dashboard'))

@app.route('/reject_leave', methods=['POST'])
def reject_leave_action():
    if 'username' not in session:
        return redirect(url_for('login_sso'))
    
    user = session['username']
    leave_id = request.form.get('id')
    reason = request.form.get('reason', 'Not specified')
    
    if not leave_id:
        flash(" Leave ID is required.")
        return redirect(url_for('dashboard'))
    
    #  CRITICAL FIX: Only reject if user is the ASSIGNED RM
    leave_check = run_query("""
        SELECT l.username, r.rm FROM leaves l
        LEFT JOIN report r ON l.username = r.username
        WHERE l.id = ? AND r.rm = ? AND l.rm_status = 'Pending'
    """, (int(leave_id), user))
    
    if leave_check.empty:
        flash(" You can only reject leaves where you are the assigned RM.")
        return redirect(url_for('dashboard'))
    
    employee_username = leave_check.iloc[0]['username']
    
    ok = run_exec("""
        UPDATE leaves 
        SET rm_status = 'Rejected', rm_approver = ?, rm_rejection_reason = ? 
        WHERE id = ? AND rm_status = 'Pending'
    """, (user, reason, int(leave_id)))
    
    if ok:
        # Notify employee about rejection
        user_email = get_user_email(employee_username)
        if user_email:
            subject = f"Leave Request Rejected - {employee_username}"
            text_content = f"""Dear {employee_username},

Your leave request has been rejected by your RM.

Reason: {reason}

Please contact your RM for clarification or resubmit your request with corrections.
https://nexus.chervicaon.com
This is an automated notification from the Timesheet & Leave Management System."""
            send_email(user_email, subject, text_content)

        flash(f" Leave rejected for {employee_username} with reason: {reason}")
        
    else:
        flash(" Failed to reject leave.")
    
    return redirect(url_for('dashboard'))

# Manager Specific Routes
# --------------------
@app.route('/approve_manager_timesheet', methods=['POST'])
def approve_manager_timesheet():
    """Approve timesheet for manager's direct reports - ROLE BASED"""
    if 'username' not in session:
        flash("Access denied.")
        return redirect(url_for('dashboard'))
    
    user = session['username']
    
    if not has_role(user, MANAGER_ROLES):
        flash("Access denied. Manager privileges required.")
        return redirect(url_for('dashboard'))
    
    timesheet_id = request.form.get('timesheet_id')
    
    if not timesheet_id:
        flash("Timesheet ID is required.")
        return redirect(url_for('dashboard'))
    
    # Get manager's team
    manager_team = get_all_reports_recursive(user)
    if not manager_team:
        flash("No team members found for approval.")
        return redirect(url_for('dashboard'))
    
    placeholders = ",".join(["?"] * len(manager_team))
    
    try:
        # FIXED: Use EXACT column names from your database schema
        query_params = [int(timesheet_id)] + list(manager_team)
        timesheet_details = run_query(f"""
            SELECT t.username, t.project_name, t.work_date, t.hours, t.work_desc 
            FROM timesheets t 
            WHERE t.id = ? AND t.username IN ({placeholders}) AND t.rm_status = 'Pending'
        """, query_params)
        
        if not timesheet_details.empty:
            # Extract variables from query result
            employee_username = timesheet_details.iloc[0]['username']
            project_name = timesheet_details.iloc[0]['project_name']
            work_date = timesheet_details.iloc[0]['work_date']
            hours = timesheet_details.iloc[0]['hours']
            work_desc = timesheet_details.iloc[0]['work_desc']
            
            # FIXED: Use correct column names and parameter order
            update_params = [user, int(timesheet_id)] + list(manager_team)
            ok = run_exec(f"""
                UPDATE timesheets 
                SET rm_status = 'Approved', rm_approver = ?, rm_rejection_reason = NULL 
                WHERE id = ? AND username IN ({placeholders}) AND rm_status = 'Pending'
            """, update_params)
            
            if ok:
                flash("Timesheet approved successfully.")
                
                # Send email notification
                user_email = get_user_email(employee_username)
                if user_email:
                    subject = f"Timesheet Approved by Manager - {employee_username}"
                    text_content = f"""Dear {employee_username},

Your timesheet has been approved by your Manager {user}.

Details:
- Date: {work_date}
- Project: {project_name}
- Hours: {hours}
- Description: {work_desc[:100]}{'...' if len(work_desc) > 100 else ''}
- Status: Approved

You can view the updated status in your dashboard.
https://nexus.chervicaon.com
This is an automated notification from the Timesheet Leave Management System."""
                    
                    send_email(user_email, subject, text_content)
            else:
                flash("Failed to approve timesheet.")
        else:
            flash("Timesheet not found in your team or already processed.")
    
    except Exception as e:
        flash(f"Error approving timesheet: {str(e)}")
    
    return redirect(url_for('dashboard'))

@app.route('/reject_manager_timesheet', methods=['POST'])
def reject_manager_timesheet():
    """Reject timesheet for manager's direct reports - ROLE BASED"""
    if 'username' not in session:
        flash("Access denied.")
        return redirect(url_for('dashboard'))
    
    user = session['username']
    
    if not has_role(user, MANAGER_ROLES):
        flash("Access denied. Manager privileges required.")
        return redirect(url_for('dashboard'))
    
    timesheet_id = request.form.get('timesheet_id')
    rejection_reason = request.form.get('rejection_reason', '').strip()
    
    if not timesheet_id:
        flash("Timesheet ID is required.")
        return redirect(url_for('dashboard'))
    
    if not rejection_reason:
        flash("Please provide a reason for rejection.")
        return redirect(url_for('dashboard'))
    
    # Get manager's team
    manager_team = get_all_reports_recursive(user)
    if not manager_team:
        flash("No team members found.")
        return redirect(url_for('dashboard'))
    
    placeholders = ",".join(["?"] * len(manager_team))
    
    try:
        # FIXED: Use correct column names and parameter order
        update_params = [user, rejection_reason, int(timesheet_id)] + list(manager_team)
        ok = run_exec(f"""
            UPDATE timesheets 
            SET rm_status = 'Rejected', rm_approver = ?, rm_rejection_reason = ?
            WHERE id = ? AND username IN ({placeholders}) AND rm_status = 'Pending'
        """, update_params)
        
        if ok:
            # Get timesheet details for email
            timesheet_details = run_query("""
                SELECT username, project_name, work_date, hours, work_desc 
                FROM timesheets
                WHERE id = ? AND rm_status = 'Rejected'
            """, [int(timesheet_id)])
            
            if not timesheet_details.empty:
                employee_username = timesheet_details.iloc[0]['username']
                project_name = timesheet_details.iloc[0]['project_name']
                work_date = timesheet_details.iloc[0]['work_date']
                hours = timesheet_details.iloc[0]['hours']
                work_desc = timesheet_details.iloc[0]['work_desc']
                
                # Send email notification
                user_email = get_user_email(employee_username)
                if user_email:
                    subject = f"Timesheet Rejected by Manager - {employee_username}"
                    text_content = f"""Dear {employee_username},

Your timesheet has been rejected by your Manager {user}.

Details:
- Date: {work_date}
- Project: {project_name}
- Hours: {hours}
- Description: {work_desc[:100]}{'...' if len(work_desc) > 100 else ''}
- Status: Rejected
- Rejection Reason: {rejection_reason}

Please contact your Manager for clarification or resubmit your timesheet with corrections.
https://nexus.chervicaon.com
This is an automated notification from the Timesheet Leave Management System."""
                    
                    send_email(user_email, subject, text_content)
            
            flash(f"Timesheet rejected. Reason: {rejection_reason}")
        else:
            flash("Failed to reject timesheet or timesheet not found.")
    
    except Exception as e:
        flash(f"Error rejecting timesheet: {str(e)}")
    
    return redirect(url_for('dashboard'))


@app.route('/approve_manager_leave_request', methods=['POST'])
def approve_manager_leave_request():
    """Approve leave for manager's direct reports - ROLE BASED"""
    if 'username' not in session:
        flash("Access denied.")
        return redirect(url_for('dashboard'))
    
    user = session['username']
    
    if not has_role(user, MANAGER_ROLES):
        flash("Access denied. Manager privileges required.")
        return redirect(url_for('dashboard'))
    
    leave_id = request.form.get('leave_id')
    
    if not leave_id:
        flash("Leave ID is required.")
        return redirect(url_for('dashboard'))
    
    # Get manager's team
    manager_team = get_all_reports_recursive(user)
    if not manager_team:
        flash("No team members found for approval.")
        return redirect(url_for('dashboard'))
    
    placeholders = ",".join(["?"] * len(manager_team))
    
    try:
        # FIXED: Use EXACT column names from your database schema
        query_params = [int(leave_id)] + list(manager_team)
        leave_details = run_query(f"""
            SELECT username, leave_type, start_date, end_date, description 
            FROM leaves 
            WHERE id = ? AND username IN ({placeholders}) AND rm_status = 'Pending'
        """, query_params)
        
        if not leave_details.empty:
            # Extract variables from query result
            leave_username = leave_details.iloc[0]['username']
            leave_type = str(leave_details.iloc[0]['leave_type'])
            start_date = parse(str(leave_details.iloc[0]['start_date']))
            end_date = parse(str(leave_details.iloc[0]['end_date']))
            description = leave_details.iloc[0]['description']
            leave_days = (end_date - start_date).days + 1
            
            # Apply leave balance deduction
            _apply_leave_balance(leave_username, leave_type, leave_days, 1)
            
            # FIXED: Use EXACT column names and correct parameter order
            update_params = [user, int(leave_id)] + list(manager_team)
            ok = run_exec(f"""
                UPDATE leaves 
                SET rm_status = 'Approved', rm_approver = ?, rm_rejection_reason = NULL 
                WHERE id = ? AND username IN ({placeholders}) AND rm_status = 'Pending'
            """, update_params)
            
            if ok:
                flash(f'Leave approved successfully for {leave_username} ({leave_days} days).')
                
                # Send email notification
                user_email = get_user_email(leave_username)
                if user_email:
                    subject = f"Leave Approved by Manager - {leave_username}"
                    text_content = f"""Dear {leave_username},

Your leave request has been approved by your Manager {user}.

Details:
- Leave Type: {leave_type}
- Duration: {leave_days} days
- Start Date: {start_date.strftime('%Y-%m-%d')}
- End Date: {end_date.strftime('%Y-%m-%d')}
- Reason: {description}
- Status: Approved

You can view the updated status in your dashboard.
https://nexus.chervicaon.com
This is an automated notification from the Timesheet Leave Management System."""
                    
                    send_email(user_email, subject, text_content)
            else:
                flash("Failed to approve leave.")
        else:
            flash("Leave not found in your team or already processed.")
    
    except Exception as e:
        flash(f"Error approving leave: {str(e)}")
    
    return redirect(url_for('dashboard'))

@app.route('/reject_manager_leave_request', methods=['POST'])
def reject_manager_leave_request():
    """Reject leave for manager's direct reports - ROLE BASED"""
    if 'username' not in session:
        flash("Access denied.")
        return redirect(url_for('dashboard'))
    
    user = session['username']
    
    if not has_role(user, MANAGER_ROLES):
        flash("Access denied. Manager privileges required.")
        return redirect(url_for('dashboard'))
    
    leave_id = request.form.get('leave_id')
    rejection_reason = request.form.get('rejection_reason', '').strip()
    
    if not leave_id:
        flash("Leave ID is required.")
        return redirect(url_for('dashboard'))
    
    if not rejection_reason:
        flash("Please provide a reason for rejection.")
        return redirect(url_for('dashboard'))
    
    # Get manager's team
    manager_team = get_all_reports_recursive(user)
    if not manager_team:
        flash("No team members found.")
        return redirect(url_for('dashboard'))
    
    placeholders = ",".join(["?"] * len(manager_team))
    
    try:
        # FIXED: Use EXACT column names and correct parameter order
        update_params = [user, rejection_reason, int(leave_id)] + list(manager_team)
        ok = run_exec(f"""
            UPDATE leaves 
            SET rm_status = 'Rejected', rm_approver = ?, rm_rejection_reason = ?
            WHERE id = ? AND username IN ({placeholders}) AND rm_status = 'Pending'
        """, update_params)
        
        if ok:
            # Get leave details for email
            leave_details = run_query("""
                SELECT username, leave_type, start_date, end_date, description 
                FROM leaves
                WHERE id = ? AND rm_status = 'Rejected'
            """, [int(leave_id)])
            
            if not leave_details.empty:
                leave_username = leave_details.iloc[0]['username']
                leave_type = leave_details.iloc[0]['leave_type']
                start_date = parse(str(leave_details.iloc[0]['start_date']))
                end_date = parse(str(leave_details.iloc[0]['end_date']))
                leave_days = (end_date - start_date).days + 1
                description = leave_details.iloc[0]['description']
                
                # Send email notification
                user_email = get_user_email(leave_username)
                if user_email:
                    subject = f"Leave Request Rejected - {leave_username}"
                    text_content = f"""Dear {leave_username},

Your leave request has been rejected by your Manager ({user}).

Details:
- Leave Type: {leave_type}
- Duration: {leave_days} days
- Start Date: {start_date.strftime('%Y-%m-%d')}
- End Date: {end_date.strftime('%Y-%m-%d')}
- Reason: {description}
- Rejection Reason: {rejection_reason}
- Rejected by: {user}

Please contact your Manager for clarification or resubmit your request with corrections.
https://nexus.chervicaon.com
This is an automated notification from the Timesheet & Leave Management System."""
                    
                    send_email(user_email, subject, text_content)  
            flash(f"Leave rejected. Reason: {rejection_reason}")
        else:
            flash("Failed to reject leave or leave not found.")
    
    except Exception as e:
        flash(f"Error rejecting leave: {str(e)}")
    
    return redirect(url_for('dashboard'))




@app.route('/api/budget_refresh')
def budget_refresh():
    """API endpoint to get current budget status for real-time updates"""
    if 'username' not in session:
        return jsonify({'error': 'Unauthorized'}), 401
    
    try:
        # Get current budget data
        total_budget_df = run_query("SELECT total_budget FROM company_budget WHERE id = 1")
        total_budget = float(total_budget_df['total_budget'].iloc[0]) if not total_budget_df.empty else 0.0
        
        # Project allocations
        project_allocated_df = run_query("""
            SELECT COALESCE(SUM(CAST(budget_amount AS DECIMAL(18,2))), 0) as allocated 
            FROM projects 
            WHERE hr_approval_status = 'Approved' 
            AND budget_amount IS NOT NULL
            AND CAST(budget_amount AS DECIMAL(18,2)) > 0
            AND project_name NOT LIKE 'Salary%'
            AND project_name NOT LIKE 'Asset Purchase%'
        """)
        project_allocated = float(project_allocated_df['allocated'].iloc[0]) if not project_allocated_df.empty else 0.0
        
        # Payroll & Asset allocations
        payroll_df = run_query("""
            SELECT COALESCE(SUM(CAST(yearly_salary AS DECIMAL(18,2))), 0) as total_payroll
            FROM users 
            WHERE status = 'Active' AND yearly_salary IS NOT NULL
        """)
        current_payroll = float(payroll_df['total_payroll'].iloc[0]) if not payroll_df.empty else 0.0
        
        asset_allocated_df = run_query("""
            SELECT COALESCE(SUM(CAST(amount AS DECIMAL(18,2))), 0) as asset_total
            FROM asset_requests 
            WHERE status = 'Approved'
        """)
        asset_allocated = float(asset_allocated_df['asset_total'].iloc[0]) if not asset_allocated_df.empty else 0.0
        
        payroll_asset_allocated = current_payroll + asset_allocated
        remaining_budget = total_budget - project_allocated - payroll_asset_allocated
        
        return jsonify({
            'success': True,
            'total_budget': total_budget,
            'project_allocated': project_allocated,
            'payroll_asset_allocated': payroll_asset_allocated,
            'remaining_budget': remaining_budget
        })
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500
    
    # Project Management Routes
# --------------------
@app.route('/create_project_action', methods=['POST'])
def create_project_action():
    """Create new project action"""
    if 'username' not in session:
        return redirect(url_for('login_sso'))
    
    user = session['username']
    pname = request.form.get('pname')
    pdesc = request.form.get('pdesc')
    due = request.form.get('due')
    
    if not pname or not pdesc or not due:
        flash("Please fill in all required fields.")
        return redirect(url_for('dashboard'))
    
    existing = run_query("SELECT project_name FROM projects WHERE project_name = ?", (pname,))
    if not existing.empty:
        flash("Project name already exists. Please choose a different name.")
        return redirect(url_for('dashboard'))
    
    ok = run_exec("""
        INSERT INTO [timesheet_db].[dbo].[projects] (project_name, description, created_on, end_date, status, hr_approval_status, created_by)
        VALUES (?, ?, ?, ?, 'Pending', 'Pending', ?)
    """, (pname, pdesc, date.today(), due, user))
    
    if ok:
        # NEW: Email notification to HR about new project creation
        hr_users = run_query("""
            SELECT email FROM users 
            WHERE role IN ('Hr & Finance Controller', 'Manager') 
            AND status = 'Active' AND email IS NOT NULL
        """)
        
        if not hr_users.empty:
            for _, hr_user in hr_users.iterrows():
                hr_email = hr_user['email']
                if hr_email:
                    subject = f"New Project Created - {pname}"
                    text_content = f"""Dear Team,

A new project has been created and requires approval.

Project Details:
- Name: {pname}
- Description: {pdesc}
- Created by: {user}
- Due date: {due}
- Status: Pending Approval

Please log in to the system to review and approve this project.
https://nexus.chervicaon.com
This is an automated notification from the Timesheet & Leave Management System."""
                    send_email(hr_email, subject, text_content)

        flash(f"Project '{pname}' created successfully and submitted for approval.")
        
    else:
        flash("Failed to create project.")
    
    return redirect(url_for('dashboard'))

@app.route('/record_expense_action', methods=['POST'])
def record_expense_action():
    """Record expense action - UPDATED WITH DOCUMENT UPLOAD"""
    if 'username' not in session:
        return redirect(url_for('login_sso'))
    
    user = session['username']
    project = request.form.get('project')
    category = request.form.get('category')
    amount = request.form.get('amount')
    exp_date = request.form.get('exp_date')
    desc = request.form.get('desc')
    
    if not project or not category or not amount or not desc:
        flash("Please fill in all required fields.")
        return redirect(url_for('dashboard'))
    
    # Handle document upload
    document_path = None
    if 'expense_document' in request.files:
        file = request.files['expense_document']
        if file.filename != '':
            document_path = save_uploaded_file(file, "expense")
    
    try:
        ok = run_exec("""
            INSERT INTO [timesheet_db].[dbo].[expenses] 
            (project_name, category, amount, date, description, spent_by, document_path)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        """, (project, category, float(amount), exp_date, desc, user, document_path))
        
        if ok:
            # NEW: Email notification to managers about expense recording
            managers = run_query("""
                SELECT email FROM users 
                WHERE role IN ('Manager', 'Hr & Finance Controller', 'Lead', 'Finance Manager') 
                AND status = 'Active' AND email IS NOT NULL
            """)
            
            if not managers.empty:
                for _, manager in managers.iterrows():
                    manager_email = manager['email']
                    if manager_email:
                        subject = f"New Expense Recorded - {project}"
                        text_content = f"""Dear Manager,

A new expense has been recorded that may require your review.

Expense Details:
- Project: {project}
- Category: {category}
- Amount: ₹{float(amount):,.2f}
- Date: {exp_date}
- Description: {desc}
- Recorded by: {user}
- Document: {'Attached' if document_path else 'Not provided'}

Please review this expense entry in the system.
https://nexus.chervicaon.com
This is an automated notification from the Timesheet & Leave Management System."""
                        send_email(manager_email, subject, text_content)

            flash("Expense recorded successfully.")
        else:
            flash("Failed to record expense.")
    except Exception as e:
        flash(f"Error recording expense: {str(e)}")
    
    return redirect(url_for('dashboard'))

@app.route('/assign_project_multiple_action', methods=['POST'])
def assign_project_multiple_action():
    """Assign project to multiple employees directly"""
    if 'username' not in session:
        return redirect(url_for('login_sso'))
    
    employee_usernames = request.form.getlist('employees')
    project_name = request.form.get('project_name')
    start_date = request.form.get('start_date')
    end_date = request.form.get('end_date')
    assignment_notes = request.form.get('assignment_notes')
    
    if not employee_usernames or not project_name or not start_date or not end_date:
        flash("Please select employees, project, and dates.")
        return redirect(url_for('dashboard'))
    
    success_count = 0
    failed_employees = []
    
    for employee in employee_usernames:
        try:
            # Use the correct assigned_work table with proper column names
            ok = run_exec("""
                INSERT INTO [timesheet_db].[dbo].[assigned_work] 
                (assigned_by, assigned_to, project_name, task_desc, start_date, due_date, 
                 assigned_on, rm_status, manager_status, work_type)
                VALUES (?, ?, ?, ?, ?, ?, ?, 'Approved', 'Approved', 'Project Assignment')
            """, (session['username'], employee, project_name, 
                  assignment_notes or f"Assigned to project: {project_name}", 
                  start_date, end_date, date.today()))
            
            if ok:
                success_count += 1
                # ADD EMAIL NOTIFICATION HERE
                emp_email = get_user_email(employee)
                if emp_email:
                    subject = f"New Project Assignment - {employee}"
                    text_content = f"""Dear {employee},

You have been assigned to a new project.

Project Assignment Details:
- Assigned by: {session['username']}
- Project: {project_name}
- Start Date: {start_date}
- End Date: {end_date}
- Notes: {assignment_notes or 'No additional notes'}

Please log in to your dashboard to view the complete project details and begin work.
https://nexus.chervicaon.com
This is an automated notification from the Timesheet & Leave Management System."""
                    
                    send_email(emp_email, subject, text_content)

            else:
                failed_employees.append(employee)
        except Exception as e:
            print(f"Error assigning to {employee}: {e}")
            failed_employees.append(employee)
    
    if success_count > 0:
        flash(f" Project '{project_name}' assigned successfully to {success_count} employee(s).")
    
    if failed_employees:
        flash(f" Failed to assign project to: {', '.join(failed_employees)}")
    
    return redirect(url_for('dashboard'))

@app.route('/manager_assign_work_action', methods=['POST'])
def manager_assign_work_action():
    """Manager assigns work to team members"""
    if 'username' not in session:
        return redirect(url_for('login_sso'))
    
    user = session['username']
    assignees_raw = request.form.get('assignees_raw', '')
    project = request.form.get('project', '')
    start_date = request.form.get('start_d')
    due_date = request.form.get('due_d')
    description = request.form.get('desc')
    
    if not assignees_raw or not description:
        flash("Please select team members and provide task description.")
        return redirect(url_for('dashboard'))
    
    # Parse assignees
    assignees = [name.strip() for name in assignees_raw.split(',') if name.strip()]
    
    success_count = 0
    failed_employees = []
    
    for assignee in assignees:
        try:
            ok = run_exec("""
                INSERT INTO [timesheet_db].[dbo].[assigned_work] 
                (assigned_by, assigned_to, project_name, task_desc, start_date, due_date, 
                 assigned_on, manager_status, rm_status, work_type)
                VALUES (?, ?, ?, ?, ?, ?, ?, 'Pending', 'Approved', 'Task Assignment')
            """, (user, assignee, project, description, start_date, due_date, date.today()))
            
            if ok:
                success_count += 1
                # ADD EMAIL NOTIFICATION HERE
                emp_email = get_user_email(assignee)
                if emp_email:
                    subject = f"New Work Assignment - {assignee}"
                    text_content = f"""Dear {assignee},

You have been assigned new work by your Manager {user}.

Assignment Details:
- Assigned by: {user}
- Project: {project or 'General Task'}
- Task Description: {description}
- Start Date: {start_date}
- Due Date: {due_date}

Please log in to your dashboard to view the complete assignment details and update the status as you progress.
https://nexus.chervicaon.com
This is an automated notification from the Timesheet & Leave Management System."""
                    
                    send_email(emp_email, subject, text_content)

            else:
                failed_employees.append(assignee)
        except Exception as e:
            print(f"Error assigning to {assignee}: {e}")
            failed_employees.append(assignee)
    
    if success_count > 0:
        flash(f" Work assigned successfully to {success_count} team member(s).")
    
    if failed_employees:
        flash(f" Failed to assign work to: {', '.join(failed_employees)}")
    
    return redirect(url_for('dashboard'))


@app.route('/rm_assign_work_action', methods=['POST'])
def rm_assign_work_action():
    """RM assign work action - UPDATED with proper validation"""
    if 'username' not in session:
        return redirect(url_for('login_sso'))
    
    user = session['username']
    employee_usernames = request.form.getlist('employee_username')
    project_name = request.form.get('project_name', '')
    task_desc = request.form.get('task_desc', '').strip()
    due_date = request.form.get('due_date')
    priority = request.form.get('priority', 'Medium')
    
    if not employee_usernames or not task_desc:
        flash(" Please select at least one employee and provide task description.")
        return redirect(url_for('dashboard'))
    
    # Get all team members user can assign work to
    all_team_members = get_all_reports_recursive(user)
    
    if not all_team_members:
        flash(" You don't have any team members to assign work to.")
        return redirect(url_for('dashboard'))
    
    # Validate that selected employees are in user's team
    invalid_employees = [emp for emp in employee_usernames if emp not in all_team_members]
    
    if invalid_employees:
        flash(f" You can only assign work to your team members. Invalid: {', '.join(invalid_employees)}")
        return redirect(url_for('dashboard'))
    
    success_count = 0
    failed_employees = []
    
    for employee in employee_usernames:
        try:
            # Insert work assignment
            ok = run_exec("""
                INSERT INTO [timesheet_db].[dbo].[assigned_work] (
                    assigned_by, assigned_to, task_desc, start_date, due_date, 
                    project_name, rm_status, manager_status, assigned_on
                ) VALUES (?, ?, ?, ?, ?, ?, 'Approved', 'Pending', ?)
            """, (user, employee, task_desc, date.today(), due_date, 
                  project_name, date.today()))
            
            if ok:
                success_count += 1
                # Send notification to assigned employee
                emp_email = get_user_email(employee)
                if emp_email:
                    subject = f"New Work Assignment - {employee}"
                    text_content = f"""Dear {employee},

You have been assigned a new task by your RM {user}.

Details:
- Assigned by: {user}
- Project: {project_name}
- Task Description: {task_desc}
- Due Date: {due_date}

Please log in to the system to view the complete assignment details.
https://nexus.chervicaon.com
This is an automated notification from the Timesheet & Leave Management System."""
                    send_email(emp_email, subject, text_content)

            else:
                failed_employees.append(employee)
                
        except Exception as e:
            print(f"Error assigning to {employee}: {e}")
            failed_employees.append(employee)
    
    # Success/failure messages
    if success_count > 0:
        successful_employees = [emp for emp in employee_usernames if emp not in failed_employees]
        flash(f" Work assigned successfully to {success_count} team member(s): {', '.join(successful_employees)}")
        
    
    if failed_employees:
        flash(f" Failed to assign work to: {', '.join(failed_employees)}")
    
    return redirect(url_for('dashboard'))


@app.route('/complete_work_assignment', methods=['POST'])
def complete_work_assignment():
    """Mark work assignment as completed"""
    if 'username' not in session:
        return redirect(url_for('login_sso'))
    
    user = session['username']
    assignment_id = request.form.get('assignment_id')
    completion_notes = request.form.get('completion_notes', '').strip()
    
    if not assignment_id:
        flash(" Assignment ID is required.")
        return redirect(url_for('dashboard'))
    
    try:
        # Verify the assignment belongs to the current user
        assignment_check = run_query("""
            SELECT assigned_to, task_desc FROM assigned_work 
            WHERE id = ? AND assigned_to = ?
        """, (int(assignment_id), user))
        
        if assignment_check.empty:
            flash(" Assignment not found or access denied.")
            return redirect(url_for('dashboard'))
        
        # Update assignment status
        ok = run_exec("""
            UPDATE assigned_work 
            SET status = 'Completed', completed_on = GETDATE(), completion_notes = ?
            WHERE id = ? AND assigned_to = ?
        """, (completion_notes, int(assignment_id), user))
        
        if ok:
            # Get assignment details for notification
            assignment_details = run_query("""
                SELECT assigned_by, task_desc, project_name 
                FROM assigned_work WHERE id = ?
            """, (int(assignment_id),))
            
            if not assignment_details.empty:
                assigner = assignment_details.iloc[0]['assigned_by']
                task_desc = assignment_details.iloc[0]['task_desc']
                project_name = assignment_details.iloc[0]['project_name']
                
                assigner_email = get_user_email(assigner)
                if assigner_email:
                    subject = f"Work Assignment Completed - {user}"
                    text_content = f"""Dear {assigner},

    {user} has completed the work assignment you assigned.

    Details:
    - Task: {task_desc}
    - Project: {project_name}
    - Completed by: {user}
    - Completion Notes: {completion_notes or 'None provided'}
    please login here
    https://nexus.chervicaon.com
    This is an automated notification from the Timesheet & Leave Management System."""
                    send_email(assigner_email, subject, text_content)
            flash(" Work assignment marked as completed!")
        else:
            flash(" Failed to update assignment status.")
            
    except Exception as e:
        flash(f" Error completing assignment: {str(e)}")
    
    return redirect(url_for('dashboard'))


@app.route('/approve_rm_assignment', methods=['POST'])
def approve_rm_assignment():
    """Approve RM work assignment (Divyaavasudevan)"""
    if 'username' not in session or session['username'].lower() not in ['divyavasudevan', 'divyaavasudevan']:
        flash(" Access denied.")
        return redirect(url_for('dashboard'))
    
    assignment_id = request.form.get('assignment_id')
    
    try:
        ok = run_exec("""
            UPDATE assigned_work 
            SET manager_status = 'Approved', manager_approver = ?
            WHERE id = ?
        """, (session['username'], int(assignment_id)))
        
        if ok:
            flash(" Work assignment approved and sent to employee.")
        else:
            flash(" Failed to approve work assignment.")
    
    except Exception as e:
        flash(f" Error approving assignment: {str(e)}")
    
    return redirect(url_for('dashboard'))

@app.route('/reject_rm_assignment', methods=['POST'])
def reject_rm_assignment():
    """Reject RM work assignment with reason (Divyaavasudevan)"""
    if 'username' not in session or session['username'].lower() not in ['Divyavasudevan', 'Divyaavasudevan']:
        flash(" Access denied.")
        return redirect(url_for('dashboard'))
    
    assignment_id = request.form.get('assignment_id')
    rejection_reason = request.form.get('rejection_reason', '').strip()
    
    if not rejection_reason:
        flash(" Please provide a reason for rejection.")
        return redirect(url_for('dashboard'))
    
    try:
        ok = run_exec("""
            UPDATE assigned_work 
            SET manager_status = 'Rejected', 
                rm_rejection_reason = ?, 
                manager_approver = ?
            WHERE id = ?
        """, (rejection_reason, session['username'], int(assignment_id)))
        
        if ok:
            flash(f" Work assignment rejected. Reason: {rejection_reason}")
        else:
            flash(" Failed to reject work assignment.")
    
    except Exception as e:
        flash(f" Error rejecting assignment: {str(e)}")
    
    return redirect(url_for('dashboard'))

# HR Finance Action Routes - COMPLETE
# --------------------
@app.route('/view_expense_document/<int:expense_id>')
def view_expense_document(expense_id):
    """View expense document"""
    if 'username' not in session:
        return redirect(url_for('login_sso'))
    
    expense = run_query("SELECT document_path FROM expenses WHERE id = ?", (expense_id,))
    
    if not expense.empty and expense.iloc[0]['document_path']:
        document_path = expense.iloc[0]['document_path']
        return send_file(os.path.join(app.config['UPLOAD_FOLDER'], document_path))
    
    flash("Document not found.")
    return redirect(url_for('dashboard'))

@app.route('/view_asset_document/<int:asset_id>')
def view_asset_document(asset_id):
    """View asset request document"""
    if 'username' not in session:
        return redirect(url_for('login_sso'))
    
    asset = run_query("SELECT document_path FROM asset_requests WHERE id = ?", (asset_id,))
    
    if not asset.empty and asset.iloc[0]['document_path']:
        document_path = asset.iloc[0]['document_path']
        return send_file(os.path.join(app.config['UPLOAD_FOLDER'], document_path))
    
    flash("Document not found.")
    return redirect(url_for('dashboard'))

@app.route('/download_expense_document/<int:expense_id>')
def download_expense_document(expense_id):
    """Download expense document"""
    if 'username' not in session:
        return redirect(url_for('login_sso'))
    
    expense = run_query("SELECT document_path FROM expenses WHERE id = ?", (expense_id,))
    
    if not expense.empty and expense.iloc[0]['document_path']:
        document_path = expense.iloc[0]['document_path']
        return send_file(
            os.path.join(app.config['UPLOAD_FOLDER'], document_path),
            as_attachment=True
        )
    
    flash("Document not found.")
    return redirect(url_for('dashboard'))

@app.route('/download_asset_document/<int:asset_id>')
def download_asset_document(asset_id):
    """Download asset request document"""
    if 'username' not in session:
        return redirect(url_for('login_sso'))
    
    asset = run_query("SELECT document_path FROM asset_requests WHERE id = ?", (asset_id,))
    
    if not asset.empty and asset.iloc[0]['document_path']:
        document_path = asset.iloc[0]['document_path']
        return send_file(
            os.path.join(app.config['UPLOAD_FOLDER'], document_path),
            as_attachment=True
        )
    
    flash("Document not found.")
    return redirect(url_for('dashboard'))



ALLOWED_EXTENSIONS = {'txt', 'pdf', 'png', 'jpg', 'jpeg', 'gif', 'doc', 'docx', 'xls', 'xlsx'}

def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def save_uploaded_file(file, prefix="doc"):
    """Save uploaded file and return the filename"""
    if file and allowed_file(file.filename):
        timestamp = int(datetime.now().timestamp())
        filename = secure_filename(file.filename)
        saved_filename = f"{prefix}{timestamp}{filename}"
        file.save(os.path.join(app.config['UPLOAD_FOLDER'], saved_filename))
        return saved_filename
    return None

@app.route('/get_pending_approvals')
def get_pending_approvals():
    """Get projects that actually need HR approval"""
    if 'username' not in session or session['role'] != 'Hr & Finance Controller':
        return jsonify({'error': 'Access denied'}), 403
    
    try:
        pending_approvals = run_query("""
            SELECT project_id, project_name, created_by, description, created_on, end_date, cost_center
            FROM projects
            WHERE hr_approval_status = 'Pending'
            ORDER BY created_on DESC
        """)
        
        return jsonify({
            'success': True,
            'pending_projects': pending_approvals.to_dict('records') if not pending_approvals.empty else []
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/allocate_budget_action', methods=['POST'])
def allocate_budget_action():
    """Allocate budget to a project from REMAINING budget"""
    if 'username' not in session:
        return redirect(url_for('login_sso'))
    
    user = session['username']
    project_name = request.form.get('project_name')
    budget_amount = request.form.get('budget_amount')
    cost_center = request.form.get('cost_center')
    notes = request.form.get('notes', '')
    
    if not project_name or not budget_amount or not cost_center:
        flash("Please fill in all required fields.")
        return redirect(url_for('dashboard'))
    
    try:
        budget_amount = float(budget_amount)
        
        budget_df = run_query("SELECT total_budget FROM company_budget WHERE id = 1")
        allocated_df = run_query("""
            SELECT COALESCE(SUM(CAST(budget_amount AS DECIMAL(18,2))), 0) as allocated 
            FROM projects 
            WHERE hr_approval_status = 'Approved' 
            AND budget_amount IS NOT NULL
            AND CAST(budget_amount AS DECIMAL(18,2)) > 0
        """)
        
        if not budget_df.empty and not allocated_df.empty:
            total_budget = float(budget_df['total_budget'].iloc[0])
            allocated = float(allocated_df['allocated'].iloc[0])
            remaining_budget = total_budget - allocated
            
            if remaining_budget >= budget_amount:
                ok = run_exec("""
                    UPDATE projects 
                    SET budget_amount = ?, cost_center = ?
                    WHERE project_name = ?
                """, (budget_amount, cost_center, project_name))
                
                if ok:
                    # Notify project creator about budget allocation
                    project_details = run_query("""
                        SELECT created_by FROM projects WHERE project_name = ?
                    """, (project_name,))
                    
                    if not project_details.empty:
                        creator = project_details.iloc[0]['created_by']
                        creator_email = get_user_email(creator)
                        
                        if creator_email:
                            subject = f"Budget Allocated - {project_name}"
                            text_content = f"""Dear {creator},

            Budget has been allocated to your project.

            Project: {project_name}
            Budget Amount: ₹{budget_amount:,.2f}
            Cost Center: {cost_center}
            Allocated by: {user}

            You can now start incurring expenses for this project.
            https://nexus.chervicaon.com
            This is an automated notification from the Timesheet & Leave Management System."""
                            send_email(creator_email, subject, text_content)

                    flash(f" Budget of ₹{budget_amount:,.2f} allocated to project '{project_name}'. Remaining budget: ₹{remaining_budget-budget_amount:,.2f}")
                else:
                    flash(" Failed to allocate budget.")
            else:
                flash(f" Insufficient remaining budget. Required: ₹{budget_amount:,.2f}, Available: ₹{remaining_budget:,.2f}")
        else:
            flash(" Unable to retrieve budget information.")
    except ValueError:
        flash(" Invalid budget amount.")
    except Exception as e:
        flash(f" Error allocating budget: {str(e)}")
    
    return redirect(url_for('dashboard'))

@app.route('/update_salary_action', methods=['POST'])
def update_salary_action():
    """Update employee salary and CORRECTLY deduct increase from remaining budget"""
    if 'username' not in session or session['role'] != 'Hr & Finance Controller':
        flash(" Access denied. HR & Finance Controller privileges required.")
        return redirect(url_for('dashboard'))
    
    username = request.form.get('username')
    monthly_salary = request.form.get('monthly_salary')
    yearly_salary = request.form.get('yearly_salary')
    
    if not username or not monthly_salary:
        flash("Username and monthly salary are required.")
        return redirect(url_for('dashboard'))
    
    try:
        new_monthly = float(monthly_salary)
        new_yearly = float(yearly_salary) if yearly_salary else new_monthly * 12
        
        # Get current salary
        current_salary_df = run_query("""
            SELECT COALESCE(monthly_salary, 0) as monthly_salary, 
                   COALESCE(yearly_salary, 0) as yearly_salary 
            FROM users WHERE username = ?
        """, (username,))
        
        if not current_salary_df.empty:
            current_monthly = float(current_salary_df.iloc[0]['monthly_salary']) if current_salary_df.iloc[0]['monthly_salary'] is not None else 0.0
            current_yearly = float(current_salary_df.iloc[0]['yearly_salary']) if current_salary_df.iloc[0]['yearly_salary'] is not None else 0.0
            yearly_increase = new_yearly - current_yearly
            
            # If salary increased, check and deduct from remaining budget
            if yearly_increase > 0:
                # Get budget status (CORRECTED calculation)
                budget_df = run_query("SELECT total_budget FROM company_budget WHERE id = 1")
                allocated_df = run_query("""
                    SELECT COALESCE(SUM(CAST(budget_amount AS DECIMAL(18,2))), 0) as allocated 
                    FROM projects 
                    WHERE hr_approval_status = 'Approved' 
                    AND budget_amount IS NOT NULL
                    AND CAST(budget_amount AS DECIMAL(18,2)) > 0
                """)
                payroll_df = run_query("""
                    SELECT COALESCE(SUM(CAST(yearly_salary AS DECIMAL(18,2))), 0) as payroll
                    FROM users 
                    WHERE status = 'Active' AND yearly_salary IS NOT NULL
                """)
                
                if not budget_df.empty and not allocated_df.empty and not payroll_df.empty:
                    total_budget = float(budget_df['total_budget'].iloc[0])
                    allocated = float(allocated_df['allocated'].iloc[0])
                    current_total_payroll = float(payroll_df['payroll'].iloc[0])
                    remaining_budget = total_budget - allocated - current_total_payroll
                    
                    if remaining_budget >= yearly_increase:
                        salary_project_name = f"Salary Increase - {username} (₹{yearly_increase:,.0f}/year)"
                        
                        # Create salary increase project to track budget usage
                        ok1 = run_exec("""
                            INSERT INTO [timesheet_db].[dbo].[projects] (project_name, description, created_by, created_on, end_date, 
                                                hr_approval_status, status, budget_amount, cost_center)
                            VALUES (?, ?, ?, GETDATE(), DATEADD(year, 1, GETDATE()), 'Approved', 'Approved', ?, 'Payroll')
                        """, (salary_project_name, 
                             f"Annual salary increase allocation for {username}",
                             session['username'], yearly_increase))
                        
                        if ok1:
                            new_remaining = remaining_budget - yearly_increase
                            flash(f" Salary increase approved! ₹{yearly_increase:,.2f}/year will be deducted from budget. New remaining: ₹{new_remaining:,.2f}")
                        else:
                            flash(" Failed to create salary increase project entry.")
                            return redirect(url_for('dashboard'))
                    else:
                        flash(f" Insufficient remaining budget for salary increase. Required: ₹{yearly_increase:,.2f}, Available: ₹{remaining_budget:,.2f}")
                        return redirect(url_for('dashboard'))
        
        # Update salary in users table
        ok = run_exec("""
            UPDATE users 
            SET monthly_salary = ?, yearly_salary = ?
            WHERE username = ?
        """, (new_monthly, new_yearly, username))
        
        if ok:
            # Notify employee about salary update
            emp_email = get_user_email(username)
            if emp_email:
                subject = f"Salary Update Notification - {username}"
                text_content = f"""Dear {username},

    Your salary has been updated in the system.

    New Salary Details:
    - Monthly Salary: ₹{float(new_monthly):,.2f}
    - Yearly Salary: ₹{float(new_yearly):,.2f}

    This change will be reflected in your next payroll cycle.
    https://nexus.chervicaon.com
    If you have any questions, please contact the HR department.

    This is an automated notification from the Timesheet & Leave Management System."""
                send_email(emp_email, subject, text_content)

            flash(f" Salary updated for {username}: ₹{new_monthly:,.2f}/month, ₹{new_yearly:,.2f}/year")
            
            # Force page refresh to show updated budget
            return redirect(url_for('dashboard') + '?tab=payroll')
        else:
            flash(" Failed to update salary.")
    
    except ValueError:
        flash(" Invalid salary amounts entered.")
    except Exception as e:
        print(f" SALARY UPDATE ERROR: {e}")
        flash(f" Error updating salary: {str(e)}")
    
    return redirect(url_for('dashboard'))

def get_asset_request_by_id(asset_request_id):
    df = run_query("SELECT * FROM asset_requests WHERE id = ?", (int(asset_request_id),))
    if df.empty:
        return None
    
    row = df.iloc[0]
    
    class AssetRequest:
        pass
    
    asset_request = AssetRequest()
    asset_request.id = row['id']
    asset_request.status = row['status']
    asset_request.amount = float(row['amount']) if row['amount'] else 0.0
    asset_request.approved_by = row['approved_by']
    asset_request.approval_date = row['approved_date']
    asset_request.rejection_reason = row.get('rejection_reason', None)
    return asset_request


@app.route('/approve_asset_request_hr', methods=['POST'])
def approve_asset_request_hr():
    """Approve asset request and CORRECTLY deduct from remaining budget"""
    if 'username' not in session or session['role'] != 'Hr & Finance Controller':
        flash(" Access denied. HR & Finance Controller privileges required.")
        return redirect(url_for('dashboard'))
    
    request_id = request.form.get('request_id')
    
    try:
        request_details = run_query("""
            SELECT CAST(COALESCE(amount, 0) AS DECIMAL(18,2)) as amount, 
                   asset_type, for_employee, requested_by 
            FROM asset_requests 
            WHERE id = ? AND status = 'Pending'
        """, (int(request_id),))
        
        if not request_details.empty:
            amount = float(request_details.iloc[0]['amount']) if request_details.iloc[0]['amount'] is not None else 0.0
            
            if amount <= 0:
                flash(" Invalid amount for asset request.")
                return redirect(url_for('dashboard'))
            
            # Check remaining budget (CORRECTED calculation)
            budget_df = run_query("SELECT total_budget FROM company_budget WHERE id = 1")
            allocated_df = run_query("""
                SELECT COALESCE(SUM(CAST(budget_amount AS DECIMAL(18,2))), 0) as allocated 
                FROM projects 
                WHERE hr_approval_status = 'Approved' 
                AND budget_amount IS NOT NULL
                AND CAST(budget_amount AS DECIMAL(18,2)) > 0
            """)
            payroll_df = run_query("""
                SELECT COALESCE(SUM(CAST(yearly_salary AS DECIMAL(18,2))), 0) as payroll
                FROM users 
                WHERE status = 'Active' AND yearly_salary IS NOT NULL
            """)
            
            if not budget_df.empty and not allocated_df.empty and not payroll_df.empty:
                total_budget = float(budget_df['total_budget'].iloc[0])
                allocated = float(allocated_df['allocated'].iloc[0])
                payroll = float(payroll_df['payroll'].iloc[0])
                remaining_budget = total_budget - allocated - payroll
                
                if remaining_budget >= amount:
                    asset_project_name = f"Asset Purchase - {request_details.iloc[0]['asset_type']} (ID: {request_id})"
                    
                    # Create asset project entry to track budget usage
                    ok1 = run_exec("""
                        INSERT INTO [timesheet_db].[dbo].[projects] (project_name, description, created_by, created_on, end_date, 
                                            hr_approval_status, status, budget_amount, cost_center)
                        VALUES (?, ?, ?, GETDATE(), DATEADD(day, 30, GETDATE()), 'Approved', 'Approved', ?, 'Assets')
                    """, (asset_project_name, 
                         f"Asset purchase for {request_details.iloc[0]['for_employee'] or 'General Use'}",
                         session['username'], amount))
                    
                    if ok1:
                        # Update asset request status
                        ok2 = run_exec("""
                            UPDATE asset_requests 
                            SET status = 'Approved', approved_by = ?, approved_date = GETDATE()
                            WHERE id = ?
                        """, (session['username'], int(request_id)))
                        
                        if ok2:
                            # Notify requester about approval
                            requester_email = get_user_email(request_details.iloc[0]['requested_by'])
                            if requester_email:
                                subject = f"Asset Request Approved - {request_details.iloc[0]['asset_type']}"
                                text_content = f"""Dear {request_details.iloc[0]['requested_by']},

            Your asset request has been approved by HR.

            Details:
            - Asset Type: {request_details.iloc[0]['asset_type']}
            - Amount: ₹{amount:,.2f}
            - Status: Approved

            The asset will be processed and delivered soon.
            https://nexus.chervicaon.com
            This is an automated notification from the Timesheet & Leave Management System."""
                                send_email(requester_email, subject, text_content)

                            
                            new_remaining = remaining_budget - amount
                            flash(f" Asset request approved! ₹{amount:,.2f} deducted from remaining budget. New remaining: ₹{new_remaining:,.2f}")
                            
                            
                            # Force page refresh to show updated budget
                            return redirect(url_for('dashboard') + '?tab=asset-approvals')
                        else:
                            flash(" Failed to update asset request status.")
                    else:
                        flash(" Failed to create asset project entry.")
                else:
                    flash(f" Insufficient remaining budget. Required: ₹{amount:,.2f}, Available: ₹{remaining_budget:,.2f}")
            else:
                flash(" Unable to retrieve budget information.")
        else:
            flash(" Asset request not found or already processed.")
    
    except Exception as e:
        print(f" ASSET APPROVAL ERROR: {e}")
        flash(f" Error approving asset request: {str(e)}")
    
    return redirect(url_for('dashboard'))


@app.route('/reject_asset_request_hr', methods=['POST'])
def reject_asset_request_hr():
    """Reject asset request"""
    if 'username' not in session or session['role'] != 'Hr & Finance Controller':
        flash("Access denied. HR & Finance Controller privileges required.")
        return redirect(url_for('dashboard'))
    
    request_id = request.form.get('request_id')
    reason = request.form.get('rejection_reason', 'Not specified')
    
    if not request_id:
        flash("Request ID is required.")
        return redirect(url_for('dashboard'))
    
    try:
        ok = run_exec("""
            UPDATE asset_requests 
            SET status = 'Rejected', approved_by = ?, approved_date = GETDATE(), rejection_reason = ?
            WHERE id = ? AND status = 'Pending'
        """, (session['username'], reason, int(request_id)))
        
        if ok:
            # Get requester details for notification
            request_details = run_query("""
                SELECT requested_by, asset_type, amount 
                FROM asset_requests WHERE id = ?
            """, (int(request_id),))
            
            if not request_details.empty:
                requester = request_details.iloc[0]['requested_by']
                asset_type = request_details.iloc[0]['asset_type']
                amount = request_details.iloc[0]['amount']
                
                requester_email = get_user_email(requester)
                if requester_email:
                    subject = f"Asset Request Rejected - {asset_type}"
                    text_content = f"""Dear {requester},

    Your asset request has been rejected by HR.

    Details:
    - Asset Type: {asset_type}
    - Amount: ₹{float(amount or 0):,.2f}
    - Status: Rejected
    - Reason: {reason}

    please login here
    https://nexus.chervicaon.com
    If you have questions about this decision, please contact the HR department.
    
    This is an automated notification from the Timesheet & Leave Management System."""
                    send_email(requester_email, subject, text_content)
            flash(f" Asset request #{request_id} rejected successfully.")
        else:
            flash(" Failed to reject asset request or request not found.")
    
    except Exception as e:
        print(f" ASSET REJECTION ERROR: {e}")
        flash(f" Error rejecting asset request: {str(e)}")
    
    return redirect(url_for('dashboard'))

@app.route('/create_project_hr', methods=['POST'])
def create_project_hr():
    """Create new project (HR Finance)"""
    if 'username' not in session or session['role'] != 'Hr & Finance Controller':
        flash("Access denied. HR & Finance Controller privileges required.")
        return redirect(url_for('dashboard'))
    
    project_name = request.form.get('project_name')
    cost_center = request.form.get('cost_center')
    start_date = request.form.get('start_date')
    end_date = request.form.get('end_date')
    project_description = request.form.get('project_description')
    
    if not all([project_name, cost_center, start_date, end_date, project_description]):
        flash("All fields are required.")
        return redirect(url_for('dashboard'))
    
    # Check if project name already exists
    existing = run_query("SELECT project_name FROM projects WHERE project_name = ?", (project_name,))
    if not existing.empty:
        flash("Project name already exists. Please choose a different name.")
        return redirect(url_for('dashboard'))
    
    # Try multiple valid status values
    valid_statuses = ['Approved', 'Pending', 'Rejected']
    project_created = False
    
    for status in valid_statuses:
        try:
            ok = run_exec("""
                INSERT INTO [timesheet_db].[dbo]. [projects] (project_name, description, created_by, created_on, end_date, 
                                   cost_center, hr_approval_status, status)
                VALUES (?, ?, ?, ?, ?, ?, 'Approved', ?)
            """, (project_name, project_description, session['username'], date.today(), 
                  end_date, cost_center, status))
            
            if ok:
                project_created = True
                break
        except Exception as e:
            print(f"Failed with status {status}: {e}")
            continue
    
    if project_created:
        flash(f" Project '{project_name}' created successfully and automatically approved.")
    else:
        flash(" Failed to create project. Please check database constraints.")
    
    return redirect(url_for('dashboard'))

@app.route('/approve_project_hr_action', methods=['POST'])
def approve_project_hr_action():
    """Approve project (HR Finance specific) - Now with edit capability"""
    if 'username' not in session or session['role'] != 'Hr & Finance Controller':
        flash(" Access denied. HR & Finance Controller privileges required.")
        return redirect(url_for('dashboard'))
    
    project_id = request.form.get('project_id')
    
    if not project_id:
        flash(" Project ID is required.")
        return redirect(url_for('dashboard'))
    
    try:
        # Get project details
        project_details = run_query("""
            SELECT project_name, created_by FROM projects WHERE project_id = ?
        """, (int(project_id),))
        
        project_name = project_details.iloc[0]['project_name'] if not project_details.empty else f"Project #{project_id}"
        
        # Update project details AND approve it
        ok = run_exec("""
            UPDATE projects 
            SET project_name = ?, 
                cost_center = ?, 
                description = ?, 
                budget_amount = ?,
                hr_approval_status = 'Approved', 
                status = 'Approved'
            WHERE project_id = ?
        """, (
            request.form.get('project_name', project_name),
            request.form.get('cost_center'),
            request.form.get('project_description'),
            float(request.form.get('budget_amount', 0)),
            int(project_id)
        ))
        
        if ok:
            # Get project creator details
            project_details = run_query("""
                SELECT created_by, project_name FROM projects WHERE project_id = ?
            """, (int(project_id),))
            
            if not project_details.empty:
                creator = project_details.iloc[0]['created_by']
                project_name = project_details.iloc[0]['project_name']
                creator_email = get_user_email(creator)
                
                if creator_email:
                    subject = f"Project Approved - {project_name}"
                    text_content = f"""Dear {creator},

    Your project has been approved by HR.

    Project: {project_name}
    Status: Approved
    Budget: ₹{float(request.form.get('budget_amount', 0)):,.2f}

    You can now start working on this project.
    https://nexus.chervicaon.com
    This is an automated notification from the Timesheet & Leave Management System."""
                    send_email(creator_email, subject, text_content)

            flash(f" Project '{project_name}' approved successfully!")
            
        else:
            flash(" Failed to approve project.")
    
    except Exception as e:
        flash(f" Error approving project: {str(e)}")
    
    return redirect(url_for('dashboard') + '?tab=project-approvals')

@app.route('/reject_project_hr_action', methods=['POST'])
def reject_project_hr_action():
    """Reject project (HR Finance specific)"""
    if 'username' not in session or session['role'] != 'Hr & Finance Controller':
        flash(" Access denied. HR & Finance Controller privileges required.")
        return redirect(url_for('dashboard'))
    
    project_id = request.form.get('project_id')
    rejection_reason = request.form.get('rejection_reason', 'Not specified')
    
    if not project_id:
        flash(" Project ID is required.")
        return redirect(url_for('dashboard'))
    
    try:
        # Get project details
        project_details = run_query("""
            SELECT project_name FROM projects WHERE project_id = ?
        """, (int(project_id),))
        
        project_name = project_details.iloc[0]['project_name'] if not project_details.empty else f"Project #{project_id}"
        
        # Reject the project
        ok = run_exec("""
            UPDATE projects 
            SET hr_approval_status = 'Rejected', status = 'Rejected', hr_rejection_reason = ?
            WHERE project_id = ?
        """, (rejection_reason, int(project_id),))
        
        if ok:
            # Get project creator details
            project_details = run_query("""
                SELECT project_name, created_by FROM projects WHERE project_id = ?
            """, (int(project_id),))
            
            if not project_details.empty:
                project_name = project_details.iloc[0]['project_name']
                creator_username = project_details.iloc[0]['created_by']
                
                # Send email notification to project creator
                creator_email = get_user_email(creator_username)
                if creator_email:
                    subject = f"Project Rejected by HR - {project_name}"
                    text_content = f"""Dear {creator_username},

        Your project has been rejected by HR.

        Project: {project_name}
        Status: Rejected
        Reason: {rejection_reason}

        Please review the feedback and consider resubmitting with required modifications.
        https://nexus.chervicaon.com
        This is an automated notification from the Timesheet & Leave Management System."""
                    
                    send_email(creator_email, subject, text_content)

            flash(f" Project '{project_name}' rejected. Reason: {rejection_reason}")
        else:
            flash(" Failed to reject project.")
    
    except Exception as e:
        flash(f" Error rejecting project: {str(e)}")
    
    return redirect(url_for('dashboard') + '?tab=project-approvals')

@app.route('/update_total_budget_action', methods=['POST'])
def update_total_budget_action():
    """Update total company budget"""
    if 'username' not in session or session['role'] != 'Hr & Finance Controller':
        flash("Access denied. HR & Finance Controller privileges required.")
        return redirect(url_for('dashboard'))
    
    new_budget = request.form.get('total_budget')
    reason = request.form.get('change_reason', 'Not specified')
    user = session['username']
    
    if not new_budget:
        flash("Budget amount is required.")
        return redirect(url_for('dashboard'))
    
    try:
        new_budget = float(new_budget)
        
        allocated_df = run_query("""
            SELECT COALESCE(SUM(CAST(budget_amount AS DECIMAL(18,2))), 0) as allocated 
            FROM projects 
            WHERE hr_approval_status = 'Approved' 
            AND budget_amount IS NOT NULL
            AND CAST(budget_amount AS DECIMAL(18,2)) > 0
        """)
        
        allocated = float(allocated_df['allocated'].iloc[0]) if not allocated_df.empty else 0.0
        
        if new_budget < allocated:
            flash(f" New budget (₹{new_budget:,.2f}) cannot be less than currently allocated amount (₹{allocated:,.2f})")
            return redirect(url_for('dashboard'))
        
        ok = run_exec("""
            UPDATE company_budget 
            SET total_budget = ?, updated_by = ?, updated_on = GETDATE(), reason = ?
            WHERE id = 1
        """, (new_budget, user, reason))
        
        if ok:
            new_remaining = new_budget - allocated
            flash(f" Total budget updated to ₹{new_budget:,.2f}. New remaining budget: ₹{new_remaining:,.2f}")
        else:
            flash(" Failed to update budget.")
    except ValueError:
        flash(" Invalid budget amount.")
    except Exception as e:
        flash(f" Error updating budget: {str(e)}")
    
    return redirect(url_for('dashboard'))

# HR Finance Work Assignment Route
@app.route('/hr_assign_work_action', methods=['POST'])
def hr_assign_work_action():
    """HR assigns work to multiple employees"""
    if 'username' not in session or session['role'] != 'Hr & Finance Controller':
        flash("Access denied. HR & Finance Controller privileges required.")
        return redirect(url_for('dashboard'))
    
    user = session['username']
    employee_usernames = request.form.getlist('employees')
    project_name = request.form.get('project_name', '')
    task_desc = request.form.get('task_desc')
    due_date = request.form.get('due_date')
    start_date = request.form.get('start_date', date.today())
    
    if not employee_usernames or not task_desc:
        flash("Please select at least one employee and provide task description.")
        return redirect(url_for('dashboard'))
    
    success_count = 0
    failed_employees = []
    
    for employee in employee_usernames:
        try:
            ok = run_exec("""
                INSERT INTO [timesheet_db].[dbo].[assigned_work] (assigned_by, assigned_to, task_desc, start_date, due_date, 
                                         project_name, rm_status, manager_status, assigned_on)
                VALUES (?, ?, ?, ?, ?, ?, 'Approved', 'Approved', ?)
            """, (user, employee, task_desc, start_date, due_date, project_name, date.today()))
            
            if ok:
                success_count += 1
                # Send email notification to assigned employee
                emp_email = get_user_email(employee)
                if emp_email:
                    subject = f"New Work Assignment - {employee}"
                    text_content = f"""Dear {employee},

            You have been assigned new work by HR.

            Assignment Details:
            - Assigned by: {user}
            - Project: {project_name or 'General Task'}
            - Task Description: {task_desc}
            - Start Date: {start_date}
            - Due Date: {due_date}

            Please log in to your dashboard to view the complete assignment details and update the status as you progress.
            https://nexus.chervicaon.com
            This is an automated notification from the Timesheet & Leave Management System."""
                    
                    send_email(emp_email, subject, text_content)

    
            else:
                failed_employees.append(employee)
        except Exception as e:
            print(f"Error assigning to {employee}: {e}")
            failed_employees.append(employee)
    
    if success_count > 0:
        flash(f" Work assigned successfully to {success_count} employee(s).")
    
    if failed_employees:
        flash(f" Failed to assign work to: {', '.join(failed_employees)}")
    
    return redirect(url_for('dashboard'))

# HR Finance Expense Recording Route
@app.route('/hr_record_expense_action', methods=['POST'])
def hr_record_expense_action():
    """HR records expense - UPDATED WITH DOCUMENT UPLOAD + OTHER CATEGORY SUPPORT"""
    if 'username' not in session or session['role'] != 'Hr & Finance Controller':
        flash("Access denied. HR & Finance Controller privileges required.")
        return redirect(url_for('dashboard'))
    
    user = session['username']
    project = request.form.get('project')
    category = request.form.get('category')
    other_category = request.form.get('other_category', '').strip()  # NEW LINE
    amount = request.form.get('amount')
    exp_date = request.form.get('exp_date')
    desc = request.form.get('desc')
    
    # NEW: Handle "Other" category with custom input
    if category == 'Other' and other_category:
        category = other_category  # Use the custom category name
    elif category == 'Other' and not other_category:
        flash("Please specify the other category when selecting 'Other'.")
        return redirect(url_for('dashboard'))
    
    if not project or not category or not amount or not desc:
        flash("Please fill in all required fields.")
        return redirect(url_for('dashboard'))
    
    # Handle document upload
    document_path = None
    if 'expense_document' in request.files:
        file = request.files['expense_document']
        if file.filename != '':
            document_path = save_uploaded_file(file, "hr_expense")
    
    try:
        ok = run_exec("""
            INSERT INTO expenses 
            (project_name, category, amount, date, description, spent_by, document_path)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        """, (project, category, float(amount), exp_date, desc, user, document_path))
        
        if ok:
            # NEW: Custom success message for other categories
            if other_category and request.form.get('category') == 'Other':
                flash(f"Expense recorded successfully with custom category '{other_category}'.")
            else:
                flash("Expense recorded successfully.")
        else:
            flash("Failed to record expense.")
    except Exception as e:
        flash(f"Error recording expense: {str(e)}")
    
    return redirect(url_for('dashboard'))
# Employee Edit/Delete Routes
# --------------------
@app.route('/edit_timesheet_form/<int:timesheet_id>')
def edit_timesheet_form(timesheet_id):
    """Display edit form for timesheet"""
    if 'username' not in session:
        return redirect(url_for('login_sso'))
    
    user = session['username']
    
    # Get timesheet data
    timesheet_data = run_query("""
        SELECT id, project_name, work_date, work_desc, start_time, end_time, break_hours, rm_status
        FROM timesheets 
        WHERE id = ? AND username = ?
    """, (timesheet_id, user))
    
    if timesheet_data.empty:
        flash("Timesheet not found or you don't have permission to edit it.")
        return redirect(url_for('dashboard'))
    
    # Check if timesheet can be edited
    timesheet = timesheet_data.iloc[0]
    if timesheet['rm_status'] not in ['Pending', 'Rejected']:
        flash("Cannot edit approved timesheet.")
        return redirect(url_for('dashboard'))
    
    # Get projects list
    projects_df = run_query("SELECT project_name FROM projects WHERE hr_approval_status = 'Approved' ORDER BY project_name")
    proj_list = ["(non-project)"] + projects_df["project_name"].astype(str).tolist() if not projects_df.empty else ["(non-project)"]
    
    # Convert timesheet data to dict and handle time objects
    timesheet_dict = timesheet.to_dict()
    
    # Convert time objects to strings if they exist
    if timesheet_dict.get('start_time') and hasattr(timesheet_dict['start_time'], 'strftime'):
        timesheet_dict['start_time'] = timesheet_dict['start_time'].strftime('%H:%M')
    
    if timesheet_dict.get('end_time') and hasattr(timesheet_dict['end_time'], 'strftime'):
        timesheet_dict['end_time'] = timesheet_dict['end_time'].strftime('%H:%M')
    
    # Convert work_date to string if it's a date object
    if timesheet_dict.get('work_date') and hasattr(timesheet_dict['work_date'], 'strftime'):
        timesheet_dict['work_date'] = timesheet_dict['work_date'].strftime('%Y-%m-%d')
    
    return render_template('edit_timesheet.html',
        timesheet=timesheet_dict,
        proj_list=proj_list,
        user=user,
        role=session['role']
    )

@app.route('/resubmit_timesheet', methods=['POST'])
def resubmit_timesheet():
    """Resubmit/update timesheet with new data"""
    if 'username' not in session:
        return redirect(url_for('login_sso'))
    
    user = session['username']
    timesheet_id = request.form.get('timesheet_id')
    project = request.form.get('project')
    work_date = request.form.get('work_date')
    desc = request.form.get('desc')
    start_t_str = request.form.get('start_t')
    end_t_str = request.form.get('end_t')
    brk = request.form.get('break_hours', 0.0)
    
    if not all([timesheet_id, project, work_date, desc, start_t_str, end_t_str]):
        flash("All fields are required for timesheet resubmission.")
        return redirect(url_for('edit_timesheet_form', timesheet_id=timesheet_id))
    
    try:
        start_t = time.fromisoformat(start_t_str)
        end_t = time.fromisoformat(end_t_str)
        hours = calc_hours(start_t, end_t, float(brk))
        
        proj_val = "(non-project)" if project == "(non-project)" or not project else project
        cost_center = None
        
        if proj_val and proj_val != "(non-project)":
            df = run_query("SELECT cost_center FROM projects WHERE project_name = ?", (proj_val,))
            if not df.empty:
                cost_center = df.iloc[0]['cost_center']
        
        start_time_str = start_t.strftime("%H:%M:%S")
        end_time_str = end_t.strftime("%H:%M:%S")
        
        # Check if timesheet belongs to user and can be edited
        check_df = run_query("""
            SELECT rm_status FROM timesheets 
            WHERE id = ? AND username = ?
        """, (int(timesheet_id), user))
        
        if check_df.empty:
            flash("Timesheet not found or you don't have permission to edit it.")
            return redirect(url_for('dashboard'))
        
        if check_df.iloc[0]['rm_status'] == 'Approved':
            flash("Cannot edit approved timesheet.")
            return redirect(url_for('dashboard'))
        
        # Update the timesheet
        ok = run_exec("""
            UPDATE timesheets 
            SET project_name = ?, work_desc = ?, hours = ?, work_date = ?, 
                start_time = ?, end_time = ?, break_hours = ?, rm_status = 'Pending', 
                cost_center = ?, rm_rejection_reason = NULL, rm_approver = NULL
            WHERE id = ? AND username = ?
        """, (proj_val, desc, int(round(hours)), work_date, start_time_str, end_time_str, 
              float(brk), cost_center, int(timesheet_id), user))
        
        if ok:
            # Get RM details for notification
            rm_details = run_query("""
                SELECT r.rm FROM report r WHERE r.username = ?
            """, (user,))
            
            if not rm_details.empty:
                rm_username = rm_details.iloc[0]['rm']
                rm_email = get_user_email(rm_username)
                if rm_email:
                    subject = f"Timesheet Resubmitted - {user}"
                    text_content = f"""Dear {rm_username},

        {user} has resubmitted their timesheet for your approval.

        Timesheet Details:
        - Date: {work_date}
        - Project: {proj_val}
        - Hours: {int(round(hours))}
        - Description: {desc}

        Please review and approve/reject through your dashboard.
        https://nexus.chervicaon.com
        This is an automated notification from the Timesheet & Leave Management System."""
                    
                    send_email(rm_email, subject, text_content)
            
            flash("Timesheet updated and resubmitted successfully (awaiting RM approval).")
        else:
            flash("Failed to update timesheet.")
    
    except ValueError as e:
        flash(f"Invalid time format: {str(e)}")
        return redirect(url_for('edit_timesheet_form', timesheet_id=timesheet_id))
    except Exception as e:
        flash(f"Error updating timesheet: {str(e)}")
        return redirect(url_for('edit_timesheet_form', timesheet_id=timesheet_id))
    
    return redirect(url_for('dashboard'))

@app.route('/delete_timesheet', methods=['POST'])
def delete_timesheet():
    """Delete a pending timesheet"""
    if 'username' not in session:
        return redirect(url_for('login_sso'))
    
    user = session['username']
    timesheet_id = request.form.get('timesheet_id')
    
    if not timesheet_id:
        flash("Timesheet ID is required.")
        return redirect(url_for('dashboard'))
    
    # Check if timesheet belongs to user and is still pending
    check_df = run_query("""
        SELECT rm_status FROM timesheets 
        WHERE id = ? AND username = ?
    """, (int(timesheet_id), user))
    
    if check_df.empty:
        flash("Timesheet not found or you don't have permission to delete it.")
        return redirect(url_for('dashboard'))
    
    if check_df.iloc[0]['rm_status'] != 'Pending':
        flash("Cannot delete timesheet that has already been processed.")
        return redirect(url_for('dashboard'))
    
    # Delete the timesheet
    ok = run_exec("""
        DELETE FROM timesheets 
        WHERE id = ? AND username = ?
    """, (int(timesheet_id), user))
    
    if ok:
        flash("Timesheet deleted successfully.")
    else:
        flash("Failed to delete timesheet.")
    
    return redirect(url_for('dashboard'))

@app.route('/edit_leave_form/<int:leave_id>')
def edit_leave_form(leave_id):
    """Display edit form for leave"""
    if 'username' not in session:
        return redirect(url_for('login_sso'))
    
    user = session['username']
    
    # Get leave data
    leave_data = run_query("""
        SELECT id, leave_type, start_date, end_date, description, rm_status, rm_rejection_reason
        FROM leaves 
        WHERE id = ? AND username = ?
    """, (leave_id, user))
    
    if leave_data.empty:
        flash("Leave request not found or you don't have permission to edit it.")
        return redirect(url_for('dashboard'))
    
    # Check if leave can be edited
    leave = leave_data.iloc[0]
    if leave['rm_status'] not in ['Pending', 'Rejected']:
        flash("Cannot edit approved leave.")
        return redirect(url_for('dashboard'))
    
    # Get remaining leave balances
    remaining_leaves = _get_remaining_balances(user)
    
    # Convert leave data to dict and handle date objects
    leave_dict = leave.to_dict()
    
    # Convert date objects to strings if they exist
    if leave_dict.get('start_date') and hasattr(leave_dict['start_date'], 'strftime'):
        leave_dict['start_date'] = leave_dict['start_date'].strftime('%Y-%m-%d')
    
    if leave_dict.get('end_date') and hasattr(leave_dict['end_date'], 'strftime'):
        leave_dict['end_date'] = leave_dict['end_date'].strftime('%Y-%m-%d')
    
    return render_template('edit_leave.html',
        leave=leave_dict,
        remaining_leaves=remaining_leaves,
        user=user,
        role=session['role']
    )

@app.route('/resubmit_leave', methods=['POST'])
def resubmit_leave():
    """Resubmit/update leave with new data"""
    if 'username' not in session:
        return redirect(url_for('login_sso'))
    
    user = session['username']
    leave_id = request.form.get('leave_id')
    leave_type = request.form.get('leave_type')
    start_d = request.form.get('start_d')
    end_d = request.form.get('end_d')
    description = request.form.get('description')
    
    if not all([leave_id, leave_type, start_d, end_d, description]):
        flash("All fields are required for leave resubmission.")
        return redirect(url_for('edit_leave_form', leave_id=leave_id))
    
    try:
        # Validate dates
        start_dt = datetime.strptime(start_d, '%Y-%m-%d')
        end_dt = datetime.strptime(end_d, '%Y-%m-%d')
        
        if start_dt > end_dt:
            flash("Start date cannot be after end date.")
            return redirect(url_for('edit_leave_form', leave_id=leave_id))
        
        # Check leave balance
        remaining = _get_remaining_balances(user)
        days_requested = (end_dt - start_dt).days + 1
        
        leave_balance_mapping = {
            'Sick': 'sick',
            'Vacation': 'paid',
            'Personal': 'paid',
            'Casual': 'casual',
            'Other': 'casual'
        }
        
        balance_key = leave_balance_mapping.get(leave_type, 'casual')
        
        if remaining.get(balance_key, 0) < days_requested:
            flash(f"Insufficient {leave_type} leave balance. Available: {remaining.get(balance_key, 0)} days")
            return redirect(url_for('edit_leave_form', leave_id=leave_id))
        
        # Check if leave belongs to user and can be edited
        check_df = run_query("""
            SELECT rm_status FROM leaves 
            WHERE id = ? AND username = ?
        """, (int(leave_id), user))
        
        if check_df.empty:
            flash("Leave request not found or you don't have permission to edit it.")
            return redirect(url_for('dashboard'))
        
        if check_df.iloc[0]['rm_status'] == 'Approved':
            flash("Cannot edit approved leave request.")
            return redirect(url_for('dashboard'))
        
        # Handle file upload for sick leave > 2 days
        doc_name = None
        need_doc = (leave_type == "Sick") and (days_requested > 2)
        
        if need_doc:
            if 'doc' in request.files and request.files['doc'].filename:
                file = request.files['doc']
                timestamp = int(datetime.now().timestamp())
                doc_name = f"{user}_{timestamp}_{secure_filename(file.filename)}"
                file.save(os.path.join(app.config['UPLOAD_FOLDER'], doc_name))
        
        # Update the leave request
        ok = run_exec("""
            UPDATE leaves 
            SET leave_type = ?, start_date = ?, end_date = ?, description = ?, 
                rm_status = 'Pending', rm_rejection_reason = NULL, rm_approver = NULL,
                health_document = ?
            WHERE id = ? AND username = ?
        """, (leave_type, start_d, end_d, description, doc_name, int(leave_id), user))
        
        if ok:
            flash("Leave request updated and resubmitted successfully (awaiting RM approval).")
        else:
            flash("Failed to update leave request.")
    
    except ValueError:
        flash("Invalid date format.")
        return redirect(url_for('edit_leave_form', leave_id=leave_id))
    except Exception as e:
        flash(f"Error updating leave request: {str(e)}")
        return redirect(url_for('edit_leave_form', leave_id=leave_id))
    
    return redirect(url_for('dashboard'))

@app.route('/delete_leave', methods=['POST'])
def delete_leave():
    """Delete a leave request"""
    if 'username' not in session:
        return redirect(url_for('login_sso'))
    
    user = session['username']
    leave_id = request.form.get('leave_id')
    
    if not leave_id:
        flash("Leave ID is required.")
        return redirect(url_for('dashboard'))
    
    # Check if leave belongs to user and can be deleted
    check_df = run_query("""
        SELECT rm_status FROM leaves 
        WHERE id = ? AND username = ?
    """, (int(leave_id), user))
    
    if check_df.empty:
        flash("Leave request not found or you don't have permission to delete it.")
        return redirect(url_for('dashboard'))
    
    if check_df.iloc[0]['rm_status'] == 'Approved':
        flash("Cannot delete approved leave request.")
        return redirect(url_for('dashboard'))
    
    # Delete the leave request
    ok = run_exec("""
        DELETE FROM leaves 
        WHERE id = ? AND username = ?
    """, (int(leave_id), user))
    
    if ok:
        flash("Leave request deleted successfully.")
    else:
        flash("Failed to delete leave request.")
    
    return redirect(url_for('dashboard'))

@app.route('/cancel_leave_action', methods=['POST'])
def cancel_leave_action():
    """Cancel leave request by employee"""
    if 'username' not in session:
        return redirect(url_for('login_sso'))
    
    user = session['username']
    leave_id = request.form.get('id')
    
    print(f"DEBUG: Received leave cancellation request - User: {user}, Leave ID: {leave_id}")
    
    if not leave_id:
        flash("Leave ID is required for cancellation.")
        return redirect(url_for('dashboard'))
    
    try:
        # Check if the leave belongs to the current user
        leave_details = run_query("""
            SELECT username, rm_status, leave_type, start_date, end_date FROM leaves 
            WHERE id = ? AND username = ?
        """, (int(leave_id), user))
        
        if leave_details.empty:
            flash("Leave request not found or you don't have permission to cancel it.")
            return redirect(url_for('dashboard'))
        
        leave_record = leave_details.iloc[0]
        rm_status = leave_record['rm_status']
        leave_type = leave_record['leave_type']
        start_date = parse(str(leave_record['start_date']))
        end_date = parse(str(leave_record['end_date']))
        leave_days = (end_date - start_date).days + 1
        
        if rm_status == 'Approved':
            # If already approved, request cancellation
            ok = run_exec("""
                UPDATE leaves 
                SET cancellation_requested = 1, cancellation_status = 'Pending'
                WHERE id = ? AND username = ?
            """, (int(leave_id), user))
            
            if ok:
                flash(" Cancellation request submitted for approved leave. Awaiting manager approval.")
            else:
                flash(" Failed to submit cancellation request.")
                
        elif rm_status == 'Pending':
            # If still pending, can directly cancel/delete
            ok = run_exec("""
                DELETE FROM leaves 
                WHERE id = ? AND username = ? AND rm_status = 'Pending'
            """, (int(leave_id), user))
            
            if ok:
                flash(" Pending leave request cancelled successfully.")
            else:
                flash(" Failed to cancel leave request.")
        else:
            flash("Leave request cannot be cancelled.")
    
    except Exception as e:
        print(f"ERROR in cancel_leave_action: {str(e)}")
        flash(f" Error processing cancellation request: {str(e)}")
    
    return redirect(url_for('dashboard'))

# Admin Manager Routes - COMPLETE
# --------------------
@app.route('/add_employee_action', methods=['POST'])
def add_employee_action():
    """Add new employee with complete details"""
    if 'username' not in session:
        return redirect(url_for('login_sso'))
   
    # Check admin privileges
    if session['role'] not in ('Admin Manager', 'Lead Staffing Specialist'):
        flash("Access denied. Admin Manager privileges required.")
        return redirect(url_for('dashboard'))
   
    # Get form data
    username = request.form.get('username')
    name = request.form.get('name')
    email = request.form.get('email')
    password = request.form.get('password')
    role = request.form.get('role')
    reporting_manager = request.form.get('reporting_manager')
   
    # Employment details
    joining_date = request.form.get('joining_date')
    employment_type = request.form.get('employment_type')
    duration = request.form.get('duration')
    blood_group = request.form.get('blood_group')
   
    # CORRECTED: Get employment ID and convert to uppercase
    employmentid = request.form.get('employmentid', '').strip().upper()
    print(f"DEBUG: Employment ID received: '{employmentid}'")
   
    # Contact info
    mobile_number = request.form.get('mobile_number')
    emergency_contact = request.form.get('emergency_contact')
   
    # Assets
    laptop_provided = bool(request.form.get('laptop_provided'))
    id_card_provided = bool(request.form.get('id_card_provided'))
    email_provided = bool(request.form.get('email_provided'))
    asset_details = request.form.get('asset_details')
   
    # Documents
    adhaar_number = request.form.get('adhaar_number')
    pan_number = request.form.get('pan_number')
    linkedin_url = request.form.get('linkedin_url')
    photo_url = request.form.get('photo_url')
   
    # Salary
    monthly_salary = request.form.get('monthly_salary')
    yearly_salary = request.form.get('yearly_salary')
   
    # Leave balance
    total_leaves = request.form.get('total_leaves', 36)
    sick_total = request.form.get('sick_total', 12)
    paid_total = request.form.get('paid_total', 18)
    casual_total = request.form.get('casual_total', 6)
   
    if not all([username, name, email, employmentid]):
        flash("All required fields must be filled.")
        return redirect(url_for('dashboard'))
   
    # CRITICAL: Check if Employment ID already exists
    existing_emp_id = run_query("""
        SELECT username, name FROM employee_details
        WHERE employmentid = ?
    """, (employmentid,))
   
        # Handle file upload for photo
    if 'photo' in request.files and request.files['photo'].filename:
        file = request.files['photo']
        filename = secure_filename(file.filename)
        timestamp = int(datetime.now().timestamp())
        photo_filename = f"{username}_{timestamp}_{filename}"
        file.save(os.path.join(app.config['UPLOAD_FOLDER'], photo_filename))
        photo_url = f"/uploads/{photo_filename}"
       
        # Convert salary values
        monthly_salary = float(monthly_salary) if monthly_salary else None
        yearly_salary = float(yearly_salary) if yearly_salary else (monthly_salary * 12 if monthly_salary else None)
   
    if not existing_emp_id.empty:
        existing_user = existing_emp_id.iloc[0]
        flash(f'❌ Employment ID "{employmentid}" is already assigned to {existing_user["name"]} ({existing_user["username"]}). Please use a different Employment ID.')
        return redirect(url_for('dashboard'))
   
    # Check if username already exists
    existing_user = run_query("SELECT username FROM users WHERE username = ?", (username,))
    if not existing_user.empty:
        flash(f'❌ Username "{username}" already exists. Please choose a different username.')
        return redirect(url_for('dashboard'))
   
    try:
        # Insert into users table
        ok1 = run_exec("""
            INSERT INTO [timesheet_db].[dbo].[users] (username, name, email, role, password, monthly_salary, yearly_salary, status)
            VALUES (?, ?, ?, ?, ?, ?, ?, 'Active')
        """, (username, name, email, role, password, monthly_salary, yearly_salary))
       
        # Insert into employee_details table
        ok2 = run_exec("""
            INSERT INTO [timesheet_db].[dbo]. [employee_details] (
                username, name, role, joining_date, employment_type, blood_group,
                mobile_number, emergency_contact, laptop_provided, id_card_provided,
                email_provided, adhaar_number, pan_number, duration, employmentid
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (username, name, role, joining_date, employment_type, blood_group,
              mobile_number, emergency_contact, laptop_provided, id_card_provided,
              email_provided, adhaar_number, pan_number, duration, employmentid))
               
        # Set up reporting relationship
        if reporting_manager:
            run_exec("""
                INSERT INTO [timesheet_db].[dbo].[report] (username, rm, manager)
                VALUES (?, ?, ?)
            """, (username, reporting_manager, reporting_manager))
 
              # Set up leave balance
        ok3 = run_exec("""
            INSERT INTO [timesheet_db].[dbo].[leave_balances] (
                username, total_leaves, sick_total, paid_total, casual_total,
                sick_used, paid_used, casual_used
            ) VALUES (?, ?, ?, ?, ?, 0, 0, 0)
        """, (username, int(total_leaves), int(sick_total), int(paid_total), int(casual_total)))
       
        if ok1 and ok2 and ok3:
            # Send welcome email to new employee
            if email:
                subject = f"Welcome to the Company - {name}"
                text_content = f"""Dear {name},
 
    Welcome to our company! Your employee account has been created successfully.
 
    Your Account Details:
    - Username: {username}
    - Temporary Password: {password}
    - Role: {role}
    - Email: {email}
 
    Please log in to the Timesheet & Leave Management System at your earliest convenience and change your password.
     https://nexus.chervicaon.com
    System Access: [Your System URL]
 
    If you have any questions, please contact your reporting manager or the HR department.
 
    Welcome aboard!
 
    This is an automated notification from the Timesheet & Leave Management System."""
                send_email(email, subject, text_content)
 
            # Notify reporting manager if assigned
            if reporting_manager:
                rm_email = get_user_email(reporting_manager)
                if rm_email:
                    subject = f"New Team Member Assigned - {name}"
                    text_content = f"""Dear {reporting_manager},
 
    A new team member has been assigned to report to you.
 
    Employee Details:
    - Name: {name}
    - Username: {username}
    - Role: {role}
    - Email: {email}
    - Joining Date: {joining_date}
 
    Please help them get settled and provide any necessary guidance.
     https://nexus.chervicaon.com
    This is an automated notification from the Timesheet & Leave Management System."""
                    send_email(rm_email, subject, text_content)
 
            flash(f"Employee '{name}' ({username}) added successfully!")
            flash(f' Employee "{name}" added successfully with Employment ID: {employmentid}')
        else:
            flash(' Failed to add employee.')
           
    except Exception as e:
        if 'UQ_employee_details_employmentid' in str(e):
            flash(f' Employment ID "{employmentid}" is already in use. Please choose a different Employment ID.')
        else:
            flash(f' Error adding employee: {str(e)}')
        print(f"Add employee error: {e}")
   
    return redirect(url_for('dashboard'))

@app.route('/request_asset_with_document', methods=['POST'])
def request_asset_with_document():
    """Request assets with document upload functionality"""
    if 'username' not in session:
        return redirect(url_for('login_sso'))
    
    if session['role'] not in ('Admin Manager', 'Lead Staffing Specialist'):
        flash("Access denied. Admin Manager privileges required.")
        return redirect(url_for('dashboard'))
    
    asset_type = request.form.get('asset_type')
    quantity = request.form.get('quantity', 1)
    amount = request.form.get('amount', 0)
    for_employee = request.form.get('for_employee')
    description = request.form.get('description')
    
    if not asset_type or not description:
        flash("Asset type and description are required.")
        return redirect(url_for('dashboard'))
    
    # Handle document upload
    document_path = None
    if 'asset_document' in request.files:
        file = request.files['asset_document']
        if file.filename != '':
            if allowed_file(file.filename):
                timestamp = int(datetime.now().timestamp())
                filename = secure_filename(file.filename)
                document_filename = f"asset_{session['username']}_{timestamp}_{filename}"
                file.save(os.path.join(app.config['UPLOAD_FOLDER'], document_filename))
                document_path = document_filename
            else:
                flash("Invalid file type. Please upload PDF, JPG, PNG, DOC, or DOCX files only.")
                return redirect(url_for('dashboard'))
    
    try:
        amount_value = float(amount) if amount else None
        quantity_value = int(quantity) if quantity else 1
        
        ok = run_exec("""
            INSERT INTO  [timesheet_db].[dbo].[asset_requests](
                asset_type, quantity, amount, for_employee, description, 
                requested_by, requested_date, status, document_path
            ) VALUES (?, ?, ?, ?, ?, ?, GETDATE(), 'Pending', ?)
        """, (asset_type, quantity_value, amount_value, for_employee, 
              description, session['username'], document_path))
        
        if ok:
            # EMAIL NOTIFICATION TO HR/ADMIN
            hr_users = run_query("""
                SELECT email FROM users 
                WHERE role IN ('Hr & Finance Controller', 'Admin Manager') 
                AND status = 'Active' AND email IS NOT NULL
            """)
            
            if not hr_users.empty:
                for _, hr_user in hr_users.iterrows():
                    hr_email = hr_user['email']
                    if hr_email:
                        subject = f"New Asset Request - {asset_type}"
                        text_content = f"""Dear HR Team,

A new asset request has been submitted that requires your approval.

Details:
- Requested by: {session['username']}
- Asset Type: {asset_type}
- Quantity: {quantity_value}
- Amount: ₹{amount_value:,.2f} (if specified)
- For Employee: {for_employee or 'General Use'}
- Description: {description}
- Document: {'Attached' if document_path else 'Not provided'}

Please log in to the system to review and approve this asset request.
https://nexus.chervicaon.com
This is an automated notification from the Timesheet & Leave Management System."""
                        send_email(hr_email, subject, text_content)



            amount_text = f"worth ₹{amount_value:,.2f}" if amount_value else ""
            doc_text = "with supporting document" if document_path else ""
            flash(f" Asset request for {quantity_value} {asset_type}(s) {amount_text} submitted successfully {doc_text}.")
            
        else:
            flash(" Failed to send asset request.")
    
    except Exception as e:
        flash(f" Error sending asset request: {str(e)}")
    
    return redirect(url_for('dashboard'))

# Add these routes after your existing admin manager routes

@app.route('/admin_assign_work_to_team', methods=['POST'])
def admin_assign_work_to_team():
    """Admin Manager/Lead Staffing Specialist assigns work to direct reports ONLY"""
    if 'username' not in session:
        return redirect(url_for('login_sso'))
    
    # Check ONLY Admin Manager and Lead Staffing Specialist can use this
    if session['role'] not in ('Admin Manager', 'Lead Staffing Specialist'):
        flash(" Access denied. Only Admin Manager and Lead Staffing Specialist can assign work.")
        return redirect(url_for('dashboard'))
    
    user = session['username']  # This would be Sabitha or Koyel
    assignee_usernames = request.form.getlist('assignee_username')
    project_name = request.form.get('project_name', '')
    task_desc = request.form.get('task_desc', '').strip()
    start_date = request.form.get('start_date')
    end_date = request.form.get('end_date')
    due_date = request.form.get('due_date')
    work_type = request.form.get('work_type', 'Project')
    
    if not assignee_usernames or not task_desc:
        flash(" Please select at least one team member and provide task description.")
        return redirect(url_for('dashboard'))
    
    # Get ONLY direct reports where current user is the RM
    direct_reports = get_direct_reports(user)
    
    print(f" DEBUG: {user} ({session['role']}) can assign work to direct reports: {direct_reports}")
    
    if not direct_reports:
        flash(f" No direct reports found for {user}. You can only assign work to employees who directly report to you as RM.")
        return redirect(url_for('dashboard'))
    
    # Validate that selected employees are DIRECT reports only
    invalid_employees = [emp for emp in assignee_usernames if emp not in direct_reports]
    
    if invalid_employees:
        flash(f" You can ONLY assign work to your DIRECT reports. Invalid selections: {', '.join(invalid_employees)}")
        flash(f" Your direct reports: {', '.join(direct_reports)}")
        return redirect(url_for('dashboard'))
    
    success_count = 0
    failed_employees = []
    
    for assignee in assignee_usernames:
        try:
            # Double-check: is this user really a direct report?
            rm_check = get_rm_for_employee(assignee)
            if rm_check != user:
                failed_employees.append(f"{assignee} (RM mismatch)")
                continue
            
            # Insert work assignment
            ok = run_exec("""
                INSERT INTO [timesheet_db].[dbo].[assigned_work] (
                    assigned_by, assigned_to, task_desc, start_date, end_date, due_date,
                    project_name, rm_status, manager_status, assigned_on, work_type, rm_approver
                ) VALUES (?, ?, ?, ?, ?, ?, ?, 'Pending', 'Approved', GETDATE(), ?, ?)
            """, (user, assignee, task_desc, start_date, end_date, due_date, 
                  project_name, work_type, user))  # rm_approver is also the assigner
            
            if ok:
                success_count += 1

                # Send email notification to assignee
                emp_email = get_user_email(assignee)
                if emp_email:
                    subject = f"New Work Assignment - {assignee}"
                    text_content = f"""Dear {assignee},

You have been assigned new work by your {session['role']}.

Assignment Details:
- Assigned by: {user}
- Project: {project_name}
- Task: {task_desc}
- Start Date: {start_date}
- Due Date: {due_date}
- Work Type: {work_type}

Please log in to your dashboard to view the complete assignment details and update the status as you progress.
https://nexus.chervicaon.com
This is an automated notification from the Timesheet & Leave Management System."""
                    send_email(emp_email, subject, text_content)
                

                print(f" {user} assigned work to {assignee}")
            else:
                failed_employees.append(assignee)
                
        except Exception as e:
            print(f" Error assigning to {assignee}: {e}")
            failed_employees.append(assignee)
    
    # Success/failure messages
    if success_count > 0:
        successful_employees = [emp for emp in assignee_usernames if emp not in failed_employees]
        flash(f" Work assigned successfully to {success_count} direct report(s): {', '.join(successful_employees)}")
    
    if failed_employees:
        flash(f" Failed to assign work to: {', '.join(failed_employees)}")
    
    return redirect(url_for('dashboard'))



@app.route('/update_admin_assignment_status', methods=['POST'])
def update_admin_assignment_status():
    """Update work assignment status (Admin Manager)"""
    if 'username' not in session:
        return redirect(url_for('login_sso'))
    
    if session['role'] not in ('Admin Manager', 'Lead Staffing Specialist'):
        flash(" Access denied.")
        return redirect(url_for('dashboard'))
    
    assignment_id = request.form.get('assignment_id')
    new_status = request.form.get('new_status')
    
    if not assignment_id or not new_status:
        flash(" Assignment ID and status are required.")
        return redirect(url_for('dashboard'))
    
    try:
        # Update assignment status (only if assigned by current user)
        ok = run_exec("""
            UPDATE assigned_work 
            SET rm_status = ?, updated_on = GETDATE()
            WHERE id = ? AND assigned_by = ?
        """, (new_status, int(assignment_id), session['username']))
        
        if ok:
            flash(f" Assignment #{assignment_id} status updated to {new_status}")
        else:
            flash(" Failed to update assignment status or you do not have permission.")
            
    except Exception as e:
        flash(f" Error updating assignment: {str(e)}")
    
    return redirect(url_for('dashboard'))



@app.route('/admin_update_assignment_action', methods=['POST'])
def admin_update_assignment_action():
    """Update work assignment details (Admin Manager)"""
    if 'username' not in session:
        return redirect(url_for('login_sso'))
    
    # Check admin privileges
    if session['role'] not in ('Admin Manager', 'Lead Staffing Specialist'):
        flash(" Access denied. Admin Manager privileges required.")
        return redirect(url_for('dashboard'))
    
    try:
        assignment_id = request.form.get('assignment_id')
        project_name = request.form.get('project_name', '').strip()
        task_desc = request.form.get('task_desc', '').strip()
        start_date = request.form.get('start_date', '').strip()
        end_date = request.form.get('end_date', '').strip()
        due_date = request.form.get('due_date', '').strip()
        work_type = request.form.get('work_type', 'Project')
        
        if not task_desc:
            flash(' Task description is required', 'error')
            return redirect(url_for('dashboard'))
        
        # Update the assignment (only if assigned by current user)
        update_query = """
            UPDATE assigned_work 
            SET project_name = ?, task_desc = ?, start_date = ?, end_date = ?, 
                due_date = ?, work_type = ?, assigned_on = GETDATE()
            WHERE id = ? AND assigned_by = ?
        """
        
        params = [
            project_name if project_name else None,
            task_desc,
            start_date if start_date else None,
            end_date if end_date else None,
            due_date if due_date else None,
            work_type,
            assignment_id,
            session['username']
        ]
        
        result = run_exec(update_query, params)
        
        if result:
            flash(f' Assignment #{assignment_id} updated successfully', 'success')
        else:
            flash(' Failed to update assignment or you do not have permission', 'error')
            
    except Exception as e:
        print(f"Error updating assignment: {e}")
        flash(' Error updating assignment', 'error')
    
    return redirect(url_for('dashboard'))

@app.route('/admin_delete_assignment_action', methods=['POST'])
def admin_delete_assignment_action():
    """Delete work assignment (Admin Manager)"""
    if 'username' not in session:
        return redirect(url_for('login_sso'))
    
    # Check admin privileges
    if session['role'] not in ('Admin Manager', 'Lead Staffing Specialist'):
        flash(" Access denied. Admin Manager privileges required.")
        return redirect(url_for('dashboard'))
    
    assignment_id = request.form.get('assignment_id')
    
    if not assignment_id:
        flash(" Assignment ID is required.")
        return redirect(url_for('dashboard'))
    
    try:
        # Delete assignment (only if assigned by current user)
        ok = run_exec("""
            DELETE FROM assigned_work 
            WHERE id = ? AND assigned_by = ?
        """, (int(assignment_id), session['username']))
        
        if ok:
            flash(f" Assignment #{assignment_id} deleted successfully.")
        else:
            flash(" Failed to delete assignment or you do not have permission.")
            
    except Exception as e:
        flash(f" Error deleting assignment: {str(e)}")
    
    return redirect(url_for('dashboard'))

# Download Routes
# --------------------
@app.route('/download-financial-report')
def download_financial_report():
    """Download financial report"""
    flash("Financial report download functionality would be implemented here.")
    return redirect(url_for('dashboard'))

@app.route('/export-budget-data')
def export_budget_data():
    """Export budget data"""
    flash("Budget data export functionality would be implemented here.")
    return redirect(url_for('dashboard'))

@app.route('/generate-payroll-report')
def generate_payroll_report():
    """Generate payroll report"""
    flash("Payroll report generation functionality would be implemented here.")
    return redirect(url_for('dashboard'))

@app.route('/generate-payslip')
def generate_payslip():
    """Generate payslip for specific employee"""
    username = request.args.get('username')
    flash(f"Payslip generation for {username} would be implemented here.")
    return redirect(url_for('dashboard'))

# API Routes - COMPLETE
# --------------------
@app.route('/api/budget_data')
def get_budget_data():
    """API endpoint to get latest budget data"""
    if 'username' not in session:
        return {'error': 'Unauthorized'}, 401
    
    try:
        budget_summary = run_query("""
            SELECT p.project_name, p.cost_center, p.budget_amount as total_budget,
                   COALESCE(e.used_amount, 0) as used_amount,
                   (p.budget_amount - COALESCE(e.used_amount, 0)) as remaining
            FROM projects p
            LEFT JOIN (
                SELECT project_name, SUM(amount) as used_amount
                FROM expenses
                GROUP BY project_name
            ) e ON p.project_name = e.project_name
            WHERE p.hr_approval_status = 'Approved'
            AND p.budget_amount IS NOT NULL
        """)
        
        budget_records = budget_summary.to_dict('records') if not budget_summary.empty else []
        total_budget = sum(float(row.get('total_budget', 0) or 0) for row in budget_records)
        allocated = sum(float(row.get('used_amount', 0) or 0) for row in budget_records)
        remaining_allocation = total_budget - allocated
        
        return {
            'total_budget': total_budget,
            'allocated': allocated,
            'remaining_allocation': remaining_allocation,
            'budget_summary': budget_records
        }
        
    except Exception as e:
        return {'error': str(e)}, 500

@app.route('/budget_usage_details')
def budget_usage_details():
    """Get detailed budget usage breakdown"""
    try:
        usage_details = run_query("""
            SELECT 
                p.project_name,
                p.cost_center,
                CAST(p.budget_amount AS DECIMAL(18,2)) as amount,
                p.created_by,
                p.created_on,
                CASE 
                    WHEN p.project_name LIKE 'Salary Increase%' THEN 'Salary Increase'
                    WHEN p.project_name LIKE 'Asset Purchase%' THEN 'Asset Purchase'
                    ELSE 'Project Allocation'
                END as usage_type,
                p.description
            FROM projects p
            WHERE p.hr_approval_status = 'Approved'
            AND p.budget_amount IS NOT NULL
            AND CAST(p.budget_amount AS DECIMAL(18,2)) > 0
            ORDER BY p.created_on DESC
        """)
        
        return jsonify({
            'success': True,
            'usage_details': usage_details.to_dict('records') if not usage_details.empty else []
        })
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        })

    


# --------------------
# Additional Utility Routes
# --------------------
@app.route('/view_timesheet_details')
def view_timesheet_details():
    """View detailed timesheet information"""
    if 'username' not in session:
        return redirect(url_for('login_sso'))
    
    timesheet_id = request.args.get('id')
    if not timesheet_id:
        flash("Timesheet ID is required.")
        return redirect(url_for('dashboard'))
    
    flash("Timesheet details viewed.")
    return redirect(url_for('dashboard'))

@app.route('/view_leave_details')
def view_leave_details():
    """View detailed leave information"""
    if 'username' not in session:
        return redirect(url_for('login_sso'))
    
    leave_id = request.args.get('id')
    if not leave_id:
        flash("Leave ID is required.")
        return redirect(url_for('dashboard'))
    
    flash("Leave details viewed.")
    return redirect(url_for('dashboard'))

# Add these missing routes to fix the BuildError:

@app.route('/request_leave_cancellation', methods=['POST'])
def request_leave_cancellation():
    """Request leave cancellation (alternative name for cancel_leave_action)"""
    return cancel_leave_action()

@app.route('/approve_leave_cancellation', methods=['POST'])
def approve_leave_cancellation():
    """Approve leave cancellation request"""
    if 'username' not in session:
        return redirect(url_for('login_sso'))
    
    user = session['username']
    leave_id = request.form.get('leave_id')
    
    if not leave_id:
        flash("Leave ID is required.")
        return redirect(url_for('dashboard'))
    
    # Check if user has permission to approve cancellations
    team = get_all_reports_recursive(user)
    is_Divyaavasudevan = user.lower() in ['Divyavasudevan', 'Divyaavasudevan']
    
    if not team and not is_Divyaavasudevan:
        flash("You don't have permission to approve leave cancellations.")
        return redirect(url_for('dashboard'))
    
    try:
        # Get leave details for balance restoration
        leave_details = run_query("""
            SELECT username, leave_type, start_date, end_date, rm_status
            FROM leaves 
            WHERE id = ? AND cancellation_requested = 1 AND cancellation_status = 'Pending'
        """, (int(leave_id),))
        
        if not leave_details.empty:
            leave_username = leave_details.iloc[0]['username']
            leave_type = str(leave_details.iloc[0]['leave_type'])
            start_date = parse(str(leave_details.iloc[0]['start_date']))
            end_date = parse(str(leave_details.iloc[0]['end_date']))
            leave_days = (end_date - start_date).days + 1
            
            # Only restore balance if leave was previously approved
            if leave_details.iloc[0]['rm_status'] == 'Approved':
                # Restore leave balance (subtract from used balance)
                _apply_leave_balance(leave_username, leave_type, leave_days, -1)
            
            # Update leave status to cancelled
            ok = run_exec("""
                UPDATE leaves 
                SET rm_status = 'Cancelled', 
                    cancellation_status = 'Approved',
                    cancellation_approver = ?
                WHERE id = ?
            """, (user, int(leave_id)))
            
            if ok:
                emp_email = get_user_email(leave_username)
                if emp_email:
                    subject = f"Leave Cancellation Approved - {leave_username}"
                    text_content = f"""Dear {leave_username},

        Your leave cancellation request has been approved.

        Leave Details:
        - Leave Type: {leave_type}
        - Duration: {leave_days} days
        - Leave Balance Restored: {leave_days} days
        please login here 
        https://nexus.chervicaon.com
        This is an automated notification from the Timesheet & Leave Management System."""
                    send_email(emp_email, subject, text_content)

                flash(f" Leave cancellation approved for {leave_username}. {leave_days} day(s) restored to balance.")
            else:
                flash(" Failed to approve leave cancellation.")
        else:
            flash(" Cancellation request not found or already processed.")
    
    except Exception as e:
        flash(f" Error approving leave cancellation: {str(e)}")
    
    return redirect(url_for('dashboard'))

@app.route('/reject_leave_cancellation', methods=['POST'])
def reject_leave_cancellation():
    """Reject leave cancellation request"""
    if 'username' not in session:
        return redirect(url_for('login_sso'))
    
    user = session['username']
    leave_id = request.form.get('leave_id')
    rejection_reason = request.form.get('rejection_reason', 'Not specified')
    
    if not leave_id:
        flash("Leave ID is required.")
        return redirect(url_for('dashboard'))
    
    # Check if user has permission to reject cancellations
    team = get_all_reports_recursive(user)
    is_Divyaavasudevan = user.lower() in ['Divyavasudevan', 'Divyaavasudevan']
    
    if not team and not is_Divyaavasudevan:
        flash("You don't have permission to reject leave cancellations.")
        return redirect(url_for('dashboard'))
    
    try:
        ok = run_exec("""
            UPDATE leaves 
            SET cancellation_status = 'Rejected',
                cancellation_rejection_reason = ?,
                cancellation_approver = ?
            WHERE id = ? AND cancellation_requested = 1 AND cancellation_status = 'Pending'
        """, (rejection_reason, user, int(leave_id)))
        
        if ok:
            flash(f" Leave cancellation rejected. Reason: {rejection_reason}")
        else:
            flash(" Failed to reject leave cancellation or request not found.")
    
    except Exception as e:
        flash(f" Error rejecting leave cancellation: {str(e)}")
    
    return redirect(url_for('dashboard'))

@app.route('/submit_expense', methods=['POST'])
def submit_expense():
    """Submit expense (alternative name for record_expense_action)"""
    return record_expense_action()

@app.route('/edit_expense_form/<int:expense_id>')
def edit_expense_form(expense_id):
    """Display edit form for expense"""
    if 'username' not in session:
        return redirect(url_for('login_sso'))
    
    user = session['username']
    
    # Get expense data
    expense_data = run_query("""
        SELECT id, project_name, category, amount, date, description, spent_by
        FROM expenses 
        WHERE id = ? AND spent_by = ?
    """, (expense_id, user))
    
    if expense_data.empty:
        flash("Expense not found or you don't have permission to edit it.")
        return redirect(url_for('dashboard'))
    
    # Get projects list
    projects_df = run_query("""
        SELECT project_name FROM projects 
        WHERE hr_approval_status = 'Approved' 
        ORDER BY project_name
    """)
    
    expense = expense_data.iloc[0].to_dict()
    
    # Convert date to string if it's a date object
    if expense.get('date') and hasattr(expense['date'], 'strftime'):
        expense['date'] = expense['date'].strftime('%Y-%m-%d')
    
    return render_template('edit_expense.html',
        expense=expense,
        projects=projects_df.to_dict('records') if not projects_df.empty else [],
        user=user,
        role=session['role']
    )

@app.route('/update_expense', methods=['POST'])
def update_expense():
    """Update expense with new data"""
    if 'username' not in session:
        return redirect(url_for('login_sso'))
    
    user = session['username']
    expense_id = request.form.get('expense_id')
    project_name = request.form.get('project_name')
    category = request.form.get('category')
    amount = request.form.get('amount')
    expense_date = request.form.get('expense_date')
    description = request.form.get('description')
    
    if not all([expense_id, project_name, category, amount, expense_date, description]):
        flash("All fields are required for expense update.")
        return redirect(url_for('edit_expense_form', expense_id=expense_id))
    
    try:
        # Check if expense belongs to user
        check_df = run_query("""
            SELECT spent_by FROM expenses 
            WHERE id = ? AND spent_by = ?
        """, (int(expense_id), user))
        
        if check_df.empty:
            flash("Expense not found or you don't have permission to edit it.")
            return redirect(url_for('dashboard'))
        
        # Update the expense
        ok = run_exec("""
            UPDATE expenses 
            SET project_name = ?, category = ?, amount = ?, date = ?, description = ?
            WHERE id = ? AND spent_by = ?
        """, (project_name, category, float(amount), expense_date, description, int(expense_id), user))
        
        if ok:
            flash("Expense updated successfully.")
        else:
            flash("Failed to update expense.")
    
    except ValueError:
        flash("Invalid amount format.")
        return redirect(url_for('edit_expense_form', expense_id=expense_id))
    except Exception as e:
        flash(f"Error updating expense: {str(e)}")
        return redirect(url_for('edit_expense_form', expense_id=expense_id))
    
    return redirect(url_for('dashboard'))

@app.route('/delete_expense', methods=['POST'])
def delete_expense():
    """Delete an expense"""
    if 'username' not in session:
        return redirect(url_for('login_sso'))
    
    user = session['username']
    expense_id = request.form.get('expense_id')
    
    if not expense_id:
        flash("Expense ID is required.")
        return redirect(url_for('dashboard'))
    
    # Check if expense belongs to user or user is manager/admin
    if session['role'] in ['Manager', 'Admin Manager', 'Hr & Finance Controller']:
        # Managers can delete any expense
        check_query = "SELECT spent_by FROM expenses WHERE id = ?"
        check_params = (int(expense_id),)
    else:
        # Regular users can only delete their own expenses
        check_query = "SELECT spent_by FROM expenses WHERE id = ? AND spent_by = ?"
        check_params = (int(expense_id), user)
    
    check_df = run_query(check_query, check_params)
    
    if check_df.empty:
        flash("Expense not found or you don't have permission to delete it.")
        return redirect(url_for('dashboard'))
    
    # Delete the expense
    ok = run_exec("DELETE FROM expenses WHERE id = ?", (int(expense_id),))
    
    if ok:
        flash("Expense deleted successfully.")
    else:
        flash("Failed to delete expense.")
    
    return redirect(url_for('dashboard'))

@app.route('/withdraw_timesheet', methods=['POST'])
def withdraw_timesheet():
    """Withdraw a pending timesheet (same as delete for pending items)"""
    if 'username' not in session:
        return redirect(url_for('login_sso'))
    
    user = session['username']
    timesheet_id = request.form.get('timesheet_id')
    
    if not timesheet_id:
        flash("Timesheet ID is required.")
        return redirect(url_for('dashboard'))
    
    # Check if timesheet belongs to user and is still pending
    check_df = run_query("""
        SELECT rm_status FROM timesheets 
        WHERE id = ? AND username = ?
    """, (int(timesheet_id), user))
    
    if check_df.empty:
        flash("Timesheet not found or you don't have permission to withdraw it.")
        return redirect(url_for('dashboard'))
    
    if check_df.iloc[0]['rm_status'] != 'Pending':
        flash("Cannot withdraw timesheet that has already been processed.")
        return redirect(url_for('dashboard'))
    
    # Delete the timesheet
    ok = run_exec("""
        DELETE FROM timesheets 
        WHERE id = ? AND username = ? AND rm_status = 'Pending'
    """, (int(timesheet_id), user))
    
    if ok:
        flash("Timesheet withdrawn successfully.")
    else:
        flash("Failed to withdraw timesheet.")
    
    return redirect(url_for('dashboard'))

@app.route('/withdraw_leave', methods=['POST'])
def withdraw_leave():
    """Withdraw a pending leave request"""
    if 'username' not in session:
        return redirect(url_for('login_sso'))
    
    user = session['username']
    leave_id = request.form.get('leave_id')
    
    if not leave_id:
        flash("Leave ID is required.")
        return redirect(url_for('dashboard'))
    
    # Check if leave belongs to user and is still pending
    check_df = run_query("""
        SELECT rm_status FROM leaves 
        WHERE id = ? AND username = ?
    """, (int(leave_id), user))
    
    if check_df.empty:
        flash("Leave request not found or you don't have permission to withdraw it.")
        return redirect(url_for('dashboard'))
    
    if check_df.iloc[0]['rm_status'] != 'Pending':
        flash("Cannot withdraw leave request that has already been processed.")
        return redirect(url_for('dashboard'))
    
    # Delete the leave request
    ok = run_exec("""
        DELETE FROM leaves 
        WHERE id = ? AND username = ? AND rm_status = 'Pending'
    """, (int(leave_id), user))
    
    if ok:
        flash("Leave request withdrawn successfully.")
    else:
        flash("Failed to withdraw leave request.")
    
    return redirect(url_for('dashboard'))

# Add these additional helper routes that might be referenced in templates:

@app.route('/get_project_details/<project_name>')
def get_project_details(project_name):
    """Get project details for AJAX calls"""
    if 'username' not in session:
        return jsonify({'error': 'Unauthorized'}), 401
    
    try:
        project = run_query("""
            SELECT project_name, description, cost_center, budget_amount, created_by
            FROM projects 
            WHERE project_name = ? AND hr_approval_status = 'Approved'
        """, (project_name,))
        
        if not project.empty:
            return jsonify(project.iloc[0].to_dict())
        else:
            return jsonify({'error': 'Project not found'}), 404
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/get_employee_leave_balance/<username>')
def get_employee_leave_balance(username):
    """Get employee leave balance for managers"""
    if 'username' not in session:
        return jsonify({'error': 'Unauthorized'}), 401
    
    # Check if current user can view this employee's data
    current_user = session['username']
    team = get_all_reports_recursive(current_user)
    is_manager = session['role'] in ['Manager', 'Admin Manager', 'Hr & Finance Controller']
    
    if username != current_user and username not in team and not is_manager:
        return jsonify({'error': 'Access denied'}), 403
    
    try:
        balance = _get_remaining_balances(username)
        return jsonify(balance)
    except Exception as e:
        return jsonify({'error': str(e)}), 500
    

        # Add these missing project management routes:

@app.route('/delete_project_Divyaavasudevan', methods=['POST'])
def delete_project_Divyaavasudevan():
    """Delete project (Divyaavasudevan/Manager specific)"""
    if 'username' not in session:
        return redirect(url_for('login_sso'))
    
    user = session['username']
    project_id = request.form.get('project_id')
    project_name = request.form.get('project_name')
    
    # Check if user has permission to delete projects
    is_Divyaavasudevan = user.lower() in ['Divyavasudevan', 'Divyaavasudevan']
    is_manager = session['role'] in ['Manager', 'Admin Manager', 'Hr & Finance Controller']
    
    if not (is_Divyaavasudevan or is_manager):
        flash(" Access denied. Manager privileges required.")
        return redirect(url_for('dashboard'))
    
    if not project_id:
        flash(" Project ID is required.")
        return redirect(url_for('dashboard'))
    
    try:
        # Check if project has any associated expenses or work
        expenses_check = run_query("SELECT COUNT(*) as count FROM expenses WHERE project_name = ?", (project_name,))
        work_check = run_query("SELECT COUNT(*) as count FROM timesheets WHERE project_name = ?", (project_name,))
        
        has_expenses = not expenses_check.empty and expenses_check.iloc[0]['count'] > 0
        has_work = not work_check.empty and work_check.iloc[0]['count'] > 0
        
        if has_expenses or has_work:
            flash(f" Cannot delete project '{project_name}' - it has associated expenses or work entries.")
            return redirect(url_for('dashboard'))
        
        # Delete the project
        ok = run_exec("DELETE FROM projects WHERE project_id = ?", (int(project_id),))
        
        if ok:
            flash(f" Project '{project_name}' deleted successfully.")
        else:
            flash(" Failed to delete project.")
    
    except Exception as e:
        flash(f" Error deleting project: {str(e)}")
    
    return redirect(url_for('dashboard'))



@app.route('/delete_expense_Divyaavasudevan', methods=['POST'])
def delete_expense_Divyaavasudevan():
    """Delete expense (Divyaavasudevan/Manager specific)"""
    if 'username' not in session:
        return redirect(url_for('login_sso'))
    
    user = session['username']
    expense_id = request.form.get('expense_id')
    
    # Check if user has permission to delete expenses
    is_Divyaavasudevan = user.lower() in ['Divyaavasudevan', 'Divyaavasudevan']
    is_manager = session['role'] in ['Manager', 'Admin Manager', 'Hr & Finance Controller']
    
    if not (is_Divyaavasudevan or is_manager):
        flash(" Access denied. Manager privileges required.")
        return redirect(url_for('dashboard'))
    
    if not expense_id:
        flash(" Expense ID is required.")
        return redirect(url_for('dashboard'))
    
    try:
        # Get expense details for confirmation
        expense_details = run_query("""
            SELECT project_name, amount, spent_by FROM expenses WHERE id = ?
        """, (int(expense_id),))
        
        if not expense_details.empty:
            expense = expense_details.iloc[0]
            ok = run_exec("DELETE FROM expenses WHERE id = ?", (int(expense_id),))
            
            if ok:
                flash(f" Expense deleted: ₹{expense['amount']} from {expense['project_name']} (by {expense['spent_by']}).")
            else:
                flash(" Failed to delete expense.")
        else:
            flash(" Expense not found.")
    
    except Exception as e:
        flash(f" Error deleting expense: {str(e)}")
    
    return redirect(url_for('dashboard'))

@app.route('/edit_expense_Divyaavasudevan', methods=['POST'])
def edit_expense_Divyaavasudevan():
    """Edit expense (Divyaavasudevan/Manager specific)"""
    if 'username' not in session:
        return redirect(url_for('login_sso'))
    
    user = session['username']
    expense_id = request.form.get('expense_id')
    project_name = request.form.get('project_name')
    category = request.form.get('category')
    amount = request.form.get('amount')
    description = request.form.get('description')
    expense_date = request.form.get('expense_date')
    
    # Check if user has permission to edit expenses
    is_Divyaavasudevan = user.lower() in ['Divyavasudevan', 'Divyaavasudevan']
    is_manager = session['role'] in ['Manager', 'Admin Manager', 'Hr & Finance Controller']
    
    if not (is_Divyaavasudevan or is_manager):
        flash(" Access denied. Manager privileges required.")
        return redirect(url_for('dashboard'))
    
    if not all([expense_id, project_name, category, amount, description]):
        flash(" All fields are required.")
        return redirect(url_for('dashboard'))
    
    try:
        ok = run_exec("""
            UPDATE expenses 
            SET project_name = ?, category = ?, amount = ?, description = ?, date = ?
            WHERE id = ?
        """, (project_name, category, float(amount), description, expense_date, int(expense_id)))
        
        if ok:
            flash(f" Expense updated: ₹{amount} for {project_name}.")
        else:
            flash(" Failed to update expense.")
    
    except ValueError:
        flash(" Invalid amount format.")
    except Exception as e:
        flash(f" Error updating expense: {str(e)}")
    
    return redirect(url_for('dashboard'))

@app.route('/approve_project_Divyaavasudevan', methods=['POST'])
def approve_project_Divyaavasudevan():
    """Approve project (Divyaavasudevan specific)"""
    if 'username' not in session or session['username'].lower() not in ['Divyavasudevan', 'Divyaavasudevan']:
        flash(" Access denied.")
        return redirect(url_for('dashboard'))
    
    project_id = request.form.get('project_id')
    project_name = request.form.get('project_name')
    
    if not project_id:
        flash(" Project ID is required.")
        return redirect(url_for('dashboard'))
    
    try:
        ok = run_exec("""
            UPDATE projects 
            SET hr_approval_status = 'Approved', status = 'Approved'
            WHERE project_id = ?
        """, (int(project_id),))
        
        if ok:
            flash(f" Project '{project_name or project_id}' approved successfully.")
        else:
            flash(" Failed to approve project.")
    
    except Exception as e:
        flash(f" Error approving project: {str(e)}")
    
    return redirect(url_for('dashboard'))

@app.route('/reject_project_Divyaavasudevan', methods=['POST'])
def reject_project_Divyaavasudevan():
    """Reject project (Divyaavasudevan specific)"""
    if 'username' not in session or session['username'].lower() not in ['Divyavasudevan', 'Divyaavasudevan']:
        flash(" Access denied.")
        return redirect(url_for('dashboard'))
    
    project_id = request.form.get('project_id')
    project_name = request.form.get('project_name')
    rejection_reason = request.form.get('rejection_reason', 'Not specified')
    
    if not project_id:
        flash(" Project ID is required.")
        return redirect(url_for('dashboard'))
    
    try:
        ok = run_exec("""
            UPDATE projects 
            SET hr_approval_status = 'Rejected', status = 'Rejected', hr_rejection_reason = ?
            WHERE project_id = ?
        """, (rejection_reason, int(project_id),))
        
        if ok:
            flash(f" Project '{project_name or project_id}' rejected. Reason: {rejection_reason}")
        else:
            flash(" Failed to reject project.")
    
    except Exception as e:
        flash(f" Error rejecting project: {str(e)}")
    
    return redirect(url_for('dashboard'))

@app.route('/update_budget_Divyaavasudevan', methods=['POST'])
def update_budget_Divyaavasudevan():
    """Update total budget (Divyaavasudevan specific)"""
    if 'username' not in session or session['username'].lower() not in ['Divyaavasudevan', 'Divyaavasudevan']:
        flash(" Access denied.")
        return redirect(url_for('dashboard'))
    
    new_total_budget = request.form.get('total_budget')
    reason = request.form.get('reason', 'Budget update')
    
    if not new_total_budget:
        flash(" Budget amount is required.")
        return redirect(url_for('dashboard'))
    
    try:
        new_budget = float(new_total_budget)
        
        # Check current allocations
        allocated_df = run_query("""
            SELECT COALESCE(SUM(CAST(budget_amount AS DECIMAL(18,2))), 0) as allocated 
            FROM projects 
            WHERE hr_approval_status = 'Approved' 
            AND budget_amount IS NOT NULL
            AND CAST(budget_amount AS DECIMAL(18,2)) > 0
        """)
        
        allocated = float(allocated_df['allocated'].iloc[0]) if not allocated_df.empty else 0.0
        
        if new_budget < allocated:
            flash(f" New budget (₹{new_budget:,.2f}) cannot be less than already allocated (₹{allocated:,.2f})")
            return redirect(url_for('dashboard'))
        
        # Update or insert budget record
        budget_exists = run_query("SELECT id FROM company_budget WHERE id = 1")
        
        if budget_exists.empty:
            ok = run_exec("""
                INSERT INTO [timesheet_db].[dbo].[company_budget] (id, total_budget, updated_by, updated_on, reason)
                VALUES (1, ?, ?, GETDATE(), ?)
            """, (new_budget, session['username'], reason))
        else:
            ok = run_exec("""
                UPDATE company_budget 
                SET total_budget = ?, updated_by = ?, updated_on = GETDATE(), reason = ?
                WHERE id = 1
            """, (new_budget, session['username'], reason))
        
        if ok:
            remaining = new_budget - allocated
            flash(f" Total budget updated to ₹{new_budget:,.2f}. Remaining: ₹{remaining:,.2f}")
        else:
            flash(" Failed to update budget.")
    
    except ValueError:
        flash(" Invalid budget amount.")
    except Exception as e:
        flash(f" Error updating budget: {str(e)}")
    
    return redirect(url_for('dashboard'))

@app.route('/allocate_budget_Divyaavasudevan', methods=['POST'])
def allocate_budget_Divyaavasudevan():
    """Allocate budget to project (Divyaavasudevan specific)"""
    if 'username' not in session or session['username'].lower() not in ['Divyaavasudevan', 'Divyaavasudevan']:
        flash(" Access denied.")
        return redirect(url_for('dashboard'))
    
    project_name = request.form.get('project_name')
    budget_amount = request.form.get('budget_amount')
    cost_center = request.form.get('cost_center')
    
    if not all([project_name, budget_amount]):
        flash(" Project name and budget amount are required.")
        return redirect(url_for('dashboard'))
    
    try:
        allocation = float(budget_amount)
        
        # Check remaining budget
        total_budget_df = run_query("SELECT total_budget FROM company_budget WHERE id = 1")
        allocated_df = run_query("""
            SELECT COALESCE(SUM(CAST(budget_amount AS DECIMAL(18,2))), 0) as allocated 
            FROM projects 
            WHERE hr_approval_status = 'Approved' 
            AND budget_amount IS NOT NULL
            AND CAST(budget_amount AS DECIMAL(18,2)) > 0
        """)
        
        if not total_budget_df.empty and not allocated_df.empty:
            total_budget = float(total_budget_df['total_budget'].iloc[0])
            currently_allocated = float(allocated_df['allocated'].iloc[0])
            remaining_budget = total_budget - currently_allocated
            
            if allocation > remaining_budget:
                flash(f" Insufficient budget. Available: ₹{remaining_budget:,.2f}, Requested: ₹{allocation:,.2f}")
                return redirect(url_for('dashboard'))
        
        # Allocate budget to project
        ok = run_exec("""
            UPDATE projects 
            SET budget_amount = ?, cost_center = ?
            WHERE project_name = ? AND hr_approval_status = 'Approved'
        """, (allocation, cost_center, project_name))
        
        if ok:
            new_remaining = remaining_budget - allocation
            flash(f" ₹{allocation:,.2f} allocated to '{project_name}'. Remaining budget: ₹{new_remaining:,.2f}")
        else:
            flash(" Failed to allocate budget. Check if project exists and is approved.")
    
    except ValueError:
        flash(" Invalid budget amount.")
    except Exception as e:
        flash(f" Error allocating budget: {str(e)}")
    
    return redirect(url_for('dashboard'))

@app.route('/view_project_expenses/<project_name>')
def view_project_expenses(project_name):
    """View expenses for a specific project"""
    if 'username' not in session:
        return redirect(url_for('login_sso'))
    
    # Check permissions
    user = session['username']
    is_Divyaavasudevan = user.lower() in ['Divyavasudevan', 'Divyaavasudevan']
    is_manager = session['role'] in ['Manager', 'Admin Manager', 'Hr & Finance Controller']
    
    if not (is_Divyaavasudevan or is_manager):
        flash(" Access denied.")
        return redirect(url_for('dashboard'))
    
    try:
        project_expenses = run_query("""
            SELECT id, category, amount, description, date, spent_by
            FROM expenses 
            WHERE project_name = ?
            ORDER BY date DESC
        """, (project_name,))
        
        project_info = run_query("""
            SELECT project_name, description, budget_amount, cost_center, created_by
            FROM projects 
            WHERE project_name = ?
        """, (project_name,))
        
        total_spent = sum(float(expense['amount'] or 0) for expense in project_expenses.to_dict('records'))
        
        return render_template('project_expenses.html',
            project_name=project_name,
            project_info=project_info.iloc[0].to_dict() if not project_info.empty else {},
            expenses=project_expenses.to_dict('records') if not project_expenses.empty else [],
            total_spent=total_spent,
            user=user,
            role=session['role']
        )
    
    except Exception as e:
        flash(f" Error viewing project expenses: {str(e)}")
        return redirect(url_for('dashboard'))
# Add these missing expense management routes:
@app.route('/edit_expense_action', methods=['POST'])
def edit_expense_action():
    # Edit expense - HR Finance Controller - FIXED WITH FOREIGN KEY HANDLING
    if 'username' not in session or session['role'] != 'Hr Finance Controller':
        flash('Access denied. HR Finance Controller privileges required.')
        return redirect(url_for('hr_finance_controller'))
    
    expense_id = request.form.get('expenseid')
    project = request.form.get('project')
    category = request.form.get('category')
    amount = request.form.get('amount')
    exp_date = request.form.get('expdate')
    desc = request.form.get('desc')
    
    if not all([expense_id, project, category, amount, exp_date, desc]):
        flash('All fields are required for expense update.')
        return redirect(url_for('hr_finance_controller'))
    
    try:
        # Handle the foreign key constraint issue
        # If project is 'non-project', set it to NULL in database
        if project == 'non-project' or project == '' or project is None:
            project_name = None  # This will be stored as NULL in database
        else:
            # Verify the project actually exists in projects table
            project_check = run_query("SELECT project_name FROM projects WHERE project_name = ?", (project,))
            if project_check.empty:
                flash('Selected project does not exist. Setting to non-project.', 'warning')
                project_name = None
            else:
                project_name = project
        
        # Update the expense with proper NULL handling
        ok = run_exec("""UPDATE expenses 
                         SET project_name = ?, category = ?, amount = ?, date = ?, description = ? 
                         WHERE id = ?""", 
                     (project_name, category, float(amount), exp_date, desc, expense_id))
        
        if ok:
            if project_name is None:
                flash(f'Expense {expense_id} updated successfully (set to non-project).')
            else:
                flash(f'Expense {expense_id} updated successfully to project {project_name}.')
        else:
            flash('Failed to update expense.')
            
    except Exception as e:
        print(f"Edit expense error: {e}")
        flash(f'Error updating expense: {str(e)}')
    
    return redirect(url_for('hr_finance_controller'))





@app.route('/delete_expense_action', methods=['POST'])
def delete_expense_action():
    """Delete expense - HR Finance Controller"""
    if 'username' not in session or session['role'] != 'Hr & Finance Controller':
        flash("Access denied. HR & Finance Controller privileges required.")
        return redirect(url_for('dashboard'))
    
    expense_id = request.form.get('expense_id')
    
    try:
        ok = run_exec("DELETE FROM expenses WHERE id = ?", (expense_id,))
        if ok:
            flash("Expense deleted successfully.")
        else:
            flash("Failed to delete expense.")
    except Exception as e:
        flash(f"Error deleting expense: {str(e)}")
    
    return redirect(url_for('dashboard'))


@app.route('/submit_expense_action', methods=['POST'])
def submit_expense_action():
    """Submit expense action (alternative name for record_expense_action)"""
    return record_expense_action()

@app.route('/approve_expense_action', methods=['POST'])
def approve_expense_action():
    """Approve expense (for managers)"""
    if 'username' not in session:
        return redirect(url_for('login_sso'))
    
    user = session['username']
    expense_id = request.form.get('expense_id')
    
    # Check if user has permission to approve expenses
    is_manager = session['role'] in ['Manager', 'Admin Manager', 'Hr & Finance Controller']
    is_Divyaavasudevan = user.lower() in ['Divyavasudevan', 'Divyaavasudevan']
    
    if not (is_manager or is_Divyaavasudevan):
        flash(" Access denied. Manager privileges required.")
        return redirect(url_for('dashboard'))
    
    if not expense_id:
        flash(" Expense ID is required.")
        return redirect(url_for('dashboard'))
    
    try:
        ok = run_exec("""
            UPDATE expenses 
            SET status = 'Approved', approved_by = ?, approved_date = GETDATE()
            WHERE id = ?
        """, (user, int(expense_id)))
        
        if ok:
            flash(" Expense approved successfully.")
        else:
            flash(" Failed to approve expense.")
    
    except Exception as e:
        flash(f" Error approving expense: {str(e)}")
    
    return redirect(url_for('dashboard'))

@app.route('/reject_expense_action', methods=['POST'])
def reject_expense_action():
    """Reject expense (for managers)"""
    if 'username' not in session:
        return redirect(url_for('login_sso'))
    
    user = session['username']
    expense_id = request.form.get('expense_id')
    rejection_reason = request.form.get('rejection_reason', 'Not specified')
    
    # Check if user has permission to reject expenses
    is_manager = session['role'] in ['Manager', 'Admin Manager', 'Hr & Finance Controller']
    is_Divyaavasudevan = user.lower() in ['Divyaavasudevan', 'Divyaavasudevan']
    
    if not (is_manager or is_Divyaavasudevan):
        flash(" Access denied. Manager privileges required.")
        return redirect(url_for('dashboard'))
    
    if not expense_id:
        flash(" Expense ID is required.")
        return redirect(url_for('dashboard'))
    
    try:
        ok = run_exec("""
            UPDATE expenses 
            SET status = 'Rejected', approved_by = ?, approved_date = GETDATE(), rejection_reason = ?
            WHERE id = ?
        """, (user, rejection_reason, int(expense_id)))
        
        if ok:
            flash(f" Expense rejected. Reason: {rejection_reason}")
        else:
            flash(" Failed to reject expense.")
    
    except Exception as e:
        flash(f" Error rejecting expense: {str(e)}")
    
    return redirect(url_for('dashboard'))

# Add missing budget-related routes:

@app.route('/create_budget_action', methods=['POST'])
def create_budget_action():
    """Create budget allocation"""
    if 'username' not in session:
        return redirect(url_for('login_sso'))
    
    # Check permissions
    if session['role'] not in ['Manager', 'Admin Manager', 'Hr & Finance Controller']:
        flash(" Access denied.")
        return redirect(url_for('dashboard'))
    
    project_name = request.form.get('project_name')
    budget_amount = request.form.get('budget_amount')
    cost_center = request.form.get('cost_center', 'General')
    
    if not project_name or not budget_amount:
        flash(" Project name and budget amount are required.")
        return redirect(url_for('dashboard'))
    
    try:
        allocation = float(budget_amount)
        
        # Update project with budget allocation
        ok = run_exec("""
            UPDATE projects 
            SET budget_amount = ?, cost_center = ?
            WHERE project_name = ? AND hr_approval_status = 'Approved'
        """, (allocation, cost_center, project_name))
        
        if ok:
            flash(f" Budget of ₹{allocation:,.2f} allocated to '{project_name}'.")
        else:
            flash(" Failed to allocate budget. Check if project exists and is approved.")
    
    except ValueError:
        flash(" Invalid budget amount.")
    except Exception as e:
        flash(f" Error: {str(e)}")
    
    return redirect(url_for('dashboard'))

@app.route('/update_budget_action', methods=['POST'])
def update_budget_action():
    """Update budget allocation"""
    if 'username' not in session:
        return redirect(url_for('login_sso'))
    
    # Check permissions
    if session['role'] not in ['Manager', 'Admin Manager', 'Hr & Finance Controller']:
        flash(" Access denied.")
        return redirect(url_for('dashboard'))
    
    project_name = request.form.get('project_name')
    new_budget = request.form.get('new_budget')
    
    if not project_name or not new_budget:
        flash(" Project name and new budget amount are required.")
        return redirect(url_for('dashboard'))
    
    try:
        new_amount = float(new_budget)
        
        ok = run_exec("""
            UPDATE projects 
            SET budget_amount = ?
            WHERE project_name = ?
        """, (new_amount, project_name))
        
        if ok:
            flash(f" Budget for '{project_name}' updated to ₹{new_amount:,.2f}.")
        else:
            flash(" Failed to update budget.")
    
    except ValueError:
        flash(" Invalid budget amount.")
    except Exception as e:
        flash(f" Error: {str(e)}")
    
    return redirect(url_for('dashboard'))

# Add missing payroll routes:

def update_payroll_no_project_deduction(username, new_monthly, new_yearly, approver):
    # Get current salary
    current_payroll = run_query("""
        SELECT ISNULL(monthly_salary,0) AS monthly, ISNULL(yearly_salary,0) AS yearly
        FROM users WHERE username = ?
    """, (username,))
    if current_payroll.empty:
        return False, "User not found"
    current_monthly = float(current_payroll.iloc[0]['monthly'])

    increase_per_year = (new_monthly - current_monthly) * 12

    # If no increase or decrease, just update payroll
    if increase_per_year <= 0:
        ok = run_exec("""
            UPDATE users SET monthly_salary = ?, yearly_salary = ? WHERE username = ?
        """, (new_monthly, new_yearly, username))
        return ok, "Updated"

    # Check budget availability
    company_budget = run_query("SELECT total_budget FROM company_budget WHERE id = 1")
    total_budget = float(company_budget.iloc[0]['total_budget'])

    total_allocated = run_query("""
        SELECT ISNULL(SUM(ISNULL(budget_amount,0)),0) AS allocated FROM projects WHERE hr_approval_status = 'Approved'
    """)[0]['allocated']

    remaining_budget = total_budget - total_allocated

    if remaining_budget < increase_per_year:
        return False, "Insufficient budget"

    # Approve payroll update without creating a project, only deduct budget externally

    ok = run_exec("""
        UPDATE users SET monthly_salary = ?, yearly_salary = ? WHERE username = ?
    """, (new_monthly, new_yearly, username))
    return ok, "Updated with increased payroll"

@app.route('/submit_asset_request_action', methods=['POST'])
def submit_asset_request_action():
    """Submit asset request"""
    return request_asset_with_document()

# Add missing employee management routes:


@app.route('/deactivate_employee_action', methods=['POST'])
def deactivate_employee_action():
    """Deactivate employee"""
    if 'username' not in session:
        return redirect(url_for('login_sso'))
    
    # Check permissions
    if session['role'] not in ['Admin Manager', 'Lead Staffing Specialist']:
        flash(" Access denied. Admin Manager privileges required.")
        return redirect(url_for('dashboard'))
    
    employee_username = request.form.get('employee_username')
    reason = request.form.get('deactivation_reason', 'Not specified')
    
    if not employee_username:
        flash(" Employee username is required.")
        return redirect(url_for('dashboard'))
    
    try:
        ok = run_exec("""
            UPDATE users 
            SET status = 'Inactive'
            WHERE username = ?
        """, (employee_username,))
        
        if ok:
            # NEW: Email notification to employee about deactivation
            emp_email = get_user_email(employee_username)
            if emp_email:
                subject = f"Account Deactivated - {employee_username}"
                text_content = f"""Dear {employee_username},

Your account has been deactivated by the administration.

Reason: {reason}
Deactivated by: {session['username']}
Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}

please login here
https://nexus.chervicaon.com
If you have any questions about this action, please contact the HR department.

This is an automated notification from the Timesheet & Leave Management System."""
                send_email(emp_email, subject, text_content)

            # NEW: Email notification to HR about employee deactivation
            hr_users = run_query("""
                SELECT email FROM users 
                WHERE role IN ('Hr & Finance Controller', 'Admin Manager') 
                AND status = 'Active' AND email IS NOT NULL
            """)
            
            if not hr_users.empty:
                for _, hr_user in hr_users.iterrows():
                    hr_email = hr_user['email']
                    if hr_email:
                        subject = f"Employee Deactivated - {employee_username}"
                        text_content = f"""Dear HR Team,

An employee account has been deactivated.

Details:
- Employee: {employee_username}
- Deactivated by: {session['username']} ({session['role']})
- Reason: {reason}
- Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}

please login here
https://nexus.chervicaon.com
This is an automated notification from the Timesheet & Leave Management System."""
                        send_email(hr_email, subject, text_content)

            flash(f" Employee {employee_username} deactivated. Reason: {reason}")
        else:
            flash(" Failed to deactivate employee.")
    
    except Exception as e:
        flash(f" Error: {str(e)}")
    
    return redirect(url_for('dashboard'))

# Add missing report generation routes:

@app.route('/generate_report_action', methods=['POST'])
def generate_report_action():
    """Generate various reports"""
    if 'username' not in session:
        return redirect(url_for('login_sso'))
    
    report_type = request.form.get('report_type')
    start_date = request.form.get('start_date')
    end_date = request.form.get('end_date')
    
    flash(f" {report_type} report generation requested for {start_date} to {end_date}.")
    return redirect(url_for('dashboard'))

@app.route('/export_data_action', methods=['POST'])
def export_data_action():
    """Export data to various formats"""
    if 'username' not in session:
        return redirect(url_for('login_sso'))
    
    export_type = request.form.get('export_type')
    data_type = request.form.get('data_type')
    
    flash(f" {data_type} data export to {export_type} format initiated.")
    return redirect(url_for('dashboard'))
# Add these missing HR Finance routes:

@app.route('/edit_budget_allocation_action', methods=['POST'])
def edit_budget_allocation_action():
    """Edit budget allocation for project"""
    if 'username' not in session or session['role'] != 'Hr & Finance Controller':
        flash("Access denied. HR & Finance Controller privileges required.")
        return redirect(url_for('dashboard'))
    
    project_name = request.form.get('project_name')
    budget_amount = request.form.get('budget_amount')
    cost_center = request.form.get('cost_center')
    
    if not project_name or not budget_amount or not cost_center:
        flash("All fields are required.")
        return redirect(url_for('dashboard'))
    
    try:
        budget_amount = float(budget_amount)
        
        ok = run_exec("""
            UPDATE projects 
            SET budget_amount = ?, cost_center = ?
            WHERE project_name = ?
        """, (budget_amount, cost_center, project_name))
        
        if ok:
            flash(f" Budget allocation updated for '{project_name}': ₹{budget_amount:,.2f}")
        else:
            flash(" Failed to update budget allocation.")
    except ValueError:
        flash(" Invalid budget amount.")
    except Exception as e:
        flash(f" Error updating budget allocation: {str(e)}")
    
    return redirect(url_for('dashboard'))

@app.route('/delete_budget_allocation_action', methods=['POST'])
def delete_budget_allocation_action():
    """Remove budget allocation from project"""
    if 'username' not in session or session['role'] != 'Hr & Finance Controller':
        flash(" Access denied. HR & Finance Controller privileges required.")
        return redirect(url_for('dashboard'))
    
    project_name = request.form.get('project_name')
    
    if not project_name:
        flash(" Project name is required.")
        return redirect(url_for('dashboard'))
    
    try:
        # Get current budget to show how much is being freed up
        current_budget_df = run_query("""
            SELECT COALESCE(CAST(budget_amount AS DECIMAL(18,2)), 0) as current_budget
            FROM projects WHERE project_name = ?
        """, (project_name,))
        
        current_budget = float(current_budget_df['current_budget'].iloc[0]) if not current_budget_df.empty else 0.0
        
        # Check if project has expenses
        expenses_check = run_query("""
            SELECT COALESCE(SUM(CAST(amount AS DECIMAL(18,2))), 0) as total_expenses
            FROM expenses WHERE project_name = ?
        """, (project_name,))
        
        total_expenses = float(expenses_check['total_expenses'].iloc[0]) if not expenses_check.empty else 0.0
        
        if total_expenses > 0:
            flash(f" Cannot remove budget allocation. Project has ₹{total_expenses:,.2f} in expenses.")
            return redirect(url_for('dashboard'))
        
        # Remove budget allocation
        ok = run_exec("""
            UPDATE projects 
            SET budget_amount = NULL, cost_center = NULL
            WHERE project_name = ?
        """, (project_name,))
        
        if ok:
            flash(f" Budget allocation removed from '{project_name}'. ₹{current_budget:,.2f} returned to available budget.")
        else:
            flash(" Failed to remove budget allocation.")
    
    except Exception as e:
        flash(f" Error removing budget allocation: {str(e)}")
    
    return redirect(url_for('dashboard'))

@app.route('/reallocate_budget_action', methods=['POST'])
def reallocate_budget_action():
    """Reallocate budget between projects"""
    if 'username' not in session or session['role'] != 'Hr & Finance Controller':
        flash(" Access denied. HR & Finance Controller privileges required.")
        return redirect(url_for('dashboard'))
    
    from_project = request.form.get('from_project')
    to_project = request.form.get('to_project')
    amount = request.form.get('amount')
    
    if not all([from_project, to_project, amount]):
        flash(" All fields are required for budget reallocation.")
        return redirect(url_for('dashboard'))
    
    try:
        realloc_amount = float(amount)
        
        # Get current budgets
        from_budget_df = run_query("""
            SELECT COALESCE(CAST(budget_amount AS DECIMAL(18,2)), 0) as budget
            FROM projects WHERE project_name = ?
        """, (from_project,))
        
        to_budget_df = run_query("""
            SELECT COALESCE(CAST(budget_amount AS DECIMAL(18,2)), 0) as budget
            FROM projects WHERE project_name = ?
        """, (to_project,))
        
        if from_budget_df.empty or to_budget_df.empty:
            flash(" One or both projects not found.")
            return redirect(url_for('dashboard'))
        
        from_current = float(from_budget_df['budget'].iloc[0])
        to_current = float(to_budget_df['budget'].iloc[0])
        
        if from_current < realloc_amount:
            flash(f" Insufficient budget in '{from_project}'. Available: ₹{from_current:,.2f}")
            return redirect(url_for('dashboard'))
        
        # Update both projects
        ok1 = run_exec("""
            UPDATE projects 
            SET budget_amount = ?
            WHERE project_name = ?
        """, (from_current - realloc_amount, from_project))
        
        ok2 = run_exec("""
            UPDATE projects 
            SET budget_amount = ?
            WHERE project_name = ?
        """, (to_current + realloc_amount, to_project))
        
        if ok1 and ok2:
            flash(f" ₹{realloc_amount:,.2f} reallocated from '{from_project}' to '{to_project}'.")
        else:
            flash(" Failed to reallocate budget.")
    
    except ValueError:
        flash(" Invalid amount.")
    except Exception as e:
        flash(f" Error reallocating budget: {str(e)}")
    
    return redirect(url_for('dashboard'))

@app.route('/freeze_budget_action', methods=['POST'])
def freeze_budget_action():
    """Freeze budget allocation to prevent changes"""
    if 'username' not in session or session['role'] != 'Hr & Finance Controller':
        flash(" Access denied. HR & Finance Controller privileges required.")
        return redirect(url_for('dashboard'))
    
    project_name = request.form.get('project_name')
    freeze_reason = request.form.get('freeze_reason', 'Budget frozen by HR')
    
    if not project_name:
        flash(" Project name is required.")
        return redirect(url_for('dashboard'))
    
    try:
        ok = run_exec("""
            UPDATE projects 
            SET budget_status = 'Frozen', budget_freeze_reason = ?, budget_frozen_by = ?, budget_frozen_date = GETDATE()
            WHERE project_name = ?
        """, (freeze_reason, session['username'], project_name))
        
        if ok:
            flash(f" Budget frozen for '{project_name}'. Reason: {freeze_reason}")
        else:
            flash(" Failed to freeze budget.")
    
    except Exception as e:
        flash(f" Error freezing budget: {str(e)}")
    
    return redirect(url_for('dashboard'))

@app.route('/unfreeze_budget_action', methods=['POST'])
def unfreeze_budget_action():
    """Unfreeze budget allocation"""
    if 'username' not in session or session['role'] != 'Hr & Finance Controller':
        flash(" Access denied. HR & Finance Controller privileges required.")
        return redirect(url_for('dashboard'))
    
    project_name = request.form.get('project_name')
    
    if not project_name:
        flash(" Project name is required.")
        return redirect(url_for('dashboard'))
    
    try:
        ok = run_exec("""
            UPDATE projects 
            SET budget_status = 'Active', budget_freeze_reason = NULL, budget_frozen_by = NULL, budget_frozen_date = NULL
            WHERE project_name = ?
        """, (project_name,))
        
        if ok:
            flash(f" Budget unfrozen for '{project_name}'.")
        else:
            flash(" Failed to unfreeze budget.")
    
    except Exception as e:
        flash(f" Error unfreezing budget: {str(e)}")
    
    return redirect(url_for('dashboard'))

@app.route('/bulk_budget_update_action', methods=['POST'])
def bulk_budget_update_action():
    """Bulk update multiple budget allocations"""
    if 'username' not in session or session['role'] != 'Hr & Finance Controller':
        flash(" Access denied. HR & Finance Controller privileges required.")
        return redirect(url_for('dashboard'))
    
    projects = request.form.getlist('project_names')
    budgets = request.form.getlist('budget_amounts')
    cost_centers = request.form.getlist('cost_centers')
    
    if len(projects) != len(budgets) or len(projects) != len(cost_centers):
        flash(" Mismatched data arrays for bulk update.")
        return redirect(url_for('dashboard'))
    
    success_count = 0
    failed_projects = []
    
    try:
        for i, project in enumerate(projects):
            if budgets[i] and project:
                try:
                    budget_amount = float(budgets[i])
                    cost_center = cost_centers[i] or 'General'
                    
                    ok = run_exec("""
                        UPDATE projects 
                        SET budget_amount = ?, cost_center = ?
                        WHERE project_name = ?
                    """, (budget_amount, cost_center, project))
                    
                    if ok:
                        success_count += 1
                    else:
                        failed_projects.append(project)
                        
                except ValueError:
                    failed_projects.append(f"{project} (invalid amount)")
        
        if success_count > 0:
            flash(f" {success_count} budget allocations updated successfully.")
        
        if failed_projects:
            flash(f" Failed to update: {', '.join(failed_projects)}")
    
    except Exception as e:
        flash(f" Error in bulk budget update: {str(e)}")
    
    return redirect(url_for('dashboard'))

@app.route('/generate_budget_report_action', methods=['POST'])
def generate_budget_report_action():
    """Generate detailed budget report"""
    if 'username' not in session or session['role'] != 'Hr & Finance Controller':
        flash(" Access denied. HR & Finance Controller privileges required.")
        return redirect(url_for('dashboard'))
    
    report_type = request.form.get('report_type', 'summary')
    include_expenses = request.form.get('include_expenses') == 'on'
    date_range = request.form.get('date_range', 'all')
    
    flash(f" Budget report ({report_type}) generation initiated. Include expenses: {include_expenses}")
    return redirect(url_for('dashboard'))

@app.route('/export_budget_data_action', methods=['POST'])
def export_budget_data_action():
    """Export budget data to various formats"""
    if 'username' not in session or session['role'] != 'Hr & Finance Controller':
        flash(" Access denied. HR & Finance Controller privileges required.")
        return redirect(url_for('dashboard'))
    
    export_format = request.form.get('export_format', 'csv')
    include_history = request.form.get('include_history') == 'on'
    
    flash(f" Budget data export to {export_format.upper()} format initiated.")
    return redirect(url_for('dashboard'))
# Fix Team Timesheet Approval Route
@app.route('/approve_team_work_hr', methods=['POST'])
def approve_team_work_hr():
    """Approve team timesheet (HR specific) - Only for direct reports"""
    if 'username' not in session or session['role'] != 'Hr & Finance Controller':
        flash("Access denied. HR & Finance Controller privileges required.")
        return redirect(url_for('dashboard'))
    
    user = session['username']
    work_id = request.form.get('work_id')
    
    if not work_id:
        flash("Work ID is required.")
        return redirect(url_for('dashboard'))
    
    try:
        # Get HR Finance team members
        team_members = get_direct_reports(user)
        
        # If no direct reports found, try alternative method
        if not team_members:
            team_query = run_query("""
                SELECT username FROM report WHERE rm = ? OR manager = ?
            """, (user, user))
            if not team_query.empty:
                team_members = team_query['username'].tolist()
        
        if not team_members:
            flash(" No team members found for approval.")
            return redirect(url_for('dashboard'))
        
        placeholders = ",".join(["?"] * len(team_members))
        
        # Only approve if the work belongs to a team member
        ok = run_exec(f"""
            UPDATE timesheets 
            SET rm_status = 'Approved', rm_approver = ?
            WHERE id = ? AND username IN ({placeholders}) AND rm_status = 'Pending'
        """, (user, int(work_id)) + tuple(team_members))
        
        if ok:
            flash(" Work approved successfully.")
            # Get employee details for email notification
            timesheet_details = run_query(f"""
                SELECT username, project_name, work_date 
                FROM timesheets 
                WHERE id = ? AND username IN ({placeholders}) AND rm_status = 'Approved'
            """, (int(work_id),) + tuple(team_members))
            
            if not timesheet_details.empty:
                employee_username = timesheet_details.iloc[0]['username']
                
                # Send email notification
                employee_email = get_user_email(employee_username)
                if employee_email:
                    subject = f"Timesheet Approved by HR - {employee_username}"
                    text_content = f"""Dear {employee_username},

        Your timesheet has been approved by HR ({user}).

        You can view the updated status in your dashboard.
        https://nexus.chervicaon.com
        This is an automated notification from the Timesheet & Leave Management System."""
                    send_email(employee_email, subject, text_content)


        else:
            flash(" Failed to approve work. Make sure this employee reports to you.")
    except Exception as e:
        flash(f" Error approving work: {str(e)}")
    
    return redirect(url_for('dashboard'))

@app.route('/approve_team_leave_hr', methods=['POST'])
def approve_team_leave_hr():
    """Approve team leave (HR specific) - Only for direct reports"""
    if 'username' not in session or session['role'] != 'Hr & Finance Controller':
        flash("Access denied. HR & Finance Controller privileges required.")
        return redirect(url_for('dashboard'))
    
    user = session['username']
    leave_id = request.form.get('leave_id')
    
    if not leave_id:
        flash("Leave ID is required.")
        return redirect(url_for('dashboard'))
    
    try:
        # Get HR Finance team members
        team_members = get_direct_reports(user)
        
        # If no direct reports found, try alternative method
        if not team_members:
            team_query = run_query("""
                SELECT username FROM report WHERE rm = ? OR manager = ?
            """, (user, user))
            if not team_query.empty:
                team_members = team_query['username'].tolist()
        
        if not team_members:
            flash(" No team members found for approval.")
            return redirect(url_for('dashboard'))
        
        placeholders = ",".join(["?"] * len(team_members))
        
        # Get leave details for balance update (only for team members)
        leave_details = run_query(f"""
            SELECT username, leave_type, start_date, end_date 
            FROM leaves 
            WHERE id = ? AND username IN ({placeholders}) AND rm_status = 'Pending'
        """, (int(leave_id),) + tuple(team_members))
        
        if not leave_details.empty:
            leave_username = leave_details.iloc[0]['username']
            leave_type = str(leave_details.iloc[0]['leave_type'])
            start_date = parse(str(leave_details.iloc[0]['start_date']))
            end_date = parse(str(leave_details.iloc[0]['end_date']))
            leave_days = (end_date - start_date).days + 1
            
            # Apply leave balance deduction
            _apply_leave_balance(leave_username, leave_type, leave_days, +1)
            
            # Approve leave
            ok = run_exec(f"""
                UPDATE leaves 
                SET rm_status = 'Approved', rm_approver = ?
                WHERE id = ? AND username IN ({placeholders}) AND rm_status = 'Pending'
            """, (user, int(leave_id)) + tuple(team_members))
            
            if ok:
                # Send email notification
                user_email = get_user_email(leave_username)
                if user_email:
                    subject = f"Leave Approved by HR - {leave_username}"
                    text_content = f"""Dear {leave_username},

            Your leave request has been approved by HR ({user}).

            Details:
            - Leave Type: {leave_type}
            - Duration: {leave_days} days
            - Status: Approved

            You can view the updated status in your dashboard.
            https://nexus.chervicaon.com
            This is an automated notification from the Timesheet & Leave Management System."""
                    send_email(user_email, subject, text_content)

                flash(f" Leave approved for {leave_username} ({leave_days} days).")
            else:
                flash(" Failed to approve leave.")
        else:
            flash(" Leave not found or employee does not report to you.")
    except Exception as e:
        flash(f" Error approving leave: {str(e)}")
    
    return redirect(url_for('dashboard'))


@app.route('/reject_team_work', methods=['POST'])
def reject_team_work():
    """Reject team work (for HR Finance Controller managing Sabitha's team)"""
    if 'username' not in session or session['role'] != 'Hr & Finance Controller':
        flash(" Access denied. HR & Finance Controller privileges required.")
        return redirect(url_for('dashboard'))
    
    user = session['username']
    timesheet_id = request.form.get('timesheet_id')
    rejection_reason = request.form.get('rejection_reason', '').strip()
    
    if not timesheet_id:
        flash(" Timesheet ID is required.")
        return redirect(url_for('dashboard'))
    
    if not rejection_reason:
        flash(" Please provide a reason for rejection.")
        return redirect(url_for('dashboard'))
    
    # Get Sabitha's team members
    sabitha_team = []
    for name_variant in ['Sabitha', 'sabitha']:
        team = get_direct_reports(name_variant)
        if team:
            sabitha_team = team
            break
    
    if not sabitha_team:
        flash(" No team members found.")
        return redirect(url_for('dashboard'))
    
    placeholders = ",".join(["?"] * len(sabitha_team))
    
    try:
        ok = run_exec(f"""
            UPDATE timesheets 
            SET rm_status = 'Rejected', rm_approver = ?, rm_rejection_reason = ?
            WHERE id = ? AND username IN ({placeholders}) AND rm_status = 'Pending'
        """, (session['username'], rejection_reason, int(timesheet_id)) + tuple(sabitha_team))
        
        if ok:
            # Get employee details for email notification
            timesheet_details = run_query(f"""
                SELECT username FROM timesheets 
                WHERE id = ? AND username IN ({placeholders}) AND rm_status = 'Rejected'
            """, (int(timesheet_id),) + tuple(sabitha_team))
            
            if not timesheet_details.empty:
                employee_username = timesheet_details.iloc[0]['username']
                
                # Send email notification
                employee_email = get_user_email(employee_username)
                if employee_email:
                    subject = f"Timesheet Rejected by HR - {employee_username}"
                    text_content = f"""Dear {employee_username},

        Your timesheet has been rejected by HR ({user}).

        Reason: {rejection_reason}
        https://nexus.chervicaon.com
        Please contact HR for clarification or resubmit your timesheet with corrections.

        This is an automated notification from the Timesheet & Leave Management System."""
                    send_email(employee_email, subject, text_content)
            flash(f" Team work rejected. Reason: {rejection_reason}")
        else:
            flash(" Failed to reject team work or work not found.")
    
    except Exception as e:
        flash(f" Error rejecting team work: {str(e)}")
    
    return redirect(url_for('dashboard'))

@app.route('/reject_team_leave', methods=['POST'])
def reject_team_leave():
    """Reject team leave (for HR Finance Controller managing Sabitha's team)"""
    if 'username' not in session or session['role'] != 'Hr & Finance Controller':
        flash(" Access denied. HR & Finance Controller privileges required.")
        return redirect(url_for('dashboard'))
    
    user = session['username']
    leave_id = request.form.get('leave_id')
    rejection_reason = request.form.get('rejection_reason', '').strip()
    
    if not leave_id:
        flash(" Leave ID is required.")
        return redirect(url_for('dashboard'))
    
    if not rejection_reason:
        flash(" Please provide a reason for rejection.")
        return redirect(url_for('dashboard'))
    
    # Get Sabitha's team members
    sabitha_team = []
    for name_variant in ['Sabitha', 'sabitha']:
        team = get_direct_reports(name_variant)
        if team:
            sabitha_team = team
            break
    
    if not sabitha_team:
        flash(" No team members found.")
        return redirect(url_for('dashboard'))
    
    placeholders = ",".join(["?"] * len(sabitha_team))
    
    try:
        ok = run_exec(f"""
            UPDATE leaves 
            SET rm_status = 'Rejected', rm_approver = ?, rm_rejection_reason = ?
            WHERE id = ? AND username IN ({placeholders}) AND rm_status = 'Pending'
        """, (session['username'], rejection_reason, int(leave_id)) + tuple(sabitha_team))
        
        if ok:
            # Get employee details for email notification
            leave_details = run_query(f"""
                SELECT username, leave_type FROM leaves 
                WHERE id = ? AND username IN ({placeholders}) AND rm_status = 'Rejected'
            """, (int(leave_id),) + tuple(sabitha_team))
            
            if not leave_details.empty:
                employee_username = leave_details.iloc[0]['username']
                leave_type = str(leave_details.iloc[0]['leave_type'])
                
                # Send email notification
                user_email = get_user_email(employee_username)
                if user_email:
                    subject = f"Leave Request Rejected by HR - {employee_username}"
                    text_content = f"""Dear {employee_username},

        Your {leave_type} leave request has been rejected by HR ({user}).

        Reason: {rejection_reason}
        https://nexus.chervicaon.com 
        Please contact HR for clarification or resubmit your leave request with corrections.

        This is an automated notification from the Timesheet & Leave Management System."""
                    send_email(user_email, subject, text_content)

            flash(f" Team leave rejected. Reason: {rejection_reason}")
        else:
            flash(" Failed to reject team leave or leave not found.")
    
    except Exception as e:
        flash(f" Error rejecting team leave: {str(e)}")
    
    return redirect(url_for('dashboard'))

@app.route('/bulk_approve_team_work', methods=['POST'])
def bulk_approve_team_work():
    """Bulk approve multiple team work entries"""
    if 'username' not in session or session['role'] != 'Hr & Finance Controller':
        flash(" Access denied. HR & Finance Controller privileges required.")
        return redirect(url_for('dashboard'))
    
    timesheet_ids = request.form.getlist('timesheet_ids')
    
    if not timesheet_ids:
        flash(" No timesheets selected for approval.")
        return redirect(url_for('dashboard'))
    
    # Get Sabitha's team members
    sabitha_team = []
    for name_variant in ['Sabitha', 'sabitha']:
        team = get_direct_reports(name_variant)
        if team:
            sabitha_team = team
            break
    
    if not sabitha_team:
        flash(" No team members found for approval.")
        return redirect(url_for('dashboard'))
    
    success_count = 0
    failed_count = 0
    
    try:
        placeholders_team = ",".join(["?"] * len(sabitha_team))
        
        for timesheet_id in timesheet_ids:
            try:
                ok = run_exec(f"""
                    UPDATE timesheets 
                    SET rm_status = 'Approved', rm_approver = ?, rm_rejection_reason = NULL
                    WHERE id = ? AND username IN ({placeholders_team}) AND rm_status = 'Pending'
                """, (session['username'], int(timesheet_id)) + tuple(sabitha_team))
                
                if ok:
                    success_count += 1
                else:
                    failed_count += 1
                    
            except Exception:
                failed_count += 1
        
        if success_count > 0:
            flash(f" {success_count} team work entries approved successfully.")
        
        if failed_count > 0:
            flash(f" {failed_count} team work entries failed to approve.")
    
    except Exception as e:
        flash(f" Error in bulk approval: {str(e)}")
    
    return redirect(url_for('dashboard'))

@app.route('/bulk_approve_team_leaves', methods=['POST'])
def bulk_approve_team_leaves():
    """Bulk approve multiple team leave requests"""
    if 'username' not in session or session['role'] != 'Hr & Finance Controller':
        flash(" Access denied. HR & Finance Controller privileges required.")
        return redirect(url_for('dashboard'))
    
    leave_ids = request.form.getlist('leave_ids')
    
    if not leave_ids:
        flash(" No leaves selected for approval.")
        return redirect(url_for('dashboard'))
    
    # Get Sabitha's team members
    sabitha_team = []
    for name_variant in ['Sabitha', 'sabitha']:
        team = get_direct_reports(name_variant)
        if team:
            sabitha_team = team
            break
    
    if not sabitha_team:
        flash(" No team members found for approval.")
        return redirect(url_for('dashboard'))
    
    success_count = 0
    failed_count = 0
    
    try:
        placeholders_team = ",".join(["?"] * len(sabitha_team))
        
        for leave_id in leave_ids:
            try:
                # Get leave details for balance update
                leave_details = run_query(f"""
                    SELECT username, leave_type, start_date, end_date 
                    FROM leaves 
                    WHERE id = ? AND username IN ({placeholders_team}) AND rm_status = 'Pending'
                """, (int(leave_id),) + tuple(sabitha_team))
                
                if not leave_details.empty:
                    leave_username = leave_details.iloc[0]['username']
                    leave_type = str(leave_details.iloc[0]['leave_type'])
                    start_date = parse(str(leave_details.iloc[0]['start_date']))
                    end_date = parse(str(leave_details.iloc[0]['end_date']))
                    leave_days = (end_date - start_date).days + 1
                    
                    # Apply leave balance deduction
                    _apply_leave_balance(leave_username, leave_type, leave_days, +1)
                    
                    # Approve leave
                    ok = run_exec(f"""
                        UPDATE leaves 
                        SET rm_status = 'Approved', rm_approver = ?, rm_rejection_reason = NULL
                        WHERE id = ? AND username IN ({placeholders_team}) AND rm_status = 'Pending'
                    """, (session['username'], int(leave_id)) + tuple(sabitha_team))
                    
                    if ok:
                        success_count += 1
                    else:
                        failed_count += 1
                else:
                    failed_count += 1
                    
            except Exception:
                failed_count += 1
        
        if success_count > 0:
            flash(f" {success_count} team leave requests approved successfully.")
        
        if failed_count > 0:
            flash(f" {failed_count} team leave requests failed to approve.")
    
    except Exception as e:
        flash(f" Error in bulk leave approval: {str(e)}")
    
    return redirect(url_for('dashboard'))

@app.route('/view_team_member_details/<username>')
def view_team_member_details(username):
    """View detailed information about a team member"""
    if 'username' not in session or session['role'] != 'Hr & Finance Controller':
        flash(" Access denied. HR & Finance Controller privileges required.")
        return redirect(url_for('dashboard'))
    
    try:
        # Get employee details
        employee_details = run_query("""
            SELECT u.username, u.name, u.role, u.email, u.monthly_salary, u.yearly_salary,
                   ed.joining_date, ed.employment_type, ed.mobile_number, ed.emergency_contact
            FROM users u
            LEFT JOIN employee_details ed ON u.username = ed.username
            WHERE u.username = ? AND u.status = 'Active'
        """, (username,))
        
        # Get recent work history
        work_history = run_query("""
            SELECT TOP 10 work_date, project_name, work_desc, hours, rm_status
            FROM timesheets 
            WHERE username = ?
            ORDER BY work_date DESC
        """, (username,))
        
        # Get leave history
        leave_history = run_query("""
            SELECT TOP 10 start_date, end_date, leave_type, description, rm_status
            FROM leaves 
            WHERE username = ?
            ORDER BY start_date DESC
        """, (username,))
        
        # Get leave balances
        leave_balances = _get_remaining_balances(username)
        
        return render_template('team_member_details.html',
            employee=employee_details.iloc[0].to_dict() if not employee_details.empty else {},
            work_history=work_history.to_dict('records') if not work_history.empty else [],
            leave_history=leave_history.to_dict('records') if not leave_history.empty else [],
            leave_balances=leave_balances,
            user=session['username'],
            role=session['role']
        )
    
    except Exception as e:
        flash(f" Error viewing team member details: {str(e)}")
        return redirect(url_for('dashboard'))
# Add these missing HR Finance project management routes:

@app.route('/edit_project_hr', methods=['POST'])
def edit_project_hr():
    """Edit project details (HR Finance)"""
    if 'username' not in session or session['role'] != 'Hr & Finance Controller':
        flash(" Access denied. HR & Finance Controller privileges required.")
        return redirect(url_for('dashboard'))
    
    project_id = request.form.get('project_id')
    project_name = request.form.get('project_name')
    description = request.form.get('description')
    cost_center = request.form.get('cost_center')
    end_date = request.form.get('end_date')
    budget_amount = request.form.get('budget_amount')
    
    if not project_id or not project_name:
        flash(" Project ID and name are required.")
        return redirect(url_for('dashboard'))
    
    try:
        # Update project details
        ok = run_exec("""
            UPDATE projects 
            SET project_name = ?, description = ?, cost_center = ?, end_date = ?, budget_amount = ?
            WHERE project_id = ?
        """, (project_name, description, cost_center, end_date, 
              float(budget_amount) if budget_amount else None, int(project_id)))
        
        if ok:
            flash(f" Project '{project_name}' updated successfully.")
        else:
            flash(" Failed to update project.")
    
    except ValueError:
        flash(" Invalid budget amount.")
    except Exception as e:
        flash(f" Error updating project: {str(e)}")
    
    return redirect(url_for('dashboard'))

@app.route('/delete_project_hr', methods=['POST'])
def delete_project_hr():
    """Delete project (HR Finance)"""
    if 'username' not in session or session['role'] != 'Hr & Finance Controller':
        flash(" Access denied. HR & Finance Controller privileges required.")
        return redirect(url_for('dashboard'))
    
    project_id = request.form.get('project_id')
    project_name = request.form.get('project_name')
    
    if not project_id:
        flash(" Project ID is required.")
        return redirect(url_for('dashboard'))
    
    try:
        # Check for dependencies
        expenses_check = run_query("SELECT COUNT(*) as count FROM expenses WHERE project_name = ?", (project_name,))
        work_check = run_query("SELECT COUNT(*) as count FROM timesheets WHERE project_name = ?", (project_name,))
        
        has_expenses = not expenses_check.empty and expenses_check.iloc[0]['count'] > 0
        has_work = not work_check.empty and work_check.iloc[0]['count'] > 0
        
        if has_expenses or has_work:
            flash(f" Cannot delete project '{project_name}' - it has associated expenses or work entries.")
            return redirect(url_for('dashboard'))
        
        # Delete the project
        ok = run_exec("DELETE FROM projects WHERE project_id = ?", (int(project_id),))
        
        if ok:
            flash(f" Project '{project_name}' deleted successfully.")
        else:
            flash(" Failed to delete project.")
    
    except Exception as e:
        flash(f" Error deleting project: {str(e)}")
    
    return redirect(url_for('dashboard'))

@app.route('/clone_project_hr', methods=['POST'])
def clone_project_hr():
    """Clone/duplicate project (HR Finance)"""
    if 'username' not in session or session['role'] != 'Hr & Finance Controller':
        flash(" Access denied. HR & Finance Controller privileges required.")
        return redirect(url_for('dashboard'))
    
    source_project_id = request.form.get('source_project_id')
    new_project_name = request.form.get('new_project_name')
    
    if not source_project_id or not new_project_name:
        flash(" Source project ID and new project name are required.")
        return redirect(url_for('dashboard'))
    
    try:
        # Get source project details
        source_project = run_query("""
            SELECT description, cost_center, end_date, budget_amount
            FROM projects WHERE project_id = ?
        """, (int(source_project_id),))
        
        if source_project.empty:
            flash(" Source project not found.")
            return redirect(url_for('dashboard'))
        
        source = source_project.iloc[0]
        
        # Create new project
        ok = run_exec("""
            INSERT INTO [timesheet_db].[dbo].[projects] (project_name, description, cost_center, end_date, 
                                 budget_amount, created_by, created_on, hr_approval_status, status)
            VALUES (?, ?, ?, ?, ?, ?, GETDATE(), 'Approved', 'Active')
        """, (new_project_name, source['description'], source['cost_center'], 
              source['end_date'], source['budget_amount'], session['username']))
        
        if ok:
            flash(f" Project '{new_project_name}' cloned successfully from source project.")
        else:
            flash(" Failed to clone project.")
    
    except Exception as e:
        flash(f" Error cloning project: {str(e)}")
    
    return redirect(url_for('dashboard'))

@app.route('/archive_project_hr', methods=['POST'])
def archive_project_hr():
    """Archive project (HR Finance)"""
    if 'username' not in session or session['role'] != 'Hr & Finance Controller':
        flash(" Access denied. HR & Finance Controller privileges required.")
        return redirect(url_for('dashboard'))
    
    project_id = request.form.get('project_id')
    project_name = request.form.get('project_name')
    archive_reason = request.form.get('archive_reason', 'Archived by HR')
    
    if not project_id:
        flash(" Project ID is required.")
        return redirect(url_for('dashboard'))
    
    try:
        ok = run_exec("""
            UPDATE projects 
            SET status = 'Archived', archive_reason = ?, archived_by = ?, archived_date = GETDATE()
            WHERE project_id = ?
        """, (archive_reason, session['username'], int(project_id)))
        
        if ok:
            flash(f" Project '{project_name}' archived successfully.")
        else:
            flash(" Failed to archive project.")
    
    except Exception as e:
        flash(f" Error archiving project: {str(e)}")
    
    return redirect(url_for('dashboard'))

@app.route('/restore_project_hr', methods=['POST'])
def restore_project_hr():
    """Restore archived project (HR Finance)"""
    if 'username' not in session or session['role'] != 'Hr & Finance Controller':
        flash(" Access denied. HR & Finance Controller privileges required.")
        return redirect(url_for('dashboard'))
    
    project_id = request.form.get('project_id')
    project_name = request.form.get('project_name')
    
    if not project_id:
        flash(" Project ID is required.")
        return redirect(url_for('dashboard'))
    
    try:
        ok = run_exec("""
            UPDATE projects 
            SET status = 'Active', archive_reason = NULL, archived_by = NULL, archived_date = NULL
            WHERE project_id = ?
        """, (int(project_id),))
        
        if ok:
            flash(f" Project '{project_name}' restored successfully.")
        else:
            flash(" Failed to restore project.")
    
    except Exception as e:
        flash(f" Error restoring project: {str(e)}")
    
    return redirect(url_for('dashboard'))

@app.route('/bulk_project_action_hr', methods=['POST'])
def bulk_project_action_hr():
    """Bulk actions on multiple projects (HR Finance)"""
    if 'username' not in session or session['role'] != 'Hr & Finance Controller':
        flash(" Access denied. HR & Finance Controller privileges required.")
        return redirect(url_for('dashboard'))
    
    project_ids = request.form.getlist('project_ids')
    action = request.form.get('bulk_action')
    
    if not project_ids or not action:
        flash(" No projects selected or action specified.")
        return redirect(url_for('dashboard'))
    
    success_count = 0
    failed_count = 0
    
    try:
        for project_id in project_ids:
            try:
                if action == 'approve':
                    ok = run_exec("""
                        UPDATE projects 
                        SET hr_approval_status = 'Approved', status = 'Active'
                        WHERE project_id = ?
                    """, (int(project_id),))
                elif action == 'reject':
                    ok = run_exec("""
                        UPDATE projects 
                        SET hr_approval_status = 'Rejected', status = 'Rejected'
                        WHERE project_id = ?
                    """, (int(project_id),))
                elif action == 'archive':
                    ok = run_exec("""
                        UPDATE projects 
                        SET status = 'Archived', archived_by = ?, archived_date = GETDATE()
                        WHERE project_id = ?
                    """, (session['username'], int(project_id)))
                else:
                    ok = False
                
                if ok:
                    success_count += 1
                else:
                    failed_count += 1
                    
            except Exception:
                failed_count += 1
        
        if success_count > 0:
            flash(f" {success_count} projects processed successfully ({action}).")
        
        if failed_count > 0:
            flash(f" {failed_count} projects failed to process.")
    
    except Exception as e:
        flash(f" Error in bulk project action: {str(e)}")
    
    return redirect(url_for('dashboard'))

@app.route('/project_analytics_hr')
def project_analytics_hr():
    """View project analytics and reports (HR Finance)"""
    if 'username' not in session or session['role'] != 'Hr & Finance Controller':
        flash(" Access denied. HR & Finance Controller privileges required.")
        return redirect(url_for('dashboard'))
    
    try:
        # Project statistics
        project_stats = run_query("""
            SELECT 
                COUNT(*) as total_projects,
                SUM(CASE WHEN hr_approval_status = 'Approved' THEN 1 ELSE 0 END) as approved_projects,
                SUM(CASE WHEN hr_approval_status = 'Pending' THEN 1 ELSE 0 END) as pending_projects,
                SUM(CASE WHEN hr_approval_status = 'Rejected' THEN 1 ELSE 0 END) as rejected_projects,
                COALESCE(SUM(CAST(budget_amount AS DECIMAL(18,2))), 0) as total_budget_allocated
            FROM projects
        """)
        
        # Budget utilization by project
        budget_utilization = run_query("""
            SELECT 
                p.project_name,
                CAST(p.budget_amount AS DECIMAL(18,2)) as allocated_budget,
                COALESCE(SUM(CAST(e.amount AS DECIMAL(18,2))), 0) as spent_amount,
                (CAST(p.budget_amount AS DECIMAL(18,2)) - COALESCE(SUM(CAST(e.amount AS DECIMAL(18,2))), 0)) as remaining_budget
            FROM projects p
            LEFT JOIN expenses e ON p.project_name = e.project_name
            WHERE p.budget_amount IS NOT NULL
            GROUP BY p.project_name, p.budget_amount
            ORDER BY allocated_budget DESC
        """)
        
        return render_template('project_analytics.html',
            project_stats=project_stats.iloc[0].to_dict() if not project_stats.empty else {},
            budget_utilization=budget_utilization.to_dict('records') if not budget_utilization.empty else [],
            user=session['username'],
            role=session['role']
        )
    
    except Exception as e:
        flash(f" Error loading project analytics: {str(e)}")
        return redirect(url_for('dashboard'))
# Add these final missing budget allocation routes:

@app.route('/remove_budget_allocation_action', methods=['POST'])
def remove_budget_allocation_action():
    """Remove budget allocation (alias for delete_budget_allocation_action)"""
    return delete_budget_allocation_action()

@app.route('/modify_budget_action', methods=['POST'])
def modify_budget_action():
    """Modify budget allocation (alias for edit_budget_allocation_action)"""
    return edit_budget_allocation_action()

@app.route('/transfer_budget_action', methods=['POST'])
def transfer_budget_action():
    """Transfer budget between projects (alias for reallocate_budget_action)"""
    return reallocate_budget_action()

@app.route('/set_budget_limit_action', methods=['POST'])
def set_budget_limit_action():
    """Set budget spending limit for project"""
    if 'username' not in session or session['role'] != 'Hr & Finance Controller':
        flash(" Access denied. HR & Finance Controller privileges required.")
        return redirect(url_for('dashboard'))
    
    project_name = request.form.get('project_name')
    spending_limit = request.form.get('spending_limit')
    
    if not project_name or not spending_limit:
        flash(" Project name and spending limit are required.")
        return redirect(url_for('dashboard'))
    
    try:
        limit_amount = float(spending_limit)
        
        ok = run_exec("""
            UPDATE projects 
            SET spending_limit = ?, spending_limit_set_by = ?, spending_limit_date = GETDATE()
            WHERE project_name = ?
        """, (limit_amount, session['username'], project_name))
        
        if ok:
            flash(f" Spending limit of ₹{limit_amount:,.2f} set for '{project_name}'.")
        else:
            flash(" Failed to set spending limit.")
    
    except ValueError:
        flash(" Invalid spending limit amount.")
    except Exception as e:
        flash(f" Error setting spending limit: {str(e)}")
    
    return redirect(url_for('dashboard'))

@app.route('/reset_budget_action', methods=['POST'])
def reset_budget_action():
    """Reset budget allocation to zero"""
    if 'username' not in session or session['role'] != 'Hr & Finance Controller':
        flash(" Access denied. HR & Finance Controller privileges required.")
        return redirect(url_for('dashboard'))
    
    project_name = request.form.get('project_name')
    reset_reason = request.form.get('reset_reason', 'Budget reset by HR')
    
    if not project_name:
        flash(" Project name is required.")
        return redirect(url_for('dashboard'))
    
    try:
        # Get current budget to show what's being reset
        current_budget_df = run_query("""
            SELECT COALESCE(CAST(budget_amount AS DECIMAL(18,2)), 0) as current_budget
            FROM projects WHERE project_name = ?
        """, (project_name,))
        
        current_budget = float(current_budget_df['current_budget'].iloc[0]) if not current_budget_df.empty else 0.0
        
        # Check if project has expenses
        expenses_check = run_query("""
            SELECT COALESCE(SUM(CAST(amount AS DECIMAL(18,2))), 0) as total_expenses
            FROM expenses WHERE project_name = ?
        """, (project_name,))
        
        total_expenses = float(expenses_check['total_expenses'].iloc[0]) if not expenses_check.empty else 0.0
        
        if total_expenses > 0:
            flash(f" Cannot reset budget. Project has ₹{total_expenses:,.2f} in expenses.")
            return redirect(url_for('dashboard'))
        
        # Reset budget to zero
        ok = run_exec("""
            UPDATE projects 
            SET budget_amount = 0, budget_reset_reason = ?, budget_reset_by = ?, budget_reset_date = GETDATE()
            WHERE project_name = ?
        """, (reset_reason, session['username'], project_name))
        
        if ok:
            flash(f" Budget reset for '{project_name}'. ₹{current_budget:,.2f} returned to available budget.")
        else:
            flash(" Failed to reset budget.")
    
    except Exception as e:
        flash(f" Error resetting budget: {str(e)}")
    
    return redirect(url_for('dashboard'))

@app.route('/lock_budget_action', methods=['POST'])
def lock_budget_action():
    """Lock budget to prevent any changes (stronger than freeze)"""
    if 'username' not in session or session['role'] != 'Hr & Finance Controller':
        flash(" Access denied. HR & Finance Controller privileges required.")
        return redirect(url_for('dashboard'))
    
    project_name = request.form.get('project_name')
    lock_reason = request.form.get('lock_reason', 'Budget locked by HR')
    
    if not project_name:
        flash(" Project name is required.")
        return redirect(url_for('dashboard'))
    
    try:
        ok = run_exec("""
            UPDATE projects 
            SET budget_status = 'Locked', budget_lock_reason = ?, budget_locked_by = ?, budget_locked_date = GETDATE()
            WHERE project_name = ?
        """, (lock_reason, session['username'], project_name))
        
        if ok:
            flash(f" Budget locked for '{project_name}'. Reason: {lock_reason}")
        else:
            flash(" Failed to lock budget.")
    
    except Exception as e:
        flash(f" Error locking budget: {str(e)}")
    
    return redirect(url_for('dashboard'))

@app.route('/unlock_budget_action', methods=['POST'])
def unlock_budget_action():
    """Unlock budget"""
    if 'username' not in session or session['role'] != 'Hr & Finance Controller':
        flash(" Access denied. HR & Finance Controller privileges required.")
        return redirect(url_for('dashboard'))
    
    project_name = request.form.get('project_name')
    
    if not project_name:
        flash(" Project name is required.")
        return redirect(url_for('dashboard'))
    
    try:
        ok = run_exec("""
            UPDATE projects 
            SET budget_status = 'Active', budget_lock_reason = NULL, budget_locked_by = NULL, budget_locked_date = NULL
            WHERE project_name = ?
        """, (project_name,))
        
        if ok:
            flash(f" Budget unlocked for '{project_name}'.")
        else:
            flash(" Failed to unlock budget.")
    
    except Exception as e:
        flash(f" Error unlocking budget: {str(e)}")
    
    return redirect(url_for('dashboard'))


@app.route('/view-team-leave-doc/<int:leave_id>')
def view_team_leave_document(leave_id):
    """View leave document for team members (enhanced permissions)"""
    if 'username' not in session:
        flash("Access denied.")
        return redirect(url_for('login_sso'))
    
    user = session['username']
    
    try:
        # Get leave details with enhanced team access
        leave_doc = run_query("""
            SELECT l.health_document, l.username, l.leave_type, l.start_date, l.end_date,
                   r.rm, r.manager, u.role as employee_role
            FROM leaves l
            LEFT JOIN report r ON l.username = r.username
            LEFT JOIN users u ON l.username = u.username
            WHERE l.id = ?
        """, (leave_id,))
        
        if leave_doc.empty:
            flash("Leave request not found.")
            return redirect(url_for('dashboard'))
        
        leave_data = leave_doc.iloc[0]
        doc_filename = leave_data['health_document']
        leave_username = leave_data['username']
        assigned_rm = leave_data['rm']
        assigned_manager = leave_data['manager']
        
        if not doc_filename:
            flash("No document attached to this leave request.")
            return redirect(url_for('dashboard'))
        
        # Enhanced permission checking for team access
        team = get_all_reports_recursive(user)
        is_manager = session['role'] in ['Manager', 'Admin Manager', 'Hr & Finance Controller', 'Lead', 'Finance Manager']
        is_assigned_rm = (user == assigned_rm)
        is_assigned_manager = (user == assigned_manager)
        
        can_view_doc = (
            user == leave_username or      # Employee can view their own
            leave_username in team or      # Team lead can view
            is_manager or                  # Managers can view all
            is_assigned_rm or             # Assigned RM can view
            is_assigned_manager           # Assigned manager can view
        )
        
        if not can_view_doc:
            flash(" Access denied - you can only view documents for your team members.")
            return redirect(url_for('dashboard'))
        
        # Construct file path
        doc_path = os.path.join(UPLOAD_DIR, doc_filename)
        
        if not os.path.exists(doc_path):
            flash(f"Document file not found: {doc_filename}")
            return redirect(url_for('dashboard'))
        
        # Determine MIME type
        file_ext = doc_filename.lower().split('.')[-1] if '.' in doc_filename else ''
        mime_types = {
            'pdf': 'application/pdf',
            'jpg': 'image/jpeg',
            'jpeg': 'image/jpeg', 
            'png': 'image/png',
            'gif': 'image/gif',
            'doc': 'application/msword',
            'docx': 'application/vnd.openxmlformats-officedocument.wordprocessingml.document'
        }
        
        mime_type = mime_types.get(file_ext, 'application/octet-stream')
        
        # Display inline for PDFs and images, download for others
        if file_ext in ['pdf', 'jpg', 'jpeg', 'png', 'gif']:
            return send_file(doc_path, as_attachment=False, mimetype=mime_type)
        else:
            return send_file(doc_path, as_attachment=True, download_name=doc_filename)
        
    except Exception as e:
        print(f" ERROR in view_team_leave_document: {str(e)}")
        flash(f"Error accessing document: {str(e)}")
        return redirect(url_for('dashboard'))
    # Add these missing Admin Manager routes:

@app.route('/admin_submit_personal_timesheet', methods=['POST'])
def admin_submit_personal_timesheet():
    """Submit timesheet for Admin Manager (personal timesheet)"""
    if 'username' not in session:
        return redirect(url_for('login_sso'))
    
    # Check admin privileges
    if session['role'] not in ('Admin Manager', 'Lead Staffing Specialist'):
        flash("Access denied. Admin Manager privileges required.")
        return redirect(url_for('dashboard'))
    
    # This is just an alias to the regular submit_timesheet_action
    result = submit_timesheet_action()

    # Additional email to HR about admin timesheet submission
    user = session['username']
    hr_users = run_query("""
        SELECT email FROM users 
        WHERE role IN ('Hr & Finance Controller', 'Manager') 
        AND status = 'Active' AND email IS NOT NULL
    """)
    
    if not hr_users.empty:
        for _, hr_user in hr_users.iterrows():
            hr_email = hr_user['email']
            if hr_email:
                subject = f"Admin Timesheet Submitted - {user}"
                text_content = f"""Dear HR Team,

{user} ({session['role']}) has submitted a personal timesheet.

This is for informational purposes as an admin-level user submission.

Please review if needed through the dashboard.
https://nexus.chervicaon.com
This is an automated notification from the Timesheet & Leave Management System."""
                send_email(hr_email, subject, text_content)
    return result

@app.route('/admin_submit_personal_leave', methods=['POST'])
def admin_submit_personal_leave():
    """Submit leave request for Admin Manager (personal leave)"""
    if 'username' not in session:
        return redirect(url_for('login_sso'))
    
    # Check admin privileges
    if session['role'] not in ('Admin Manager', 'Lead Staffing Specialist'):
        flash("Access denied. Admin Manager privileges required.")
        return redirect(url_for('dashboard'))
    
    # This is just an alias to the regular request_leave_action
    return request_leave_action()

@app.route('/admin_edit_personal_timesheet', methods=['POST'])
def admin_edit_personal_timesheet():
    """Edit personal timesheet for Admin Manager"""
    if 'username' not in session:
        return redirect(url_for('login_sso'))
    
    # Check admin privileges
    if session['role'] not in ('Admin Manager', 'Lead Staffing Specialist'):
        flash("Access denied. Admin Manager privileges required.")
        return redirect(url_for('dashboard'))
    
    # This is just an alias to the regular resubmit_timesheet
    return resubmit_timesheet()

@app.route('/admin_delete_personal_timesheet', methods=['POST'])
def admin_delete_personal_timesheet():
    """Delete personal timesheet for Admin Manager"""
    if 'username' not in session:
        return redirect(url_for('login_sso'))
    
    # Check admin privileges
    if session['role'] not in ('Admin Manager', 'Lead Staffing Specialist'):
        flash("Access denied. Admin Manager privileges required.")
        return redirect(url_for('dashboard'))
    
    # This is just an alias to the regular delete_timesheet
    return delete_timesheet()

@app.route('/admin_edit_personal_leave', methods=['POST'])
def admin_edit_personal_leave():
    """Edit personal leave for Admin Manager"""
    if 'username' not in session:
        return redirect(url_for('login_sso'))
    
    # Check admin privileges
    if session['role'] not in ('Admin Manager', 'Lead Staffing Specialist'):
        flash("Access denied. Admin Manager privileges required.")
        return redirect(url_for('dashboard'))
    
    # This is just an alias to the regular resubmit_leave
    return resubmit_leave()

@app.route('/admin_delete_personal_leave', methods=['POST'])
def admin_delete_personal_leave():
    """Delete personal leave for Admin Manager"""
    if 'username' not in session:
        return redirect(url_for('login_sso'))
    
    # Check admin privileges
    if session['role'] not in ('Admin Manager', 'Lead Staffing Specialist'):
        flash("Access denied. Admin Manager privileges required.")
        return redirect(url_for('dashboard'))
    
    # This is just an alias to the regular delete_leave
    return delete_leave()

@app.route('/admin_approve_team_timesheet', methods=['POST'])
def admin_approve_team_timesheet():
    """Approve team timesheet for Admin Manager"""
    if 'username' not in session:
        return redirect(url_for('login_sso'))
    
    # Check admin privileges
    if session['role'] not in ('Admin Manager', 'Lead Staffing Specialist'):
        flash("Access denied. Admin Manager privileges required.")
        return redirect(url_for('dashboard'))
    
   
    timesheet_id = request.form.get('timesheet_id')
    
    if not timesheet_id:
        flash(" Timesheet ID is required.")
        return redirect(url_for('dashboard'))
    
    try:
        user = session['username']
        # Get direct reports for this admin
        team = get_direct_reports(user)
        
        if not team:
            flash(" No team members found for approval.")
            return redirect(url_for('dashboard'))
        
        placeholders = ",".join(["?"] * len(team))
        
        ok = run_exec(f"""
            UPDATE timesheets 
            SET rm_status = 'Approved', rm_approver = ?
            WHERE id = ? AND username IN ({placeholders}) AND rm_status = 'Pending'
        """, (user, int(timesheet_id)) + tuple(team))
        
        if ok:
            flash(" Timesheet approved successfully.")
            # Get timesheet details and send email notification
            timesheet_details = run_query(f"""
                SELECT t.username, t.projectname, t.workdate, t.hours, t.workdesc 
                FROM timesheets t 
                WHERE t.id = ? AND t.username IN ({placeholders})
            """, (int(timesheet_id),) + tuple(team))

            if not timesheet_details.empty:
                employee_username = timesheet_details.iloc[0]['username']
                project_name = timesheet_details.iloc[0]['projectname']
                work_date = timesheet_details.iloc[0]['workdate']
                hours = timesheet_details.iloc[0]['hours']
                work_desc = timesheet_details.iloc[0]['workdesc']
                
                user_email = get_user_email(employee_username)
                if user_email:
                    subject = f"Timesheet Approved by Admin - {employee_username}"
                    text_content = f"""Dear {employee_username},

            Your timesheet has been approved by Admin {user}.

            Details:
            - Date: {work_date}
            - Project: {project_name}
            - Hours: {hours}
            - Description: {work_desc[:100]}{'...' if len(work_desc) > 100 else ''}
            - Status: Approved

            You can view the updated status in your dashboard.
            https://nexus.chervicaon.com
            This is an automated notification from the Timesheet Leave Management System."""
                    send_email(user_email, subject, text_content)

            
        else:
            flash(" Failed to approve timesheet or timesheet not found.")
    
    except Exception as e:
        flash(f" Error approving timesheet: {str(e)}")
    
    return redirect(url_for('dashboard'))

@app.route('/admin_reject_team_timesheet', methods=['POST'])
def admin_reject_team_timesheet():
    """Reject team timesheet for Admin Manager"""
    if 'username' not in session:
        return redirect(url_for('login_sso'))
    
    # Check admin privileges
    if session['role'] not in ('Admin Manager', 'Lead Staffing Specialist'):
        flash("Access denied. Admin Manager privileges required.")
        return redirect(url_for('dashboard'))
    
    
    timesheet_id = request.form.get('timesheet_id')
    rejection_reason = request.form.get('rejection_reason', '').strip()
    
    if not timesheet_id:
        flash(" Timesheet ID is required.")
        return redirect(url_for('dashboard'))
    
    if not rejection_reason:
        flash(" Please provide a reason for rejection.")
        return redirect(url_for('dashboard'))
    
    try:
        user = session['username']
        team = get_direct_reports(user)
        
        if not team:
            flash(" No team members found.")
            return redirect(url_for('dashboard'))
        
        placeholders = ",".join(["?"] * len(team))
        
        ok = run_exec(f"""
            UPDATE timesheets 
            SET rm_status = 'Rejected', rm_approver = ?, rm_rejection_reason = ?
            WHERE id = ? AND username IN ({placeholders}) AND rm_status = 'Pending'
        """, (user, rejection_reason, int(timesheet_id)) + tuple(team))
        
        if ok:
            flash(f" Timesheet rejected. Reason: {rejection_reason}")
            # Get timesheet details and send email notification
            timesheet_details = run_query(f"""
                SELECT t.username, t.projectname, t.workdate, t.hours, t.workdesc 
                FROM timesheets t 
                WHERE t.id = ? AND t.username IN ({placeholders})
            """, (int(timesheet_id),) + tuple(team))

            if not timesheet_details.empty:
                employee_username = timesheet_details.iloc[0]['username']
                project_name = timesheet_details.iloc[0]['projectname']
                work_date = timesheet_details.iloc[0]['workdate']
                hours = timesheet_details.iloc[0]['hours']
                work_desc = timesheet_details.iloc[0]['workdesc']
                
                user_email = get_user_email(employee_username)
                if user_email:
                    subject = f"Timesheet Rejected by Admin - {employee_username}"
                    text_content = f"""Dear {employee_username},

            Your timesheet has been rejected by Admin {user}.

            Details:
            - Date: {work_date}
            - Project: {project_name}
            - Hours: {hours}
            - Description: {work_desc[:100]}{'...' if len(work_desc) > 100 else ''}
            - Status: Rejected
            - Rejection Reason: {rejection_reason}

            Please contact your Admin for clarification or resubmit your timesheet with corrections.
            https://nexus.chervicaon.com
            This is an automated notification from the Timesheet Leave Management System."""
                    send_email(user_email, subject, text_content)

        else:
            flash(" Failed to reject timesheet or timesheet not found.")
    
    except Exception as e:
        flash(f" Error rejecting timesheet: {str(e)}")
    
    return redirect(url_for('dashboard'))

@app.route('/admin_approve_team_leave', methods=['POST'])
def admin_approve_team_leave():
    """Approve team leave for Admin Manager"""
    if 'username' not in session:
        return redirect(url_for('login_sso'))
    
    # Check admin privileges
    if session['role'] not in ('Admin Manager', 'Lead Staffing Specialist'):
        flash("Access denied. Admin Manager privileges required.")
        return redirect(url_for('dashboard'))
    
    leave_id = request.form.get('leave_id')
    
    if not leave_id:
        flash(" Leave ID is required.")
        return redirect(url_for('dashboard'))
    
    try:
        user = session['username']
        team = get_direct_reports(user)
        
        if not team:
            flash(" No team members found for approval.")
            return redirect(url_for('dashboard'))
        
        placeholders = ",".join(["?"] * len(team))
        
        # Get leave details for balance update
        leave_details = run_query(f"""
            SELECT username, leave_type, start_date, end_date 
            FROM leaves 
            WHERE id = ? AND username IN ({placeholders}) AND rm_status = 'Pending'
        """, (int(leave_id),) + tuple(team))
        
        if not leave_details.empty:
            leave_username = leave_details.iloc[0]['username']
            leave_type = str(leave_details.iloc[0]['leave_type'])
            start_date = parse(str(leave_details.iloc[0]['start_date']))
            end_date = parse(str(leave_details.iloc[0]['end_date']))
            leave_days = (end_date - start_date).days + 1
            
            # Apply leave balance deduction
            _apply_leave_balance(leave_username, leave_type, leave_days, +1)
            
            # Approve leave
            ok = run_exec(f"""
                UPDATE leaves 
                SET rm_status = 'Approved', rm_approver = ?
                WHERE id = ? AND username IN ({placeholders}) AND rm_status = 'Pending'
            """, (user, int(leave_id)) + tuple(team))
            
            if ok:
                flash(f" Leave approved for {leave_username} ({leave_days} days).")
                user_email = get_user_email(leave_username)
                if user_email:
                    subject = f"Leave Approved by Admin - {leave_username}"
                    text_content = f"""Dear {leave_username},

                Your leave request has been approved by Admin {user}.

                Details:
                - Leave Type: {leave_type}
                - Duration: {leave_days} days
                - Start Date: {start_date.strftime('%Y-%m-%d')}
                - End Date: {end_date.strftime('%Y-%m-%d')}
                - Status: Approved
                - Processed by: {user}

                You can view the updated status in your dashboard.
                https://nexus.chervicaon.com 
                This is an automated notification from the Timesheet Leave Management System."""
                    send_email(user_email, subject, text_content)

            else:
                flash(" Failed to approve leave.")
        else:
            flash(" Leave not found in team or already processed.")
    
    except Exception as e:
        flash(f" Error approving leave: {str(e)}")
    
    return redirect(url_for('dashboard'))

@app.route('/admin_reject_team_leave', methods=['POST'])
def admin_reject_team_leave():
    """Reject team leave for Admin Manager"""
    if 'username' not in session:
        return redirect(url_for('login_sso'))
    
    # Check admin privileges
    if session['role'] not in ('Admin Manager', 'Lead Staffing Specialist'):
        flash("Access denied. Admin Manager privileges required.")
        return redirect(url_for('dashboard'))
    
    leave_id = request.form.get('leave_id')
    rejection_reason = request.form.get('rejection_reason', '').strip()
    
    if not leave_id:
        flash(" Leave ID is required.")
        return redirect(url_for('dashboard'))
    
    if not rejection_reason:
        flash(" Please provide a reason for rejection.")
        return redirect(url_for('dashboard'))
    
    try:
        user = session['username']
        team = get_direct_reports(user)
        
        if not team:
            flash(" No team members found.")
            return redirect(url_for('dashboard'))
        
        placeholders = ",".join(["?"] * len(team))
        
        ok = run_exec(f"""
            UPDATE leaves 
            SET rm_status = 'Rejected', rm_approver = ?, rm_rejection_reason = ?
            WHERE id = ? AND username IN ({placeholders}) AND rm_status = 'Pending'
        """, (user, rejection_reason, int(leave_id)) + tuple(team))
        
        if ok:
            flash(f" Leave rejected. Reason: {rejection_reason}")
            # Get leave details for email notification
            leave_details = run_query(f"""
                SELECT username, leave_type, start_date, end_date, description 
                FROM leaves 
                WHERE id = ? AND username IN ({placeholders})
            """, (int(leave_id),) + tuple(team))

            if not leave_details.empty:
                leave_username = leave_details.iloc[0]['username']
                leave_type = str(leave_details.iloc[0]['leave_type'])
                start_date = parse(str(leave_details.iloc[0]['start_date']))
                end_date = parse(str(leave_details.iloc[0]['end_date']))
                leave_days = (end_date - start_date).days + 1
                description = leave_details.iloc[0]['description']
                
                user_email = get_user_email(leave_username)
                if user_email:
                    subject = f"Leave Rejected by Admin - {leave_username}"
                    text_content = f"""Dear {leave_username},

            Your leave request has been rejected by Admin {user}.

            Details:
            - Leave Type: {leave_type}
            - Duration: {leave_days} days
            - Start Date: {start_date.strftime('%Y-%m-%d')}
            - End Date: {end_date.strftime('%Y-%m-%d')}
            - Reason: {description}
            - Status: Rejected
            - Rejection Reason: {rejection_reason}
            - Processed by: {user}

            Please contact your Admin for clarification or resubmit your request with corrections.
            https://nexus.chervicaon.com
            This is an automated notification from the Timesheet Leave Management System."""
                    send_email(user_email, subject, text_content)

        else:
            flash(" Failed to reject leave or leave not found.")
    
    except Exception as e:
        flash(f" Error rejecting leave: {str(e)}")
    
    return redirect(url_for('dashboard'))


@app.route('/admin_bulk_employee_action', methods=['POST'])
def admin_bulk_employee_action():
    """Bulk actions on employees for Admin Manager"""
    if 'username' not in session:
        return redirect(url_for('login_sso'))
    
    # Check admin privileges
    if session['role'] not in ('Admin Manager', 'Lead Staffing Specialist'):
        flash("Access denied. Admin Manager privileges required.")
        return redirect(url_for('dashboard'))
    
    employee_usernames = request.form.getlist('employee_usernames')
    action = request.form.get('bulk_action')
    
    if not employee_usernames or not action:
        flash(" No employees selected or action specified.")
        return redirect(url_for('dashboard'))
    
    success_count = 0
    failed_count = 0
    
    try:
        for username in employee_usernames:
            try:
                if action == 'activate':
                    ok = run_exec("UPDATE users SET status = 'Active' WHERE username = ?", (username,))
                elif action == 'deactivate':
                    ok = run_exec("UPDATE users SET status = 'Inactive' WHERE username = ?", (username,))
                elif action == 'reset_password':
                    ok = run_exec("UPDATE users SET password = 'password123' WHERE username = ?", (username,))
                else:
                    ok = False
                
                if ok:
                    success_count += 1
                else:
                    failed_count += 1
                    
            except Exception:
                failed_count += 1
        
        if success_count > 0:
            flash(f" {success_count} employees processed successfully ({action}).")
        
        if failed_count > 0:
            flash(f" {failed_count} employees failed to process.")
    
    except Exception as e:
        flash(f" Error in bulk employee action: {str(e)}")
    
    return redirect(url_for('dashboard'))

@app.route('/admin_view_employee_history/<username>')
def admin_view_employee_history(username):
    """View comprehensive employee history for Admin Manager"""
    if 'username' not in session:
        return redirect(url_for('login_sso'))
    
    # Check admin privileges
    if session['role'] not in ('Admin Manager', 'Lead Staffing Specialist'):
        flash("Access denied. Admin Manager privileges required.")
        return redirect(url_for('dashboard'))
    
    try:
        # Get employee details
        employee = run_query("""
            SELECT u.username, u.name, u.role, u.email, u.monthly_salary, u.yearly_salary, u.status,
                   ed.joining_date, ed.employment_type, ed.mobile_number, ed.emergency_contact,
                   ed.blood_group, ed.adhaar_number, ed.pan_number
            FROM users u
            LEFT JOIN employee_details ed ON u.username = ed.username
            WHERE u.username = ?
        """, (username,))
        
        # Get work history
        work_history = run_query("""
            SELECT TOP 50 work_date, project_name, work_desc, hours, break_hours, rm_status, rm_rejection_reason
            FROM timesheets 
            WHERE username = ?
            ORDER BY work_date DESC
        """, (username,))
        
        # Get leave history
        leave_history = run_query("""
            SELECT TOP 50 start_date, end_date, leave_type, description, rm_status, rm_rejection_reason,
                   DATEDIFF(day, start_date, end_date) + 1 as duration_days
            FROM leaves 
            WHERE username = ?
            ORDER BY start_date DESC
        """, (username,))
        
        # Get leave balances
        leave_balances = _get_remaining_balances(username)
        
        return render_template('employee_history.html',
            employee=employee.iloc[0].to_dict() if not employee.empty else {},
            work_history=work_history.to_dict('records') if not work_history.empty else [],
            leave_history=leave_history.to_dict('records') if not leave_history.empty else [],
            leave_balances=leave_balances,
            user=session['username'],
            role=session['role']
        )
    
    except Exception as e:
        flash(f" Error viewing employee history: {str(e)}")
        return redirect(url_for('dashboard'))

@app.route('/admin_generate_employee_report', methods=['POST'])
def admin_generate_employee_report():
    """Generate employee report for Admin Manager"""
    if 'username' not in session:
        return redirect(url_for('login_sso'))
    
    # Check admin privileges
    if session['role'] not in ('Admin Manager', 'Lead Staffing Specialist'):
        flash("Access denied. Admin Manager privileges required.")
        return redirect(url_for('dashboard'))
    
    report_type = request.form.get('report_type', 'summary')
    employee_username = request.form.get('employee_username', 'all')
    date_range = request.form.get('date_range', 'month')
    
    flash(f" Employee report ({report_type}) generation initiated for {employee_username} - {date_range} range.")
    return redirect(url_for('dashboard'))

@app.route('/admin_manage_resignations', methods=['POST'])
def admin_manage_resignations():
    """Manage employee resignations for Admin Manager"""
    if 'username' not in session:
        return redirect(url_for('login_sso'))
    
    # Check admin privileges
    if session['role'] not in ('Admin Manager', 'Lead Staffing Specialist'):
        flash("Access denied. Admin Manager privileges required.")
        return redirect(url_for('dashboard'))
    
    action = request.form.get('action')
    employee_username = request.form.get('employee_username')
    resignation_reason = request.form.get('resignation_reason', 'Voluntary resignation')
    
    if not employee_username:
        flash(" Employee username is required.")
        return redirect(url_for('dashboard'))
    
    try:
        if action == 'process_resignation':
            # Get employee details before resignation
            employee_details = run_query("""
                SELECT u.username, u.name, u.role, u.monthly_salary, u.yearly_salary,
                       ed.joining_date, ed.employment_type, ed.mobile_number, ed.emergency_contact
                FROM users u
                LEFT JOIN employee_details ed ON u.username = ed.username
                WHERE u.username = ?
            """, (employee_username,))
            
            if not employee_details.empty:
                emp = employee_details.iloc[0]
                
                # Move to resigned_employees table
                ok1 = run_exec("""
                    INSERT INTO [timesheet_db].[dbo].[resigned_employees] 
                    (username, name, role, joining_date, resigned_date, monthly_salary, yearly_salary,
                     employment_type, mobile_number, emergency_contact, resigned_by, resignation_reason)
                    VALUES (?, ?, ?, ?, GETDATE(), ?, ?, ?, ?, ?, ?, ?)
                """, (emp['username'], emp['name'], emp['role'], emp['joining_date'],
                      emp['monthly_salary'], emp['yearly_salary'], emp['employment_type'],
                      emp['mobile_number'], emp['emergency_contact'], session['username'], resignation_reason))
                
                # Deactivate user
                ok2 = run_exec("UPDATE users SET status = 'Resigned' WHERE username = ?", (employee_username,))
                
                if ok1 and ok2:
                    flash(f" Resignation processed for {employee_username}.")
                else:
                    flash(" Failed to process resignation.")
            else:
                flash(" Employee not found.")
                
    except Exception as e:
        flash(f" Error processing resignation: {str(e)}")
    
    return redirect(url_for('dashboard'))
# Add these final missing Admin Manager routes with correct naming:

@app.route('/admin_request_personal_leave', methods=['POST'])
def admin_request_personal_leave():
    """Request personal leave for Admin Manager (correct naming)"""
    if 'username' not in session:
        return redirect(url_for('login_sso'))
    
    # Check admin privileges
    if session['role'] not in ('Admin Manager', 'Lead Staffing Specialist'):
        flash("Access denied. Admin Manager privileges required.")
        return redirect(url_for('dashboard'))
    
    # This is just an alias to the regular request_leave_action
    return request_leave_action()

@app.route('/admin_cancel_personal_leave', methods=['POST'])
def admin_cancel_personal_leave():
    """Cancel personal leave for Admin Manager"""
    if 'username' not in session:
        return redirect(url_for('login_sso'))
    
    # Check admin privileges
    if session['role'] not in ('Admin Manager', 'Lead Staffing Specialist'):
        flash("Access denied. Admin Manager privileges required.")
        return redirect(url_for('dashboard'))
    
    # This is just an alias to the regular cancel_leave_action
    return cancel_leave_action()

@app.route('/admin_withdraw_personal_timesheet', methods=['POST'])
def admin_withdraw_personal_timesheet():
    """Withdraw personal timesheet for Admin Manager"""
    if 'username' not in session:
        return redirect(url_for('login_sso'))
    
    # Check admin privileges
    if session['role'] not in ('Admin Manager', 'Lead Staffing Specialist'):
        flash("Access denied. Admin Manager privileges required.")
        return redirect(url_for('dashboard'))
    
    # This is just an alias to the regular withdraw_timesheet
    return withdraw_timesheet()

@app.route('/admin_withdraw_personal_leave', methods=['POST'])
def admin_withdraw_personal_leave():
    """Withdraw personal leave for Admin Manager"""
    if 'username' not in session:
        return redirect(url_for('login_sso'))
    
    # Check admin privileges
    if session['role'] not in ('Admin Manager', 'Lead Staffing Specialist'):
        flash("Access denied. Admin Manager privileges required.")
        return redirect(url_for('dashboard'))
    
    # This is just an alias to the regular withdraw_leave
    return withdraw_leave()

@app.route('/admin_view_personal_history', methods=['GET'])
def admin_view_personal_history():
    """View personal work/leave history for Admin Manager"""
    if 'username' not in session:
        return redirect(url_for('login_sso'))
    
    # Check admin privileges
    if session['role'] not in ('Admin Manager', 'Lead Staffing Specialist'):
        flash("Access denied. Admin Manager privileges required.")
        return redirect(url_for('dashboard'))
    
    # Redirect to dashboard with personal history view
    flash(" Viewing personal work and leave history.")
    return redirect(url_for('dashboard'))

@app.route('/admin_export_personal_data', methods=['POST'])
def admin_export_personal_data():
    """Export personal data for Admin Manager"""
    if 'username' not in session:
        return redirect(url_for('login_sso'))
    
    # Check admin privileges
    if session['role'] not in ('Admin Manager', 'Lead Staffing Specialist'):
        flash("Access denied. Admin Manager privileges required.")
        return redirect(url_for('dashboard'))
    
    export_type = request.form.get('export_type', 'csv')
    data_type = request.form.get('data_type', 'all')
    
    flash(f" Personal data export ({data_type}) to {export_type.upper()} format initiated.")
    return redirect(url_for('dashboard'))

@app.route('/admin_bulk_timesheet_action', methods=['POST'])
def admin_bulk_timesheet_action():
    """Bulk approve/reject team timesheets for Admin Manager"""
    if 'username' not in session:
        return redirect(url_for('login_sso'))
    
    # Check admin privileges
    if session['role'] not in ('Admin Manager', 'Lead Staffing Specialist'):
        flash("Access denied. Admin Manager privileges required.")
        return redirect(url_for('dashboard'))
    
    timesheet_ids = request.form.getlist('timesheet_ids')
    action = request.form.get('bulk_action')
    rejection_reason = request.form.get('bulk_rejection_reason', 'Bulk rejection')
    
    if not timesheet_ids or not action:
        flash(" No timesheets selected or action specified.")
        return redirect(url_for('dashboard'))
    
    user = session['username']
    team = get_all_reports_recursive(user)
    
    if not team:
        flash(" No team members found for bulk action.")
        return redirect(url_for('dashboard'))
    
    success_count = 0
    failed_count = 0
    
    try:
        placeholders = ",".join(["?"] * len(team))
        
        for timesheet_id in timesheet_ids:
            try:
                if action == 'approve':
                    ok = run_exec(f"""
                        UPDATE timesheets 
                        SET rm_status = 'Approved', rm_approver = ?, rm_rejection_reason = NULL
                        WHERE id = ? AND username IN ({placeholders}) AND rm_status = 'Pending'
                    """, (user, int(timesheet_id)) + tuple(team))
                elif action == 'reject':
                    ok = run_exec(f"""
                        UPDATE timesheets 
                        SET rm_status = 'Rejected', rm_approver = ?, rm_rejection_reason = ?
                        WHERE id = ? AND username IN ({placeholders}) AND rm_status = 'Pending'
                    """, (user, rejection_reason, int(timesheet_id)) + tuple(team))
                else:
                    ok = False
                
                if ok:
                    success_count += 1
                else:
                    failed_count += 1
                    
            except Exception:
                failed_count += 1
        
        if success_count > 0:
            flash(f" {success_count} timesheets {action}d successfully.")

            # Send bulk notification email to affected employees
            affected_employees = []
            for timesheet_id in timesheet_ids:
                try:
                    emp_details = run_query("SELECT username FROM timesheets WHERE id = ?", (int(timesheet_id),))
                    if not emp_details.empty:
                        username = emp_details.iloc[0]['username']
                        if username not in affected_employees:
                            affected_employees.append(username)
                except:
                    continue
            
            # Send individual emails to each affected employee
            for emp_username in affected_employees:
                emp_email = get_user_email(emp_username)
                if emp_email:
                    subject = f"Bulk Timesheet {action.title()} - {emp_username}"
                    text_content = f"""Dear {emp_username},

    Your timesheets have been {action}d in a bulk action by {session['username']} ({session['role']}).

    Action: {action.title()}
    Processed by: {session['username']}
    Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}

    Please check your dashboard for the updated status of your timesheet entries.
    https://nexus.chervicaon.com
    This is an automated notification from the Timesheet & Leave Management System."""
                    send_email(emp_email, subject, text_content)

        
        if failed_count > 0:
            flash(f" {failed_count} timesheets failed to process.")
    
    except Exception as e:
        flash(f" Error in bulk timesheet action: {str(e)}")
    
    return redirect(url_for('dashboard'))

@app.route('/admin_bulk_leave_action', methods=['POST'])
def admin_bulk_leave_action():
    """Bulk approve/reject team leaves for Admin Manager"""
    if 'username' not in session:
        return redirect(url_for('login_sso'))
    
    # Check admin privileges
    if session['role'] not in ('Admin Manager', 'Lead Staffing Specialist'):
        flash("Access denied. Admin Manager privileges required.")
        return redirect(url_for('dashboard'))
    
    leave_ids = request.form.getlist('leave_ids')
    action = request.form.get('bulk_action')
    rejection_reason = request.form.get('bulk_rejection_reason', 'Bulk rejection')
    
    if not leave_ids or not action:
        flash(" No leaves selected or action specified.")
        return redirect(url_for('dashboard'))
    
    user = session['username']
    team = get_all_reports_recursive(user)
    
    if not team:
        flash(" No team members found for bulk action.")
        return redirect(url_for('dashboard'))
    
    success_count = 0
    failed_count = 0
    
    try:
        placeholders = ",".join(["?"] * len(team))
        
        for leave_id in leave_ids:
            try:
                # Get leave details first for email notification
                leave_details = run_query(f"""
                    SELECT username, leavetype, startdate, enddate, description 
                    FROM leaves 
                    WHERE id = ? AND username IN ({placeholders}) AND rmstatus = 'Pending'
                """, [int(leave_id)] + tuple(team))
                
                if not leave_details.empty:
                    leave_username = leave_details.iloc[0]['username']
                    leave_type = str(leave_details.iloc[0]['leavetype'])
                    start_date = parse(str(leave_details.iloc[0]['startdate']))
                    end_date = parse(str(leave_details.iloc[0]['enddate']))
                    description = leave_details.iloc[0]['description']
                    leave_days = (end_date - start_date).days + 1
                    
                    if action == 'approve':
                        # Apply leave balance deduction
                        _apply_leave_balance(leave_username, leave_type, leave_days, 1)
                        
                        ok = run_exec(f"""
                            UPDATE leaves 
                            SET rmstatus = 'Approved', rmapprover = ?, rmrejectionreason = NULL 
                            WHERE id = ? AND username IN ({placeholders}) AND rmstatus = 'Pending'
                        """, [user, int(leave_id)] + tuple(team))
                        
                        if ok:
                            # Send approval email
                            user_email = get_user_email(leave_username)
                            if user_email:
                                subject = f"Leave Approved (Bulk Action) - {leave_username}"
                                text_content = f"""Dear {leave_username},

Your leave request has been approved in a bulk action by {user}.

Details:
- Leave Type: {leave_type}
- Duration: {leave_days} days
- Start Date: {start_date.strftime('%Y-%m-%d')}
- End Date: {end_date.strftime('%Y-%m-%d')}
- Reason: {description}
- Status: Approved
- Processed by: {user}

You can view the updated status in your dashboard.
https://nexus.chervicaon.com
This is an automated notification from the Timesheet Leave Management System."""
                                
                                send_email(user_email, subject, text_content)
                    
                    elif action == 'reject':
                        ok = run_exec(f"""
                            UPDATE leaves 
                            SET rmstatus = 'Rejected', rmapprover = ?, rmrejectionreason = ? 
                            WHERE id = ? AND username IN ({placeholders}) AND rmstatus = 'Pending'
                        """, [user, rejection_reason, int(leave_id)] + tuple(team))
                        
                        if ok:
                            # Send rejection email
                            user_email = get_user_email(leave_username)
                            if user_email:
                                subject = f"Leave Rejected (Bulk Action) - {leave_username}"
                                text_content = f"""Dear {leave_username},

Your leave request has been rejected in a bulk action by {user}.

Details:
- Leave Type: {leave_type}
- Duration: {leave_days} days
- Start Date: {start_date.strftime('%Y-%m-%d')}
- End Date: {end_date.strftime('%Y-%m-%d')}
- Reason: {description}
- Status: Rejected
- Rejection Reason: {rejection_reason}
- Processed by: {user}

Please contact your supervisor for clarification or resubmit your request with corrections.
https://nexus.chervicaon.com
This is an automated notification from the Timesheet Leave Management System."""
                                
                                send_email(user_email, subject, text_content)

                else:
                    ok = False
                
                if ok:
                    success_count += 1
                else:
                    failed_count += 1
                    
            except Exception:
                failed_count += 1
        
        if success_count > 0:
            flash(f" {success_count} leave requests {action}d successfully.")
        
        if failed_count > 0:
            flash(f" {failed_count} leave requests failed to process.")
    
    except Exception as e:
        flash(f" Error in bulk leave action: {str(e)}")
    
    return redirect(url_for('dashboard'))

# Add these FINAL missing Admin Manager salary and employee management routes:
@app.route('/update_salary_admin', methods=['POST'])
def update_salary_admin():
    """Update employee salary (Admin Manager specific) - ALL FIELDS OPTIONAL"""
    if 'username' not in session:
        return redirect(url_for('login_sso'))
    
    # Check admin privileges
    if session['role'] not in ('Admin Manager', 'Lead Staffing Specialist'):
        flash(" Access denied. Admin Manager privileges required.")
        return redirect(url_for('dashboard'))
    
    employee_username = request.form.get('employee_username', '').strip()
    monthly_salary = request.form.get('monthly_salary', '').strip()
    yearly_salary = request.form.get('yearly_salary', '').strip()
    
    # If no username provided, show error
    if not employee_username:
        flash("Employee username is required.")
        return redirect(url_for('dashboard'))
    
    try:
        # Get current employee details (check if employee exists)
        current_details = run_query("""
            SELECT username, name, monthly_salary, yearly_salary 
            FROM users 
            WHERE username = ? AND status IN ('Active', 'Inactive', 'Suspended')
        """, (employee_username,))
        
        if current_details.empty:
            # Employee not found - show available employees for reference
            available_employees = run_query("""
                SELECT TOP 10 username, name, role 
                FROM users 
                WHERE status IN ('Active', 'Inactive') 
                ORDER BY username
            """)
            
            if not available_employees.empty:
                employee_list = ", ".join(available_employees['username'].astype(str).tolist())
                flash(f" Employee '{employee_username}' not found. Available employees: {employee_list}")
            else:
                flash(f" Employee '{employee_username}' not found in the system.")
            
            return redirect(url_for('dashboard'))
        
        # Employee found - get current values
        current = current_details.iloc[0]
        current_monthly = float(current['monthly_salary'] or 0)
        current_yearly = float(current['yearly_salary'] or 0)
        
        # Determine new salary values (use current if not provided)
        if monthly_salary:
            new_monthly = float(monthly_salary)
        else:
            new_monthly = current_monthly
            
        if yearly_salary:
            new_yearly = float(yearly_salary)
        else:
            # If yearly is not provided but monthly is, calculate yearly
            if monthly_salary:
                new_yearly = new_monthly * 12
            else:
                new_yearly = current_yearly
        
        # Check if any change is being made
        if new_monthly == current_monthly and new_yearly == current_yearly:
            flash(f"ℹ️ No salary changes made for {employee_username}. Current: ₹{current_monthly:,.2f}/month, ₹{current_yearly:,.2f}/year")
            return redirect(url_for('dashboard'))
        
        # Update salary in database
        ok = run_exec("""
            UPDATE users 
            SET monthly_salary = ?, yearly_salary = ?
            WHERE username = ?
        """, (new_monthly, new_yearly, employee_username))
        
        if ok:
            # Calculate and show the change
            monthly_change = new_monthly - current_monthly
            yearly_change = new_yearly - current_yearly
            
            if monthly_change > 0:
                flash(f" Salary INCREASED for {employee_username}:")
                flash(f"   Monthly: ₹{current_monthly:,.2f} → ₹{new_monthly:,.2f} (+₹{monthly_change:,.2f})")
                flash(f"   Yearly: ₹{current_yearly:,.2f} → ₹{new_yearly:,.2f} (+₹{yearly_change:,.2f})")
            elif monthly_change < 0:
                flash(f" Salary DECREASED for {employee_username}:")
                flash(f"   Monthly: ₹{current_monthly:,.2f} → ₹{new_monthly:,.2f} (₹{monthly_change:,.2f})")
                flash(f"   Yearly: ₹{current_yearly:,.2f} → ₹{new_yearly:,.2f} (₹{yearly_change:,.2f})")
            else:
                flash(f" Salary updated for {employee_username}: ₹{new_monthly:,.2f}/month, ₹{new_yearly:,.2f}/year")
        else:
            flash(" Failed to update salary in database. Please try again.")
    
    except ValueError as e:
        flash(f" Invalid salary amount entered. Please enter valid numbers only. Error: {str(e)}")
    except Exception as e:
        flash(f" Error updating salary: {str(e)}")
        print(f"Salary update error for {employee_username}: {e}")
    
    return redirect(url_for('dashboard'))

@app.route('/get_all_employees_for_salary_update')
def get_all_employees_for_salary_update():
    """Get all employees for salary update dropdown"""
    if 'username' not in session or session['role'] not in ('Admin Manager', 'Lead Staffing Specialist'):
        return jsonify({'error': 'Access denied'}), 403
    
    try:
        employees = run_query("""
            SELECT username, name, role, monthly_salary, yearly_salary, status
            FROM users 
            WHERE status IN ('Active', 'Inactive')
            ORDER BY name, username
        """)
        
        return jsonify({
            'success': True,
            'employees': employees.to_dict('records') if not employees.empty else []
        })
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/activate_employee_admin', methods=['POST'])
def activate_employee_admin():
    """Activate employee account (Admin Manager specific)"""
    if 'username' not in session:
        return redirect(url_for('login_sso'))
    
    # Check admin privileges  
    if session['role'] not in ('Admin Manager', 'Lead Staffing Specialist'):
        flash(" Access denied. Admin Manager privileges required.")
        return redirect(url_for('dashboard'))
    
    employee_username = request.form.get('employee_username')
    
    if not employee_username:
        flash(" Employee username is required.")
        return redirect(url_for('dashboard'))
    
    try:
        ok = run_exec("UPDATE users SET status = 'Active' WHERE username = ?", (employee_username,))
        
        if ok:
            emp_email = get_user_email(employee_username)
            if emp_email:
                subject = f"Account Activated - {employee_username}"
                text_content = f"""Dear {employee_username},

    Your account has been activated by the administration.

    You can now access the Timesheet & Leave Management System.
    https://nexus.chervicaon.com
    If you have any questions, please contact the HR department.

    This is an automated notification from the Timesheet & Leave Management System."""
                send_email(emp_email, subject, text_content)

            flash(f" Employee {employee_username} activated successfully.")
        else:
            flash(" Failed to activate employee.")
    
    except Exception as e:
        flash(f" Error activating employee: {str(e)}")
    
    return redirect(url_for('dashboard'))

@app.route('/suspend_employee_admin', methods=['POST'])
def suspend_employee_admin():
    """Suspend employee account (Admin Manager specific)"""
    if 'username' not in session:
        return redirect(url_for('login_sso'))
    
    # Check admin privileges
    if session['role'] not in ('Admin Manager', 'Lead Staffing Specialist'):
        flash(" Access denied. Admin Manager privileges required.")
        return redirect(url_for('dashboard'))
    
    employee_username = request.form.get('employee_username')
    suspension_reason = request.form.get('suspension_reason', 'Suspended by Admin')
    
    if not employee_username:
        flash(" Employee username is required.")
        return redirect(url_for('dashboard'))
    
    try:
        ok = run_exec("UPDATE users SET status = 'Suspended' WHERE username = ?", (employee_username,))
        
        if ok:
            flash(f" Employee {employee_username} suspended. Reason: {suspension_reason}")
        else:
            flash(" Failed to suspend employee.")
    
    except Exception as e:
        flash(f" Error suspending employee: {str(e)}")
    
    return redirect(url_for('dashboard'))

@app.route('/reset_password_admin', methods=['POST'])
def reset_password_admin():
    """Reset employee password (Admin Manager specific)"""
    if 'username' not in session:
        return redirect(url_for('login_sso'))
    
    # Check admin privileges
    if session['role'] not in ('Admin Manager', 'Lead Staffing Specialist'):
        flash(" Access denied. Admin Manager privileges required.")
        return redirect(url_for('dashboard'))
    
    employee_username = request.form.get('employee_username')
    new_password = request.form.get('new_password', 'password123')
    
    if not employee_username:
        flash(" Employee username is required.")
        return redirect(url_for('dashboard'))
    
    try:
        ok = run_exec("UPDATE users SET password = ? WHERE username = ?", (new_password, employee_username))
        
        if ok:
            emp_email = get_user_email(employee_username)
            if emp_email:
                subject = f"Password Reset - {employee_username}"
                text_content = f"""Dear {employee_username},

    Your password has been reset by the administration.

    New Password: {new_password}

    Please log in with your new password and change it immediately for security reasons.
    https://nexus.chervicaon.com
    This is an automated notification from the Timesheet & Leave Management System."""
                send_email(emp_email, subject, text_content)

            flash(f" Password reset for {employee_username}. New password: {new_password}")
        else:
            flash(" Failed to reset password.")
    
    except Exception as e:
        flash(f" Error resetting password: {str(e)}")
    
    return redirect(url_for('dashboard'))

@app.route('/update_employee_role_admin', methods=['POST'])
def update_employee_role_admin():
    """Update employee role (Admin Manager specific)"""
    if 'username' not in session:
        return redirect(url_for('login_sso'))
    
    # Check admin privileges
    if session['role'] not in ('Admin Manager', 'Lead Staffing Specialist'):
        flash(" Access denied. Admin Manager privileges required.")
        return redirect(url_for('dashboard'))
    
    employee_username = request.form.get('employee_username')
    new_role = request.form.get('new_role')
    role_change_reason = request.form.get('role_change_reason', 'Role updated by Admin')
    
    if not employee_username or not new_role:
        flash(" Employee username and new role are required.")
        return redirect(url_for('dashboard'))
    
    try:
        # Get current role
        current_role_df = run_query("SELECT role FROM users WHERE username = ?", (employee_username,))
        
        if not current_role_df.empty:
            current_role = current_role_df.iloc[0]['role']
            
            # Update role in both tables
            ok1 = run_exec("UPDATE users SET role = ? WHERE username = ?", (new_role, employee_username))
            ok2 = run_exec("UPDATE employee_details SET role = ? WHERE username = ?", (new_role, employee_username))
            
            if ok1 and ok2:
                emp_email = get_user_email(employee_username)
                if emp_email:
                    subject = f"Role Updated - {employee_username}"
                    text_content = f"""Dear {employee_username},

        Your role has been updated in the system.

        Previous Role: {current_role}
        New Role: {new_role}
        Updated by: {session['username']}
        Reason: {role_change_reason}

        Please log in to see your updated permissions.
        https://nexus.chervicaon.com
        This is an automated notification from the Timesheet & Leave Management System."""
                    send_email(emp_email, subject, text_content)

                flash(f" Role updated for {employee_username}: {current_role} → {new_role}")
            else:
                flash(" Failed to update role.")
        else:
            flash(" Employee not found.")
    
    except Exception as e:
        flash(f" Error updating role: {str(e)}")
    
    return redirect(url_for('dashboard'))

@app.route('/transfer_employee_admin', methods=['POST'])
def transfer_employee_admin():
    """Transfer employee to different manager (Admin Manager specific)"""
    if 'username' not in session:
        return redirect(url_for('login_sso'))
    
    # Check admin privileges
    if session['role'] not in ('Admin Manager', 'Lead Staffing Specialist'):
        flash(" Access denied. Admin Manager privileges required.")
        return redirect(url_for('dashboard'))
    
    employee_username = request.form.get('employee_username')
    new_manager = request.form.get('new_manager')
    transfer_reason = request.form.get('transfer_reason', 'Transferred by Admin')
    
    if not employee_username or not new_manager:
        flash(" Employee username and new manager are required.")
        return redirect(url_for('dashboard'))
    
    try:
        # Update reporting manager
        ok = run_exec("""
            UPDATE report SET rm = ?, manager = ? WHERE username = ?
        """, (new_manager, new_manager, employee_username))
        
        if not ok:
            # If no existing record, create one
            ok = run_exec("""
                INSERT INTO [timesheet_db].[dbo].[report] (username, rm, manager) VALUES (?, ?, ?)
            """, (employee_username, new_manager, new_manager))
        
        if ok:
            flash(f" Employee {employee_username} transferred to manager {new_manager}.")
        else:
            flash(" Failed to transfer employee.")
    
    except Exception as e:
        flash(f" Error transferring employee: {str(e)}")
    
    return redirect(url_for('dashboard'))
# Add these ABSOLUTELY FINAL missing Admin Manager routes:

@app.route('/view_employee_admin/<username>')
def view_employee_admin(username):
    """View comprehensive employee details (Admin Manager specific)"""
    if 'username' not in session:
        return redirect(url_for('login_sso'))
    
    # Check admin privileges
    if session['role'] not in ('Admin Manager', 'Lead Staffing Specialist'):
        flash(" Access denied. Admin Manager privileges required.")
        return redirect(url_for('dashboard'))
    
    try:
        # Get complete employee details
        employee = run_query("""
            SELECT u.username, u.name, u.role, u.email, u.monthly_salary, u.yearly_salary, u.status,
                   ed.joining_date, ed.employment_type, ed.mobile_number, ed.emergency_contact,
                   ed.blood_group, ed.adhaar_number, ed.pan_number, ed.laptop_provided, 
                   ed.id_card_provided, ed.email_provided, ed.asset_details
            FROM users u
            LEFT JOIN employee_details ed ON u.username = ed.username
            WHERE u.username = ?
        """, (username,))
        
        # Get reporting manager
        manager = run_query("SELECT rm FROM report WHERE username = ?", (username,))
        
        # Get recent work activity
        recent_work = run_query("""
            SELECT TOP 20 work_date, project_name, hours, rm_status
            FROM timesheets 
            WHERE username = ?
            ORDER BY work_date DESC
        """, (username,))
        
        # Get recent leave activity
        recent_leaves = run_query("""
            SELECT TOP 20 start_date, end_date, leave_type, rm_status
            FROM leaves 
            WHERE username = ?
            ORDER BY start_date DESC
        """, (username,))
        
        # Get leave balances
        leave_balances = _get_remaining_balances(username)
        
        return render_template('view_employee_admin.html',
            employee=employee.iloc[0].to_dict() if not employee.empty else {},
            manager=manager.iloc[0]['rm'] if not manager.empty else 'No Manager',
            recent_work=recent_work.to_dict('records') if not recent_work.empty else [],
            recent_leaves=recent_leaves.to_dict('records') if not recent_leaves.empty else [],
            leave_balances=leave_balances,
            user=session['username'],
            role=session['role']
        )
    
    except Exception as e:
        flash(f" Error viewing employee details: {str(e)}")
        return redirect(url_for('dashboard'))

@app.route('/clone_employee_admin', methods=['POST'])
def clone_employee_admin():
    """Clone employee details to create new employee (Admin Manager specific)"""
    if 'username' not in session:
        return redirect(url_for('login_sso'))
    
    # Check admin privileges
    if session['role'] not in ('Admin Manager', 'Lead Staffing Specialist'):
        flash(" Access denied. Admin Manager privileges required.")
        return redirect(url_for('dashboard'))
    
    source_username = request.form.get('source_username')
    new_username = request.form.get('new_username')
    new_name = request.form.get('new_name')
    new_email = request.form.get('new_email')
    
    if not all([source_username, new_username, new_name]):
        flash(" Source username, new username, and name are required.")
        return redirect(url_for('dashboard'))
    
    try:
        # Get source employee details
        source_employee = run_query("""
            SELECT u.role, u.monthly_salary, u.yearly_salary,
                   ed.employment_type, ed.blood_group
            FROM users u
            LEFT JOIN employee_details ed ON u.username = ed.username
            WHERE u.username = ?
        """, (source_username,))
        
        if source_employee.empty:
            flash(" Source employee not found.")
            return redirect(url_for('dashboard'))
        
        source = source_employee.iloc[0]
        
        # Create new employee with cloned details
        ok1 = run_exec("""
            INSERT INTO [timesheet_db].[dbo].[users] (username, password, role, name, email, status, monthly_salary, yearly_salary)
            VALUES (?, 'password123', ?, ?, ?, 'Active', ?, ?)
        """, (new_username, source['role'], new_name, new_email or '', 
              source['monthly_salary'], source['yearly_salary']))
        
        ok2 = run_exec("""
            INSERT INTO [timesheet_db].[dbo].[employee_details] (username, name, role, employment_type, blood_group)
            VALUES (?, ?, ?, ?, ?)
        """, (new_username, new_name, source['role'], 
              source['employment_type'], source['blood_group']))
        
        # Set up default leave balance
        ok3 = run_exec("""
            INSERT INTO [timesheet_db].[dbo].[leave_balances] (username, total_leaves, sick_total, paid_total, casual_total, sick_used, paid_used, casual_used)
            VALUES (?, 36, 12, 18, 6, 0, 0, 0)
        """, (new_username,))
        
        if ok1 and ok2 and ok3:
            flash(f" Employee '{new_name}' ({new_username}) cloned successfully from {source_username}.")
        else:
            flash(" Failed to clone employee.")
    
    except Exception as e:
        flash(f" Error cloning employee: {str(e)}")
    
    return redirect(url_for('dashboard'))

@app.route('/export_employee_data_admin', methods=['POST'])
def export_employee_data_admin():
    """Export employee data (Admin Manager specific)"""
    if 'username' not in session:
        return redirect(url_for('login_sso'))
    
    # Check admin privileges
    if session['role'] not in ('Admin Manager', 'Lead Staffing Specialist'):
        flash(" Access denied. Admin Manager privileges required.")
        return redirect(url_for('dashboard'))
    
    export_format = request.form.get('export_format', 'csv')
    include_salary = request.form.get('include_salary') == 'on'
    include_personal = request.form.get('include_personal') == 'on'
    
    flash(f" Employee data export to {export_format.upper()} format initiated. Includes salary: {include_salary}, personal info: {include_personal}")
    return redirect(url_for('dashboard'))

@app.route('/import_employees_admin', methods=['POST'])
def import_employees_admin():
    """Import employees from file (Admin Manager specific)"""
    if 'username' not in session:
        return redirect(url_for('login_sso'))
    
    # Check admin privileges
    if session['role'] not in ('Admin Manager', 'Lead Staffing Specialist'):
        flash(" Access denied. Admin Manager privileges required.")
        return redirect(url_for('dashboard'))
    
    if 'import_file' not in request.files:
        flash(" No file selected for import.")
        return redirect(url_for('dashboard'))
    
    file = request.files['import_file']
    if file.filename == '':
        flash(" No file selected for import.")
        return redirect(url_for('dashboard'))
    
    flash(" Employee import functionality initiated. File processing would be implemented here.")
    return redirect(url_for('dashboard'))
# Add these ULTIMATE FINAL missing API/JSON routes for Admin Manager:
@app.route('/edit_employee_admin', methods=['POST'])
def edit_employee_admin():
    """Edit employee details - COMPREHENSIVE VERSION - FULLY UPDATED"""
    if 'username' not in session:
        return redirect(url_for('login_sso'))
    
    # Check admin privileges
    if session['role'] not in ('Admin Manager', 'Lead Staffing Specialist'):
        flash("Access denied. Admin Manager privileges required.")
        return redirect(url_for('dashboard'))
    
    employee_username = request.form.get('employee_username')
    if not employee_username:
        flash("Employee username is required.")
        return redirect(url_for('dashboard'))
    
    try:
        # ENHANCED: Get current employee details INCLUDING employmentid
        current_details = run_query("""
            SELECT u.name, u.email, u.role, u.password, u.monthly_salary, u.yearly_salary, u.status,
                   ed.joining_date, ed.employment_type, ed.blood_group, ed.mobile_number,
                   ed.emergency_contact, ed.id_card, ed.id_card_provided, ed.photo_url,
                   ed.linkedin_url, ed.laptop_provided, ed.email_provided, ed.asset_details,
                   ed.adhaar_number, ed.pan_number, ed.duration, ed.employmentid,
                   r.rm, r.manager
            FROM users u
            LEFT JOIN employee_details ed ON u.username = ed.username
            LEFT JOIN report r ON u.username = r.username
            WHERE u.username = ?
        """, (employee_username,))
        
        if current_details.empty:
            flash("Employee not found.")
            return redirect(url_for('dashboard'))
        
        current = current_details.iloc[0]
        
        # Get form data with fallbacks to current values
        name = request.form.get('name', '').strip() or current.get('name')
        email = request.form.get('email', '').strip() or current.get('email')
        role = request.form.get('role', '').strip() or current.get('role')
        password = request.form.get('password', '').strip() or current.get('password')
        
        # Employment details
        joining_date = request.form.get('joining_date', '').strip() or current.get('joining_date')
        employment_type = request.form.get('employment_type', '').strip() or current.get('employment_type', 'Full-Time')
        blood_group = request.form.get('blood_group', '').strip() or current.get('blood_group')
        duration = request.form.get('duration', '').strip() or current.get('duration')
        
        # ENHANCED: Get employmentid from form (MISSING FROM VERSION 2)
        employmentid = request.form.get('employmentid', '').strip().upper() or current.get('employmentid')
        
        # Contact information
        mobile_number = request.form.get('mobile_number', '').strip() or current.get('mobile_number')
        emergency_contact = request.form.get('emergency_contact', '').strip() or current.get('emergency_contact')
        
        # Asset information
        laptop_provided = bool(request.form.get('laptop_provided')) if request.form.get('laptop_provided') is not None else bool(current.get('laptop_provided'))
        id_card_provided = bool(request.form.get('id_card_provided')) if request.form.get('id_card_provided') is not None else bool(current.get('id_card_provided'))
        email_provided = bool(request.form.get('email_provided')) if request.form.get('email_provided') is not None else bool(current.get('email_provided'))
        id_card = request.form.get('id_card', '').strip() or current.get('id_card')
        asset_details = request.form.get('asset_details', '').strip() or current.get('asset_details')
        
        # Documents
        adhaar_number = request.form.get('adhaar_number', '').strip() or current.get('adhaar_number')
        pan_number = request.form.get('pan_number', '').strip() or current.get('pan_number')
        linkedin_url = request.form.get('linkedin_url', '').strip() or current.get('linkedin_url')
        photo_url = request.form.get('photo_url', '').strip() or current.get('photo_url')
        
        # Salary information
        monthly_salary = None
        yearly_salary = None
        if request.form.get('monthly_salary'):
            monthly_salary = float(request.form.get('monthly_salary'))
            yearly_salary = float(request.form.get('yearly_salary')) if request.form.get('yearly_salary') else monthly_salary * 12
        else:
            monthly_salary = current.get('monthly_salary')
            yearly_salary = current.get('yearly_salary')
        
        # Reporting manager
        new_reporting_manager = request.form.get('reporting_manager', '').strip() or current.get('rm')
        
        # Leave balance
        total_leaves = request.form.get('total_leaves') or 36
        sick_total = request.form.get('sick_total') or 12
        paid_total = request.form.get('paid_total') or 18
        casual_total = request.form.get('casual_total') or 6
        
        # Handle file upload for photo
        if 'photo' in request.files and request.files['photo'].filename:
            file = request.files['photo']
            filename = secure_filename(file.filename)
            timestamp = int(datetime.now().timestamp())
            photo_filename = f"{employee_username}_{timestamp}_{filename}"
            file.save(os.path.join(app.config['UPLOAD_FOLDER'], photo_filename))
            photo_url = f"/uploads/{photo_filename}"
        
        # ENHANCED: Employment ID validation (MISSING FROM VERSION 2)
        print(f"DEBUG: Updating employee {employee_username} with employmentid: '{employmentid}'")
        if employmentid and employmentid != current.get('employmentid'):
            existing_emp_id = run_query("""
                SELECT username, name FROM employee_details 
                WHERE employmentid = ? AND username != ?
            """, (employmentid, employee_username))
            
            if not existing_emp_id.empty:
                existing_user = existing_emp_id.iloc[0]
                flash(f'❌ Employment ID "{employmentid}" is already assigned to {existing_user["name"]} ({existing_user["username"]}). Please use a different Employment ID.')
                return redirect(url_for('dashboard'))
        
        # Update users table
        ok1 = run_exec("""
            UPDATE users 
            SET name = ?, email = ?, role = ?, password = ?, monthly_salary = ?, yearly_salary = ?
            WHERE username = ?
        """, (name, email, role, password, monthly_salary, yearly_salary, employee_username))
        
        # Update or insert employee_details table
        employee_details_exists = run_query("SELECT username FROM employee_details WHERE username = ?", (employee_username,))
        
        if employee_details_exists.empty:
            # ENHANCED: Insert new record WITH employmentid (MISSING FROM VERSION 2)
            ok2 = run_exec("""
                INSERT INTO [timesheet_db].[dbo]. [employee_details] (
                    username, name, role, joining_date, employment_type, blood_group,
                    mobile_number, emergency_contact, id_card, id_card_provided, photo_url,
                    linkedin_url, laptop_provided, email_provided, asset_details,
                    adhaar_number, pan_number, duration, employmentid
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (employee_username, name, role, joining_date, employment_type, blood_group,
                  mobile_number, emergency_contact, id_card, id_card_provided, photo_url,
                  linkedin_url, laptop_provided, email_provided, asset_details,
                  adhaar_number, pan_number, duration, employmentid))
        else:
            # ENHANCED: Update existing record WITH employmentid (MISSING FROM VERSION 2)
            ok2 = run_exec("""
                UPDATE employee_details 
                SET name = ?, role = ?, joining_date = ?, employment_type = ?, blood_group = ?,
                    mobile_number = ?, emergency_contact = ?, id_card = ?, id_card_provided = ?, 
                    photo_url = ?, linkedin_url = ?, laptop_provided = ?, email_provided = ?, 
                    asset_details = ?, adhaar_number = ?, pan_number = ?, duration = ?, employmentid = ?
                WHERE username = ?
            """, (name, role, joining_date, employment_type, blood_group,
                  mobile_number, emergency_contact, id_card, id_card_provided, photo_url,
                  linkedin_url, laptop_provided, email_provided, asset_details,
                  adhaar_number, pan_number, duration, employmentid, employee_username))
        
        # ADDED FROM VERSION 2: Update reporting structure (MISSING FROM VERSION 1)
        if new_reporting_manager:
            report_exists = run_query("SELECT username FROM report WHERE username = ?", (employee_username,))
            if report_exists.empty:
                ok3 = run_exec("""
                    INSERT INTO [timesheet_db].[dbo].[report] (username, rm, manager)
                    VALUES (?, ?, ?)
                """, (employee_username, new_reporting_manager, new_reporting_manager))
            else:
                ok3 = run_exec("""
                    UPDATE report
                    SET rm = ?, manager = ?
                    WHERE username = ?
                """, (new_reporting_manager, new_reporting_manager, employee_username))
        
        # ADDED FROM VERSION 2: Update leave balances (MISSING FROM VERSION 1)
        leave_balance_exists = run_query("SELECT username FROM leave_balances WHERE username = ?", (employee_username,))
        if leave_balance_exists.empty:
            ok4 = run_exec("""
                INSERT INTO [timesheet_db].[dbo].[leave_balances] (
                    username, total_leaves, sick_total, paid_total, casual_total,
                    sick_used, paid_used, casual_used
                ) VALUES (?, ?, ?, ?, ?, 0, 0, 0)
            """, (employee_username, int(total_leaves), int(sick_total), int(paid_total), int(casual_total)))
        else:
            ok4 = run_exec("""
                UPDATE leave_balances
                SET total_leaves = ?, sick_total = ?, paid_total = ?, casual_total = ?
                WHERE username = ?
            """, (int(total_leaves), int(sick_total), int(paid_total), int(casual_total), employee_username))
        
        # ENHANCED: Success/Failure check including all operations
        if ok1 and ok2:
            flash(f' Employee "{name}" ({employee_username}) updated successfully with Employment ID: {employmentid}')
        else:
            flash(' Failed to update some employee details. Please try again.')
            
    except Exception as e:
        # ENHANCED: Better error handling for Employment ID conflicts
        if 'UQ_employee_details_employmentid' in str(e):
            flash(f' Employment ID "{employmentid}" is already in use. Please choose a different Employment ID.')
        else:
            flash(f' Error updating employee: {str(e)}')
        print(f"Edit employee error: {e}")
    
    return redirect(url_for('dashboard'))



def check_user_role(required_roles):
    """
    Check if current user has required role - CASE INSENSITIVE
    Args:
        required_roles: list of role names or single role name
    Returns:
        True if user has required role, False otherwise
    """
    if 'username' not in session:
        return False
    
    if isinstance(required_roles, str):
        required_roles = [required_roles]
    
    user_role = session['role'].lower().strip()
    allowed_roles = [role.lower().strip() for role in required_roles]
    
    return user_role in allowed_roles


@app.route('/get_employee_details_json')
def get_employee_details_json():
    """Get employee details as JSON with RM information - ENHANCED with case-insensitive roles"""
    if 'username' not in session:
        return jsonify({'error': 'Unauthorized'}), 401
    
    # Check admin privileges - CASE INSENSITIVE
    user_role = session['role'].lower().strip()
    allowed_roles = ['admin manager', 'lead staffing specialist', 'hr & finance controller']
    
    if user_role not in allowed_roles:
        return jsonify({'error': 'Access denied'}), 403
    
    username = request.args.get('username')
    if not username:
        return jsonify({'error': 'Username parameter required'}), 400
    
    try:
        # CORRECTED: Added ed.employmentid to the SELECT statement
        employee = run_query("""
            SELECT u.username, u.name, u.role, u.email, u.monthly_salary, u.yearly_salary, u.status, u.password,
                   ed.joining_date, ed.employment_type, ed.mobile_number, ed.emergency_contact,
                   ed.blood_group, ed.adhaar_number, ed.pan_number, ed.laptop_provided, 
                   ed.id_card_provided, ed.email_provided, ed.asset_details, ed.id_card,
                   ed.photo_url, ed.linkedin_url, ed.duration, ed.employmentid,
                   r.rm, r.manager,
                   lb.total_leaves, lb.sick_total, lb.paid_total, lb.casual_total,
                   lb.sick_used, lb.paid_used, lb.casual_used,
                   rm_user.name as rm_name, rm_user.role as rm_role, rm_user.email as rm_email
            FROM users u
            LEFT JOIN employee_details ed ON u.username = ed.username
            LEFT JOIN report r ON u.username = r.username
            LEFT JOIN leave_balances lb ON u.username = lb.username
            LEFT JOIN users rm_user ON r.rm = rm_user.username
            WHERE u.username = ?
        """, (username,))
        
        if employee.empty:
            return jsonify({
                'success': False,
                'error': 'Employee not found'
            })
        
        emp_data = employee.iloc[0].to_dict()
        
        # Convert any date objects to strings and handle NaN values
        for key, value in emp_data.items():
            if hasattr(value, 'strftime'):
                emp_data[key] = value.strftime('%Y-%m-%d')
            elif value is None or str(value).lower() == 'nan':
                emp_data[key] = ''
        
        # Add RM details specifically
        emp_data['rm_username'] = emp_data.get('rm', '')
        emp_data['rm_name'] = emp_data.get('rm_name', '')
        emp_data['rm_role'] = emp_data.get('rm_role', '')
        emp_data['rm_email'] = emp_data.get('rm_email', '')
        
        return jsonify({
            'success': True,
            'employee': emp_data
        })
    
    except Exception as e:
        print(f"ERROR in get_employee_details_json: {e}")
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500
    # Check admin privileges - FLEXIBLE ROLE CHECK



@app.route('/delete_employee_admin', methods=['POST'])
def delete_employee_admin():
    """Delete employee (move to resigned employees) - CORRECTED ROLE CHECK"""
    if 'username' not in session:
        return redirect(url_for('login_sso'))
    
    # Check admin privileges - FIXED: Use exact database role names
    # Check admin privileges - FLEXIBLE ROLE CHECK
    allowed_roles = ('admin manager', 'Lead staffing Specialist', 'Admin Manager', 'Lead Staffing Specialist', 'admin manager ')
    if session['role'].strip() not in allowed_roles:
        flash("Access denied. Admin Manager privileges required.")
        return redirect(url_for('dashboard'))

    
    username = request.form.get('username')
    if not username:
        flash("Username is required.")
        return redirect(url_for('dashboard'))
    
    try:
        # Get employee details before deletion
        employee_details = run_query("""
            SELECT u.username, u.email, u.role, u.monthly_salary, u.yearly_salary,
                   ed.name, ed.joining_date, ed.employment_type, ed.mobile_number, ed.emergency_contact
            FROM users u
            LEFT JOIN employee_details ed ON u.username = ed.username
            WHERE u.username = ? AND (u.status IS NULL OR u.status = 'Active')
        """, (username,))
        
        if employee_details.empty:
            flash("Employee not found or already inactive.")
            return redirect(url_for('dashboard'))
        
        emp = employee_details.iloc[0]
        
        # Move to resigned employees table
        ok1 = run_exec("""
            INSERT INTO [timesheet_db].[dbo].[resigned_employees] (
                username, name, role, joining_date, resigned_date, monthly_salary, yearly_salary,
                employment_type, mobile_number, emergency_contact, resigned_by, resignation_reason
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (username, emp.get('name', ''), emp['role'], emp.get('joining_date'), date.today(),
              emp.get('monthly_salary'), emp.get('yearly_salary'), emp.get('employment_type'),
              emp.get('mobile_number'), emp.get('emergency_contact'), session['username'], 'Deleted by Admin'))
        
        # Update user status to Inactive instead of deleting
        ok2 = run_exec("UPDATE users SET status = 'Inactive' WHERE username = ?", (username,))
        
        if ok1 and ok2:
            flash(f" Employee {username} moved to resigned employees successfully.")
        else:
            flash(" Failed to delete employee.")
    
    except Exception as e:
        flash(f" Error deleting employee: {str(e)}")
    
    return redirect(url_for('dashboard'))




@app.route('/view_resigned_employee_details')
def view_resigned_employee_details():
    """Get resigned employee details as JSON"""
    if 'username' not in session or session['role'] not in ('Admin Manager', 'Lead Staffing Specialist'):
        return jsonify({'error': 'Access denied'}), 403
    
    username = request.args.get('username')
    if not username:
        return jsonify({'error': 'Username parameter required'}), 400
    
    try:
        employee = run_query("""
            SELECT username, name, role, joining_date, resigned_date, monthly_salary, yearly_salary,
                   employment_type, mobile_number, emergency_contact, resigned_by, resignation_reason
            FROM resigned_employees
            WHERE username = ?
        """, (username,))
        
        if employee.empty:
            return jsonify({'success': False, 'error': 'Resigned employee not found'})
        
        emp_data = employee.iloc[0].to_dict()
        
        # Convert dates to strings
        for key, value in emp_data.items():
            if hasattr(value, 'strftime'):
                emp_data[key] = value.strftime('%Y-%m-%d')
            elif value is None:
                emp_data[key] = ''
        
        return jsonify({'success': True, 'employee': emp_data})
    
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

# Add this function for duration field toggle in edit mode
def toggleDurationFieldForEdit():
    pass 

@app.route('/get_employee_stats_json')
def get_employee_stats_json():
    """Get employee statistics as JSON for dashboard charts (Admin Manager)"""
    if 'username' not in session:
        return jsonify({'error': 'Unauthorized'}), 401
    
    # Check admin privileges
    if session['role'] not in ('Admin Manager', 'Lead Staffing Specialist'):
        return jsonify({'error': 'Access denied'}), 403
    
    try:
        # Get employee count by role
        role_stats = run_query("""
            SELECT role, COUNT(*) as count
            FROM users 
            WHERE status = 'Active'
            GROUP BY role
            ORDER BY count DESC
        """)
        
        # Get employee count by status
        status_stats = run_query("""
            SELECT status, COUNT(*) as count
            FROM users
            GROUP BY status
        """)
        
        # Get recent hires (last 30 days)
        recent_hires = run_query("""
            SELECT COUNT(*) as count
            FROM employee_details
            WHERE joining_date >= DATEADD(day, -30, GETDATE())
        """)
        
        return jsonify({
            'success': True,
            'role_stats': role_stats.to_dict('records') if not role_stats.empty else [],
            'status_stats': status_stats.to_dict('records') if not status_stats.empty else [],
            'recent_hires': int(recent_hires.iloc[0]['count']) if not recent_hires.empty else 0
        })
    
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

@app.route('/get_employee_work_summary_json')
def get_employee_work_summary_json():
    """Get employee work summary as JSON (Admin Manager)"""
    if 'username' not in session:
        return jsonify({'error': 'Unauthorized'}), 401
    
    # Check admin privileges
    if session['role'] not in ('Admin Manager', 'Lead Staffing Specialist'):
        return jsonify({'error': 'Access denied'}), 403
    
    username = request.args.get('username')
    if not username:
        return jsonify({'error': 'Username parameter required'}), 400
    
    try:
        # Get work summary for the last 30 days
        work_summary = run_query("""
            SELECT 
                COUNT(*) as total_entries,
                SUM(hours) as total_hours,
                AVG(hours) as avg_hours_per_day,
                COUNT(CASE WHEN rm_status = 'Approved' THEN 1 END) as approved_entries,
                COUNT(CASE WHEN rm_status = 'Pending' THEN 1 END) as pending_entries,
                COUNT(CASE WHEN rm_status = 'Rejected' THEN 1 END) as rejected_entries
            FROM timesheets 
            WHERE username = ? AND work_date >= DATEADD(day, -30, GETDATE())
        """, (username,))
        
        # Get leave summary for the last 30 days
        leave_summary = run_query("""
            SELECT 
                COUNT(*) as total_requests,
                SUM(DATEDIFF(day, start_date, end_date) + 1) as total_days,
                COUNT(CASE WHEN rm_status = 'Approved' THEN 1 END) as approved_requests,
                COUNT(CASE WHEN rm_status = 'Pending' THEN 1 END) as pending_requests,
                COUNT(CASE WHEN rm_status = 'Rejected' THEN 1 END) as rejected_requests
            FROM leaves 
            WHERE username = ? AND start_date >= DATEADD(day, -30, GETDATE())
        """, (username,))
        
        # Get leave balances
        leave_balances = _get_remaining_balances(username)
        
        return jsonify({
            'success': True,
            'work_summary': work_summary.iloc[0].to_dict() if not work_summary.empty else {},
            'leave_summary': leave_summary.iloc[0].to_dict() if not leave_summary.empty else {},
            'leave_balances': leave_balances
        })
    
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

@app.route('/validate_employee_data_json', methods=['POST'])
def validate_employee_data_json():
    """Validate employee data for forms (Admin Manager)"""
    if 'username' not in session:
        return jsonify({'error': 'Unauthorized'}), 401
    
    # Check admin privileges
    if session['role'] not in ('Admin Manager', 'Lead Staffing Specialist'):
        return jsonify({'error': 'Access denied'}), 403
    
    try:
        data = request.get_json()
        username = data.get('username')
        email = data.get('email')
        
        errors = []
        
        # Check username availability
        if username:
            existing_user = run_query("SELECT username FROM users WHERE username = ?", (username,))
            if not existing_user.empty:
                errors.append(f"Username '{username}' already exists")
        
        # Check email format and availability
        if email:
            import re
            if not re.match(r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}₹', email):
                errors.append("Invalid email format")
            else:
                existing_email = run_query("SELECT email FROM users WHERE email = ?", (email,))
                if not existing_email.empty:
                    errors.append(f"Email '{email}' already exists")
        
        return jsonify({
            'success': len(errors) == 0,
            'errors': errors
        })
    
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

@app.route('/search_employees_json')
def search_employees_json():
    """Search employees for autocomplete/dropdown (Admin Manager)"""
    if 'username' not in session:
        return jsonify({'error': 'Unauthorized'}), 401
    
    # Check admin privileges
    if session['role'] not in ('Admin Manager', 'Lead Staffing Specialist'):
        return jsonify({'error': 'Access denied'}), 403
    
    query = request.args.get('q', '').strip()
    
    try:
        if query:
            # Search by username or name
            employees = run_query("""
                SELECT TOP 10 u.username, u.name, u.role, u.status
                FROM users u
                WHERE (u.username LIKE ? OR u.name LIKE ?)
                AND u.status = 'Active'
                ORDER BY u.name
            """, (f"%{query}%", f"%{query}%"))
        else:
            # Return all active employees
            employees = run_query("""
                SELECT TOP 50 u.username, u.name, u.role, u.status
                FROM users u
                WHERE u.status = 'Active'
                ORDER BY u.name
            """)
        
        return jsonify({
            'success': True,
            'employees': employees.to_dict('records') if not employees.empty else []
        })
    
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500
    
@app.route('/approve_work_admin', methods=['POST'])
def approve_work_admin():
    """Approve work/timesheet (Admin Manager specific)"""
    if 'username' not in session:
        return redirect(url_for('login_sso'))
    
    # Check admin privileges
    if session['role'] not in ('Admin Manager', 'Lead Staffing Specialist'):
        flash(" Access denied. Admin Manager privileges required.")
        return redirect(url_for('dashboard'))
    
    timesheet_id = request.form.get('timesheet_id')
    
    if not timesheet_id:
        flash(" Timesheet ID is required.")
        return redirect(url_for('dashboard'))
    
    user = session['username']
    team = get_all_reports_recursive(user)
    
    if not team:
        flash(" No team members found for approval.")
        return redirect(url_for('dashboard'))
    
    placeholders = ",".join(["?"] * len(team))
    
    try:
        ok = run_exec(f"""
            UPDATE timesheets 
            SET rm_status = 'Approved', rm_approver = ?, rm_rejection_reason = NULL
            WHERE id = ? AND username IN ({placeholders}) AND rm_status = 'Pending'
        """, (user, int(timesheet_id)) + tuple(team))
        
        if ok:
            # Get timesheet details for email
            timesheet_details = run_query(f"""
                SELECT t.username, t.project_name, t.work_date, t.hours, t.work_desc 
                FROM timesheets t 
                WHERE t.id = ? AND t.username IN ({placeholders})
            """, (int(timesheet_id),) + tuple(team))
            
            if not timesheet_details.empty:
                employee_username = timesheet_details.iloc[0]['username']
                
                # Send email notification
                user_email = get_user_email(employee_username)
                if user_email:
                    subject = f"Timesheet Approved - {employee_username}"
                    text_content = f"""Dear {employee_username},

        Your timesheet has been approved by Admin.

        Status: Approved
        Approved by: {user}

        You can view the updated status in your dashboard.
        https://nexus.chervicaon.com
        This is an automated notification from the Timesheet & Leave Management System."""
                    
                    send_email(user_email, subject, text_content)
            flash(" Work approved successfully.")
        else:
            flash(" Failed to approve work or work not found.")
    
    except Exception as e:
        flash(f" Error approving work: {str(e)}")
    
    return redirect(url_for('dashboard'))

@app.route('/reject_work_admin', methods=['POST'])
def reject_work_admin():
    """Reject work/timesheet (Admin Manager specific)"""
    if 'username' not in session:
        return redirect(url_for('login_sso'))
    
    # Check admin privileges
    if session['role'] not in ('Admin Manager', 'Lead Staffing Specialist'):
        flash(" Access denied. Admin Manager privileges required.")
        return redirect(url_for('dashboard'))
    
    timesheet_id = request.form.get('timesheet_id')
    rejection_reason = request.form.get('rejection_reason', '').strip()
    
    if not timesheet_id:
        flash(" Timesheet ID is required.")
        return redirect(url_for('dashboard'))
    
    if not rejection_reason:
        flash(" Please provide a reason for rejection.")
        return redirect(url_for('dashboard'))
    
    user = session['username']
    team = get_all_reports_recursive(user)
    
    if not team:
        flash(" No team members found.")
        return redirect(url_for('dashboard'))
    
    placeholders = ",".join(["?"] * len(team))
    
    try:
        ok = run_exec(f"""
            UPDATE timesheets 
            SET rm_status = 'Rejected', rm_approver = ?, rm_rejection_reason = ?
            WHERE id = ? AND username IN ({placeholders}) AND rm_status = 'Pending'
        """, (user, rejection_reason, int(timesheet_id)) + tuple(team))
        
        if ok:
            # Get timesheet details for email
            timesheet_details = run_query(f"""
                SELECT t.username, t.project_name, t.work_date, t.hours, t.work_desc 
                FROM timesheets t 
                WHERE t.id = ? AND t.username IN ({placeholders})
            """, (int(timesheet_id),) + tuple(team))
            
            if not timesheet_details.empty:
                employee_username = timesheet_details.iloc[0]['username']
                
                # Send email notification
                user_email = get_user_email(employee_username)
                if user_email:
                    subject = f"Timesheet Rejected - {employee_username}"
                    text_content = f"""Dear {employee_username},

        Your timesheet has been rejected by Admin.

        Status: Rejected
        Rejection Reason: {rejection_reason}
        Rejected by: {user}

        Please contact your Admin for clarification or resubmit with corrections.
        https://nexus.chervicaon.com
        This is an automated notification from the Timesheet & Leave Management System."""
                    
                    send_email(user_email, subject, text_content)
            flash(f" Work rejected. Reason: {rejection_reason}")
        else:
            flash(" Failed to reject work or work not found.")
    
    except Exception as e:
        flash(f" Error rejecting work: {str(e)}")
    
    return redirect(url_for('dashboard'))
@app.route('/approve_leave_admin', methods=['POST'])
def approve_leave_admin():
    """Approve leave (Admin Manager specific)"""
    if 'username' not in session:
        return redirect(url_for('login_sso'))
    
    # Check admin privileges
    if session['role'] not in ('Admin Manager', 'Lead Staffing Specialist'):
        flash(" Access denied. Admin Manager privileges required.")
        return redirect(url_for('dashboard'))
    
    leave_id = request.form.get('leave_id')
    
    if not leave_id:
        flash(" Leave ID is required.")
        return redirect(url_for('dashboard'))
    
    user = session['username']
    team = get_all_reports_recursive(user)
    
    if not team:
        flash(" No team members found for approval.")
        return redirect(url_for('dashboard'))
    
    placeholders = ",".join(["?"] * len(team))
    
    try:
        # Get leave details for balance update
        leave_details = run_query(f"""
            SELECT username, leave_type, start_date, end_date 
            FROM leaves 
            WHERE id = ? AND username IN ({placeholders}) AND rm_status = 'Pending'
        """, (int(leave_id),) + tuple(team))
        
        if not leave_details.empty:
            leave_username = leave_details.iloc[0]['username']
            leave_type = str(leave_details.iloc[0]['leave_type'])
            start_date = parse(str(leave_details.iloc[0]['start_date']))
            end_date = parse(str(leave_details.iloc[0]['end_date']))
            leave_days = (end_date - start_date).days + 1
            
            # Apply leave balance deduction
            _apply_leave_balance(leave_username, leave_type, leave_days, +1)
            
            # Approve leave
            ok = run_exec(f"""
                UPDATE leaves 
                SET rm_status = 'Approved', rm_approver = ?, rm_rejection_reason = NULL
                WHERE id = ? AND username IN ({placeholders}) AND rm_status = 'Pending'
            """, (user, int(leave_id)) + tuple(team))
            
            if ok:
                # Send email notification to employee
                user_email = get_user_email(leave_username)
                if user_email:
                    subject = f"Leave Request Approved - {leave_username}"
                    text_content = f"""Dear {leave_username},

            Your leave request has been approved by Admin.

            Details:
            - Leave Type: {leave_type}
            - Start Date: {start_date.strftime('%Y-%m-%d')}
            - End Date: {end_date.strftime('%Y-%m-%d')}
            - Duration: {leave_days} days
            - Approved by: {user}

            Your leave balance has been updated accordingly. You can view the status in your dashboard.
            https://nexus.chervicaon.com
            This is an automated notification from the Timesheet & Leave Management System."""
                    
                    send_email(user_email, subject, text_content)
                flash(f" Leave approved for {leave_username} ({leave_days} days).")
            else:
                flash(" Failed to approve leave.")
        else:
            flash(" Leave not found in team or already processed.")
    
    except Exception as e:
        flash(f" Error approving leave: {str(e)}")
    
    return redirect(url_for('dashboard'))

@app.route('/reject_leave_admin', methods=['POST'])
def reject_leave_admin():
    """Reject leave (Admin Manager specific)"""
    if 'username' not in session:
        return redirect(url_for('login_sso'))
    
    # Check admin privileges
    if session['role'] not in ('Admin Manager', 'Lead Staffing Specialist'):
        flash(" Access denied. Admin Manager privileges required.")
        return redirect(url_for('dashboard'))
    
    leave_id = request.form.get('leave_id')
    rejection_reason = request.form.get('rejection_reason', '').strip()
    
    if not leave_id:
        flash(" Leave ID is required.")
        return redirect(url_for('dashboard'))
    
    if not rejection_reason:
        flash(" Please provide a reason for rejection.")
        return redirect(url_for('dashboard'))
    
    user = session['username']
    team = get_all_reports_recursive(user)
    
    if not team:
        flash(" No team members found.")
        return redirect(url_for('dashboard'))
    
    placeholders = ",".join(["?"] * len(team))
    
    try:
        ok = run_exec(f"""
            UPDATE leaves 
            SET rm_status = 'Rejected', rm_approver = ?, rm_rejection_reason = ?
            WHERE id = ? AND username IN ({placeholders}) AND rm_status = 'Pending'
        """, (user, rejection_reason, int(leave_id)) + tuple(team))
        
        if ok:
            # Get employee username for email notification
            leave_details = run_query(f"""
                SELECT username, leave_type, start_date, end_date 
                FROM leaves 
                WHERE id = ? AND username IN ({placeholders}) AND rm_status = 'Rejected'
            """, (int(leave_id),) + tuple(team))
            
            if not leave_details.empty:
                leave_username = leave_details.iloc[0]['username']
                leave_type = str(leave_details.iloc[0]['leave_type'])
                start_date = parse(str(leave_details.iloc[0]['start_date']))
                end_date = parse(str(leave_details.iloc[0]['end_date']))
                
                # Send email notification to employee
                user_email = get_user_email(leave_username)
                if user_email:
                    subject = f"Leave Request Rejected - {leave_username}"
                    text_content = f"""Dear {leave_username},

        Your leave request has been rejected by Admin.

        Details:
        - Leave Type: {leave_type}
        - Start Date: {start_date.strftime('%Y-%m-%d')}
        - End Date: {end_date.strftime('%Y-%m-%d')}
        - Rejection Reason: {rejection_reason}
        - Rejected by: {user}

        Please contact your Admin for clarification or resubmit your request with corrections.
        https://nexus.chervicaon.com
        This is an automated notification from the Timesheet & Leave Management System."""
                    
                    send_email(user_email, subject, text_content)

            flash(f" Leave rejected. Reason: {rejection_reason}")
        else:
            flash(" Failed to reject leave or leave not found.")
    
    except Exception as e:
        flash(f" Error rejecting leave: {str(e)}")
    
    return redirect(url_for('dashboard'))



@app.route('/restore_resigned_employee', methods=['POST'])
def restore_resigned_employee():
    """Restore resigned employee back to active status (Admin Manager)"""
    if 'username' not in session:
        return redirect(url_for('login_sso'))
    
    # Check admin privileges
    if session['role'] not in ('Admin Manager', 'Lead Staffing Specialist'):
        flash(" Access denied. Admin Manager privileges required.")
        return redirect(url_for('dashboard'))
    
    employee_username = request.form.get('employee_username')
    restore_reason = request.form.get('restore_reason', 'Restored by Admin')
    
    if not employee_username:
        flash(" Employee username is required.")
        return redirect(url_for('dashboard'))
    
    try:
        # Get resigned employee details
        resigned_emp = run_query("""
            SELECT username, name, role, joining_date, monthly_salary, yearly_salary,
                   employment_type, mobile_number, emergency_contact
            FROM resigned_employees
            WHERE username = ?
        """, (employee_username,))
        
        if not resigned_emp.empty:
            emp = resigned_emp.iloc[0]
            
            # Restore to users table
            ok1 = run_exec("""
                INSERT INTO [timesheet_db].[dbo].[users] (username, password, role, name, email, status, monthly_salary, yearly_salary)
                VALUES (?, 'password123', ?, ?, '', 'Active', ?, ?)
            """, (emp['username'], emp['role'], emp['name'], emp['monthly_salary'], emp['yearly_salary']))
            
            # Restore to employee_details table
            ok2 = run_exec("""
                INSERT INTO [timesheet_db].[dbo].[employee_details] (username, name, role, joining_date, employment_type, mobile_number, emergency_contact)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            """, (emp['username'], emp['name'], emp['role'], emp['joining_date'],
                  emp['employment_type'], emp['mobile_number'], emp['emergency_contact']))
            
            # Restore leave balances
            ok3 = run_exec("""
                INSERT INTO [timesheet_db].[dbo].[leave_balances] (username, total_leaves, sick_total, paid_total, casual_total, sick_used, paid_used, casual_used)
                VALUES (?, 36, 12, 18, 6, 0, 0, 0)
            """, (emp['username'],))
            
            if ok1 and ok2 and ok3:
                # Remove from resigned_employees table
                run_exec("DELETE FROM resigned_employees WHERE username = ?", (employee_username,))
                flash(f" Employee {employee_username} restored successfully.")
            else:
                flash(" Failed to restore employee.")
        else:
            flash(" Resigned employee not found.")
    
    except Exception as e:
        flash(f" Error restoring employee: {str(e)}")
    
    return redirect(url_for('dashboard'))

@app.route('/permanently_delete_resigned_employee', methods=['POST'])
def permanently_delete_resigned_employee():
    """Permanently delete resigned employee record (Admin Manager)"""
    if 'username' not in session:
        return redirect(url_for('login_sso'))
    
    # Check admin privileges
    if session['role'] not in ('Admin Manager', 'Lead Staffing Specialist'):
        flash(" Access denied. Admin Manager privileges required.")
        return redirect(url_for('dashboard'))
    
    employee_username = request.form.get('employee_username')
    deletion_reason = request.form.get('deletion_reason', 'Permanently deleted by Admin')
    
    if not employee_username:
        flash(" Employee username is required.")
        return redirect(url_for('dashboard'))
    
    try:
        ok = run_exec("DELETE FROM resigned_employees WHERE username = ?", (employee_username,))
        
        if ok:
            flash(f" Resigned employee {employee_username} permanently deleted.")
        else:
            flash(" Failed to delete resigned employee.")
    
    except Exception as e:
        flash(f" Error deleting resigned employee: {str(e)}")
    
    return redirect(url_for('dashboard'))

@app.route('/export_resigned_employees_data', methods=['POST'])
def export_resigned_employees_data():
    """Export resigned employees data (Admin Manager)"""
    if 'username' not in session:
        return redirect(url_for('login_sso'))
    
    # Check admin privileges
    if session['role'] not in ('Admin Manager', 'Lead Staffing Specialist'):
        flash(" Access denied. Admin Manager privileges required.")
        return redirect(url_for('dashboard'))
    
    export_format = request.form.get('export_format', 'csv')
    include_salary = request.form.get('include_salary') == 'on'
    
    flash(f" Resigned employees data export to {export_format.upper()} format initiated.")
    return redirect(url_for('dashboard'))

@app.route('/create_project_lead', methods=['POST'])
def create_project_lead():
    """Create project (Lead specific)"""
    if 'username' not in session:
        return redirect(url_for('login_sso'))
    
    # Check Lead privileges
    if session['role'] not in ('Lead', 'Finance Manager'):
        flash(" Access denied. Lead privileges required.")
        return redirect(url_for('dashboard'))
    
    project_name = request.form.get('project_name')
    description = request.form.get('description')
    cost_center = request.form.get('cost_center')
    start_date = request.form.get('start_date')
    end_date = request.form.get('end_date')
    budget_amount = request.form.get('budget_amount')
    
    if not all([project_name, description, cost_center, end_date]):
        flash(" All required fields must be filled.")
        return redirect(url_for('dashboard'))
    
    try:
        # Check if project name already exists
        existing = run_query("SELECT project_name FROM projects WHERE project_name = ?", (project_name,))
        if not existing.empty:
            flash(" Project name already exists. Please choose a different name.")
            return redirect(url_for('dashboard'))
        
        # Try multiple valid status values for compatibility
        valid_statuses = ['Approved', 'Active', 'Pending']
        project_created = False
        
        for status in valid_statuses:
            try:
                ok = run_exec("""
                    INSERT INTO [timesheet_db].[dbo].[projects] (project_name, description, cost_center, created_by, created_on, 
                                        end_date, budget_amount, hr_approval_status, status)
                    VALUES (?, ?, ?, ?, GETDATE(), ?, ?, 'Approved', ?)
                """, (project_name, description, cost_center, session['username'], 
                      end_date, float(budget_amount) if budget_amount else None, status))
                
                if ok:
                    project_created = True
                    break
            except Exception as e:
                print(f"Failed with status {status}: {e}")
                continue
        
        if project_created:
            flash(f" Project '{project_name}' created successfully and automatically approved.")
        else:
            flash(" Failed to create project. Please check database constraints.")
    
    except ValueError:
        flash(" Invalid budget amount.")
    except Exception as e:
        flash(f" Error creating project: {str(e)}")
    
    return redirect(url_for('dashboard'))

@app.route('/edit_project_lead', methods=['POST'])
def edit_project_lead():
    """Edit project (Lead specific)"""
    if 'username' not in session:
        return redirect(url_for('login_sso'))
    
    # Check Lead privileges
    if session['role'] not in ('Lead', 'Finance Manager'):
        flash(" Access denied. Lead privileges required.")
        return redirect(url_for('dashboard'))
    
    project_id = request.form.get('project_id')
    project_name = request.form.get('project_name')
    description = request.form.get('description')
    cost_center = request.form.get('cost_center')
    end_date = request.form.get('end_date')
    budget_amount = request.form.get('budget_amount')
    
    if not project_id or not project_name:
        flash(" Project ID and name are required.")
        return redirect(url_for('dashboard'))
    
    try:
        ok = run_exec("""
            UPDATE projects 
            SET project_name = ?, description = ?, cost_center = ?, end_date = ?, budget_amount = ?
            WHERE project_id = ?
        """, (project_name, description, cost_center, end_date, 
              float(budget_amount) if budget_amount else None, int(project_id)))
        
        if ok:
            flash(f" Project '{project_name}' updated successfully.")
        else:
            flash(" Failed to update project.")
    
    except ValueError:
        flash(" Invalid budget amount.")
    except Exception as e:
        flash(f" Error updating project: {str(e)}")
    
    return redirect(url_for('dashboard'))

@app.route('/delete_project_lead', methods=['POST'])
def delete_project_lead():
    """Delete project (Lead specific)"""
    if 'username' not in session:
        return redirect(url_for('login_sso'))
    
    # Check Lead privileges
    if session['role'] not in ('Lead', 'Finance Manager'):
        flash(" Access denied. Lead privileges required.")
        return redirect(url_for('dashboard'))
    
    project_id = request.form.get('project_id')
    project_name = request.form.get('project_name')
    
    if not project_id:
        flash(" Project ID is required.")
        return redirect(url_for('dashboard'))
    
    try:
        # Check for dependencies
        expenses_check = run_query("SELECT COUNT(*) as count FROM expenses WHERE project_name = ?", (project_name,))
        work_check = run_query("SELECT COUNT(*) as count FROM timesheets WHERE project_name = ?", (project_name,))
        
        has_expenses = not expenses_check.empty and expenses_check.iloc[0]['count'] > 0
        has_work = not work_check.empty and work_check.iloc[0]['count'] > 0
        
        if has_expenses or has_work:
            flash(f" Cannot delete project '{project_name}' - it has associated expenses or work entries.")
            return redirect(url_for('dashboard'))
        
        ok = run_exec("DELETE FROM projects WHERE project_id = ?", (int(project_id),))
        
        if ok:
            flash(f" Project '{project_name}' deleted successfully.")
        else:
            flash(" Failed to delete project.")
    
    except Exception as e:
        flash(f" Error deleting project: {str(e)}")
    
    return redirect(url_for('dashboard'))

@app.route('/approve_project_lead', methods=['POST'])
def approve_project_lead():
    """Approve project (Lead specific)"""
    if 'username' not in session:
        return redirect(url_for('login_sso'))
    
    # Check Lead privileges
    if session['role'] not in ('Lead', 'Finance Manager'):
        flash(" Access denied. Lead privileges required.")
        return redirect(url_for('dashboard'))
    
    project_id = request.form.get('project_id')
    project_name = request.form.get('project_name')
    
    if not project_id:
        flash(" Project ID is required.")
        return redirect(url_for('dashboard'))
    
    try:
        ok = run_exec("""
            UPDATE projects 
            SET hr_approval_status = 'Approved', status = 'Active'
            WHERE project_id = ?
        """, (int(project_id),))
        
        if ok:
            flash(f" Project '{project_name or project_id}' approved successfully.")
        else:
            flash(" Failed to approve project.")
    
    except Exception as e:
        flash(f" Error approving project: {str(e)}")
    
    return redirect(url_for('dashboard'))

@app.route('/reject_project_lead', methods=['POST'])
def reject_project_lead():
    """Reject project (Lead specific)"""
    if 'username' not in session:
        return redirect(url_for('login_sso'))
    
    # Check Lead privileges  
    if session['role'] not in ('Lead', 'Finance Manager'):
        flash(" Access denied. Lead privileges required.")
        return redirect(url_for('dashboard'))
    
    project_id = request.form.get('project_id')
    project_name = request.form.get('project_name')
    rejection_reason = request.form.get('rejection_reason', 'Not specified')
    
    if not project_id:
        flash(" Project ID is required.")
        return redirect(url_for('dashboard'))
    
    try:
        ok = run_exec("""
            UPDATE projects 
            SET hr_approval_status = 'Rejected', status = 'Rejected', hr_rejection_reason = ?
            WHERE project_id = ?
        """, (rejection_reason, int(project_id),))
        
        if ok:
            flash(f" Project '{project_name or project_id}' rejected. Reason: {rejection_reason}")
        else:
            flash(" Failed to reject project.")
    
    except Exception as e:
        flash(f" Error rejecting project: {str(e)}")
    
    return redirect(url_for('dashboard'))
# Add these ABSOLUTELY ULTIMATE FINAL COMPLETE missing Lead dashboard expense routes:
@app.route('/record_expense_lead', methods=['POST'])
def record_expense_lead():
    """Record expense (Lead specific) - UPDATED WITH DOCUMENT UPLOAD"""
    if 'username' not in session:
        return redirect(url_for('login_sso'))
    
    # Check Lead privileges
    if session['role'] not in ('Lead', 'Finance Manager'):
        flash(" Access denied. Lead privileges required.")
        return redirect(url_for('dashboard'))
    
    project = request.form.get('project')
    category = request.form.get('category')
    amount = request.form.get('amount')
    exp_date = request.form.get('exp_date')
    desc = request.form.get('desc')
    
    if not all([project, category, amount, desc]):
        flash(" Please fill in all required fields.")
        return redirect(url_for('dashboard'))
    
    # Handle document upload
    document_path = None
    if 'expense_document' in request.files:
        file = request.files['expense_document']
        if file.filename != '':
            document_path = save_uploaded_file(file, "lead_expense")
    
    try:
        ok = run_exec("""
            INSERT INTO [timesheet_db].[dbo].[expenses] 
            (project_name, category, amount, date, description, spent_by, document_path)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        """, (project, category, float(amount), exp_date, desc, session['username'], document_path))
        
        if ok:
            flash(f" Expense of ₹{float(amount):,.2f} recorded for project '{project}'.")
        else:
            flash(" Failed to record expense.")
    
    except ValueError:
        flash(" Invalid amount format.")
    except Exception as e:
        flash(f" Error recording expense: {str(e)}")
    
    return redirect(url_for('dashboard'))

@app.route('/edit_expense_lead', methods=['POST'])
def edit_expense_lead():
    """Edit expense (Lead specific)"""
    if 'username' not in session:
        return redirect(url_for('login_sso'))
    
    # Check Lead privileges
    if session['role'] not in ('Lead', 'Finance Manager'):
        flash(" Access denied. Lead privileges required.")
        return redirect(url_for('dashboard'))
    
    expense_id = request.form.get('expense_id')
    project_name = request.form.get('project_name')
    category = request.form.get('category')
    amount = request.form.get('amount')
    description = request.form.get('description')
    expense_date = request.form.get('expense_date')
    
    if not all([expense_id, project_name, category, amount, description]):
        flash(" All fields are required.")
        return redirect(url_for('dashboard'))
    
    try:
        ok = run_exec("""
            UPDATE expenses 
            SET project_name = ?, category = ?, amount = ?, description = ?, date = ?
            WHERE id = ?
        """, (project_name, category, float(amount), description, expense_date, int(expense_id)))
        
        if ok:
            flash(f" Expense updated: ₹{float(amount):,.2f} for {project_name}.")
        else:
            flash(" Failed to update expense.")
    
    except ValueError:
        flash(" Invalid amount format.")
    except Exception as e:
        flash(f" Error updating expense: {str(e)}")
    
    return redirect(url_for('dashboard'))

@app.route('/delete_expense_lead', methods=['POST'])
def delete_expense_lead():
    """Delete expense (Lead specific)"""
    if 'username' not in session:
        return redirect(url_for('login_sso'))
    
    # Check Lead privileges
    if session['role'] not in ('Lead', 'Finance Manager'):
        flash(" Access denied. Lead privileges required.")
        return redirect(url_for('dashboard'))
    
    expense_id = request.form.get('expense_id')
    
    if not expense_id:
        flash(" Expense ID is required.")
        return redirect(url_for('dashboard'))
    
    try:
        # Get expense details for confirmation
        expense_details = run_query("""
            SELECT project_name, amount, spent_by FROM expenses WHERE id = ?
        """, (int(expense_id),))
        
        if not expense_details.empty:
            expense = expense_details.iloc[0]
            ok = run_exec("DELETE FROM expenses WHERE id = ?", (int(expense_id),))
            
            if ok:
                flash(f" Expense deleted: ₹{expense['amount']} from {expense['project_name']} (by {expense['spent_by']}).")
            else:
                flash(" Failed to delete expense.")
        else:
            flash(" Expense not found.")
    
    except Exception as e:
        flash(f" Error deleting expense: {str(e)}")
    
    return redirect(url_for('dashboard'))

@app.route('/approve_expense_lead', methods=['POST'])
def approve_expense_lead():
    """Approve expense (Lead specific)"""
    if 'username' not in session:
        return redirect(url_for('login_sso'))
    
    # Check Lead privileges
    if session['role'] not in ('Lead', 'Finance Manager'):
        flash(" Access denied. Lead privileges required.")
        return redirect(url_for('dashboard'))
    
    expense_id = request.form.get('expense_id')
    
    if not expense_id:
        flash(" Expense ID is required.")
        return redirect(url_for('dashboard'))
    
    try:
        ok = run_exec("""
            UPDATE expenses 
            SET status = 'Approved', approved_by = ?, approved_date = GETDATE()
            WHERE id = ?
        """, (session['username'], int(expense_id)))
        
        if ok:
            flash(" Expense approved successfully.")
        else:
            flash(" Failed to approve expense.")
    
    except Exception as e:
        flash(f" Error approving expense: {str(e)}")
    
    return redirect(url_for('dashboard'))

@app.route('/reject_expense_lead', methods=['POST'])
def reject_expense_lead():
    """Reject expense (Lead specific)"""
    if 'username' not in session:
        return redirect(url_for('login_sso'))
    
    # Check Lead privileges
    if session['role'] not in ('Lead', 'Finance Manager'):
        flash(" Access denied. Lead privileges required.")
        return redirect(url_for('dashboard'))
    
    expense_id = request.form.get('expense_id')
    rejection_reason = request.form.get('rejection_reason', 'Not specified')
    
    if not expense_id:
        flash(" Expense ID is required.")
        return redirect(url_for('dashboard'))
    
    try:
        ok = run_exec("""
            UPDATE expenses 
            SET status = 'Rejected', approved_by = ?, approved_date = GETDATE(), rejection_reason = ?
            WHERE id = ?
        """, (session['username'], rejection_reason, int(expense_id)))
        
        if ok:
            flash(f" Expense rejected. Reason: {rejection_reason}")
        else:
            flash(" Failed to reject expense.")
    
    except Exception as e:
        flash(f" Error rejecting expense: {str(e)}")
    
    return redirect(url_for('dashboard'))
@app.route('/delete_project_company', methods=['POST'])
def delete_project_company():
    """Delete project - Role-based access"""
    if 'username' not in session:
        flash("Access denied.")
        return redirect(url_for('dashboard'))
    
    user = session['username']
    
    # Check if user has company-wide access
    if not has_company_access(user): # type: ignore
        flash("Access denied. Company-level permissions required.")
        return redirect(url_for('dashboard'))
    
    project_id = request.form.get('project_id')
    
    if not project_id:
        flash("Project ID is required.")
        return redirect(url_for('dashboard'))
    
    try:
        ok = run_exec("DELETE FROM projects WHERE project_id = ?", (int(project_id),))
        
        if ok:
            flash(" Project deleted successfully.")
        else:
            flash(" Failed to delete project.")
    
    except Exception as e:
        flash(f" Error deleting project: {str(e)}")
    
    return redirect(url_for('dashboard'))

@app.route('/edit_project_company', methods=['POST'])
def edit_project_company():
    """Edit project - Role-based access"""
    if 'username' not in session:
        flash("Access denied.")
        return redirect(url_for('dashboard'))
    
    user = session['username']
    
    # Check if user has company-wide access
    if not has_company_access(user): # type: ignore
        flash("Access denied. Company-level permissions required.")
        return redirect(url_for('dashboard'))
    
    project_id = request.form.get('project_id')
    project_name = request.form.get('project_name', '').strip()
    description = request.form.get('description', '').strip()
    cost_center = request.form.get('cost_center', '').strip()
    budget_amount = request.form.get('budget_amount', '').strip()
    
    if not project_id or not project_name or not description:
        flash(" Project ID, name and description are required.")
        return redirect(url_for('dashboard'))
    
    try:
        # Convert budget amount
        budget_val = float(budget_amount) if budget_amount else None
        
        ok = run_exec("""
            UPDATE projects 
            SET project_name = ?, description = ?, cost_center = ?, budget_amount = ?
            WHERE project_id = ?
        """, (project_name, description, cost_center, budget_val, int(project_id)))
        
        if ok:
            flash(f" Project '{project_name}' updated successfully.")
        else:
            flash(" Failed to update project.")
    
    except Exception as e:
        flash(f" Error updating project: {str(e)}")
    
    return redirect(url_for('dashboard'))

@app.route('/update_assignment_status', methods=['POST'])
def update_assignment_status():
    assignment_id = request.form.get('assignment_id')
    status = request.form.get('status')
    
    try:
        cursor = conn.cursor() # type: ignore
        cursor.execute("""
            UPDATE work_assignments 
            SET rm_status = ? 
            WHERE id = ?
        """, (status, assignment_id))
        conn.commit() # type: ignore
        cursor.close()
        
        flash(f'Assignment status updated to {status}', 'success')
    except Exception as e:
        flash(f'Error updating assignment status: {str(e)}', 'error')
    
    return redirect(request.referrer or url_for('dashboard'))
# lead route
@app.route('/assign_work_lead', methods=['POST'])
def assign_work_lead():
    """Lead assigns work to any employee"""
    if 'username' not in session or session.get('role') != 'Lead':
        flash('Access denied. Lead privileges required.', 'error')
        return redirect(url_for('login'))
    
    user = session['username']
    assigned_to_list = request.form.getlist('assigned_to')  # Support multiple selection
    project_name = request.form.get('project_name')
    task_desc = request.form.get('task_desc', '').strip()
    due_date = request.form.get('due_date')
    
    
    if not assigned_to_list or not task_desc:
        flash('Please select at least one employee and provide task description.', 'error')
        return redirect(url_for('dashboard') + '?tab=work-assignments')
    
    success_count = 0
    failed_employees = []
    
    for assigned_to in assigned_to_list:
        try:
            # Use the SAME table name as other views (without schema prefix)
            ok = run_exec("""
                INSERT INTO [timesheet_db].[dbo].[assigned_work] 
                (assigned_by, assigned_to, project_name, task_desc, start_date, due_date, assigned_on, rm_status, manager_status, work_type) 
                VALUES (?, ?, ?, ?, ?, ?, GETDATE(), 'Pending', 'Approved', 'Task Assignment')
            """, (user, assigned_to, project_name or None, task_desc, date.today(), due_date))
            
            if ok:
                success_count += 1
                # Send email notification
                emp_email = get_user_email(assigned_to)
                if emp_email:
                    subject = f"New Work Assignment - {assigned_to}"
                    text_content = f"""Dear {assigned_to},

You have been assigned new work by Lead {user}.

Assignment Details:
- Assigned by: {user}
- Project: {project_name or 'General Task'}
- Task: {task_desc}
- Due Date: {due_date}


Please log in to your dashboard to view the complete assignment details.
https://nexus.chervicaon.com
This is an automated notification from the Timesheet & Leave Management System."""
                    
                    send_email(emp_email, subject, text_content)
            else:
                failed_employees.append(assigned_to)
                
        except Exception as e:
            print(f"Error assigning work to {assigned_to}: {e}")
            failed_employees.append(assigned_to)
    
    # Success/failure messages
    if success_count > 0:
        successful_employees = [emp for emp in assigned_to_list if emp not in failed_employees]
        flash(f'Work successfully assigned to {success_count} employee(s): {", ".join(successful_employees)}', 'success')
        
    if failed_employees:
        flash(f'Failed to assign work to: {", ".join(failed_employees)}', 'error')
    
    return redirect(url_for('dashboard') + '?tab=work-assignments')


# Add this route anywhere in your app.py file (around line 11000+)
@app.route('/uploads/<filename>')
def uploaded_file(filename):
    """Serve uploaded files"""
    try:
        return send_from_directory(app.config['UPLOAD_FOLDER'], filename)
    except Exception as e:
        print(f"Error serving file {filename}: {e}")
        return '', 404
    
    # --------------------
# Add this function to create missing database columns:
def ensure_cancellation_columns():
    """Ensure leave cancellation columns exist in the database"""
    try:
        # Check if columns exist and add them if they don't
        run_exec("""
            IF NOT EXISTS (SELECT * FROM sys.columns WHERE object_id = OBJECT_ID('leaves') AND name = 'cancellation_approver')
            ALTER TABLE leaves ADD cancellation_approver NVARCHAR(100)
        """)
        
        run_exec("""
            IF NOT EXISTS (SELECT * FROM sys.columns WHERE object_id = OBJECT_ID('leaves') AND name = 'cancellation_rejection_reason')
            ALTER TABLE leaves ADD cancellation_rejection_reason NVARCHAR(500)
        """)
        
        print(" Database columns verified/created successfully")
    except Exception as e:
        print(f" Database column creation error: {e}")

# Call this function when the app starts:
# Add this line near the end of the file, before the if _name_ == '_main_': block
ensure_cancellation_columns()

def ensure_database_columns():
    """Ensure all required database columns exist"""
    try:
        # Add approver column to timesheets table
        run_exec("""
            IF NOT EXISTS (SELECT * FROM sys.columns WHERE object_id = OBJECT_ID('timesheets') AND name = 'approver')
            ALTER TABLE timesheets ADD approver NVARCHAR(100)
        """)
        
        # Add approver column to leaves table  
        run_exec("""
            IF NOT EXISTS (SELECT * FROM sys.columns WHERE object_id = OBJECT_ID('leaves') AND name = 'approver')
            ALTER TABLE leaves ADD approver NVARCHAR(100)
        """)
        
        # Add cancellation columns to leaves table
        run_exec("""
            IF NOT EXISTS (SELECT * FROM sys.columns WHERE object_id = OBJECT_ID('leaves') AND name = 'cancellation_approver')
            ALTER TABLE leaves ADD cancellation_approver NVARCHAR(100)
        """)
        
        run_exec("""
            IF NOT EXISTS (SELECT * FROM sys.columns WHERE object_id = OBJECT_ID('leaves') AND name = 'cancellation_rejection_reason')
            ALTER TABLE leaves ADD cancellation_rejection_reason NVARCHAR(500)
        """)
        
        # Update existing records to set approver based on reporting manager
        run_exec("""
            UPDATE t SET t.approver = r.rm
            FROM timesheets t
            INNER JOIN report r ON t.username = r.username
            WHERE t.approver IS NULL
        """)
        
        run_exec("""
            UPDATE l SET l.approver = r.rm
            FROM leaves l
            INNER JOIN report r ON l.username = r.username
            WHERE l.approver IS NULL
        """)
        
        print(" All database columns created/updated successfully")
        
    except Exception as e:
        print(f" Database schema update error: {e}")

# Add this function call when the app starts
def initialize_database():
    """Initialize database with proper schema"""
    ensure_database_columns()
    ensure_cancellation_columns()  # From previous fix   
def make_serializable(obj):
    """Convert numpy types to Python native types for JSON serialization"""
    if isinstance(obj, np.integer):
        return int(obj)
    elif isinstance(obj, np.floating):
        return float(obj)
    elif isinstance(obj, np.ndarray):
        return obj.tolist()
    elif isinstance(obj, dict):
        return {key: make_serializable(value) for key, value in obj.items()}
    elif isinstance(obj, list):
        return [make_serializable(item) for item in obj]
    return obj
# ADD THE DEBUG FUNCTION HERE:
def debug_reporting_structure(username):
    """Debug function to check reporting relationships"""
    print(f"\n=== DEBUG REPORTING STRUCTURE for {username} ===")
    
    # Check direct reports
    direct_reports = run_query("SELECT username, rm, manager FROM report WHERE rm = ?", (username,))
    print(f"Direct reports: {direct_reports.to_dict('records') if not direct_reports.empty else 'None'}")
    
    # Check all report table entries
    all_reports = run_query("SELECT username, rm, manager FROM report ORDER BY rm")
    print(f"All reporting relationships: {all_reports.to_dict('records') if not all_reports.empty else 'None'}")
    
    # Check users table
    users = run_query("SELECT username, role FROM users WHERE status = 'Active' ORDER BY username")
    print(f"Active users: {users.to_dict('records') if not users.empty else 'None'}")
    
    print("=== END DEBUG ===\n")
if __name__ == '__main__':
    flask_port = int(os.getenv('FLASK_PORT', '8084'))
    flask_host = os.getenv('FLASK_HOST', '0.0.0.0')
    
    print(f" Starting Flask app with SocketIO on {flask_host}:{flask_port}...")
    print(f" Redirect URI: {REDIRECT_URI}")
    print(f" Client ID: {CLIENT_ID[:10] if CLIENT_ID else 'NOT SET'}...")
    print(f" Email configured: {'Yes' if os.getenv('SMTP_USER') else 'No'}")
    print(f" Database: {SQL_SERVER}/{SQL_DATABASE}")
    
    # Initialize database and run with SocketIO
    initialize_database()
    socketio.run(app, debug=app.debug, port=flask_port, host=flask_host, allow_unsafe_werkzeug=True)
    
