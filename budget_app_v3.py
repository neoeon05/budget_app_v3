import streamlit as st
import pandas as pd
import sqlite3
from datetime import date, datetime, timedelta
import hashlib
import secrets
import json
import io
import shutil
import os
from pathlib import Path

# --- MUST BE THE VERY FIRST STREAMLIT COMMAND ---
st.set_page_config(page_title="Receipt & Expenditure Tracker", layout="wide", page_icon="💰")

# Try to import optional dependencies
try:
    import plotly.express as px
    import plotly.graph_objects as go
    PLOTLY_AVAILABLE = True
except ImportError:
    PLOTLY_AVAILABLE = False

try:
    from reportlab.lib.pagesizes import letter, A4
    from reportlab.lib import colors
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer
    from reportlab.lib.units import inch
    REPORTLAB_AVAILABLE = True
except ImportError:
    REPORTLAB_AVAILABLE = False

# ---------------- CONFIG ----------------

DB_FILE = "transactions.db"
BACKUP_DIR = "backups"
# Updated to 10 heads
HEADS = ["Head 1", "Head 2", "Head 3", "Head 4", "Head 5", "Head 6", "Head 7", "Head 8", "Head 9", "Head 10"]

# Create backup directory safely
os.makedirs(BACKUP_DIR, exist_ok=True)

# ---------------- SECURITY FUNCTIONS ----------------
def hash_password(password, salt=None):
    """Hash password with salt using SHA-256"""
    if salt is None:
        salt = secrets.token_hex(16)
    pwd_hash = hashlib.sha256((password + salt).encode()).hexdigest()
    return pwd_hash, salt

def verify_password(password, stored_hash, salt):
    """Verify password against stored hash"""
    pwd_hash, _ = hash_password(password, salt)
    return pwd_hash == stored_hash

# ---------------- DATABASE ----------------
def get_connection():
    return sqlite3.connect(DB_FILE, check_same_thread=False)

def create_tables():
    conn = get_connection()
    
    # Users table
    conn.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            salt TEXT NOT NULL,
            full_name TEXT,
            email TEXT,
            role TEXT DEFAULT 'user',
            created_at TEXT DEFAULT CURRENT_TIMESTAMP,
            last_login TEXT
        )
    """)
    
    # Transactions table with audit fields
    conn.execute("""
        CREATE TABLE IF NOT EXISTS transactions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            date TEXT,
            amount REAL,
            purpose TEXT,
            head TEXT,
            type TEXT,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP,
            created_by INTEGER,
            modified_at TEXT,
            modified_by INTEGER,
            FOREIGN KEY (user_id) REFERENCES users (id),
            FOREIGN KEY (created_by) REFERENCES users (id),
            FOREIGN KEY (modified_by) REFERENCES users (id)
        )
    """)
    
    # Audit trail table
    conn.execute("""
        CREATE TABLE IF NOT EXISTS audit_trail (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            transaction_id INTEGER,
            user_id INTEGER,
            action TEXT,
            old_data TEXT,
            new_data TEXT,
            timestamp TEXT DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (transaction_id) REFERENCES transactions (id),
            FOREIGN KEY (user_id) REFERENCES users (id)
        )
    """)
    
    # Budget limits table
    conn.execute("""
        CREATE TABLE IF NOT EXISTS budget_limits (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            head TEXT,
            monthly_limit REAL,
            yearly_limit REAL,
            alert_threshold REAL DEFAULT 80.0,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users (id),
            UNIQUE(user_id, head)
        )
    """)
    
    # Saved filter presets table
    conn.execute("""
        CREATE TABLE IF NOT EXISTS filter_presets (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            preset_name TEXT,
            filter_config TEXT,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users (id)
        )
    """)
    
    # NEW: Head names table to store custom names for each head
    conn.execute("""
        CREATE TABLE IF NOT EXISTS head_names (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            head_id TEXT NOT NULL,
            head_name TEXT NOT NULL,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP,
            updated_at TEXT DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users (id),
            UNIQUE(user_id, head_id)
        )
    """)
    
    conn.commit()
    
    # Create default admin user if no users exist
    cursor = conn.execute("SELECT COUNT(*) FROM users")
    if cursor.fetchone()[0] == 0:
        pwd_hash, salt = hash_password("admin123")
        conn.execute(
            "INSERT INTO users (username, password_hash, salt, full_name, role) VALUES (?, ?, ?, ?, ?)",
            ("admin", pwd_hash, salt, "Administrator", "admin")
        )
        conn.commit()
    
    conn.close()

def backup_database():
    """Create a backup of the database"""
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    backup_file = os.path.join(BACKUP_DIR, f"transactions_backup_{timestamp}.db")
    shutil.copy2(DB_FILE, backup_file)
    return backup_file

def authenticate_user(username, password):
    """Authenticate user and return user data if successful"""
    conn = get_connection()
    cursor = conn.execute(
        "SELECT id, username, password_hash, salt, full_name, role FROM users WHERE username = ?",
        (username,)
    )
    user = cursor.fetchone()
    conn.close()
    
    if user and verify_password(password, user[2], user[3]):
        return {
            'id': user[0],
            'username': user[1],
            'full_name': user[4],
            'role': user[5]
        }
    return None

def update_last_login(user_id):
    """Update last login timestamp"""
    conn = get_connection()
    conn.execute(
        "UPDATE users SET last_login = ? WHERE id = ?",
        (datetime.now().isoformat(), user_id)
    )
    conn.commit()
    conn.close()

def create_user(username, password, full_name, email, role='user'):
    """Create a new user"""
    conn = get_connection()
    try:
        pwd_hash, salt = hash_password(password)
        conn.execute(
            "INSERT INTO users (username, password_hash, salt, full_name, email, role) VALUES (?, ?, ?, ?, ?, ?)",
            (username, pwd_hash, salt, full_name, email, role)
        )
        conn.commit()
        conn.close()
        return True, "User created successfully"
    except sqlite3.IntegrityError:
        conn.close()
        return False, "Username already exists"

def delete_user(user_id):
    """Delete a user and all their data"""
    conn = get_connection()
    conn.execute("DELETE FROM transactions WHERE user_id = ?", (user_id,))
    conn.execute("DELETE FROM audit_trail WHERE user_id = ?", (user_id,))
    conn.execute("DELETE FROM budget_limits WHERE user_id = ?", (user_id,))
    conn.execute("DELETE FROM filter_presets WHERE user_id = ?", (user_id,))
    conn.execute("DELETE FROM head_names WHERE user_id = ?", (user_id,))
    conn.execute("DELETE FROM users WHERE id = ?", (user_id,))
    conn.commit()
    conn.close()

def change_password(user_id, new_password):
    """Change user password"""
    conn = get_connection()
    pwd_hash, salt = hash_password(new_password)
    conn.execute(
        "UPDATE users SET password_hash = ?, salt = ? WHERE id = ?",
        (pwd_hash, salt, user_id)
    )
    conn.commit()
    conn.close()

def load_all_users():
    """Load all users (admin only)"""
    conn = get_connection()
    df = pd.read_sql_query(
        "SELECT id, username, full_name, email, role, created_at, last_login FROM users ORDER BY created_at DESC",
        conn
    )
    conn.close()
    return df

# ---------------- HEAD NAMES FUNCTIONS ----------------
def get_head_names(user_id):
    """Get custom head names for a user"""
    conn = get_connection()
    cursor = conn.execute(
        "SELECT head_id, head_name FROM head_names WHERE user_id = ?",
        (user_id,)
    )
    head_names = {}
    for row in cursor.fetchall():
        head_names[row[0]] = row[1]
    conn.close()
    
    # Return default names for heads that haven't been customized
    result = {}
    for head in HEADS:
        result[head] = head_names.get(head, head)
    
    return result

def update_head_name(user_id, head_id, head_name):
    """Update custom name for a head"""
    conn = get_connection()
    try:
        conn.execute(
            """INSERT INTO head_names (user_id, head_id, head_name, updated_at) 
               VALUES (?, ?, ?, ?) 
               ON CONFLICT(user_id, head_id) 
               DO UPDATE SET head_name = ?, updated_at = ?""",
            (user_id, head_id, head_name, datetime.now().isoformat(), 
             head_name, datetime.now().isoformat())
        )
        conn.commit()
        conn.close()
        return True
    except Exception as e:
        conn.close()
        return False

# ---------------- TRANSACTION FUNCTIONS ----------------
def load_data(user_id, is_admin=False):
    """Load transactions"""
    conn = get_connection()
    if is_admin:
        query = """
            SELECT t.*, u.username 
            FROM transactions t
            LEFT JOIN users u ON t.user_id = u.id
            ORDER BY t.date DESC
        """
        df = pd.read_sql_query(query, conn)
    else:
        df = pd.read_sql_query(
            "SELECT * FROM transactions WHERE user_id = ? ORDER BY date DESC",
            conn,
            params=(user_id,)
        )
    conn.close()
    return df

def insert_record(user_id, record, created_by):
    """Insert a new transaction"""
    conn = get_connection()
    cursor = conn.execute(
        """INSERT INTO transactions (user_id, date, amount, purpose, head, type, created_by) 
           VALUES (?, ?, ?, ?, ?, ?, ?)""",
        (user_id, *record, created_by)
    )
    transaction_id = cursor.lastrowid
    
    # Audit trail
    log_audit(transaction_id, user_id, "CREATE", None, {
        'date': record[0], 'amount': record[1], 'purpose': record[2],
        'head': record[3], 'type': record[4]
    }, conn=conn)
    
    conn.commit()
    conn.close()

def update_record(transaction_id, user_id, old_data, new_data, modified_by):
    """Update a transaction"""
    conn = get_connection()
    conn.execute(
        """UPDATE transactions 
           SET date=?, amount=?, purpose=?, head=?, type=?, modified_at=?, modified_by=?
           WHERE id=?""",
        (new_data[0], new_data[1], new_data[2], new_data[3], new_data[4],
         datetime.now().isoformat(), modified_by, transaction_id)
    )
    
    # Audit trail
    log_audit(transaction_id, user_id, "UPDATE", old_data, new_data, conn=conn)
    
    conn.commit()
    conn.close()

def delete_record(transaction_id, user_id, record_data):
    """Delete a transaction"""
    conn = get_connection()
    conn.execute("DELETE FROM transactions WHERE id = ?", (transaction_id,))
    
    # Audit trail
    log_audit(transaction_id, user_id, "DELETE", record_data, None, conn=conn)
    
    conn.commit()
    conn.close()

def log_audit(transaction_id, user_id, action, old_data, new_data, conn=None):
    """Log an audit trail entry. Accepts an existing connection to avoid locking."""
    close_after = False
    if conn is None:
        conn = get_connection()
        close_after = True
    conn.execute(
        """INSERT INTO audit_trail (transaction_id, user_id, action, old_data, new_data)
           VALUES (?, ?, ?, ?, ?)""",
        (transaction_id, user_id, action,
         json.dumps(old_data) if old_data else None,
         json.dumps(new_data) if new_data else None)
    )
    if close_after:
        conn.commit()
        conn.close()

def get_audit_trail(user_id=None, limit=100):
    """Get audit trail records"""
    conn = get_connection()
    if user_id:
        query = """
            SELECT a.*, u.username, t.purpose
            FROM audit_trail a
            LEFT JOIN users u ON a.user_id = u.id
            LEFT JOIN transactions t ON a.transaction_id = t.id
            WHERE a.user_id = ?
            ORDER BY a.timestamp DESC
            LIMIT ?
        """
        df = pd.read_sql_query(query, conn, params=(user_id, limit))
    else:
        query = """
            SELECT a.*, u.username, t.purpose
            FROM audit_trail a
            LEFT JOIN users u ON a.user_id = u.id
            LEFT JOIN transactions t ON a.transaction_id = t.id
            ORDER BY a.timestamp DESC
            LIMIT ?
        """
        df = pd.read_sql_query(query, conn, params=(limit,))
    conn.close()
    return df

# ---------------- BUDGET LIMITS ----------------
def get_budget_limits(user_id):
    """Get budget limits for user"""
    conn = get_connection()
    df = pd.read_sql_query(
        "SELECT * FROM budget_limits WHERE user_id = ?",
        conn,
        params=(user_id,)
    )
    conn.close()
    return df

def set_budget_limit(user_id, head, monthly_limit, yearly_limit, alert_threshold):
    """Set or update budget limit"""
    conn = get_connection()
    try:
        conn.execute(
            """INSERT INTO budget_limits (user_id, head, monthly_limit, yearly_limit, alert_threshold)
               VALUES (?, ?, ?, ?, ?)
               ON CONFLICT(user_id, head)
               DO UPDATE SET monthly_limit=?, yearly_limit=?, alert_threshold=?""",
            (user_id, head, monthly_limit, yearly_limit, alert_threshold,
             monthly_limit, yearly_limit, alert_threshold)
        )
        conn.commit()
        conn.close()
        return True
    except Exception as e:
        conn.close()
        return False

def check_budget_alerts(user_id, df):
    """Check if any budget limits are exceeded"""
    alerts = []
    limits_df = get_budget_limits(user_id)
    
    if limits_df.empty:
        return alerts
    
    current_month = datetime.now().strftime("%Y-%m")
    current_year = datetime.now().year
    
    for _, limit in limits_df.iterrows():
        head = limit['head']
        head_df = df[df['head'] == head]
        
        # Monthly check
        if limit['monthly_limit'] and limit['monthly_limit'] > 0:
            month_exp = head_df[
                (head_df['type'] == 'expenditure') & 
                (head_df['date'].str.startswith(current_month))
            ]['amount'].sum()
            
            usage_pct = (month_exp / limit['monthly_limit']) * 100
            if usage_pct >= limit['alert_threshold']:
                alerts.append({
                    'head': head,
                    'period': 'Monthly',
                    'usage': month_exp,
                    'limit': limit['monthly_limit'],
                    'percentage': usage_pct
                })
        
        # Yearly check
        if limit['yearly_limit'] and limit['yearly_limit'] > 0:
            year_exp = head_df[
                (head_df['type'] == 'expenditure') & 
                (pd.to_datetime(head_df['date']).dt.year == current_year)
            ]['amount'].sum()
            
            usage_pct = (year_exp / limit['yearly_limit']) * 100
            if usage_pct >= limit['alert_threshold']:
                alerts.append({
                    'head': head,
                    'period': 'Yearly',
                    'usage': year_exp,
                    'limit': limit['yearly_limit'],
                    'percentage': usage_pct
                })
    
    return alerts

# ---------------- FILTER PRESETS ----------------
def save_filter_preset(user_id, preset_name, filter_config):
    """Save a filter preset"""
    conn = get_connection()
    try:
        conn.execute(
            "INSERT INTO filter_presets (user_id, preset_name, filter_config) VALUES (?, ?, ?)",
            (user_id, preset_name, json.dumps(filter_config))
        )
        conn.commit()
        conn.close()
        return True
    except Exception:
        conn.close()
        return False

def load_filter_presets(user_id):
    """Load all filter presets for user"""
    conn = get_connection()
    df = pd.read_sql_query(
        "SELECT * FROM filter_presets WHERE user_id = ? ORDER BY created_at DESC",
        conn,
        params=(user_id,)
    )
    conn.close()
    return df

def delete_filter_preset(preset_id):
    """Delete a filter preset"""
    conn = get_connection()
    conn.execute("DELETE FROM filter_presets WHERE id = ?", (preset_id,))
    conn.commit()
    conn.close()

# ---------------- ANALYTICS FUNCTIONS ----------------
def get_monthly_summary(df):
    """Get monthly summary of receipts and expenditure"""
    if df.empty:
        return pd.DataFrame()
    
    df_copy = df.copy()
    df_copy['date'] = pd.to_datetime(df_copy['date'])
    df_copy['month'] = df_copy['date'].dt.to_period('M')
    
    summary = df_copy.groupby(['month', 'type'])['amount'].sum().unstack(fill_value=0)
    summary = summary.reset_index()
    summary['month'] = summary['month'].astype(str)
    
    if 'receipt' not in summary.columns:
        summary['receipt'] = 0
    if 'expenditure' not in summary.columns:
        summary['expenditure'] = 0
    
    summary['net'] = summary['receipt'] - summary['expenditure']
    
    return summary

def get_head_wise_summary(df):
    """Get summary by head"""
    if df.empty:
        return pd.DataFrame()
    
    summary = df.groupby(['head', 'type'])['amount'].sum().unstack(fill_value=0)
    summary = summary.reset_index()
    
    if 'receipt' not in summary.columns:
        summary['receipt'] = 0
    if 'expenditure' not in summary.columns:
        summary['expenditure'] = 0
    
    summary['net'] = summary['receipt'] - summary['expenditure']
    
    return summary

def forecast_trend(df, months=3, forecast_periods=3):
    """Simple linear forecast based on historical data"""
    if df.empty or len(df) < months:
        return None
    
    df_copy = df.copy()
    df_copy['date'] = pd.to_datetime(df_copy['date'])
    
    # Get last N months of data
    cutoff_date = datetime.now() - timedelta(days=months*30)
    recent_df = df_copy[df_copy['date'] >= cutoff_date]
    
    # Group by month
    recent_df['month'] = recent_df['date'].dt.to_period('M')
    monthly = recent_df.groupby(['month', 'type'])['amount'].sum().unstack(fill_value=0)
    
    if 'expenditure' not in monthly.columns:
        return None
    
    # Simple linear regression (average)
    avg_exp = monthly['expenditure'].mean()
    
    # Generate forecast
    last_month = monthly.index[-1]
    forecast_months = []
    forecast_values = []
    
    for i in range(1, forecast_periods + 1):
        next_month = last_month + i
        forecast_months.append(str(next_month))
        forecast_values.append(avg_exp)
    
    return pd.DataFrame({
        'month': forecast_months,
        'forecast': forecast_values
    })

# ---------------- LOGIN PAGE ----------------
def login_page():
    st.title("🔐 Login")
    
    tab1, tab2 = st.tabs(["Login", "Register"])
    
    with tab1:
        with st.form("login_form"):
            username = st.text_input("Username")
            password = st.text_input("Password", type="password")
            login_btn = st.form_submit_button("Login")
            
            if login_btn:
                user = authenticate_user(username, password)
                if user:
                    st.session_state.logged_in = True
                    st.session_state.user = user
                    update_last_login(user['id'])
                    st.success(f"Welcome, {user['full_name']}!")
                    st.rerun()
                else:
                    st.error("Invalid username or password")
    
    with tab2:
        with st.form("register_form"):
            reg_username = st.text_input("Username")
            reg_password = st.text_input("Password", type="password")
            reg_confirm_pwd = st.text_input("Confirm Password", type="password")
            reg_full_name = st.text_input("Full Name")
            reg_email = st.text_input("Email")
            register_btn = st.form_submit_button("Register")
            
            if register_btn:
                if not all([reg_username, reg_password, reg_full_name]):
                    st.error("Please fill all required fields")
                elif reg_password != reg_confirm_pwd:
                    st.error("Passwords do not match")
                elif len(reg_password) < 6:
                    st.error("Password must be at least 6 characters")
                else:
                    success, message = create_user(reg_username, reg_password, reg_full_name, reg_email)
                    if success:
                        st.success(message + " - Please login")
                    else:
                        st.error(message)

# ---------------- MAIN APP ----------------
def main_app():
    # Initialize session state for success messages
    if 'success_message' not in st.session_state:
        st.session_state.success_message = None
    
    # Check if user is admin
    is_admin = st.session_state.user['role'] == 'admin'
    
    # Sidebar
    with st.sidebar:
        st.title(f"👋 {st.session_state.user['full_name']}")
        st.caption(f"Role: {st.session_state.user['role'].title()}")
        
        # Menu
        menu_items = [
            "📊 Dashboard",
            "➕ Add Record",
            "📋 View/Edit/Delete",
            "📈 Advanced Analytics",
            "🎯 Budget Limits",
            "💾 Data Management",
            "🏷️ Manage Head Names",  # NEW
            "🔍 Audit Trail",
            "👤 Profile"
        ]
        
        if is_admin:
            menu_items.append("👥 User Management")
        
        menu = st.radio("Navigation", menu_items)
        
        st.divider()
        
        # Quick stats
        user_df = load_data(st.session_state.user['id'], is_admin=False)
        st.metric("Total Transactions", len(user_df))
        
        if not user_df.empty:
            total_receipts = user_df[user_df['type']=='receipt']['amount'].sum()
            total_exp = user_df[user_df['type']=='expenditure']['amount'].sum()
            st.metric("Net Balance", f"₹{total_receipts - total_exp:,.2f}")
        
        st.divider()
        
        # Download data
        if not user_df.empty:
            csv = user_df.to_csv(index=False)
            st.download_button(
                "📥 Download Data (CSV)",
                csv,
                f"transactions_{datetime.now().strftime('%Y%m%d')}.csv",
                "text/csv"
            )
        
        if st.button("🚪 Logout"):
            st.session_state.logged_in = False
            st.session_state.user = None
            st.rerun()
    
    # Display success message if any
    if st.session_state.success_message:
        st.success(st.session_state.success_message)
        st.session_state.success_message = None
    
    # ---------------- DASHBOARD ----------------
    if menu == "📊 Dashboard":
        st.title("📊 Dashboard")
        
        # Load data
        df = load_data(st.session_state.user['id'], is_admin)
        
        if df.empty:
            st.info("No transactions yet. Add your first transaction!")
        else:
            # Get custom head names
            head_names = get_head_names(st.session_state.user['id'])
            
            # Overall metrics
            st.subheader("Overall Summary")
            col1, col2, col3, col4 = st.columns(4)
            
            total_receipts = df[df['type']=='receipt']['amount'].sum()
            total_exp = df[df['type']=='expenditure']['amount'].sum()
            net_balance = total_receipts - total_exp
            total_transactions = len(df)
            
            col1.metric("Total Receipts", f"₹{total_receipts:,.2f}")
            col2.metric("Total Expenditure", f"₹{total_exp:,.2f}")
            col3.metric("Net Balance", f"₹{net_balance:,.2f}")
            col4.metric("Total Transactions", total_transactions)
            
            st.divider()
            
            # NEW: Head-wise metrics
            st.subheader("Head-wise Summary")
            
            for head in HEADS:
                head_df = df[df['head'] == head]
                if not head_df.empty:
                    head_receipts = head_df[head_df['type']=='receipt']['amount'].sum()
                    head_exp = head_df[head_df['type']=='expenditure']['amount'].sum()
                    head_net = head_receipts - head_exp
                    head_count = len(head_df)
                    
                    with st.expander(f"📂 {head_names[head]}", expanded=False):
                        col1, col2, col3, col4 = st.columns(4)
                        col1.metric("Receipts", f"₹{head_receipts:,.2f}")
                        col2.metric("Expenditure", f"₹{head_exp:,.2f}")
                        col3.metric("Net Balance", f"₹{head_net:,.2f}")
                        col4.metric("Transactions", head_count)
            
            st.divider()
            
            # Budget alerts
            alerts = check_budget_alerts(st.session_state.user['id'], df)
            if alerts:
                st.warning("⚠️ Budget Alerts")
                for alert in alerts:
                    st.error(
                        f"**{alert['head']}** ({alert['period']}): "
                        f"₹{alert['usage']:,.2f} / ₹{alert['limit']:,.2f} "
                        f"({alert['percentage']:.1f}%)"
                    )
            
            # Charts
            if PLOTLY_AVAILABLE:
                col1, col2 = st.columns(2)
                
                with col1:
                    st.subheader("Type Distribution")
                    type_summary = df.groupby('type')['amount'].sum().reset_index()
                    fig = px.pie(type_summary, values='amount', names='type', 
                                color='type',
                                color_discrete_map={'receipt': '#2ecc71', 'expenditure': '#e74c3c'})
                    st.plotly_chart(fig, use_container_width=True)
                
                with col2:
                    st.subheader("Head-wise Expenditure")
                    head_exp = df[df['type']=='expenditure'].groupby('head')['amount'].sum().reset_index()
                    # Replace head IDs with custom names
                    head_exp['head_display'] = head_exp['head'].map(head_names)
                    fig = px.bar(head_exp, x='head_display', y='amount', 
                                labels={'head_display': 'Head', 'amount': 'Amount (₹)'})
                    st.plotly_chart(fig, use_container_width=True)
                
                # Monthly trend
                st.subheader("Monthly Trends")
                monthly_summary = get_monthly_summary(df)
                if not monthly_summary.empty:
                    fig = go.Figure()
                    fig.add_trace(go.Scatter(x=monthly_summary['month'], y=monthly_summary['receipt'],
                                           mode='lines+markers', name='Receipt',
                                           line=dict(color='#2ecc71', width=2)))
                    fig.add_trace(go.Scatter(x=monthly_summary['month'], y=monthly_summary['expenditure'],
                                           mode='lines+markers', name='Expenditure',
                                           line=dict(color='#e74c3c', width=2)))
                    fig.update_layout(xaxis_title='Month', yaxis_title='Amount (₹)',
                                    hovermode='x unified')
                    st.plotly_chart(fig, use_container_width=True)

    # ---------------- ADD RECORD ----------------
    elif menu == "➕ Add Record":
        st.title("➕ Add New Transaction")
        
        # Get custom head names
        head_names = get_head_names(st.session_state.user['id'])
        head_options = [f"{head} - {head_names[head]}" for head in HEADS]
        
        with st.form("add_record_form"):
            col1, col2 = st.columns(2)
            
            with col1:
                txn_date = st.date_input("Date", value=date.today())
                amount = st.number_input("Amount (₹)", min_value=0.0, step=0.01)
                purpose = st.text_input("Purpose")
            
            with col2:
                head_selection = st.selectbox("Head", head_options)
                head = head_selection.split(" - ")[0]  # Extract actual head ID
                txn_type = st.selectbox("Type", ["receipt", "expenditure"])
            
            submit_btn = st.form_submit_button("Add Transaction", use_container_width=True)
            
            if submit_btn:
                if amount <= 0:
                    st.error("Amount must be greater than 0")
                elif not purpose:
                    st.error("Purpose is required")
                else:
                    insert_record(
                        st.session_state.user['id'],
                        (txn_date.isoformat(), amount, purpose, head, txn_type),
                        st.session_state.user['id']
                    )
                    # NEW: Set success message
                    st.session_state.success_message = f"✅ Record added successfully! Amount: ₹{amount:,.2f}, Purpose: {purpose}"
                    st.rerun()

    # ---------------- VIEW/EDIT/DELETE ----------------
    elif menu == "📋 View/Edit/Delete":
        st.title("📋 View/Edit/Delete Transactions")
        
        df = load_data(st.session_state.user['id'], is_admin)
        
        if df.empty:
            st.info("No transactions found")
        else:
            # Get custom head names for display
            head_names = get_head_names(st.session_state.user['id'])
            
            # Filters
            st.subheader("Filters")
            col1, col2, col3 = st.columns(3)
            
            with col1:
                filter_type = st.multiselect("Type", ["receipt", "expenditure"], default=["receipt", "expenditure"])
            with col2:
                filter_heads = st.multiselect("Head", HEADS, default=HEADS)
            with col3:
                date_range = st.date_input("Date Range", value=[])
            
            # Apply filters
            filtered_df = df[
                (df['type'].isin(filter_type)) &
                (df['head'].isin(filter_heads))
            ]
            
            if len(date_range) == 2:
                filtered_df = filtered_df[
                    (pd.to_datetime(filtered_df['date']) >= pd.to_datetime(date_range[0])) &
                    (pd.to_datetime(filtered_df['date']) <= pd.to_datetime(date_range[1]))
                ]
            
            st.write(f"Showing {len(filtered_df)} of {len(df)} transactions")
            
            # Display transactions
            for idx, row in filtered_df.iterrows():
                with st.expander(
                    f"📝 {row['date']} | ₹{row['amount']:,.2f} | {head_names[row['head']]} | {row['purpose'][:50]}"
                ):
                    with st.form(f"edit_form_{row['id']}"):
                        col1, col2 = st.columns(2)
                        
                        with col1:
                            edit_date = st.date_input("Date", value=pd.to_datetime(row['date']).date(), key=f"date_{row['id']}")
                            edit_amount = st.number_input("Amount", value=float(row['amount']), min_value=0.0, step=0.01, key=f"amt_{row['id']}")
                            edit_purpose = st.text_input("Purpose", value=row['purpose'], key=f"purp_{row['id']}")
                        
                        with col2:
                            head_options = [f"{head} - {head_names[head]}" for head in HEADS]
                            current_head_display = f"{row['head']} - {head_names[row['head']]}"
                            head_idx = head_options.index(current_head_display) if current_head_display in head_options else 0
                            edit_head_selection = st.selectbox("Head", head_options, index=head_idx, key=f"head_{row['id']}")
                            edit_head = edit_head_selection.split(" - ")[0]
                            edit_type = st.selectbox("Type", ["receipt", "expenditure"], 
                                                    index=0 if row['type']=='receipt' else 1, 
                                                    key=f"type_{row['id']}")
                        
                        col_btn1, col_btn2 = st.columns(2)
                        
                        with col_btn1:
                            update_btn = st.form_submit_button("💾 Update", use_container_width=True)
                        with col_btn2:
                            delete_btn = st.form_submit_button("🗑️ Delete", use_container_width=True)
                        
                        if update_btn:
                            old_data = {
                                'date': row['date'],
                                'amount': row['amount'],
                                'purpose': row['purpose'],
                                'head': row['head'],
                                'type': row['type']
                            }
                            new_data = (edit_date.isoformat(), edit_amount, edit_purpose, edit_head, edit_type)
                            
                            update_record(
                                row['id'],
                                st.session_state.user['id'],
                                old_data,
                                new_data,
                                st.session_state.user['id']
                            )
                            # NEW: Set success message
                            st.session_state.success_message = f"✅ Record updated successfully! New amount: ₹{edit_amount:,.2f}"
                            st.rerun()
                        
                        if delete_btn:
                            record_data = {
                                'date': row['date'],
                                'amount': row['amount'],
                                'purpose': row['purpose'],
                                'head': row['head'],
                                'type': row['type']
                            }
                            delete_record(row['id'], st.session_state.user['id'], record_data)
                            st.session_state.success_message = f"✅ Record deleted successfully!"
                            st.rerun()

    # ---------------- ADVANCED ANALYTICS ----------------
    elif menu == "📈 Advanced Analytics":
        st.title("📈 Advanced Analytics")
        
        df = load_data(st.session_state.user['id'], is_admin)
        
        if df.empty:
            st.info("No data available for analytics")
        else:
            # Get custom head names
            head_names = get_head_names(st.session_state.user['id'])
            
            tab1, tab2, tab3 = st.tabs(["Monthly Trends", "Forecasting", "Detailed Analysis"])
            
            with tab1:
                st.subheader("Monthly Receipt vs Expenditure")
                
                # NEW: Add option to select head or all heads
                analysis_options = ["All Heads Combined"] + [f"{head} - {head_names[head]}" for head in HEADS]
                selected_analysis = st.selectbox("Select Head for Analysis", analysis_options)
                
                # Filter data based on selection
                if selected_analysis == "All Heads Combined":
                    analysis_df = df
                    chart_title = "All Heads Combined"
                else:
                    selected_head = selected_analysis.split(" - ")[0]
                    analysis_df = df[df['head'] == selected_head]
                    chart_title = head_names[selected_head]
                
                if not analysis_df.empty and PLOTLY_AVAILABLE:
                    monthly_summary = get_monthly_summary(analysis_df)
                    
                    if not monthly_summary.empty:
                        fig = go.Figure()
                        fig.add_trace(go.Scatter(
                            x=monthly_summary['month'], 
                            y=monthly_summary['receipt'],
                            mode='lines+markers', 
                            name='Receipt',
                            line=dict(color='#2ecc71', width=3),
                            marker=dict(size=8)
                        ))
                        fig.add_trace(go.Scatter(
                            x=monthly_summary['month'], 
                            y=monthly_summary['expenditure'],
                            mode='lines+markers', 
                            name='Expenditure',
                            line=dict(color='#e74c3c', width=3),
                            marker=dict(size=8)
                        ))
                        fig.update_layout(
                            title=f"Monthly Trends - {chart_title}",
                            xaxis_title='Month', 
                            yaxis_title='Amount (₹)',
                            hovermode='x unified',
                            height=500
                        )
                        st.plotly_chart(fig, use_container_width=True)
                        
                        # Show data table
                        st.dataframe(monthly_summary, use_container_width=True)
                    else:
                        st.info(f"No data available for {chart_title}")
                else:
                    st.info(f"No data available for {chart_title}")
            
            with tab2:
                st.subheader("Expenditure Forecasting")
                
                # NEW: Options for head selection and period
                col1, col2 = st.columns(2)
                
                with col1:
                    forecast_options = ["All Heads Combined"] + [f"{head} - {head_names[head]}" for head in HEADS]
                    selected_forecast = st.selectbox("Select Head for Forecasting", forecast_options, key="forecast_head")
                
                with col2:
                    forecast_months = st.selectbox(
                        "Based on last N months",
                        options=[3, 4, 5, 6, 7, 8, 9, 10, 11, 12],
                        index=0,
                        key="forecast_period"
                    )
                
                forecast_periods = st.slider("Forecast for next N months", 1, 12, 3, key="forecast_future")
                
                # Filter data based on selection
                if selected_forecast == "All Heads Combined":
                    forecast_df = df
                    forecast_title = "All Heads Combined"
                else:
                    selected_head = selected_forecast.split(" - ")[0]
                    forecast_df = df[df['head'] == selected_head]
                    forecast_title = head_names[selected_head]
                
                if not forecast_df.empty:
                    # Get historical data for selected period
                    forecast_df_copy = forecast_df.copy()
                    forecast_df_copy['date'] = pd.to_datetime(forecast_df_copy['date'])
                    
                    # Calculate forecast
                    forecast_result = forecast_trend(forecast_df_copy, months=forecast_months, forecast_periods=forecast_periods)
                    
                    if forecast_result is not None and PLOTLY_AVAILABLE:
                        # Get actual historical data
                        forecast_df_copy['month'] = forecast_df_copy['date'].dt.to_period('M').astype(str)
                        historical = forecast_df_copy[forecast_df_copy['type']=='expenditure'].groupby('month')['amount'].sum().reset_index()
                        historical = historical.tail(forecast_months)
                        
                        # Create combined chart
                        fig = go.Figure()
                        
                        # Historical data
                        fig.add_trace(go.Scatter(
                            x=historical['month'],
                            y=historical['amount'],
                            mode='lines+markers',
                            name='Historical',
                            line=dict(color='#3498db', width=2),
                            marker=dict(size=8)
                        ))
                        
                        # Forecast
                        fig.add_trace(go.Scatter(
                            x=forecast_result['month'],
                            y=forecast_result['forecast'],
                            mode='lines+markers',
                            name='Forecast',
                            line=dict(color='#e74c3c', width=2, dash='dash'),
                            marker=dict(size=8)
                        ))
                        
                        fig.update_layout(
                            title=f"Expenditure Forecast - {forecast_title} (Based on last {forecast_months} months)",
                            xaxis_title='Month',
                            yaxis_title='Amount (₹)',
                            hovermode='x unified',
                            height=500
                        )
                        
                        st.plotly_chart(fig, use_container_width=True)
                        
                        # Show forecast values
                        st.subheader("Forecast Values")
                        col1, col2 = st.columns(2)
                        with col1:
                            st.write("**Historical Average:**")
                            st.metric("Avg Monthly Expenditure", f"₹{historical['amount'].mean():,.2f}")
                        with col2:
                            st.write("**Forecasted:**")
                            st.dataframe(forecast_result, use_container_width=True)
                    else:
                        st.warning(f"Insufficient data for forecasting {forecast_title}. Need at least {forecast_months} months of data.")
                else:
                    st.info(f"No data available for {forecast_title}")
            
            with tab3:
                st.subheader("Detailed Analysis")
                
                # Head-wise summary
                head_summary = get_head_wise_summary(df)
                if not head_summary.empty:
                    # Replace head IDs with custom names
                    head_summary['head_display'] = head_summary['head'].map(head_names)
                    st.dataframe(
                        head_summary[['head_display', 'receipt', 'expenditure', 'net']].rename(
                            columns={'head_display': 'Head', 'receipt': 'Receipt', 'expenditure': 'Expenditure', 'net': 'Net'}
                        ),
                        use_container_width=True
                    )
                
                # Top expenses
                st.subheader("Top 10 Expenses")
                top_expenses = df[df['type']=='expenditure'].nlargest(10, 'amount')[['date', 'amount', 'purpose', 'head']]
                top_expenses['head_display'] = top_expenses['head'].map(head_names)
                st.dataframe(
                    top_expenses[['date', 'amount', 'purpose', 'head_display']].rename(
                        columns={'head_display': 'Head'}
                    ),
                    use_container_width=True
                )

    # ---------------- MANAGE HEAD NAMES (NEW) ----------------
    elif menu == "🏷️ Manage Head Names":
        st.title("🏷️ Manage Head Names")
        
        st.info("Customize the names of your budget heads to match your needs (e.g., 'Food & Refreshment', 'Rent & Transport', etc.)")
        
        # Get current head names
        head_names = get_head_names(st.session_state.user['id'])
        
        # Create form for editing head names
        with st.form("manage_head_names"):
            st.subheader("Edit Head Names")
            
            updated_names = {}
            
            # Create two columns for better layout
            col1, col2 = st.columns(2)
            
            for i, head in enumerate(HEADS):
                with col1 if i < 5 else col2:
                    updated_names[head] = st.text_input(
                        f"{head}",
                        value=head_names[head],
                        key=f"head_name_{head}"
                    )
            
            submit_btn = st.form_submit_button("💾 Save Head Names", use_container_width=True)
            
            if submit_btn:
                # Update all head names
                success_count = 0
                for head, name in updated_names.items():
                    if name.strip():  # Only update if name is not empty
                        if update_head_name(st.session_state.user['id'], head, name.strip()):
                            success_count += 1
                
                if success_count > 0:
                    st.session_state.success_message = f"✅ Successfully updated {success_count} head name(s)!"
                    st.rerun()
                else:
                    st.error("Failed to update head names")
        
        # Show current mapping
        st.divider()
        st.subheader("Current Head Names")
        
        mapping_df = pd.DataFrame([
            {"Head ID": head, "Custom Name": head_names[head]}
            for head in HEADS
        ])
        st.dataframe(mapping_df, use_container_width=True)

    # ---------------- BUDGET LIMITS ----------------
    elif menu == "🎯 Budget Limits":
        st.title("🎯 Budget Limits")
        
        # Get custom head names
        head_names = get_head_names(st.session_state.user['id'])
        
        tab1, tab2 = st.tabs(["Set Limits", "View Current Limits"])
        
        with tab1:
            st.subheader("Set Budget Limits")
            
            with st.form("budget_limit_form"):
                head_options = [f"{head} - {head_names[head]}" for head in HEADS]
                selected_head = st.selectbox("Head", head_options)
                head = selected_head.split(" - ")[0]
                
                col1, col2, col3 = st.columns(3)
                
                with col1:
                    monthly_limit = st.number_input("Monthly Limit (₹)", min_value=0.0, step=100.0)
                with col2:
                    yearly_limit = st.number_input("Yearly Limit (₹)", min_value=0.0, step=1000.0)
                with col3:
                    alert_threshold = st.slider("Alert Threshold (%)", 50, 100, 80)
                
                submit_btn = st.form_submit_button("Set Limit")
                
                if submit_btn:
                    if monthly_limit > 0 or yearly_limit > 0:
                        success = set_budget_limit(
                            st.session_state.user['id'],
                            head,
                            monthly_limit,
                            yearly_limit,
                            alert_threshold
                        )
                        if success:
                            st.success("Budget limit updated successfully!")
                            st.rerun()
                        else:
                            st.error("Failed to update budget limit")
                    else:
                        st.error("Please set at least one limit (monthly or yearly)")
        
        with tab2:
            st.subheader("Current Budget Limits")
            
            limits_df = get_budget_limits(st.session_state.user['id'])
            
            if limits_df.empty:
                st.info("No budget limits set")
            else:
                # Replace head IDs with custom names
                limits_df['head_display'] = limits_df['head'].map(head_names)
                display_df = limits_df[['head_display', 'monthly_limit', 'yearly_limit', 'alert_threshold']].rename(
                    columns={
                        'head_display': 'Head',
                        'monthly_limit': 'Monthly Limit (₹)',
                        'yearly_limit': 'Yearly Limit (₹)',
                        'alert_threshold': 'Alert Threshold (%)'
                    }
                )
                st.dataframe(display_df, use_container_width=True)

    # ---------------- DATA MANAGEMENT ----------------
    elif menu == "💾 Data Management":
        st.title("💾 Data Management")
        
        tab1, tab2, tab3 = st.tabs(["Export Data", "Import Data", "Backup"])
        
        with tab1:
            st.subheader("Export Transactions")
            
            df = load_data(st.session_state.user['id'], is_admin)
            
            if df.empty:
                st.info("No data to export")
            else:
                col1, col2 = st.columns(2)
                
                with col1:
                    # CSV Export
                    csv = df.to_csv(index=False)
                    st.download_button(
                        "📥 Download CSV",
                        csv,
                        f"transactions_{datetime.now().strftime('%Y%m%d')}.csv",
                        "text/csv",
                        use_container_width=True
                    )
                
                with col2:
                    # Excel Export (if openpyxl available)
                    try:
                        buffer = io.BytesIO()
                        with pd.ExcelWriter(buffer, engine='openpyxl') as writer:
                            df.to_excel(writer, index=False, sheet_name='Transactions')
                        
                        st.download_button(
                            "📥 Download Excel",
                            buffer.getvalue(),
                            f"transactions_{datetime.now().strftime('%Y%m%d')}.xlsx",
                            "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
                            use_container_width=True
                        )
                    except ImportError:
                        st.info("Install openpyxl for Excel export")
                
                # PDF Export
                if REPORTLAB_AVAILABLE:
                    if st.button("📄 Generate PDF Report", use_container_width=True):
                        buffer = io.BytesIO()
                        doc = SimpleDocTemplate(buffer, pagesize=letter)
                        elements = []
                        
                        # Title
                        styles = getSampleStyleSheet()
                        title = Paragraph("Transaction Report", styles['Title'])
                        elements.append(title)
                        elements.append(Spacer(1, 0.2*inch))
                        
                        # Summary
                        summary_text = f"""
                        Report Generated: {datetime.now().strftime('%Y-%m-%d %H:%M')}
                        Total Transactions: {len(df)}
                        Total Receipts: ₹{df[df['type']=='receipt']['amount'].sum():,.2f}
                        Total Expenditure: ₹{df[df['type']=='expenditure']['amount'].sum():,.2f}
                        """
                        summary = Paragraph(summary_text.replace('\n', '<br/>'), styles['Normal'])
                        elements.append(summary)
                        elements.append(Spacer(1, 0.3*inch))
                        
                        # Table
                        table_data = [['Date', 'Amount', 'Purpose', 'Head', 'Type']]
                        for _, row in df.head(50).iterrows():
                            table_data.append([
                                row['date'],
                                f"₹{row['amount']:,.2f}",
                                row['purpose'][:30],
                                row['head'],
                                row['type']
                            ])
                        
                        t = Table(table_data)
                        t.setStyle(TableStyle([
                            ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
                            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                            ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
                            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                            ('FONTSIZE', (0, 0), (-1, 0), 12),
                            ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
                            ('GRID', (0, 0), (-1, -1), 1, colors.black)
                        ]))
                        elements.append(t)
                        
                        doc.build(elements)
                        pdf_data = buffer.getvalue()
                        
                        st.download_button(
                            "📥 Download PDF",
                            pdf_data,
                            f"report_{datetime.now().strftime('%Y%m%d')}.pdf",
                            "application/pdf"
                        )
                else:
                    st.error("Install reportlab for PDF export: pip install reportlab")
        
        with tab2:
            st.subheader("Import Transactions")
            st.info("Upload a CSV file with columns: date, amount, purpose, head, type")
            
            uploaded_file = st.file_uploader("Choose CSV file", type=['csv'])
            
            if uploaded_file:
                try:
                    import_df = pd.read_csv(uploaded_file)
                    
                    # Validate columns
                    required_cols = ['date', 'amount', 'purpose', 'head', 'type']
                    if not all(col in import_df.columns for col in required_cols):
                        st.error(f"CSV must contain columns: {', '.join(required_cols)}")
                    else:
                        st.dataframe(import_df.head())
                        
                        if st.button("Import Records"):
                            conn = get_connection()
                            imported = 0
                            for _, row in import_df.iterrows():
                                try:
                                    insert_record(
                                        st.session_state.user['id'],
                                        (row['date'], row['amount'], row['purpose'], 
                                         row['head'], row['type']),
                                        st.session_state.user['id']
                                    )
                                    imported += 1
                                except Exception as e:
                                    st.error(f"Error importing row: {e}")
                            
                            st.success(f"Successfully imported {imported} records!")
                            st.rerun()
                except Exception as e:
                    st.error(f"Error reading file: {e}")
        
        with tab3:
            st.subheader("Database Backup")
            st.info("Note: On Streamlit Cloud, file system is temporary. Please use the Download button in sidebar to save your data locally.")
            
            col1, col2 = st.columns(2)
            
            with col1:
                if st.button("🔒 Create Backup Now"):
                    backup_file = backup_database()
                    st.success(f"Backup created: {backup_file}")
            
            # List existing backups
            if os.path.exists(BACKUP_DIR):
                backup_files = sorted(Path(BACKUP_DIR).glob("*.db"), reverse=True)
                if backup_files:
                    st.subheader("Available Backups")
                    for backup in backup_files[:5]:
                        st.text(backup.name)

    # ---------------- AUDIT TRAIL ----------------
    elif menu == "🔍 Audit Trail":
        st.title("🔍 Audit Trail")
        
        if is_admin:
            view_all = st.checkbox("View all users' audit trail", value=False)
            audit_user_id = None if view_all else st.session_state.user['id']
        else:
            audit_user_id = st.session_state.user['id']
        
        audit_df = get_audit_trail(user_id=audit_user_id, limit=200)
        
        if audit_df.empty:
            st.info("No audit records found")
        else:
            # Filters
            col1, col2 = st.columns(2)
            with col1:
                action_filter = st.selectbox("Action", ["All", "CREATE", "UPDATE", "DELETE"])
            with col2:
                limit = st.slider("Records to show", 10, 200, 50)
            
            filtered_audit = audit_df.copy()
            if action_filter != "All":
                filtered_audit = filtered_audit[filtered_audit['action'] == action_filter]
            
            filtered_audit = filtered_audit.head(limit)
            
            # Display audit records
            for _, record in filtered_audit.iterrows():
                with st.expander(f"🕒 {record['timestamp']} - {record['action']} by {record['username']}"):
                    col1, col2 = st.columns(2)
                    
                    with col1:
                        if record['old_data']:
                            st.write("**Old Data:**")
                            old_data = json.loads(record['old_data'])
                            st.json(old_data)
                    
                    with col2:
                        if record['new_data']:
                            st.write("**New Data:**")
                            new_data = json.loads(record['new_data'])
                            st.json(new_data)
                    
                    if record['purpose']:
                        st.write(f"**Purpose:** {record['purpose']}")

    # ---------------- PROFILE ----------------
    elif menu == "👤 Profile":
        st.title("👤 User Profile")
        
        col1, col2 = st.columns(2)
        
        with col1:
            st.subheader("Account Information")
            st.write(f"**Username:** {st.session_state.user['username']}")
            st.write(f"**Full Name:** {st.session_state.user['full_name']}")
            st.write(f"**Role:** {st.session_state.user['role'].title()}")
            
            # User statistics
            user_df = load_data(st.session_state.user['id'], is_admin=False)
            st.write(f"**Total Transactions:** {len(user_df)}")
            if not user_df.empty:
                st.write(f"**Total Receipts:** ₹{user_df[user_df['type']=='receipt']['amount'].sum():,.2f}")
                st.write(f"**Total Expenditure:** ₹{user_df[user_df['type']=='expenditure']['amount'].sum():,.2f}")
        
        with col2:
            st.subheader("Change Password")
            with st.form("change_password_form"):
                new_pwd = st.text_input("New Password", type="password")
                confirm_pwd = st.text_input("Confirm New Password", type="password")
                change_btn = st.form_submit_button("Change Password")
                
                if change_btn:
                    if not new_pwd or not confirm_pwd:
                        st.error("Please fill both fields")
                    elif new_pwd != confirm_pwd:
                        st.error("Passwords do not match")
                    elif len(new_pwd) < 6:
                        st.error("Password must be at least 6 characters")
                    else:
                        change_password(st.session_state.user['id'], new_pwd)
                        st.success("Password changed successfully!")

    # ---------------- USER MANAGEMENT (Admin Only) ----------------
    elif menu == "👥 User Management":
        st.title("👥 User Management")
        
        users_df = load_all_users()
        st.dataframe(users_df)
        
        tab1, tab2 = st.tabs(["Create User", "Delete User"])
        
        with tab1:
            st.subheader("Create New User")
            with st.form("admin_create_user"):
                col1, col2 = st.columns(2)
                with col1:
                    admin_username = st.text_input("Username")
                    admin_password = st.text_input("Password", type="password")
                    admin_full_name = st.text_input("Full Name")
                with col2:
                    admin_email = st.text_input("Email")
                    admin_role = st.selectbox("Role", ["user", "admin"])
                
                create_btn = st.form_submit_button("Create User")
                
                if create_btn:
                    if all([admin_username, admin_password, admin_full_name]):
                        success, message = create_user(
                            admin_username, admin_password, admin_full_name, admin_email, admin_role
                        )
                        if success:
                            st.success(message)
                            st.rerun()
                        else:
                            st.error(message)
                    else:
                        st.error("Please fill all required fields")
        
        with tab2:
            st.subheader("Delete User")
            user_to_delete = st.selectbox(
                "Select User to Delete",
                users_df[users_df['id'] != st.session_state.user['id']]['username'].tolist()
            )
            
            st.warning("⚠️ This will delete the user and ALL their data permanently!")
            
            if st.button("Delete User"):
                user_id = users_df[users_df['username'] == user_to_delete]['id'].iloc[0]
                delete_user(user_id)
                st.success(f"User '{user_to_delete}' deleted successfully")
                st.rerun()

# ---------------- MAIN ----------------
# Initialize session state
if 'logged_in' not in st.session_state:
    st.session_state.logged_in = False
if 'user' not in st.session_state:
    st.session_state.user = None

# Create tables
create_tables()

if not st.session_state.logged_in:
    login_page()
else:
    main_app()
