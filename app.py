import os, secrets, imghdr, csv, io, sys
from datetime import datetime
from flask import (
    Flask, render_template_string, request, redirect, url_for,
    flash, make_response, abort, session, send_from_directory
)
from flask_sqlalchemy import SQLAlchemy
from flask_login import (
    LoginManager, UserMixin, login_user, login_required,
    logout_user, current_user
)
from flask_bcrypt import Bcrypt
from werkzeug.utils import secure_filename
from dotenv import load_dotenv

load_dotenv()

# --- Ledger ---
def print_log(text=""):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    print(f"[{timestamp}] {text}")

# --- Configuration ---

app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'NO_SECRET_KEY_SET')
if app.config['SECRET_KEY'] == 'NO_SECRET_KEY_SET':
    print_log("SECRET_KEY NOT SET! EXITING...")
    sys.exit(1)

INITIAL_ADMIN_PASSWORD = os.environ.get('INITIAL_ADMIN_PASSWORD', 'NO_PASSWORD_SET')
if INITIAL_ADMIN_PASSWORD == 'NO_PASSWORD_SET':
    print_log("INITIAL_ADMIN_PASSWORD NOT SET! EXITING...")
    sys.exit(1)
app.config['UPLOAD_FOLDER'] = 'static/uploads'
try:
    os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
except Exception:
    print_log(f"CANNOT CREATE UPLOAD FOLDER! EXITING...")
    sys.exit(1)

MAX_IMAGE_SIZE_MB = int(os.environ.get('MAX_IMAGE_SIZE_MB', '404'))
if MAX_IMAGE_SIZE_MB == 404:
    print_log("MAX_IMAGE_SIZE_MB NOT SET! USING : 50 MB.")
    MAX_IMAGE_SIZE_MB = 50
app.config['MAX_CONTENT_LENGTH'] = MAX_IMAGE_SIZE_MB * 1024 * 1024

FLASK_DEBUG = os.environ.get('FLASK_DEBUG', '').strip().lower() in ('1', 'true', 'yes')
FLASK_HOST = os.environ.get('FLASK_HOST', 'NO_HOST_SET')
if FLASK_HOST == 'NO_HOST_SET':
    print_log("FLASK_HOST NOT SET! EXITING...")
    sys.exit(1)
FLASK_PORT = int(os.environ.get('FLASK_PORT', 'NO_PORT_SET'))
if FLASK_PORT == 'NO_PORT_SET':
    print_log("FLASK_PORT NOT SET! EXITING...")
    sys.exit(1)

APP_VERSION = os.environ.get('APP_VERSION', 'STABLE RELEASE')
if APP_VERSION == 'STABLE RELEASE':
    print_log("APP_VERSION NOT SET! USING : 'STABLE RELEASE'.")

ALLOWED_IMAGE_EXTENSIONS = {'jpg', 'jpeg', 'png', 'webp', 'gif', 'bmp'}

RESET_DB = os.environ.get('RESET_DB', '').strip().lower() in ('1', 'true', 'yes')
RESET_DB_CONFIRM = os.environ.get('RESET_DB_CONFIRM', '').strip().lower() in ('1', 'true', 'yes')

DATABASE_URL = (os.environ.get('DATABASE_URL') or '').strip()
if not DATABASE_URL:
    print_log("DATABASE_URL NOT SET! EXITING...")
    sys.exit(1)

app.config['SQLALCHEMY_DATABASE_URI'] = DATABASE_URL
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SQLALCHEMY_ENGINE_OPTIONS'] = {"pool_pre_ping": True, "pool_recycle": 300}
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'
login_manager.login_message = None  # Suppress default login flash

# --- CSRF protection (session token) ---
def _get_csrf_token() -> str:
    token = session.get('_csrf_token')
    if not token:
        token = secrets.token_urlsafe(32)
        session['_csrf_token'] = token
    return token

def _require_csrf() -> None:
    if request.method == 'POST':
        sent = request.form.get('csrf_token', '')
        if not sent or sent != session.get('_csrf_token'):
            abort(400)

@app.context_processor
def inject_globals():
    return {'csrf_token': _get_csrf_token(), 'app_version': APP_VERSION}

@app.errorhandler(400)
def bad_request(e):
    flash('Bad request. Please refresh and try again.', 'danger')
    return redirect(request.referrer or url_for('dashboard'))

@app.errorhandler(413)
def too_large(e):
    flash('File too large. Maximum allowed is 50 MB.', 'danger')
    return redirect(request.referrer or url_for('dashboard'))

# --- Models ---
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    role = db.Column(db.String(20), default='user', nullable=False)  # 'viewer', 'user', 'admin'

class Category(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    type = db.Column(db.String(50), nullable=False)  # income/expense

class FeeOption(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    amount = db.Column(db.Float, nullable=False)  # percent

class Transaction(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    trx_id = db.Column(db.String(32), unique=True, nullable=False, index=True)
    date = db.Column(db.DateTime, default=datetime.utcnow)
    created_by = db.Column(db.String(150), nullable=True)
    type = db.Column(db.String(50), nullable=False)
    category = db.Column(db.String(100), nullable=True)
    amount = db.Column(db.Float, nullable=False)
    fee = db.Column(db.Float, default=0.0)
    method = db.Column(db.String(50), nullable=False)
    description = db.Column(db.String(200))
    advance_person = db.Column(db.String(100), nullable=True)
    acc_sender = db.Column(db.String(100), nullable=True)
    acc_receiver = db.Column(db.String(100), nullable=True)
    withdrawn_by = db.Column(db.String(100), nullable=True)
    receipt_image = db.Column(db.String(200), nullable=True)
    is_settled = db.Column(db.Boolean, default=False)
    parent_id = db.Column(db.Integer, nullable=True)

class AuditLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    user = db.Column(db.String(150), nullable=True)
    action = db.Column(db.String(100), nullable=False)
    details = db.Column(db.Text, nullable=False)

@login_manager.user_loader
def load_user(user_id):
    return db.session.get(User, int(user_id))

# --- Helpers ---
def generate_trx_id() -> str:
    while True:
        candidate = "TX-" + secrets.token_hex(6).upper()
        exists = Transaction.query.filter_by(trx_id=candidate).first()
        if not exists:
            return candidate

def allowed_image_filename(filename: str) -> bool:
    if not filename or '.' not in filename:
        return False
    ext = filename.rsplit('.', 1)[1].lower().strip()
    return ext in ALLOWED_IMAGE_EXTENSIONS

def validate_image_stream(file_storage) -> bool:
    try:
        head = file_storage.stream.read(512)
        file_storage.stream.seek(0)
        kind = imghdr.what(None, head)
        return kind in ('jpeg', 'png')
    except Exception:
        try:
            file_storage.stream.seek(0)
        except Exception:
            pass
        return False

def save_receipt_image(file_storage) -> str | None:
    if not file_storage or not getattr(file_storage, 'filename', ''):
        return None
    filename = secure_filename(file_storage.filename)
    if not allowed_image_filename(filename):
        return None
    if not validate_image_stream(file_storage):
        return None
    prefix = secrets.token_hex(8)
    stored = f"{prefix}_{filename}"
    os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
    file_storage.save(os.path.join(app.config['UPLOAD_FOLDER'], stored))
    return stored

def log_action(action: str, details: str):
    log = AuditLog(user=current_user.username if current_user.is_authenticated else "System",
                   action=action, details=details)
    db.session.add(log)
    db.session.commit()

# --- Balance helpers ---
def get_bank_balance() -> float:
    txs = Transaction.query.all()
    bal = 0.0
    for t in txs:
        if t.type == 'bank_in':
            bal += float(t.amount)
        elif t.type == 'withdrawal':
            bal -= float(t.amount)
        elif t.type == 'expense' and t.method == 'Bank':
            bal -= float(t.amount)
    return bal

def get_total_income() -> float:
    txs = Transaction.query.all()
    return sum(float(t.amount) for t in txs if t.type in ('income', 'bank_in'))

def get_total_expense() -> float:
    txs = Transaction.query.all()
    return sum(float(t.amount) for t in txs if t.type == 'expense')

def get_unsettled_advances_total() -> float:
    txs = Transaction.query.all()
    return sum(float(t.amount) for t in txs if t.type == 'advance' and not t.is_settled)

def get_cash_in_hand() -> float:
    total_income = get_total_income()
    total_expense = get_total_expense()
    bank_balance = get_bank_balance()
    unsettled_advances = get_unsettled_advances_total()
    return total_income - (total_expense + bank_balance + unsettled_advances)

# --- Routes ---
@app.route('/uploads/<filename>')
@login_required
def uploaded_file(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)

@app.route('/')
@app.route('/home')
@login_required
def dashboard():
    inc_cats = Category.query.filter_by(type='income').all()
    exp_cats = Category.query.filter_by(type='expense').all()
    fees = FeeOption.query.order_by(FeeOption.amount).all()
    pending_advances = Transaction.query.filter_by(type='advance', is_settled=False).all()
    total_income = get_total_income()
    total_expense = get_total_expense()
    bank_balance = get_bank_balance()
    unsettled_advances = get_unsettled_advances_total()
    cash_in_hand = get_cash_in_hand()
    return render_template_string(
        HTML_TEMPLATE,
        page='dashboard',
        cash=cash_in_hand,
        bank=bank_balance,
        income=total_income,
        expense=total_expense,
        advances_total=unsettled_advances,
        inc_cats=inc_cats,
        exp_cats=exp_cats,
        fees=fees,
        pending_advances=pending_advances,
        db_status="Neon Cloud"
    )

@app.route('/income')
@login_required
def income_page():
    if current_user.role == 'viewer':
        return redirect(url_for('dashboard'))
    txs = Transaction.query.all()
    inc_breakdown = {}
    total_inc = 0.0
    for t in txs:
        amt = float(t.amount)
        if t.type == 'income':
            cat = t.category if t.category else "Uncategorized Income"
            inc_breakdown[cat] = inc_breakdown.get(cat, 0.0) + amt
            total_inc += amt
        elif t.type == 'bank_in':
            cat = "Bank Deposit"
            inc_breakdown[cat] = inc_breakdown.get(cat, 0.0) + amt
            total_inc += amt
    return render_template_string(
        HTML_TEMPLATE,
        page='income',
        inc_breakdown=inc_breakdown,
        total_inc=total_inc
    )

@app.route('/expense')
@login_required
def expense_page():
    if current_user.role == 'viewer':
        return redirect(url_for('dashboard'))
    txs = Transaction.query.all()
    exp_breakdown = {}
    total_exp = 0.0
    total_fees = 0.0
    for t in txs:
        amt = float(t.amount)
        if t.type == 'expense':
            cat = t.category if t.category else "Uncategorized Expense"
            exp_breakdown[cat] = exp_breakdown.get(cat, 0.0) + amt
            total_exp += amt
        if t.type == 'withdrawal' and t.fee:
            total_fees += float(t.fee)
    return render_template_string(
        HTML_TEMPLATE,
        page='expense',
        exp_breakdown=exp_breakdown,
        total_exp=total_exp,
        total_fees=total_fees
    )

@app.route('/bank')
@login_required
def bank():
    if current_user.role == 'viewer':
        return redirect(url_for('dashboard'))
    bank_ins = Transaction.query.filter_by(type='bank_in').order_by(Transaction.date.desc()).all()
    withdrawals = Transaction.query.filter_by(type='withdrawal').order_by(Transaction.date.desc()).all()
    total_fees = sum(float(t.fee or 0) for t in withdrawals)
    return render_template_string(
        HTML_TEMPLATE,
        page='bank',
        bank_ins=bank_ins,
        withdrawals=withdrawals,
        total_fees=total_fees
    )

@app.route('/active_advances')
@login_required
def active_advances():
    if current_user.role == 'viewer':
        return redirect(url_for('dashboard'))
    advances_all = Transaction.query.filter(Transaction.type == 'advance').order_by(Transaction.date.desc()).all()
    returns_all = Transaction.query.filter(Transaction.type == 'advance_return').order_by(Transaction.date.desc()).all()
    active_adv = [t for t in advances_all if not t.is_settled]
    total_active = sum(float(t.amount) for t in active_adv)
    return render_template_string(
        HTML_TEMPLATE,
        page='active_advances',
        advances_all=advances_all,
        returns_all=returns_all,
        active_advances=active_adv,
        total_active=total_active
    )

@app.route('/charts')
@login_required
def charts():
    total_income = get_total_income()
    total_expense = get_total_expense()
    bank_balance = get_bank_balance()
    unsettled_advances = get_unsettled_advances_total()
    cash_in_hand = get_cash_in_hand()
    chart_allocation = {
        'labels': ['Cash In Hand', 'Bank Balance', 'Active Advances', 'Total Expense'],
        'data': [float(cash_in_hand), float(bank_balance), float(unsettled_advances), float(total_expense)]
    }
    expenses = Transaction.query.filter_by(type='expense').all()
    exp_totals = {}
    for tx in expenses:
        cat = tx.category if tx.category else "Uncategorized"
        exp_totals[cat] = exp_totals.get(cat, 0.0) + float(tx.amount)
    txs = Transaction.query.all()
    inc_totals = {}
    for t in txs:
        amt = float(t.amount)
        if t.type == 'income':
            cat = t.category if t.category else "Uncategorized Income"
            inc_totals[cat] = inc_totals.get(cat, 0.0) + amt
        elif t.type == 'bank_in':
            cat = "Bank Deposit"
            inc_totals[cat] = inc_totals.get(cat, 0.0) + amt
    return render_template_string(
        HTML_TEMPLATE,
        page='charts',
        chart_allocation=chart_allocation,
        exp_labels=list(exp_totals.keys()),
        exp_values=list(exp_totals.values()),
        inc_labels=list(inc_totals.keys()),
        inc_values=list(inc_totals.values()),
    )

@app.route('/log')
@login_required
def log_page():
    if current_user.role != 'admin':
        flash("Only admins can view logs.", "danger")
        return redirect(url_for('dashboard'))
    page_num = request.args.get('page', 1, type=int)
    pagination = AuditLog.query.order_by(AuditLog.timestamp.desc()).paginate(page=page_num, per_page=30, error_out=False)
    return render_template_string(
        HTML_TEMPLATE,
        page='log',
        pagination=pagination,
        logs=pagination.items
    )

@app.route('/add', methods=['POST'])
@login_required
def add_transaction():
    if current_user.role == 'viewer':
        flash("Viewers cannot add transactions.", "danger")
        return redirect(url_for('dashboard'))
    _require_csrf()
    t_type = (request.form.get('type') or '').strip()
    allowed_types = {'income', 'expense', 'bank_in', 'withdrawal', 'advance', 'settle_advance'}
    if t_type not in allowed_types:
        flash("Invalid transaction type.", "danger")
        return redirect(url_for('dashboard'))

    # --- Parse date (common for all types) ---
    transaction_date_str = request.form.get('transaction_date')
    if not transaction_date_str:
        flash("Date is required.", "danger")
        return redirect(url_for('dashboard'))
    try:
        selected_date = datetime.strptime(transaction_date_str, '%Y-%m-%d')
        tx_date = selected_date.replace(hour=0, minute=0, second=0, microsecond=0)
    except ValueError:
        flash("Invalid date selected.", "danger")
        return redirect(url_for('dashboard'))

    if t_type == 'settle_advance':
        adv_id_raw = (request.form.get('advance_id') or '').strip()
        settle_type = (request.form.get('settle_type') or 'return').strip()
        if not adv_id_raw.isdigit():
            flash("Please select an active advance.", "danger")
            return redirect(url_for('dashboard'))
        original_adv = Transaction.query.get(int(adv_id_raw))
        if not original_adv or original_adv.type != 'advance' or original_adv.is_settled:
            flash("Selected advance is not available for settlement.", "danger")
            return redirect(url_for('dashboard'))
        spend_cats = request.form.getlist('spend_category[]')
        spend_amts = request.form.getlist('spend_amount[]')
        spend_descs = request.form.getlist('spend_desc[]')
        spend_files = request.files.getlist('spend_receipt[]')
        total_spent = 0.0
        items = []
        max_len = max(len(spend_cats), len(spend_amts), len(spend_descs), len(spend_files))
        for i in range(max_len):
            cat = (spend_cats[i] if i < len(spend_cats) else '').strip()
            amt_raw = (spend_amts[i] if i < len(spend_amts) else '').strip()
            dsc = (spend_descs[i] if i < len(spend_descs) else '').strip()
            file = spend_files[i] if i < len(spend_files) else None
            if not cat and not amt_raw and not dsc and (not file or not file.filename):
                continue
            if not cat:
                flash("Each settlement item must have a category.", "danger")
                return redirect(url_for('dashboard'))
            try:
                amt = float(amt_raw) if amt_raw else 0.0
            except (TypeError, ValueError):
                flash("Each settlement item must have a valid amount.", "danger")
                return redirect(url_for('dashboard'))
            if amt < 0:
                flash("Settlement item amount cannot be negative.", "danger")
                return redirect(url_for('dashboard'))
            if amt > 0 or (file and file.filename):
                items.append((cat, amt, dsc, file))
                total_spent += amt
        if total_spent > float(original_adv.amount):
            flash(f"Settlement total (৳{total_spent:.2f}) exceeds available advance (৳{float(original_adv.amount):.2f}).", 'danger')
            return redirect(url_for('dashboard'))
        leftover = float(original_adv.amount) - total_spent
        if not items and total_spent == 0 and settle_type == 'return':
            ret = Transaction(
                trx_id=generate_trx_id(),
                type='advance_return',
                amount=float(original_adv.amount),
                method='Cash',
                description=f"Advance fully returned ({original_adv.advance_person})",
                advance_person=original_adv.advance_person,
                created_by=current_user.username,
                parent_id=original_adv.id,
                date=tx_date
            )
            db.session.add(ret)
            original_adv.is_settled = True
            db.session.commit()
            log_action("Advance Full Return", f"TRX: {original_adv.trx_id} | Person: {original_adv.advance_person} | Full Amount: ৳{original_adv.amount:.2f} | Date: {tx_date.strftime('%d %b %Y')}")
            flash("Advance fully returned to box.", "success")
            return redirect(url_for('dashboard'))
        if total_spent > 0 and not items:
            flash("Add at least one settlement expense item.", "danger")
            return redirect(url_for('dashboard'))
        created_expenses = []
        for cat, amount, desc, file in items:
            new_exp = Transaction(
                trx_id=generate_trx_id(),
                type='expense',
                amount=float(amount),
                method='Cash',
                category=cat,
                description=f"Settlement ({original_adv.advance_person}): {desc}".strip(),
                created_by=current_user.username,
                parent_id=original_adv.id,
                date=tx_date
            )
            if file and file.filename:
                stored = save_receipt_image(file)
                if stored:
                    new_exp.receipt_image = stored
                else:
                    flash('One of the receipt images was invalid. Continuing without it.', 'warning')
            db.session.add(new_exp)
            created_expenses.append(new_exp)
        if leftover > 0 and settle_type == 'carry':
            new_adv = Transaction(
                trx_id=generate_trx_id(),
                type='advance',
                amount=float(leftover),
                method='Cash',
                advance_person=original_adv.advance_person,
                description=f"Carryover from settlement of {original_adv.trx_id}",
                created_by=current_user.username,
                date=tx_date
            )
            db.session.add(new_adv)
            flash(f'Expenses recorded. Remaining ৳{leftover:.2f} kept as a new active advance.', 'warning')
        else:
            if leftover > 0:
                ret = Transaction(
                    trx_id=generate_trx_id(),
                    type='advance_return',
                    amount=float(leftover),
                    method='Cash',
                    description=f"Advance returned ({original_adv.advance_person})",
                    advance_person=original_adv.advance_person,
                    created_by=current_user.username,
                    parent_id=original_adv.id,
                    date=tx_date
                )
                db.session.add(ret)
            flash('Advance settled. Unspent cash returned to box.', 'success')
        original_adv.is_settled = True
        db.session.commit()
        settle_details = f"Settled TRX: {original_adv.trx_id} | Person: {original_adv.advance_person} | Original: ৳{original_adv.amount:.2f} | Spent: ৳{total_spent:.2f} ({len(created_expenses)} expenses)"
        if leftover > 0:
            if settle_type == 'carry':
                settle_details += f" | Leftover ৳{leftover:.2f} carried as new advance"
            else:
                settle_details += f" | Leftover ৳{leftover:.2f} returned to cash"
        else:
            settle_details += " | Fully spent"
        settle_details += f" | Date: {tx_date.strftime('%d %b %Y')}"
        log_action("Advance Settlement", settle_details)
        return redirect(url_for('dashboard'))

    # --- Standard transaction (not settle_advance) ---
    try:
        amount = float((request.form.get('amount') or '').strip())
    except (TypeError, ValueError):
        flash("Invalid amount.", "danger")
        return redirect(url_for('dashboard'))
    if amount <= 0:
        flash("Amount must be greater than 0.", "danger")
        return redirect(url_for('dashboard'))
    desc = (request.form.get('description') or '').strip()
    category = (request.form.get('category') or '').strip()
    acc_sender = (request.form.get('acc_sender') or '').strip()
    acc_receiver = (request.form.get('acc_receiver') or '').strip()
    advance_person = (request.form.get('advance_person') or '').strip()
    withdrawn_by = (request.form.get('withdrawn_by') or '').strip()
    method = 'Bank' if t_type in ('bank_in', 'withdrawal') else 'Cash'
    if t_type in ('income', 'expense'):
        if not category:
            flash("Category is required for income/expense.", "danger")
            return redirect(url_for('dashboard'))
    if t_type == 'bank_in':
        if not acc_sender or not acc_receiver:
            flash("Sender and Receiver accounts are required for Bank In.", "danger")
            return redirect(url_for('dashboard'))
    if t_type == 'withdrawal':
        if not withdrawn_by:
            flash("Withdrawn by is required for Bank Out.", "danger")
            return redirect(url_for('dashboard'))
    if t_type == 'advance':
        if not advance_person:
            flash("Person name is required for Advance.", "danger")
            return redirect(url_for('dashboard'))
    fee_pct_raw = (request.form.get('fee_percentage') or '0').strip()
    try:
        fee_pct = float(fee_pct_raw)
    except ValueError:
        flash("Invalid fee percentage.", "danger")
        return redirect(url_for('dashboard'))
    if fee_pct < 0:
        flash("Fee percentage cannot be negative.", "danger")
        return redirect(url_for('dashboard'))
    calculated_fee = 0.0
    if t_type == 'withdrawal' and fee_pct > 0:
        calculated_fee = round(amount * (fee_pct / 100.0), 2)
    if t_type == 'withdrawal':
        available_bank = float(get_bank_balance())
        if amount > available_bank:
            flash(f"Insufficient bank balance. Available: ৳{available_bank:.2f}", 'danger')
            return redirect(url_for('dashboard'))
    if t_type == 'advance':
        available_cash = float(max(0.0, get_cash_in_hand()))
        if amount > available_cash:
            flash(f"Insufficient cash in hand. Available: ৳{available_cash:.2f}", 'danger')
            return redirect(url_for('dashboard'))
    new_tx = Transaction(
        trx_id=generate_trx_id(),
        type=t_type,
        amount=amount,
        fee=calculated_fee,
        method=method,
        description=desc,
        created_by=current_user.username,
        category=category if t_type in ('income', 'expense') else None,
        acc_sender=acc_sender if t_type == 'bank_in' else None,
        acc_receiver=acc_receiver if t_type == 'bank_in' else None,
        withdrawn_by=withdrawn_by if t_type == 'withdrawal' else None,
        advance_person=advance_person if t_type == 'advance' else None,
        date=tx_date,
    )
    file = request.files.get('receipt')
    if file and file.filename:
        stored = save_receipt_image(file)
        if not stored:
            flash('Invalid receipt file. Only JPG/PNG images are allowed.', 'danger')
            return redirect(url_for('dashboard'))
        new_tx.receipt_image = stored
    db.session.add(new_tx)
    db.session.commit()
    details = f"{t_type.capitalize()} | TRX: {new_tx.trx_id} | ৳{amount:.2f} | Date: {new_tx.date.strftime('%d %b %Y')}"
    if desc:
        details += f" | Note: {desc}"
    if t_type in ('income', 'expense') and category:
        details += f" | Category: {category}"
    elif t_type == 'advance' and advance_person:
        details += f" | Person: {advance_person}"
    elif t_type == 'bank_in':
        details += f" | From: {acc_sender} → To: {acc_receiver}"
    elif t_type == 'withdrawal' and withdrawn_by:
        details += f" | Withdrawn by: {withdrawn_by}"
    log_action("Transaction Added", details)
    flash('Entry Added Successfully', 'success')
    return redirect(url_for('dashboard'))

@app.route('/admin')
@login_required
def admin_panel():
    if current_user.role != 'admin':
        return redirect(url_for('dashboard'))
    users = User.query.all()
    cats = Category.query.all()
    fees = FeeOption.query.order_by(FeeOption.amount).all()
    return render_template_string(
        HTML_TEMPLATE,
        page='admin',
        users=users,
        cats=cats,
        fees=fees
    )

@app.route('/admin/category', methods=['POST'])
@login_required
def admin_category():
    _require_csrf()
    if current_user.role != 'admin':
        return "Unauthorized"
    action = request.form.get('action')
    if action == 'add':
        name = (request.form.get('name') or '').strip()
        ctype = (request.form.get('type') or '').strip()
        if not name or ctype not in ('income', 'expense'):
            flash('Invalid category.', 'danger')
            return redirect(url_for('admin_panel'))
        db.session.add(Category(name=name, type=ctype))
        db.session.commit()
        log_action("Category Added", f"Added {ctype.capitalize()} Category: '{name}'")
    elif action == 'edit':
        cat_id = request.form.get('id')
        new_name = (request.form.get('new_name') or '').strip()
        cat = Category.query.get_or_404(cat_id)
        old_name = cat.name
        cat.name = new_name
        db.session.commit()
        log_action("Category Edited", f"Changed '{old_name}' to '{new_name}' ({cat.type})")
    elif action == 'delete':
        cat_id = request.form.get('id')
        cat = Category.query.get_or_404(cat_id)
        db.session.delete(cat)
        db.session.commit()
        log_action("Category Deleted", f"Deleted category '{cat.name}' ({cat.type})")
    return redirect(url_for('admin_panel'))

@app.route('/admin/fee', methods=['POST'])
@login_required
def admin_fee():
    _require_csrf()
    if current_user.role != 'admin':
        return "Unauthorized"
    action = request.form.get('action')
    if action == 'add':
        try:
            pct = float(request.form.get('amount'))
        except (TypeError, ValueError):
            flash('Invalid fee percent.', 'danger')
            return redirect(url_for('admin_panel'))
        if pct < 0:
            flash('Invalid fee percent.', 'danger')
            return redirect(url_for('admin_panel'))
        db.session.add(FeeOption(amount=pct))
        db.session.commit()
        log_action("Fee Added", f"Added withdrawal fee {pct}%")
    elif action == 'delete':
        fee_id = request.form.get('id')
        fee = FeeOption.query.get_or_404(fee_id)
        db.session.delete(fee)
        db.session.commit()
        log_action("Fee Deleted", f"Deleted withdrawal fee {fee.amount}%")
    return redirect(url_for('admin_panel'))

@app.route('/admin/user', methods=['POST'])
@login_required
def admin_user():
    _require_csrf()
    if current_user.role != 'admin':
        return "Unauthorized"
    action = request.form.get('action')
    if action == 'add':
        uname = (request.form.get('username') or '').strip()
        pw_raw = (request.form.get('password') or '').strip()
        role = (request.form.get('role') or 'user').strip().lower()
        if role not in ('viewer', 'user', 'admin'):
            role = 'user'
        if not uname or not pw_raw:
            flash('Invalid user data.', 'danger')
            return redirect(url_for('admin_panel'))
        existing = User.query.filter_by(username=uname).first()
        if existing:
            flash('Username already exists', 'danger')
        else:
            hashed_pw = bcrypt.generate_password_hash(pw_raw).decode('utf-8')
            db.session.add(User(username=uname, password=hashed_pw, role=role))
            db.session.commit()
            log_action("User Added", f"Created user {uname} with role {role}")
            flash('User created', 'success')
    elif action == 'delete':
        uid = int(request.form.get('id'))
        if uid == current_user.id:
            flash("You cannot delete yourself!", 'danger')
        else:
            u = User.query.get(uid)
            db.session.delete(u)
            db.session.commit()
            log_action("User Deleted", f"Deleted user {u.username}")
    elif action == 'change_role':
        uid = int(request.form.get('id'))
        new_role = (request.form.get('new_role') or 'user').strip().lower()
        if new_role not in ('viewer', 'user', 'admin'):
            flash('Invalid role.', 'danger')
            return redirect(url_for('admin_panel'))
        u = User.query.get(uid)
        if u.id == current_user.id:
            flash("You cannot change your own role.", 'danger')
            return redirect(url_for('admin_panel'))
        old_role = u.role
        u.role = new_role
        db.session.commit()
        log_action("User Role Changed", f"{u.username} from {old_role.capitalize()} to {new_role.capitalize()}")
        flash(f"Role updated for {u.username}", 'success')
    elif action == 'change_pass':
        uid = int(request.form.get('id'))
        new_pass = (request.form.get('new_password') or '').strip()
        u = User.query.get(uid)
        if u and new_pass:
            u.password = bcrypt.generate_password_hash(new_pass).decode('utf-8')
            db.session.commit()
            log_action("Password Changed", f"Password updated for {u.username}")
            flash(f"Password updated for {u.username}", 'success')
    return redirect(url_for('admin_panel'))

@app.route('/statement')
@login_required
def statement():
    if current_user.role == 'viewer':
        return redirect(url_for('dashboard'))
    page_num = request.args.get('page', 1, type=int)
    filter_type = request.args.get('type')
    q = (request.args.get('q') or '').strip()
    query = Transaction.query
    if filter_type:
        query = query.filter_by(type=filter_type)
    if q:
        if q.isdigit():
            query = query.filter((Transaction.id == int(q)) | (Transaction.trx_id.ilike(f"%{q}%")))
        else:
            query = query.filter(Transaction.trx_id.ilike(f"%{q}%"))
    pagination = query.order_by(Transaction.date.desc()).paginate(page=page_num, per_page=20, error_out=False)
    inc_cats = Category.query.filter_by(type='income').all()
    exp_cats = Category.query.filter_by(type='expense').all()
    fees = FeeOption.query.order_by(FeeOption.amount).all()
    return render_template_string(
        HTML_TEMPLATE,
        page='statement',
        pagination=pagination,
        transactions=pagination.items,
        filter_type=filter_type,
        q=q,
        inc_cats=inc_cats,
        exp_cats=exp_cats,
        fees=fees,
        db_status="Neon Cloud"
    )

@app.route('/export_csv')
@login_required
def export_csv():
    if current_user.role == 'viewer':
        return redirect(url_for('dashboard'))
    si = io.StringIO()
    cw = csv.writer(si)
    cw.writerow(['DB_ID', 'TRX_ID', 'Date', 'Added By', 'Type', 'Method', 'Details', 'Amount', 'Fee', 'Description', 'Status'])
    transactions = Transaction.query.order_by(Transaction.date.desc()).all()
    for t in transactions:
        details = ""
        if t.category:
            details = t.category
        elif t.type == 'advance':
            details = f"Advance: {t.advance_person}"
        elif t.type == 'advance_return':
            details = f"Return: {t.advance_person}"
        elif t.withdrawn_by:
            details = f"Withdrawn By: {t.withdrawn_by}"
        elif t.acc_sender:
            details = f"From: {t.acc_sender} To: {t.acc_receiver}"
        status = "-"
        if t.type == 'advance':
            status = "Settled" if t.is_settled else "Active"
        cw.writerow([
            t.id,
            t.trx_id,
            t.date.strftime('%Y-%m-%d %H:%M'),
            t.created_by,
            t.type,
            t.method,
            details,
            t.amount,
            t.fee,
            t.description,
            status
        ])
    output = make_response(si.getvalue())
    output.headers["Content-Disposition"] = f"attachment; filename=Puja_Export_{datetime.now().strftime('%Y%m%d')}.csv"
    output.headers["Content-type"] = "text/csv"
    return output

@app.route('/delete/<int:id>', methods=['POST'])
@login_required
def delete_transaction(id):
    if current_user.role != 'admin':
        flash('Only admins can delete.', 'danger')
        return redirect(url_for('statement'))
    _require_csrf()
    admin_pw = request.form.get('admin_password', '')
    if not bcrypt.check_password_hash(current_user.password, admin_pw):
        flash('Wrong Password. Could not delete.', 'danger')
        return redirect(url_for('statement'))
    tx = Transaction.query.get_or_404(id)
    if tx.type == 'advance' and tx.is_settled:
        children = Transaction.query.filter(
            (Transaction.parent_id == tx.id) &
            (Transaction.type.in_(['expense', 'advance_return']))
        ).all()
        for child in children:
            db.session.delete(child)
        tx.is_settled = False
        db.session.commit()
        log_action("Transaction Deleted", f"Reopened advance {tx.trx_id} and deleted {len(children)} associated entries")
        flash(f"Advance reopened and {len(children)} associated entries deleted.", "success")
        return redirect(url_for('statement'))
    if tx.parent_id:
        parent_adv = Transaction.query.get(tx.parent_id)
        if parent_adv and parent_adv.type == 'advance':
            siblings = Transaction.query.filter_by(parent_id=parent_adv.id).all()
            for s in siblings:
                db.session.delete(s)
            parent_adv.is_settled = False
            db.session.delete(tx)
            db.session.commit()
            log_action("Transaction Deleted", f"Deleted settlement entry for advance {parent_adv.trx_id}, reopened advance")
            flash("Settlement entries deleted and advance reopened.", "success")
            return redirect(url_for('statement'))
    db.session.delete(tx)
    db.session.commit()
    log_action("Transaction Deleted", f"Deleted {tx.type} {tx.trx_id}")
    flash('Transaction Deleted', 'success')
    return redirect(url_for('statement'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        _require_csrf()
        user = User.query.filter_by(username=request.form.get('username')).first()
        if user and bcrypt.check_password_hash(user.password, request.form.get('password')):
            login_user(user)
            flash(f'Welcome back, {user.username}!', 'success')
            return redirect(url_for('dashboard'))
        flash('Invalid Credentials', 'danger')
    return render_template_string(HTML_LOGIN)

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('Logged out successfully', 'success')
    return redirect(url_for('login'))

# -------------------- TEMPLATES --------------------
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
TEMPLATE_DIR = os.path.join(BASE_DIR, "templates_inline")

def _read_template(filename: str) -> str:
    path = os.path.join(TEMPLATE_DIR, filename)
    with open(path, "r", encoding="utf-8") as f:
        return f.read()

HTML_LOGIN = _read_template("login.html")
HTML_TEMPLATE = _read_template("main.html")

if __name__ == '__main__':
    with app.app_context():
        if RESET_DB and RESET_DB_CONFIRM:
            print_log("DATABASE RESET REQUESTED.")
            try:
                db.drop_all()
                print_log("STANDARD RESET SUCCEEDED.")
            except Exception as e:
                print_log(f"STANDARD RESET FAILED: {e}")
                print_log("FORCING MANUAL RESET...")
                with db.engine.begin() as conn:
                    conn.execute(db.text("DROP TABLE IF EXISTS audit_log CASCADE"))
                    conn.execute(db.text("DROP TABLE IF EXISTS transaction CASCADE"))
                    conn.execute(db.text("DROP TABLE IF EXISTS \"user\" CASCADE"))
                    conn.execute(db.text("DROP TABLE IF EXISTS category CASCADE"))
                    conn.execute(db.text("DROP TABLE IF EXISTS fee_option CASCADE"))
                print_log("FORCED RESET SUCCEEDED.")
        else:
            print_log("DATABASE RESET NOT REQUESTED.")
        db.create_all()
        print_log("TABLES READY.")
        if not User.query.filter_by(username='admin').first():
            pw_hash = bcrypt.generate_password_hash(INITIAL_ADMIN_PASSWORD).decode('utf-8')
            admin = User(username='admin', password=pw_hash, role='admin')
            db.session.add(admin)
            db.session.commit()
            print_log(f"ADMIN USER CREATED. USERNAME: 'admin' PASSWORD: '{INITIAL_ADMIN_PASSWORD}'")
        else:
            print_log("ADMIN USER ALREADY EXISTS.")
    app.run(host=FLASK_HOST, port=FLASK_PORT, debug=FLASK_DEBUG)
