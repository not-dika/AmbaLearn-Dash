from flask import Flask, render_template, jsonify, request, redirect, url_for, flash, session
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, login_user, logout_user, login_required, current_user
from flask_bcrypt import Bcrypt
from sqlalchemy import func, desc
from datetime import datetime, timedelta
import os
import requests
from models import db, User, Organization, ActiveUser, Feedback, PromptStat, ExamScore, CourseMetadata
from sentiment import analyzer

app = Flask(__name__)
# Secure secret key
app.config["SECRET_KEY"] = os.urandom(24)
API_BASE_URL = "http://localhost:8080"

# --- Database Configuration ---
# Connect to the SAME database as AmbaLearn-Engine
app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql+pymysql://root@localhost/ambalearn'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# --- Extensions ---
db.init_app(app)
bcrypt = Bcrypt(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

# --- Auth Helper ---
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(user_id)

# --- Routes ---

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('overview'))

    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        
        # Delegate login to Engine to run side-effects (Active User Tracking, Last Login)
        try:
            # Note: We use json kwarg for the ost
            engine_resp = requests.post(
                API_BASE_URL + "/login", 
                json={"email": email, "password": password},
                # We don't need to verify SSL on localhost, though it's HTTP anyway
            )
            
            if engine_resp.status_code == 200:
                # Engine login successful
                # Since we share the DB, we can just fetch the user here
                # And since we share the SECRET_KEY, our session cookie *might* be compatible if domains match.
                
                # Capture authentication cookies for future requests to Engine
                session['engine_cookies'] = engine_resp.cookies.get_dict()
                
                user = User.query.filter_by(email=email).first()
                if user:
                     if user.role not in ['admin', 'manager']:
                        flash('Access denied. Admin or Manager privileges required.', 'error')
                     else:
                        login_user(user)
                        if user.role == 'manager':
                            return redirect(url_for('my_organization'))
                        return redirect(url_for('overview'))
                else:
                    flash('Login successful on engine but user not found locally.', 'error')

            else:
                 flash('Invalid email or password (Engine rejected)', 'error')

        except requests.RequestException as e:
            # Fallback or Error
            print(f"Engine connection failed: {e}")
            flash('Could not connect to authentication server.', 'error')
            
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

@app.route('/')
@login_required
def overview():
    if current_user.role != 'admin':
        return redirect(url_for('my_organization'))

    # --- Analytics for Cards ---
    total_organizations = Organization.query.count()
    
    # Fetch Course Stats from DB directly
    total_courses = CourseMetadata.query.count()

    total_prompts_count = db.session.query(func.sum(PromptStat.amount)).scalar() or 0
    total_users_count = User.query.count()

    # --- Data for Charts (last 30 days) ---
    days_range = [datetime.utcnow().date() - timedelta(days=i) for i in range(30)]
    days_range.reverse()
    
    # Prompts per day
    prompts_query = PromptStat.query.filter(PromptStat.date >= datetime.utcnow().date() - timedelta(days=30)).all()
    prompts_map = {p.date: p.amount for p in prompts_query}
    prompt_counts = [prompts_map.get(day, 0) for day in days_range]

    # New users per day
    new_users_query = db.session.query(func.date(User.registered_at), func.count(User.id))\
        .filter(User.registered_at >= datetime.utcnow() - timedelta(days=30))\
        .group_by(func.date(User.registered_at)).all()
    new_users_map = {date: count for date, count in new_users_query}
    new_user_counts = [new_users_map.get(day, 0) for day in days_range]
    
    # Active users per day
    active_users_query = ActiveUser.query.filter(ActiveUser.date >= datetime.utcnow().date() - timedelta(days=30)).all()
    active_users_map = {a.date: a.amount for a in active_users_query}
    active_user_counts = [active_users_map.get(day, 0) for day in days_range]

    chart_labels = [day.strftime('%m-%d') for day in days_range]

    return render_template('index.html', 
                           total_organizations=total_organizations,
                           total_courses=total_courses, # From CourseMetadata DB
                           total_prompts_count=total_prompts_count,
                           total_users_count=total_users_count,
                           chart_labels=chart_labels,
                           prompt_counts=prompt_counts,
                           new_user_counts=new_user_counts,
                           active_user_counts=active_user_counts,
                           user=current_user)


@app.route('/models')
@login_required
def models():
    if current_user.role != 'admin':
        flash('Access restricted to admins.', 'error')
        return redirect(url_for('my_organization'))
    return render_template('models.html', user=current_user)

# --- Course Routes (Disabled/Dummy for now as they are JSON based in Engine) ---
@app.route('/generate_course_action', methods=['POST'])
@login_required
def generate_course_action():
    topic = request.form.get('topic')
    if not topic:
        flash('Topic is required.', 'error')
        return redirect(url_for('courses'))

    # Determine organization_id
    org_id = current_user.organization_id
    if not org_id and current_user.role == 'manager':
         flash('You are not assigned to an organization.', 'error')
         return redirect(url_for('courses'))
    
    # If admin (without org) is trying to generate, we might need a context. 
    # For now, let's assume this action is primarily for managers or users within an org.
    if not org_id:
         flash('Organization context required to generate course.', 'error')
         return redirect(url_for('courses'))

    # Retrieve stored cookies
    cookies = session.get('engine_cookies')
    if not cookies:
        flash('Session expired or engine connection lost. Please login again.', 'error')
        return redirect(url_for('login'))

    try:
        url = f"{API_BASE_URL}/organization/{org_id}/generate_course"
        resp = requests.post(
            url,
            json={"topic": topic},
            cookies=cookies  # Pass the authentication cookies
        )
        
        if resp.status_code in [200, 201]:
            flash(f"Course generation started for topic: {topic}", 'success')
        else:
             # Try to get error message from JSON
            try:
                err_msg = resp.json().get('error', 'Unknown Error')
            except:
                err_msg = resp.text
            flash(f"Failed to generate course: {err_msg}", 'error')

    except requests.RequestException as e:
        flash(f"Connection to Engine failed: {e}", 'error')

    return redirect(url_for('courses'))

@app.route('/courses')
@login_required
def courses():
    # If manager, show only their org's courses
    if current_user.role == 'manager' and not current_user.organization_id:
         flash('You are not assigned to an organization.', 'warning')
         return render_template('courses.html', courses=[], user=current_user)
    
    # If admin viewing courses, they probably need to select an org first or view all? 
    # For simplicity, if Admin has an org_id set (mimicking manager view), show that.
    # Otherwise, show empty or all (requires new Engine endpoint). 
    # Let's assume Admin acts as Manager of their selected org context.
    
    org_id = current_user.organization_id
    if not org_id:
         # TODO: Admin view all courses across all orgs?
         return render_template('courses.html', courses=[], user=current_user)

    courses_list = []
    
    # Fetch from Engine
    try:
        cookies = session.get('engine_cookies')
        if cookies:
            resp = requests.get(
                f"{API_BASE_URL}/organization/{org_id}/courses",
                cookies=cookies
            )
            if resp.status_code == 200:
                courses_list = resp.json()
            else:
                print(f"Failed to fetch courses: {resp.status_code} - {resp.text}")
    except Exception as e:
        print(f"Error fetching courses: {e}")

    return render_template('courses.html', courses=courses_list, user=current_user)

@app.route('/my_organization')
@login_required
def my_organization():
    if not current_user.organization_id:
        # If admin tries to access but has no org, or logic error
        if current_user.role == 'admin':
             flash("You are an admin without an organization. Navigate to 'Organizations' to manage them.", "info")
             return redirect(url_for('overview'))
        return render_template('my_organization.html', org=None, user=current_user)
    
    org = Organization.query.get(current_user.organization_id)
    # Calcluate stats
    member_count = len(org.users)
    course_count = 0 # Placeholder until course link is established
    
    return render_template('my_organization.html', org=org, member_count=member_count, course_count=course_count, user=current_user)

@app.route('/my_organization/members')
@login_required
def organization_members():
    if not current_user.organization_id:
        return redirect(url_for('my_organization'))
    
    org = Organization.query.get(current_user.organization_id)
    return render_template('organization_members.html', org=org, members=org.users, user=current_user)


@app.route('/edit_course/<string:course_uid>', methods=['GET', 'POST'])
@login_required
def edit_course(course_uid):
    org_id = current_user.organization_id
    if not org_id:
        flash("Organization context missing", "error")
        return redirect(url_for('courses'))
    
    cookies = session.get('engine_cookies')
    if not cookies:
        flash("Please login again to sync with Engine.", "error")
        return redirect(url_for('login'))

    # CHECK IF NEW COURSE (We use 'new' or '0' as identifier for creation)
    is_new = (course_uid == '0' or course_uid == 'new')
    
    if request.method == 'POST':
        # Construct JSON from form
        # Form data: course_title, difficulty, description
        # Steps data: step_title_0, step_objective_0, step_content_0 ...
        
        course_data = {
            "course_title": request.form.get("course_title"),
            "difficulty": request.form.get("difficulty"),
            "description": request.form.get("description"),
            "steps": []
        }
        
        # Parse steps
        # We need to iterate until we find no more steps
        idx = 0
        while True:
            if f"step_title_{idx}" not in request.form and f"step_objective_{idx}" not in request.form:
                # Try checking if we skipped one? No, assuming sequential from JS for now or just collecting all keys
                # Better approach: Iterate keys or use a reasonably high max
                # Given the JS implementation in template, indices might be sparse if deleted.
                # Let's iterate keys to be safe?
                # Actually, simply checking up to 50 is safe enough for a prototype.
                if idx > 50: break 
                
            title = request.form.get(f"step_title_{idx}")
            if title: # Only add if title exists (simple validation)
                 obj = request.form.get(f"step_objective_{idx}")
                 content_raw = request.form.get(f"step_content_{idx}", "")
                 content_list = [c.strip() for c in content_raw.split(',') if c.strip()]
                 
                 course_data["steps"].append({
                     "step_number": len(course_data["steps"]) + 1,
                     "title": title,
                     "objective": obj,
                     "content_outline": content_list
                 })
            
            # If we missed a key but there are more (sparse array due to deletion), we continue?
            # The JS `stepIndex` increments. If I delete step 1, I have step 0 and 2.
            # So we should check if we ran out of KEYS in the form that start with step_title_
            # Optimization: check up to max index found in keys.
            idx += 1
            if idx > 100: break # Safety break

        try:
            if is_new:
                resp = requests.post(f"{API_BASE_URL}/organization/{org_id}/add_course", json=course_data, cookies=cookies)
            else:
                resp = requests.post(f"{API_BASE_URL}/organization/{org_id}/edit_course/{course_uid}", json=course_data, cookies=cookies)
            
            if resp.status_code in [200, 201]:
                flash("Course saved successfully.", "success")
                return redirect(url_for('courses'))
            else:
                flash(f"Error saving course: {resp.text}", "error")

        except Exception as e:
            flash(f"Connection error: {e}", "error")
            
    # GET REQUEST
    course = None
    if not is_new:
        try:
            resp = requests.get(f"{API_BASE_URL}/organization/{org_id}/course/{course_uid}", cookies=cookies)
            if resp.status_code == 200:
                course = resp.json()
            else:
                flash("Course not found or error loading.", "error")
                return redirect(url_for('courses'))
        except Exception as e:
            flash(f"Connection error loading course: {e}", "error")
            return redirect(url_for('courses'))

    return render_template('edit_course.html', course=course, course_id=course_uid, user=current_user)

@app.route('/delete_course/<string:course_uid>')
@login_required
def delete_course(course_uid):
    org_id = current_user.organization_id
    if not org_id:
         flash("Organization context missing", "error")
         return redirect(url_for('courses'))

    cookies = session.get('engine_cookies')
    try:
        resp = requests.delete(f"{API_BASE_URL}/organization/{org_id}/course/{course_uid}", cookies=cookies)
        
        if resp.status_code == 200:
            flash("Course deleted successfully", "success")
        else:
            flash(f"Failed to delete course: {resp.text}", "error")
    except Exception as e:
        flash(f"Connection error: {e}", "error")
        
    return redirect(url_for('courses'))

# --- Organization Routes ---
@app.route('/organizations')
@login_required
def organizations():
    all_orgs = Organization.query.all()
    all_users = User.query.all()
    return render_template('organizations.html', organizations=all_orgs, users=all_users, user=current_user)

@app.route('/add_organization', methods=['POST'])
@login_required
def add_organization():
    org_name = request.form['organization_name']
    description = request.form.get('description', '')
    if org_name:
        new_org.invitation_code = generate_invitation_code()
        
        manager_id = request.form.get('manager_id')
        if manager_id:
            new_org.manager_id = manager_id
            # Auto-join manager and update role
            manager_user = User.query.get(manager_id)
            if manager_user:
                manager_user.organization = new_org
                if manager_user.role != 'admin':
                    manager_user.role = 'manager'
        # If no manager selected, default to current user if they are creating it? 
        # Requirement says "can be blank to set the manager later". 
        # "Assuming current admin is the manager for now" was old logic.
        # If blank, manager_id remains None (as defined in Model default or we set it explicitly)
        elif not new_org.manager_id: 
            # If we didn't set it above, ensure it's None. 
            # The model default for migration might be an issue if we don't set it.
            new_org.manager_id = None

        db.session.add(new_org)
        # We need to add/commit new_org first to get an ID? 
        # Actually SQLAlchemy handles object references. 
        # Setting manager_user.organization = new_org works before commit.
        
        db.session.commit()
    return redirect(url_for('organizations'))

def generate_invitation_code(length=6):
    """Generates a unique random string of a given length."""
    alphabet = string.ascii_letters + string.digits
    while True:
        code = ''.join(secrets.choice(alphabet) for _ in range(length))
        if not Organization.query.filter_by(invitation_code=code).first():
            return code

@app.route('/organization/<string:org_id>')
@login_required
def view_organization(org_id):
    org = Organization.query.get_or_404(org_id)
    return render_template('view_organization.html', org=org, user=current_user)

@app.route('/edit_organization/<string:org_id>', methods=['GET', 'POST'])
@login_required
def edit_organization(org_id):
    org = Organization.query.get_or_404(org_id)
    all_users = User.query.all()
    if request.method == 'POST':
        org.name = request.form['organization_name']
        org.description = request.form.get('description')
        
        manager_id = request.form.get('manager_id')
        
        # Check if manager changed
        if manager_id != org.manager_id:
             # Handle Old Manager
             if org.manager_id:
                 old_manager = User.query.get(org.manager_id)
                 if old_manager and old_manager.role != 'admin':
                     old_manager.role = 'user'
            
             # Handle New Manager
             if manager_id:
                 org.manager_id = manager_id
                 new_manager = User.query.get(manager_id)
                 if new_manager:
                     new_manager.organization = org # Auto-join
                     if new_manager.role != 'admin':
                         new_manager.role = 'manager'
             else:
                 org.manager_id = None
        
        db.session.commit()
        return redirect(url_for('organizations'))
    return render_template('edit_organization.html', org=org, users=all_users, user=current_user)

@app.route('/delete_organization/<string:org_id>')
@login_required
def delete_organization(org_id):
    org = Organization.query.get_or_404(org_id)
    # Logic to handle users in this org? Set to null?
    # Users will have org_id set to null automatically if not defined otherwise, but let's be safe
    # Actually, SQLAlchemy might error if foreign keys are strict.
    # For now, simplistic delete.
    db.session.delete(org)
    db.session.commit()
    return redirect(url_for('organizations'))

# --- User Routes ---
@app.route('/users')
@login_required
def users():
    all_users = User.query.all()
    all_orgs = Organization.query.all()
    return render_template('users.html', users=all_users, organizations=all_orgs, user=current_user)

@app.route('/add_user', methods=['POST'])
@login_required
def add_user():
    # In this system, users usually register themselves.
    # Creating a user manually requires hashing the password.
    username = request.form['username']
    email = request.form['email'] # Assuming form has email now
    password = request.form['password']
    org_id = request.form.get('organization_id')
    
    if username and email and password:
        hashed_pw = bcrypt.generate_password_hash(password).decode('utf-8')
        role = request.form.get('role', 'user')
        new_user = User(
            username=username, 
            email=email, 
            password_hash=hashed_pw,
            role=role,
            organization_id=org_id if org_id else None
        )
        db.session.add(new_user)
        db.session.commit()
    return redirect(url_for('users'))

@app.route('/edit_user/<string:user_id>', methods=['GET', 'POST'])
@login_required
def edit_user(user_id):
    user_to_edit = User.query.get_or_404(user_id)
    all_orgs = Organization.query.all()
    if request.method == 'POST':
        user_to_edit.username = request.form['username']
        
        # Only update password if provided
        new_password = request.form.get('password')
        if new_password:
             user_to_edit.password_hash = bcrypt.generate_password_hash(new_password).decode('utf-8')

        org_id = request.form.get('organization_id')
        user_to_edit.organization_id = org_id if org_id else None
        
        role = request.form.get('role')
        if role:
            user_to_edit.role = role
        
        db.session.commit()
        return redirect(url_for('users'))
    return render_template('edit_user.html', user=user_to_edit, organizations=all_orgs, current_user=current_user)

@app.route('/delete_user/<string:user_id>')
@login_required
def delete_user(user_id):
    user_to_delete = User.query.get_or_404(user_id)
    if user_to_delete.id == current_user.id:
        flash("Cannot delete yourself!", "error")
        return redirect(url_for('users'))
        
    db.session.delete(user_to_delete)
    db.session.commit()
    return redirect(url_for('users'))


@app.route('/feedback')
@login_required
def feedback():
    if current_user.role != 'admin':
        return "Access Forbidden: Admins Only", 403

    feedback_data = Feedback.query.order_by(desc(Feedback.created_at)).all()
    return render_template('feedback.html', feedback_data=feedback_data)

@app.route('/analyze_feedback', methods=['POST'])
@login_required
def analyze_feedback():
    if current_user.role != 'admin':
        return "Access Forbidden", 403

    feedbacks = Feedback.query.filter_by(sentiment='unknown').all()
    count = 0
    for fb in feedbacks:
        # Re-analyze
        new_sentiment = analyzer.analyze(fb.comment)
        if fb.sentiment != new_sentiment:
            fb.sentiment = new_sentiment
            count += 1
    
    if count > 0:
        db.session.commit()
        flash(f"Analyzed and updated {count} feedback entries.", "success")
    else:
        flash("Sentiment analysis up to date.", "info")

    return redirect(url_for('feedback'))

if __name__ == '__main__':
    # No more drop_all() !
    app.run(debug=True, port=8081, host='0.0.0.0')

