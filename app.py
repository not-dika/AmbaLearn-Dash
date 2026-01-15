from flask import Flask, render_template, jsonify, request, redirect, url_for
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import func, distinct, UniqueConstraint
from datetime import datetime, timedelta
import random

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///:memory:'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

# --- Database Models ---
class Organization(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(120), unique=True, nullable=False)

class Course(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(120), unique=True, nullable=False)

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    last_seen = db.Column(db.DateTime, default=datetime.utcnow)
    organization_id = db.Column(db.Integer, db.ForeignKey('organization.id'), nullable=True)
    organization = db.relationship('Organization', backref=db.backref('users', lazy=True))

    def __repr__(self):
        return f'<User {self.username}>'

class Prompt(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    prompt_text = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    user = db.relationship('User', backref=db.backref('prompts', lazy=True))

    def __repr__(self):
        return f'<Prompt {self.id}>'

class DailyActiveUser(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    date = db.Column(db.Date, nullable=False)
    __table_args__ = (UniqueConstraint('user_id', 'date', name='_user_date_uc'),)


# --- Routes ---
@app.route('/')
def overview():
    # --- Analytics for Cards ---
    total_organizations = Organization.query.count()
    total_courses = Course.query.count()
    total_prompts_count = Prompt.query.count()
    total_users_count = User.query.count()

    # --- Data for Charts (last 30 days) ---
    days_range = [datetime.utcnow().date() - timedelta(days=i) for i in range(30)]
    days_range.reverse()
    
    # Prompts per day
    prompts_per_day_query = db.session.query(func.date(Prompt.created_at), func.count(Prompt.id)).filter(Prompt.created_at >= datetime.utcnow() - timedelta(days=30)).group_by(func.date(Prompt.created_at)).all()
    prompts_per_day = {date.strftime('%Y-%m-%d'): count for date, count in prompts_per_day_query}
    prompt_counts = [prompts_per_day.get(day.strftime('%Y-%m-%d'), 0) for day in days_range]

    # New users per day
    new_users_per_day_query = db.session.query(func.date(User.created_at), func.count(User.id)).filter(User.created_at >= datetime.utcnow() - timedelta(days=30)).group_by(func.date(User.created_at)).all()
    new_users_per_day = {date.strftime('%Y-%m-%d'): count for date, count in new_users_per_day_query}
    new_user_counts = [new_users_per_day.get(day.strftime('%Y-%m-%d'), 0) for day in days_range]
    
    # Active users per day (users who made a prompt)
    active_users_per_day_query = db.session.query(DailyActiveUser.date, func.count(DailyActiveUser.user_id)).filter(DailyActiveUser.date >= datetime.utcnow().date() - timedelta(days=30)).group_by(DailyActiveUser.date).all()
    active_users_per_day = {date.strftime('%Y-%m-%d'): count for date, count in active_users_per_day_query}
    active_user_counts = [active_users_per_day.get(day.strftime('%Y-%m-%d'), 0) for day in days_range]


    chart_labels = [day.strftime('%m-%d') for day in days_range]

    return render_template('index.html', 
                           total_organizations=total_organizations,
                           total_courses=total_courses,
                           total_prompts_count=total_prompts_count,
                           total_users_count=total_users_count,
                           chart_labels=chart_labels,
                           prompt_counts=prompt_counts,
                           new_user_counts=new_user_counts,
                           active_user_counts=active_user_counts)


# --- Models Route ---
@app.route('/models')
def models():
    return render_template('models.html')

# --- Organization Routes ---
@app.route('/organizations')
def organizations():
    all_orgs = Organization.query.all()
    return render_template('organizations.html', organizations=all_orgs)

@app.route('/add_organization', methods=['POST'])
def add_organization():
    org_name = request.form['organization_name']
    if org_name:
        new_org = Organization(name=org_name)
        db.session.add(new_org)
        db.session.commit()
    return redirect(url_for('organizations'))

@app.route('/edit_organization/<int:org_id>', methods=['GET', 'POST'])
def edit_organization(org_id):
    org = Organization.query.get_or_404(org_id)
    if request.method == 'POST':
        org.name = request.form['organization_name']
        db.session.commit()
        return redirect(url_for('organizations'))
    return render_template('edit_organization.html', org=org)

@app.route('/delete_organization/<int:org_id>')
def delete_organization(org_id):
    org = Organization.query.get_or_404(org_id)
    db.session.delete(org)
    db.session.commit()
    return redirect(url_for('organizations'))

# --- User Routes ---
@app.route('/users')
def users():
    all_users = User.query.all()
    all_orgs = Organization.query.all()
    return render_template('users.html', users=all_users, organizations=all_orgs)

@app.route('/add_user', methods=['POST'])
def add_user():
    username = request.form['username']
    org_id = request.form.get('organization_id')
    if username:
        new_user = User(username=username, organization_id=org_id if org_id else None)
        db.session.add(new_user)
        db.session.commit()
    return redirect(url_for('users'))

@app.route('/edit_user/<int:user_id>', methods=['GET', 'POST'])
def edit_user(user_id):
    user = User.query.get_or_404(user_id)
    all_orgs = Organization.query.all()
    if request.method == 'POST':
        user.username = request.form['username']
        user.organization_id = request.form.get('organization_id')
        db.session.commit()
        return redirect(url_for('users'))
    return render_template('edit_user.html', user=user, organizations=all_orgs)

@app.route('/delete_user/<int:user_id>')
def delete_user(user_id):
    user = User.query.get_or_404(user_id)
    db.session.delete(user)
    db.session.commit()
    return redirect(url_for('users'))


@app.route('/feedback')
def feedback():
    """Renders the feedback page with placeholder data."""
    # Placeholder data
    feedback_data = [
        {'user': 'user1', 'comment': 'This course was great!', 'course_name': 'Intro to AI', 'sentiment': 'Good'},
        {'user': 'user2', 'comment': 'I did not like this course.', 'course_name': 'Advanced Machine Learning', 'sentiment': 'Bad'},
        {'user': 'user3', 'comment': 'The instructor was very clear.', 'course_name': 'Data Science 101', 'sentiment': 'Good'},
        {'user': 'user4', 'comment': 'The course content was outdated.', 'course_name': 'Python for Beginners', 'sentiment': 'Bad'},
    ]
    return render_template('feedback.html', feedback_data=feedback_data)

if __name__ == '__main__':
    with app.app_context():
        # Since the user said they dropped the tables, we will always recreate and seed.
        # For production, you'd want a more robust migration system.
        print("Dropping all tables and recreating them...")
        db.drop_all()
        db.create_all()
        print("Database is ready.")
    app.run(debug=True)
