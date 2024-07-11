from flask import Flask, render_template, request, redirect, url_for, session, flash
from pymongo import MongoClient
from bson.objectid import ObjectId
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, IntegerField
from wtforms.validators import InputRequired, Length
from werkzeug.security import generate_password_hash, check_password_hash
import re

app = Flask(__name__)

app.secret_key = 'abc@123'

mongo_url = "mongodb://localhost:27017/"

client = MongoClient(mongo_url)

db = client.School
collection = db.student_details
collection_signup = db.signup


class User:
    def __init__(self, username, password):
        self.username = username
        self.password = password


def is_password_strong(password):
    if len(password) < 8 or \
            not re.search(r"[a-z]", password) or \
            not re.search(r"[A-Z]", password) or \
            not re.search(r"\d", password) or \
            not re.search(r"[!@#$%^&*()-+{}|\"<>]?", password):
        return False
    return True


from wtforms.validators import InputRequired, Length

class signinform(FlaskForm):
    username = StringField('Username', validators=[InputRequired(), Length(min=4, max=20)])
    password = PasswordField('Password', validators=[InputRequired()])
    submit = SubmitField('Sign Up')

class loginform(FlaskForm):
    username = StringField('Username', validators=[InputRequired(), Length(min=4, max=20)])
    password = PasswordField('Password', validators=[InputRequired(), Length(min=8, max=15)])
    submit = SubmitField('Login')



@app.route('/signup/', methods=['GET', 'POST'])
def signup():
    form = signinform()
    if form.validate_on_submit():
        username = form.username.data 
        password = form.password.data
        
        
        if not is_password_strong(password):
            flash('Password should be 8 characters long with upper case, lower case, and special characters.', 'danger')
            return redirect(url_for('signup'))
        
        hashed_password = generate_password_hash(password)

        old_user = collection_signup.find_one({"Username": username})
        if old_user:
            flash('Username already taken. Please choose a different one.', 'danger')
            return render_template('signup.html', form=form)
        
        collection_signup.insert_one({
            "Username": username,          
            "Password": hashed_password
        })
        
        flash('Signup Successful', 'success')
        return redirect(url_for('login'))
    
    return render_template('signup.html', form=form)


@app.route('/login/', methods=['GET', 'POST'])
def login():
    form = loginform()
    if form.validate_on_submit():
        username = form.username.data
        password = form.password.data
        
        login_detail = collection_signup.find_one({"Username": username})
        if login_detail and check_password_hash(login_detail["Password"], password):
            user = User(username=login_detail["Username"], password=login_detail["Password"])
            session['name'] = user.username
            return redirect(url_for('table'))
        
        flash('Invalid Credentials', 'danger')
    
    return render_template('login.html', form=form)


@app.route('/')
def home():
    return render_template('base.html')


@app.route('/table/')
def table():
    if 'name' not in session:
        flash('You need to be logged in to view the table.', 'danger')
        return redirect(url_for('login'))

    username = session['name']
    data = collection.find({"Username": username}) 
    return render_template('index.html', data=data)


@app.route('/add/', methods=['GET', 'POST'])
def add():
    if request.method == 'POST':
        if 'name' not in session:
            flash('You need to be logged in to add details.', 'danger')
            return redirect(url_for('login'))

        username = request.form["name"]
        age = request.form["age"]
        mob = request.form["mob"]
        mail = request.form["mail"]

        info = {
            "Name": username,
            "Age": age,
            "Mob": mob,
            'Email': mail,
            "Username": session['name'] 
        }
        collection.insert_one(info)
        return redirect(url_for('table'))
    return render_template('add.html')


@app.route('/edit/<string:id>', methods=['GET', 'POST'])
def edit(id):
    if 'name' not in session:
        flash('You need to be logged in to edit details.', 'danger')
        return redirect(url_for('login'))

    username = session['name']
    existing_data = collection.find_one({"_id": ObjectId(id), "Username": username})

    if not existing_data:
        flash('You are not authorized to edit this record.', 'danger')
        return redirect(url_for('table'))

    if request.method == 'POST':
        name = request.form.get('name')
        age = request.form.get('age')
        mob = request.form.get('mob')
        mail = request.form.get('mail')

        collection.update_one({"_id": ObjectId(id)}, {"$set": {"Name": name, "Age": age, "Mob": mob, 'Email': mail}})
        flash('Details updated successfully.', 'success')
        return redirect(url_for('table'))

    return render_template('edit.html', data=existing_data)


@app.route('/delete/<string:id>')
def delete(id):

    username = session['name']
    existing_data = collection.find_one({"_id": ObjectId(id), "Username": username})

    if not existing_data:
        flash('You are not authorized to delete this record.', 'danger')
        return redirect(url_for('table'))

    collection.delete_one({"_id": ObjectId(id)})
    return redirect(url_for('table'))


@app.route('/logout/')
def logout():
    session.pop('name', None)
    flash('Logged out successfully', 'success')
    return redirect(url_for('login'))


if __name__ == '__main__':
    app.run(debug=True)
