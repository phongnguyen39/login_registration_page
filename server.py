# Login and Registration server file

from flask import Flask, render_template, redirect, request, session, flash
from mysqlconnection import connectToMySQL
from flask_bcrypt import Bcrypt
import re

app = Flask(__name__)
app.secret_key = 'secret'
bcrypt = Bcrypt(app)

# add session data

EMAIL_REGEX = re.compile(r'^[a-zA-z0-9.+_-]+@[a-zA-z0-9.+_-]+\.[a-zA-Z]+$')


@app.route('/')
def index():
    return render_template('index.html')


@app.route('/registration', methods=['post'])
def registration():
    print(request.form['first_name'], request.form['last_name'],
          request.form['emails'], request.form['password'])

    session['first_name']=request.form['first_name']
    session['last_name']=request.form['last_name'],
    session['emails']=request.form['emails']

    is_valid = True

    if len(request.form['first_name']) < 3:
        is_valid = False
        print('*'*10, False, '*'*10)
        flash('Please enter a first name that is at least two characters long')
        return redirect('/')

    if len(request.form['last_name']) < 3:
        is_valid = False
        print('*'*10, False, '*'*10)
        flash('Please enter a last name that is at least two characters long')
        return redirect('/')

    if not EMAIL_REGEX.match(request.form['emails']):
        flash(f'"{request.form["emails"]}"" is invalid')
        return redirect('/')

    if len(request.form['password']) < 8:
        is_valid = False
        print('*'*10, False, '*'*10)
        flash('Please enter a password name that is at least 8 characters long')
        return redirect('/')

    if request.form['password'] != request.form['password_conf']:
        is_valid = True
        flash('Make sure your passwords match')
        return redirect('/')

    if is_valid:
        login_reg = connectToMySQL('login_reg')
        query = 'INSERT INTO login_reg (first_names, last_names, emails, passwords_hash) VALUES (%(first_name)s,%(last_name)s,%(email)s,%(password)s);'
        data = {
            'first_name': request.form['first_name'],
            'last_name': request.form['last_name'],
            'email': request.form['emails'],
            'password': bcrypt.generate_password_hash(request.form['password'])
        }

        login_reg = login_reg.query_db(query, data)
        flash("You've successfully registered!")
        return redirect('/success')


@app.route('/login', methods=['post'])
def login():

    is_valid = True

    if not EMAIL_REGEX.match(request.form['emails']):
        flash(f'"{request.form["emails"]}"" is invalid')
        return redirect('/')

    login_reg = connectToMySQL('login_reg')
    query = 'SELECT emails, passwords_hash FROM login_reg WHERE emails = %(emails)s'
    data = {
        'emails': request.form['emails']
    }
    
    logins = login_reg.query_db(query, data)
    print(logins)

    if len(logins) ==0:
        flash("Failed login! Email not found.")
        return redirect('/')
    
    if logins:
        if bcrypt.check_password_hash(logins[0]['passwords_hash'], request.form['password']):
            print("*"*20,'Whoopie')
            return redirect('/success')
        else:
            flash("Failed login! Password was incorrect.")
            return redirect('/')

@app.route('/success')
def success():
    return render_template('success.html')


@app.route('/logout', methods=['post'])
def logout():
    session.clear()
    print(session.items())
    return redirect('/')


if __name__ == '__main__':
    app.run(debug=True)
