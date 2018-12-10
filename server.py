from flask import Flask, render_template, session, request, redirect, flash
from flask_bcrypt import Bcrypt    
from mysqlconnection import connectToMySQL
import re

app = Flask(__name__)
app.secret_key = "ThisIsSecret!"
bcrypt = Bcrypt(app)
mysql = connectToMySQL('login')

EMAIL_REGEX = re.compile(r'^[a-zA-Z0-9.+_-]+@[a-zA-Z0-9._-]+\.[a-zA-Z]+$')


@app.route("/")
def index():
    debugHelp("INDEX METHOD")
    return render_template("index.html")


@app.route("/register", methods=['POST'])
def register():
    # Let's add validtion rules
    if len(request.form['first_name']) < 1:
        flash("First name cannot be blank!", 'first_name')
    elif len(request.form['first_name']) < 3:
        flash("First name must be 2+ characters", 'first_name')

    if len(request.form['last_name']) < 1:
        flash("Last name cannot be blank!", 'last_name')
    elif len(request.form['first_name']) < 3:
        flash("Last name must be 2+ characters", 'last_name')

    if len(request.form['email']) < 1:
        flash("Email cannot be blank!", 'email')
    elif not EMAIL_REGEX.match(request.form['email']):
        flash("Invalid Email Address!", 'email')

    if len(request.form['password']) < 1:
        flash("Password cannot be blank!", 'password')
    elif len(request.form['password']) < 8:
        flash("Password must be 8+ characters", 'password')
    
    if len(request.form['password_confirm']) < 1:
        flash("Password confirmation cannot be blank!", 'password_confirm')
    elif request.form['password_confirm'] != request.form['password']:
        flash("Password confirmation should be tha same like password!", 'password_confirm')
    
    # debugHelp('RESERVE METHOD')
    if '_flashes' in session.keys():
        bed_first = session["first_name"]
        bed_last = request.form['last_name']
        return redirect("/")

    else:
        query = "SELECT * FROM users WHERE email = %(email)s;"
        data = {"email": request.form["email"]}
        result = mysql.query_db(query, data)
        session['user_info'] = result
        if result:
            flash("Email had been already accessed!", 'email')
            return redirect("/")
        else:    
            session["first_name"] = request.form['first_name']
            pw_hash = bcrypt.generate_password_hash(request.form['password'])  
            print(pw_hash)  
            query = "INSERT INTO users (first_name, last_name, email, password, created_at, updated_at) " \
                    "VALUES (%(first_name)s, %(last_name)s, %(email)s,%(password)s, NOW(), NOW());"
            data = {
                'first_name': request.form['first_name'],
                'last_name':  request.form['last_name'],
                'email': request.form['email'],
                'password': pw_hash
            }
            mysql.query_db(query, data)
            return redirect('/wall')


@app.route('/login', methods=['POST'])
def login():
    # see if the username provided exists in the database
    email = request.form['email1']
    password = request.form['password1']
    if len(email) < 1:
        flash("Email cannot be empty!", 'email1')
    elif not EMAIL_REGEX.match(email):
        flash("Invalid Email Address!", 'email1')
      
    mysql = connectToMySQL("login")
    query = "SELECT * FROM users WHERE email = %(email)s;"
    data = {"email": request.form["email1"]}
    result = mysql.query_db(query, data)
    session['user_info'] = result
    if result:
        if bcrypt.check_password_hash(result[0]['password'], request.form['password1']):
            session['user_info'] = result[0]['id']
            session["first_name"] = result[0]['first_name']
            return redirect('/wall')
    flash("You could not be logged in", 'email1')
    return redirect("/")


@app.route("/wall")
def wall():
    if "user_info" in session:
        messages = mysql.query_db(
            'SELECT messages.message, '
            'messages.id,'
            'messages.created_at, ' 
            'messages.user_id, '
            'first_name '
            'FROM messages JOIN users ON messages.user_id = users.id')
        comments = mysql.query_db(
            'SELECT comments.comment, '
            'comments.id, '
            'comments.created_at, '
            'comments.message_id, '
            'comments.user_id, '
            'users.first_name, '
            'users.last_name '
            'FROM comments JOIN users ON comments.user_id = users.id')
        return render_template('wall.html', messages=messages, comments=comments)
    else:
        flash("You must login first!", "error")
        return redirect('/')

 
@app.route("/create_msg", methods=['POST'])
def create_msg():
    message = request.form['message']
    user_id = session['user_info']
    print(message)
    print(user_id)
    if len(message) > 0:
        query = "INSERT INTO messages (user_id, message, created_at, updated_at) " \
                "VALUES (%(user_id)s, %(message)s, NOW(), NOW())"
        
        data = {
            'user_id': user_id,
            'message': message
        }
        print(data)
        mysql.query_db(query, data)
    
    return redirect('/wall')


@app.route("/create_comment", methods=['POST'])
def create_com():
    comment = request.form['comment']
    user_id = session['user_info']
    message_id = request.form['message_id']
    if len(comment) > 0:
        query = "INSERT INTO comments (user_id, comment, message_id, created_at, updated_at) " \
                "VALUES (%(user_id)s, %(comment)s, %(message_id)s, NOW(), NOW())"
        data = {
            'user_id': user_id,
            'comment': comment,
            'message_id': message_id
        }
        print(data)
        mysql.query_db(query, data)
    return redirect('/wall')


@app.route("/delete_msg", methods=['GET', 'POST'])
def delete_msg():
    comments_query = "DELETE FROM comments WHERE comments.message_id = %(message_id)s"
    message_query = "DELETE FROM messages WHERE messages.id = %(message_id)s"
    data = {
        'message_id': request.form['message_id'],
    }
    mysql.query_db(comments_query, data)
    mysql.query_db(message_query, data)
    return redirect('/wall')


@app.route('/clear')
def clear():
    session.clear()
    return redirect('/')


def debugHelp(message=""):
    print("\n\n-----------------------", message, "--------------------")
    print('REQUEST.FORM:', request.form)
    print('SESSION:', session)


if __name__ == "__main__":
    app.run(debug=True)