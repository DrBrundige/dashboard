from flask import Flask, render_template, redirect, request, flash, session
from src.mysqlconnection import connectToMySQL
from flask_bcrypt import Bcrypt

app = Flask(__name__)
app.secret_key = 'bigm00d'
bcrypt = Bcrypt(app)

from datetime import datetime, timedelta, date


@app.route('/')
def index():
	if 'access' not in session:
		session['access'] = -1

	return render_template('dashboard_login.html')


@app.route('/login', methods=['POST'])
def login():
	mysql = connectToMySQL('dashboard')

	# session['email'] = request.form['email']

	query = "SELECT * FROM users WHERE username=%(e)s"
	data = {
		"e": request.form['name'],
	}
	username = mysql.query_db(query, data)
	print(f"Username: {username}")

	if len(username) == 0:
		print("User not found!")
		flash("Could not log in!", 'login')
	else:
		if bcrypt.check_password_hash(username[0]['password'], request.form['password']):
			print("Passwords match!")
			session['is_logged'] = True
			session['permission'] = username[0]['permission']
			session['id'] = username[0]['id']
			session['max_latest'] = int(username[0]['max_latest'])
			session['refresh'] = int(username[0]['refresh'])
			return redirect('/dashboard')
		else:
			print("Password incorrect!")
			flash("Could not log in!", 'login')

	return redirect('/')


@app.route('/dashboard')
def dashboard():
	if 'permission' not in session:
		session['permission'] = -1
	if session['permission'] < 1:
		flash("You must log in to view this page!", 'login')
		print("You must log in to view this page!")
	else:
		# mysql = connectToMySQL('dashboard')
		# query = "SELECT mules.id, success, finished_at, name FROM mules JOIN organizations ON organizations_id = organizations.id WHERE finished_at < now() ORDER BY finished_at DESC limit 12"
		# all_mules = mysql.query_db(query)

		all_mules = get_rows_between('1970-01-01', datetime.now(), session['max_latest'])

		start = datetime.now() - timedelta(hours=8)
		r1 = create_report(get_rows_between(start, datetime.now()))
		start = datetime.now() - timedelta(hours=24)
		r2 = create_report(get_rows_between(start, datetime.now()))
		f = count_failures()

		return render_template('dashboard_page.html', all_mules=all_mules, r1=r1, r2=r2, f=f)

	return redirect('/')


@app.route('/dashboard/custom')
def custom(query=None):
	if 'permission' not in session:
		session['permission'] = -1
	if session['permission'] < 1:
		flash("You must log in to view this page!", 'login')
		print("You must log in to view this page!")
	elif session['permission'] < 2:
		print("You lack the permissions to access custom reports!")
		return redirect('/dashboard')
	else:

		header = ""
		# tbl = False
		start = ""
		end = ""
		all_mules = None
		if "custom" in session:
			rform = session["custom"]
			session.pop("custom")
			start = rform["start"]
			end = rform["end"]
			header = rform["format"]
			print(rform)
			if rform["format"] == 'lst_txt' or rform["format"] == 'lst_tbl':
				if rform["custom"] == False:
					all_mules = get_rows_between(rform["end"], rform["start"])
				else:
					all_mules = get_rows_where(rform["start"])

			elif rform["format"] == 'rpt_txt' or rform["format"] == 'rpt_tbl':
				if rform["custom"] == False:
					all_mules = create_report(get_rows_between(rform["end"], rform["start"]))
				else:
					all_mules = create_report(get_rows_where(rform["start"]))

			print(f"All mules: {all_mules}")
		else:
			tdy = date.today()
			start = tdy.strftime("%Y-%m-%d")
			tdy = tdy - timedelta(days=2)
			end = tdy.strftime("%Y-%m-%d")

		return render_template('dashboard_custom.html', header=header, start=start, end=end, all_mules=all_mules,
		                       you=session['id'])

	return redirect('/')


@app.route('/dashboard/custom/report', methods=['POST'])
def custom_report():
	if 'permission' not in session:
		session['permission'] = -1
	if session['permission'] < 1:
		flash("You must log in to view this page!", 'login')
		print("You must log in to view this page!")
	elif session['permission'] < 2:
		print("You lack the permissions to access custom reports!")
		return redirect('/dashboard')
	else:
		# print(request.form)
		session["custom"] = {
			"format": request.form["format"],
			"start": request.form["start"],
			"end": request.form["end"],
			"custom": False,
		}

		# today = datetime.today()

		return redirect('/dashboard/custom')

	return redirect('/')


@app.route('/dashboard/custom/query', methods=['POST'])
def custom_query():
	if 'permission' not in session:
		session['permission'] = -1
	if session['permission'] < 1:
		flash("You must log in to view this page!", 'login')
		print("You must log in to view this page!")
	elif session['permission'] < 8:
		print("You lack the permissions to access custom queries!")
		return redirect('/dashboard')
	else:
		# print(request.form)
		session["custom"] = {
			"format": request.form["format"],
			"start": request.form["start"],
			"end": "",
			"custom": True,
		}

		# today = datetime.today()

		return redirect('/dashboard/custom')

	return redirect('/')


@app.route('/dashboard/admin')
def admin():
	if 'permission' not in session:
		session['permission'] = -1
	if session['permission'] < 1:
		flash("You must log in to view this page!", 'login')
		print("You must log in to view this page!")
		return redirect('/')
	else:
		mysql = connectToMySQL('dashboard')
		query = "SELECT id, username, permission FROM dashboard.users ORDER BY username"
		all_users = mysql.query_db(query)

		return render_template('dashboard_admin.html', permission=session['permission'], all_users=all_users,
		                       you=session['id'])


@app.route('/create', methods=['POST'])
def register():
	if 'access' not in session:
		session['access'] = -1
	print("\nValidating!")
	print(request.form)

	is_valid = True
	mysql = connectToMySQL('dashboard')

	query = "SELECT * FROM users WHERE username=%(u)s"
	data = {
		"u": request.form['name'],
	}
	name_exists = mysql.query_db(query, data)
	print(f"Name exists: {name_exists}")

	if name_exists.__len__() > 0:
		print("Username already registered!")
		flash("Username already registered!", 'register')
		is_valid = False
	if len(request.form['name']) < 3:
		print("Username too short!")
		flash("Username too short!", 'register')
		is_valid = False
	if not request.form['pword1'] == request.form['pword2']:
		print("Passwords do not match!")
		flash("Passwords do not match!", 'register')
		is_valid = False
	if len(request.form['pword1']) < 8:
		print("Password too short!")
		flash("Password too short!", 'register')
		is_valid = False
	if request.form['pword1'].isalpha():
		print("Password too weak!")
		flash("Password too weak!", 'register')
		is_valid = False

	# print(f"The registration is: { is_valid}")

	if is_valid:
		print("Registration Valid!")
		pw_hash = bcrypt.generate_password_hash(request.form['pword1'])

		# INSERT INTO users (first_name, last_name, email, password) VALUES ('Big', 'Mood','big@mood.com','11111111');

		query = "INSERT INTO users (username, password, permission, created_at, updated_at) VALUES (%(u)s,%(p)s,%(a)s, now(), now());"
		data = {
			"u": request.form["name"],
			"p": pw_hash,
			"a": request.form["permission"],
		}
		print(query)
		print(data)
		mysql = connectToMySQL('dashboard')
		mysql.query_db(query, data)

	return redirect('/dashboard/admin')


@app.route('/dashboard/settings')
def settings():
	if 'permission' not in session:
		session['permission'] = -1
	if session['permission'] < 1:
		flash("You must log in to view this page!", 'login')
		print("You must log in to view this page!")
	else:

		mysql = connectToMySQL('dashboard')

		query = "SELECT * FROM users WHERE id=%(i)s"
		data = {
			"i": session['id']
		}
		user_q = mysql.query_db(query, data)
		# print(user_q)

		user = {
			"un": user_q[0]['username'],
			"p": user_q[0]['permission'],
			"ml": user_q[0]['max_latest'],
			"rr": user_q[0]['refresh_rate'],
		}
		# print(user)

		return render_template('dashboard_settings.html', user=user)

	return redirect('/')


@app.route('/dashboard/settings/update', methods=['POST'])
def settings_update():

	print("\nValidating!")
	print(request.form)

	is_valid = True

	try:
		int(request.form['mule_no'])
	except:
		print("Mule number must be a number!")
		flash("Mule number must be a number!", 'settings')
		is_valid = False
	try:
		int(request.form['refresh'])
	except:
		print("Refresh rate must be a number!")
		flash("Refresh rate must be a number!", 'settings')
		is_valid = False

	if is_valid:
		query = "UPDATE users SET max_latest = %(ml)s, refresh_rate = %(rr)s WHERE id = %(id)s"
		data = {
			"ml": request.form['mule_no'],
			"rr": request.form['refresh'],
			"id": session['id']
		}

		mysql = connectToMySQL('dashboard')
		success = mysql.query_db(query, data)

		if success == False:
			print("An unexpected error has occurred! Settings not updated!")
			flash("An unexpected error has occurred! Settings not updated!", 'settings')
		else:
			print("User settings successfully updated!")
			flash("User settings successfully updated!", 'settings')
			session['max_latest'] = int(request.form['mule_no'])
			session['refresh'] = int(request.form['refresh'])

	return redirect('/dashboard/settings')


def get_rows_between(start, end, limit=8192):
	query = "SELECT mules.id, success, finished_at, name FROM mules JOIN organizations ON organizations_id = organizations.id WHERE finished_at > %(start)s AND finished_at < %(end)s ORDER BY finished_at DESC LIMIT %(limit)s"

	data = {
		"start": start,
		"end": end,
		"limit": limit,
	}

	mysql = connectToMySQL('dashboard')
	return mysql.query_db(query, data)


def create_report(raw_report):
	report = {}

	for line in raw_report:
		if line['name'] not in report:
			report[line['name']] = [0, 0]
		if line['success'] == 0:
			report[line['name']][0] += 1
		else:
			report[line['name']][1] += 1

	return report


def get_rows_where(where):
	query = f"SELECT mules.id, success, finished_at, name FROM mules JOIN organizations ON organizations_id = organizations.id WHERE {where} ORDER BY finished_at DESC"

	data = {
		"where": where,
	}

	mysql = connectToMySQL('dashboard')
	return mysql.query_db(query)


def count_failures():
	then = datetime.now() - timedelta(hours=24)

	query = "SELECT success FROM mules WHERE finished_at > %(then)s AND finished_at < now()"
	data = {"then": then}

	mysql = connectToMySQL('dashboard')
	raw_report = mysql.query_db(query, data)
	failures = 0

	for line in raw_report:
		if line['success'] == 0:
			failures += 1

	return failures


def create():
	e = datetime.now()
	e = e.replace(hour=8)
	e = e.replace(minute=30)
	e = e.replace(second=0)
	for x in range(128):
		e = e + timedelta(hours=4)
		print(e.strftime('%c'))
		mysql = connectToMySQL('dashboard')
		query = f"INSERT INTO mules (success, organizations_id, started_at, finished_at) VALUES (1, 2, '{e}', '{e}+30');"
		mule = mysql.query_db(query)


@app.route('/logout', methods=['POST'])
def logout():
	print("Logging out")
	session.clear()

	return redirect('/')


# create()

if __name__ == "__main__":
	app.run(debug=True)
