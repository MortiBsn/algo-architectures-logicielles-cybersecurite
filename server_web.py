from flask import Flask, request, render_template, redirect, url_for, session
from auth import add_user, verify_user
app = Flask(__name__)

app.secret_key = 'secret_key'

@app.route('/')
def home():
    return render_template('home.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == "POST":
        username = request.form['username']
        password = request.form['password']
        
        # Ajoute l'utilisateur dans le fichier
        add_user(username, password)
        
        return redirect(url_for('login'))
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == "POST":
        username = request.form['username']
        password = request.form['password']
    
        if verify_user(username, password):
            session['username'] = username
            return redirect(url_for('home'))
        else:
            return "Identifiants incorrects!", 401
    return render_template('login.html')

@app.route('/payment')
def payment():
    if 'username' not in session:
        return redirect(url_for('login'))

    return render_template('payment.html')

@app.route('/logout')
def logout():
    session.clear()
    return render_template('logout.html')

if __name__ == "__main__":
    app.run(ssl_context=('certificates/web.cer', 'certificates/web.key'), port=8043, host='0.0.0.0')