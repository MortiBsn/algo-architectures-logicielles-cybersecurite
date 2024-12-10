from flask import Flask, request, render_template, redirect, url_for, session
from auth import add_user, verify_user
import certificates

app = Flask(__name__)
app.secret_key = 'votre_cle_secrète'  # clé secrète pour gérer les sessions

@app.route('/')
def home():
    return render_template('home.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
    
        if verify_user(username, password):
            session['username'] = username
            return redirect(url_for('home'))
        else:
            return "Identifiants incorrects!", 401
    
    return render_template('login.html')


@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        # Ajoute l'utilisateur dans le fichier
        add_user(username, password)
        
        return redirect(url_for('login'))
    
    return render_template('register.html')

@app.route('/payment')
def payment():
    if 'username' not in session:
        return redirect(url_for('login'))

    return render_template('payment.html')

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8043, ssl_context=('certificates/web_cert.pem', 'certificates/web_key.pem'))