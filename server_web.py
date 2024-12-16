import ssl
import socket
from flask import Flask, request, render_template, redirect, url_for, session
from auth import add_user, verify_user
from ports import PORT_VERIFICATION, PORT_RESPONSE
app = Flask(__name__)

app.secret_key = 'secret_key'
HOST = "127.0.0.1"


context = ssl.SSLContext(ssl.PROTOCOL_TLSv1_2)
context.load_cert_chain('certificates/web.cer', 'certificates/web.key')
context.load_verify_locations('certificates/myCA.cer')

def isCodeVerified(code):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM, 0) as sock:
        with context.wrap_socket(sock, server_hostname=HOST) as client_socket:
            # Connect to the server
            client_socket.connect((HOST, PORT_VERIFICATION))
            client_socket.sendall(code.encode('utf-8'))
            client_socket.close()
    response = getACSResponse()
    print(f"Response : {response}")
    if(response == "ACK"):
        return True
    return False
        
def getACSResponse():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM, 0) as sock:
        sock.bind((HOST, PORT_RESPONSE))
        sock.listen(5)
        with context.wrap_socket(sock, server_side=True) as ssock:
            client_socket, addr = ssock.accept()
            response = client_socket.recv(1024)
            response = response.decode('utf-8')
            client_socket.close()

            return response

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

@app.route('/payment', methods=['GET', 'POST'])
def payment():
    if 'username' not in session:
        return redirect(url_for('login'))
    if request.method == "POST":
        code = request.form['code']
        verified = isCodeVerified(code)
        if(verified):
            return render_template('valid.html')
        else:
            return render_template('invalid.html')


    return render_template('payment.html')

@app.route('/logout')
def logout():
    session.clear()
    return render_template('logout.html')

if __name__ == "__main__":
    app.run(ssl_context=('certificates/web.cer', 'certificates/web.key'), port=8043, host='0.0.0.0')