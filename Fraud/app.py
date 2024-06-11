from flask import Flask, render_template, request, redirect, flash, url_for
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash
import joblib
import pandas as pd

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql://root:root@localhost/frauddb'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.secret_key = b'_5#y2L"F4Q8z\n\xec]/'
app.config['UPLOAD_FOLDER'] = 'static/uploads'

db = SQLAlchemy(app)

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'
model = joblib.load('random_forest_model.pkl')

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(255), unique=True)
    email = db.Column(db.String(255), unique=True)
    password = db.Column(db.String(255))

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@app.route('/', methods=['GET', 'POST'])
def index():
    return render_template("index.html")

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']
        user = User.query.filter_by(email=email).first()
        if user:
            flash('Email address already exists.')
            return redirect(url_for('register'))
        new_user = User(username=username, email=email, password=generate_password_hash(password, method='sha256'))
        db.session.add(new_user)
        db.session.commit()
        return redirect(url_for('login'))
    else:
        return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()
        if not user or not check_password_hash(user.password, password):
            flash('Invalid Username & Password')
            return redirect(url_for('login'))
        else:
            login_user(user)
            return redirect(url_for('predictpage'))
    return render_template('login.html')


@app.route('/predictpage', methods=['POST','GET'])
@login_required
def predictpage():
    return render_template('predictpage.html')

@app.route('/prediction', methods=['POST','GET'])
@login_required
def prediction():
    return render_template('prediction.html')

def preprocess_data(data):
    col_categorical = data.select_dtypes(include=['object']).columns
    data[col_categorical] = data[col_categorical].apply(lambda x: x.astype('category').cat.codes)
    data['age'] = data['age'].astype(int)
    return data

@app.route('/predict', methods=['POST'])
@login_required
def predict():
    if request.method == 'POST':
        data = request.form
        input_data = pd.DataFrame({
            'step': [int(data.get('step'))],
            'customer': [data.get('customer')],
            'age': [int(data.get('age'))],
            'gender': [data.get('gender')],
            'merchant': [data.get('merchant')],
            'category': [data.get('category')],
            'amount': [float(data.get('amount'))]
        })
        input_data = preprocess_data(input_data)
        prediction_probability = model.predict_proba(input_data)[:, 1]
        is_fraudulent = prediction_probability[0] > 0.3
        prediction_result = "Fraud" if is_fraudulent else "Non-Fraud"
        flash(f"Predicted class: {prediction_result}")
        return render_template('predicted.html', prediction_result=prediction_result)
    else:
        return redirect(url_for('prediction'))

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))

@app.route('/analysis', methods=['POST', 'GET'])
@login_required
def analysis():
    return render_template("analysis.html")

@app.route('/graphs', methods=['POST', 'GET'])
@login_required
def graphs():
    return render_template("graphs.html")

if __name__ == "__main__":
    app.run(debug=True)
