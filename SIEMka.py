import sqlite3
import logging
from flask import Flask, request, render_template, redirect, url_for, session

app = Flask(__name__)
app.secret_key = 'SUPER_SECRET_KEY'

logging.basicConfig(
    filename='honeypot.log',
    level=logging.INFO,
    format='%(asctime)s %(levelname)s: %(message)s'
)
DB_FILE = 'honeypot_shop.db'

def init_db():
    if os.path.exists(DB_FILE):
        os.remove(DB_FILE)
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute('''
        CREATE TABLE users(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE,
            password TEXT,
            is_admin INTEGER DEFAULT 0
        );
    ''')
    c.executemany(
        "INSERT INTO users(username,password,is_admin) VALUES(?,?,?);",
        [
            ('admin','admin123',1),
            ('alice','alicepass',0),
            ('bob','bobpass',0)
        ]
    )
    c.execute('''
        CREATE TABLE products(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT,
            price REAL
        );
    ''')
    products = [
        ('Laptop', 799.00), ('Smartphone', 499.99),
        ('Headphones', 199.50), ('Camera', 299.99)
    ]
    c.executemany("INSERT INTO products(name,price) VALUES(?,?);", products)
    c.execute('''
        CREATE TABLE reviews(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            product_id INTEGER,
            user TEXT,
            content TEXT
        );
    ''')
    conn.commit()
    conn.close()
    logging.info('Database initialized with users, products, reviews.')

def get_conn():
    conn = sqlite3.connect(DB_FILE)
    conn.row_factory = sqlite3.Row
    return conn

@app.route('/')
def index():
    return render_template('base.html')

@app.route('/login', methods=['GET','POST'])
def login():
    error = None
    if request.method == 'POST':
        u = request.form['username']
        p = request.form['password']
        logging.info(f"Login attempt: {u} / {p} from {request.remote_addr}")
        conn = get_conn(); cur = conn.cursor()
        q = f"SELECT * FROM users WHERE username = '{u}' AND password = '{p}';"
        try:
            cur.execute(q)
            user = cur.fetchone()
        except Exception as e:
            user = None
            error = str(e)
        conn.close()
        if user:
            session['username'] = user['username']
            session['is_admin'] = bool(user['is_admin'])
            return redirect(url_for('index'))
        error = error or 'Invalid credentials'
    return render_template('login.html', error=error)

@app.route('/search', methods=['GET','POST'])
def search():
    results = []
    error = None
    qstr = ''
    if request.method == 'POST':
        qstr = request.form['query']
        logging.info(f"Search: {qstr} from {request.remote_addr}")
        conn = get_conn(); cur = conn.cursor()
        sql = f"SELECT id,name,price FROM products WHERE name LIKE '%{qstr}%';"
        try:
            cur.execute(sql)
            results = cur.fetchall()
        except Exception as e:
            error = str(e)
        conn.close()
    return render_template('search.html', results=results, error=error, query=qstr)

@app.route('/reviews/<int:product_id>', methods=['GET','POST'])
def reviews(product_id):
    conn = get_conn(); cur = conn.cursor()
    if request.method == 'POST':
        user = request.form['user']
        content = request.form['content']
        logging.info(f"Review by {user} on {product_id}: {content}")
        cur.execute("INSERT INTO reviews(product_id,user,content) VALUES(?,?,?);",
                    (product_id,user,content))
        conn.commit()
    cur.execute("SELECT * FROM products WHERE id = ?;", (product_id,))
    product = cur.fetchone()
    cur.execute("SELECT * FROM reviews WHERE product_id = ?;", (product_id,))
    revs = cur.fetchall()
    conn.close()
    return render_template('reviews.html', product=product, reviews=revs)

@app.route('/admin', methods=['GET','POST'])
def admin():
    if not session.get('is_admin'):
        return '<h1>Access denied</h1>', 403
    conn = get_conn(); cur = conn.cursor()
    if request.method == 'POST':
        uid = request.form.get('user_id')
        if uid and uid.isdigit():
            logging.warning(f"Admin deletes user {uid}")
            cur.execute("DELETE FROM users WHERE id = ?;", (uid,)); conn.commit()
    cur.execute("SELECT id,username,is_admin FROM users;")
    users = cur.fetchall()
    conn.close()
    return render_template('admin.html', users=users)

if __name__ == '__main__':
    init_db()
    app.run(host='0.0.0.0', port=5000)
