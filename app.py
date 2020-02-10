from flask import Flask, abort, jsonify
from flask import render_template
from Crypto.Cipher import AES
from Crypto import Random
import mysql.connector
import base64

app = Flask(__name__)

app.config.from_pyfile('gawa-ss.cfg')

DB_USER = app.config['DB_USER']
DB_PASSWORD = app.config['DB_PASSWORD']
DB_HOST = app.config['DB_HOST']
DB_DB = app.config['DB_DB']

try:
    conn = mysql.connector.connect(user=DB_USER, password=DB_PASSWORD,
                                   host=DB_HOST, database=DB_DB)
except mysql.connector.Error as err:
    app.logger.error(err)
    exit(1)
app.logger.info("Connected to database")


class PKCS7Encoder():
    """
    Technique for padding a string as defined in RFC 2315, section 10.3,
    note #2
    """
    class InvalidBlockSizeError(Exception):
        """Raised for invalid block sizes"""
        pass

    def __init__(self, block_size=16):
        if block_size < 2 or block_size > 255:
            raise PKCS7Encoder.InvalidBlockSizeError('The block size must be '
                                                     'between 2 and 255, inclusive')
        self.block_size = block_size

    def encode(self, text):
        text_length = len(text)
        amount_to_pad = self.block_size - (text_length % self.block_size)
        if amount_to_pad == 0:
            amount_to_pad = self.block_size
        pad = chr(amount_to_pad)
        return text + pad * amount_to_pad

    def decode(self, text):
        pad = ord(text[-1])
        return text[:-pad]


def encrypt_val(clear_text, password):
    if len(password) < 16:
        password = password + "j" * (16 - len(password))
    elif len(password) > 16:
        password = password[0:16]
    encoder = PKCS7Encoder()
    raw = encoder.encode(clear_text)
    iv = Random.new().read(16)
    cipher = AES.new(password, AES.MODE_CBC, iv, segment_size=128)
    res = base64.b64encode(iv + cipher.encrypt(raw))
    return res.decode('ascii')


def encrypt(text, password):
    if len(password) < 16:
        password = password + "j" * (16 - len(password))
    elif len(password) > 16:
        password = password[0:16]

    iv = 16 * '\x00'
    mode = AES.MODE_CBC
    encryptor = AES.new(password, mode, IV=iv)

    if len(text) < 16:
        text = text + (16 - len(text)) * "\0"
    elif len(text) > 16:
        text = text[0:16]

    encrypt_text = encryptor.encrypt(text)
    encoded = base64.encodebytes(encrypt_text)

    return encoded.decode('ascii')


@app.errorhandler(404)
def resource_not_found(e):
    return jsonify(error=str(e)), 404


@app.route('/')
def hello():
    return "<h>HELLO</h>"


@app.route('/ss')
def show_ss_page():
    return render_template('ss.html')


@app.route('/ss/<name>')
def show_user_content(name):
    cursor = conn.cursor()

    user_query = "SELECT password FROM users WHERE name = '{}'".format(name)

    app.logger.debug("query string: {}".format(user_query))

    try:
        cursor.execute(user_query)
    except mysql.connector.Error as err:
        app.logger.debug("Database error: {}".format(err))
        abort(404, description="Resource not found")

    user_pass = None

    for (p, ) in cursor:
        user_pass = p

    if user_pass == None:
        abort(404, description="No such a user")

    app.logger.debug(user_pass)
    cursor.reset()
    query = "SELECT host, port, password, method \
            FROM host_info \
            WHERE location NOT LIKE 'CN%' \
            ORDER BY RAND() \
            LIMIT 1"

    try:
        cursor.execute(query)
    except mysql.connector.Error:
        abort(404, description="Resource not found")

    host = ""
    port = ""
    password = ""
    method = ""

    for (h, p, psw, m) in cursor:
        host = h
        port = str(p)
        password = str(psw)
        method = m

    return {
        "name": encrypt_val(name, user_pass),
        "host": encrypt_val(host, user_pass),
        "port": encrypt_val(port, user_pass),
        "password": encrypt_val(password, user_pass),
        "method": encrypt_val(method, user_pass),
    }


# if __name__ == "__main__":
#     app.run()
