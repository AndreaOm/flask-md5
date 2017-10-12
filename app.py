from flask import Flask
from flask import render_template, request

from flask_wtf import Form
from wtforms import StringField, SubmitField
from wtforms.validators import Required
from math import sin


class MD5(object):

    rotate_amounts = [7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22,
                      5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20,
                      4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23,
                      6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21]

    constants = [int(abs(2 ** 32 * sin(i + 1))) & 0xffffffff for i in range(64)]


    _functions = {'f': lambda b, c, d: (b & c) | (~b & d),
                  'g': lambda b, c, d: (d & b) | (~d & c),
                  'h': lambda b, c, d: b ^ c ^ d,
                  'k': lambda b, c, d: c ^ (b | ~d)}

    functions = []

    index_functions = (lambda i: i,
                       lambda i: (5 * i + 1) % 16,
                       lambda i: (3 * i + 5) % 16,
                       lambda i: (7 * i) % 16)

    def __init__(self, order=('f', 'g', 'h', 'k'), init_values=(0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476)):
        self.init_values = list(init_values)
        self.functions = []
        for i in order:
            self.functions.append(self._functions[i])

    @staticmethod

    #
    def left_rotate(x, amount):
        x &= 0xffffffff
        return ((x << amount) | (x >> (32 - amount))) & 0xffffffff

    def md5_digest(self, message, encoding='UTF-8'):

        message = bytearray(message, encoding=encoding)
        orig_bits_len = (8 * len(message)) & 0xffffffffffffffff

        message.append(0x80)

        while len(message) % 64 != 56:
            message.append(0)

        message += orig_bits_len.to_bytes(8, byteorder='little')

        registers = self.init_values[:]

        for chunk_offset in range(0, len(message), 64):
            a, b, c, d = registers
            chunk = message[chunk_offset:chunk_offset + 64]
            for i in range(64):
                f = self.functions[i // 16](b, c, d)
                g = self.index_functions[i // 16](i)
                to_rotate = a + f + self.constants[i] + int.from_bytes(chunk[4 * g:4 * g + 4], byteorder='little')
                new_b = (b + self.left_rotate(to_rotate, self.rotate_amounts[i])) & 0xffffffff
                a, b, c, d = d, new_b, b, c
            for i, val in enumerate([a, b, c, d]):
                registers[i] += val
                registers[i] &= 0xffffffff

        digest = sum(x << (32 * j) for j, x in enumerate(registers))

        return digest

    @staticmethod
    def md5_to_hex(digest):
        raw = digest.to_bytes(16, byteorder='little')
        return '{:032x}'.format(int.from_bytes(raw, byteorder='big'))

    def md5(self, message, encoding='UTF-8'):
        return self.md5_to_hex(self.md5_digest(message, encoding))

def str_to_hex(message):
    ascii = map(ord, message)
    he = ""
    for x in ascii:
        he = he +"\\"+ str(hex(x))
    return he

def str_to_bin(message):
    ascii = map(ord, message)
    bi = ""
    for x in ascii:
        bi = bi + str(bin(x))[2::].zfill(8)
    return bi

def str_append_bin(message):
    final = ""
    str_len = len(message)
    bin_str = str_to_bin(message)
    if len(final) % 512 == 448:
        final = bin_str + str(bin(str_len))[2::].zfill(64)
    else:
        final = bin_str + "1"
        while len(final) % 512 != 448:
            final = final + "0"
        final = final + str(bin(str_len))[2::].zfill(64)
    return final

def x_cut(string,width):
    return [string[x:x+width] for x in range(0,len(string),width)]


def str_append_hex(message):
    x = x_cut(str_append_bin(message),8)
    final_hex = ""
    for i in x:
        final_hex = final_hex +"\\0x"+ "%02x"%int(i,2)
    return final_hex


DEBUG = True
PORT = 8000
HOST = "0.0.0.0"

app = Flask(__name__)
app.config['SECRET_KEY'] = 'xxxxxxxxxx'


@app.route("/", methods=['GET', 'POST'])
def index():
    x = request.args.get('md5', '')
    hex_str = str_to_hex(x)
    bin_str = str_to_bin(x)
    final = str_append_bin(x)
    final_hex = str_append_hex(x)
    tmp = MD5()
    md5 = tmp.md5(x)
    if md5 != "d41d8cd98f00b204e9800998ecf8427e":
        return render_template('index.html',md5 = md5 , hex_str = hex_str, bin_str = bin_str, final_hex = final_hex , final = final , x = x)
    else:
        return render_template('index.html')
@app.route("/md5s", methods=['GET', 'POST'])
def md5s():
    txt = request.args.get('md5s', '')
    txts = txt.splitlines()
    tmp = MD5()
    tmplist = [ x + ":" + tmp.md5(x) for x in txts ]
    return render_template("md5s.html",md5s = tmplist)

@app.route("/algorithm")
def algorithm():
    return render_template("algorithm.html")

@app.route("/source")
def source():
    return render_template("source.html")


if __name__ == '__main__':
    app.run(debug=DEBUG, host=HOST, port=PORT)
