import base64
import json
import tornado.websocket
import hashlib
import binascii
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes

def hex_to_bin(hex_string):
    return bin(int(hex_string, 16))[2:].zfill(len(hex_string) * 4)
def bin_to_hex(bin_string):
    return hex(int(bin_string, 2))[2:]
def aes_encrypt(plain_text, key,iv):
    cipher = AES.new(key.encode(), AES.MODE_CBC, IV=iv)
    padded_data = pad(plain_text.encode(), AES.block_size)
    encrypted_data = cipher.encrypt(padded_data)
    return binascii.hexlify(encrypted_data).decode()

def aes_decrypt(encrypted_text, key,iv):
    cipher = AES.new(key.encode(), AES.MODE_CBC, IV=iv)
    encrypted_data = binascii.unhexlify(encrypted_text)
    decrypted_data = cipher.decrypt(encrypted_data)
    return unpad(decrypted_data, AES.block_size).decode()




io_loop = tornado.ioloop.IOLoop.current()
# class MainHandler(tornado.web.RequestHandler):
#     def get(self):
#         self.render("rt.html")
class MainHandlerxt(tornado.web.RequestHandler):
    def get(self):
        self.render("tt.html")     
class WebSocketHandler(tornado.websocket.WebSocketHandler):
    def open(self):
        pass  
    def on_message(self, message):
        print(message)
        try:
            dat = json.loads(message)

            #base64encode
            if dat["t"] == "e":

                if dat["d"] == "":
                        response = {
                        "t": "d",
                        "d": "Field required"
                        }
                        self.write_message(response)
                        return
                f={}
                f["t"]="e"
                f["d"]=base64.b64encode(dat["d"].encode()).decode()
                self.write_message(f)

            # Convert hexadecimal to binary
            elif dat["t"] == "hex_to_bin":
                if dat["d"] == "":
                    response = {"t": "d", "d": "Field required"}
                    self.write_message(response)
                    return

                binary_data = hex_to_bin(dat["d"])
                response = {"t": "hex_to_bin", "d": binary_data}
                self.write_message(response)



            # Convert binary to hexadecimal
            elif dat["t"] == "bin_to_hex":
                if dat["d"] == "":
                    response = {"t": "d", "d": "Field required"}
                    self.write_message(response)
                    return

                hexadecimal_data = bin_to_hex(dat["d"])
                response = {"t": "bin_to_hex", "d": hexadecimal_data}
                self.write_message(response)


            # Convert string to hexadecimal
            if dat["t"] == "str_to_hex":
                if dat["d"] == "":
                    response = {"t": "d", "d": "Field required"}
                    self.write_message(response)
                    return

                hexadecimal_data = dat["d"].encode().hex()
                response = {"t": "str_to_hex", "d": hexadecimal_data}
                self.write_message(response)

            # Convert hexadecimal to string
            elif dat["t"] == "hex_to_str":
                if dat["d"] == "":
                    response = {"t": "d", "d": "Field required"}
                    self.write_message(response)
                    return

                string_data = bytes.fromhex(dat["d"]).decode()
                response = {"t": "hex_to_str", "d": string_data}
                self.write_message(response)


   
           

           

            #md5 hash

            if dat["t"] == "m":

                if dat["d"] == "":
                        response = {
                        "t": "d",
                        "d": "Field required"
                }
                        self.write_message(response)
                        return


                hashed_data = hashlib.md5(dat["d"].encode()).hexdigest()

                response = {
                    "t": "m",
                    "d":hashed_data
                }
                self.write_message(response)


             # SHA-1 hash
            elif dat["t"] == "s1":
                if dat["d"] == "":
                    response = {
                        "t": "d",
                        "d": "Field required"
                    }
                    self.write_message(response)
                    return
                hashed_data = hashlib.sha1(dat["d"].encode()).hexdigest()
                response = {
                    "t": "s1",
                    "d": hashed_data
                }
                self.write_message(response)

            # SHA-256 hash
            elif dat["t"] == "s256":
                if dat["d"] == "":
                    response = {
                        "t": "d",
                        "d": "Field required"
                    }
                    self.write_message(response)
                    return
                hashed_data = hashlib.sha256(dat["d"].encode()).hexdigest()
                response = {
                    "t": "s256",
                    "d": hashed_data
                }
                self.write_message(response)

            # SHA-512 hash
            elif dat["t"] == "s512":
                if dat["d"] == "":
                    response = {
                        "t": "d",
                        "d": "Field required"
                    }
                    self.write_message(response)
                    return
                hashed_data = hashlib.sha512(dat["d"].encode()).hexdigest()
                response = {
                    "t": "s512",
                    "d": hashed_data
                }
                self.write_message(response)





            #base64decode
            elif dat["t"] == "d":
                if dat["d"] == "":
                        response = {
                        "t": "d",
                        "d": "Field required"
                }
                        self.write_message(response)
                        return
               
                decoded_data = base64.b64decode(dat["d"]).decode()
                response = {
                    "t": "d",
                    "d": decoded_data
                }
                self.write_message(response)
              
            # AES encryption
            elif dat["t"] == "ae":
                if dat["d"]["data"] == "" or dat["d"]["key"] == "":
                    response = {"t": "ae", "d": "Field required"}
                    self.write_message(response)
                    return

                encrypted_data = aes_encrypt(dat["d"]["data"], dat["d"]["key"])
                response = {"t": "ae", "d": encrypted_data}
                self.write_message(response)

            # AES decryption
            elif dat["t"] == "ad":
                if dat["d"]["data"] == "" or dat["d"]["key"] == "":
                    response = {"t": "", "d": "Field required"}
                    self.write_message(response)
                    return

                decrypted_data = aes_decrypt(dat["d"]["data"], dat["d"]["key"])
                response = {"t": "ad", "d": decrypted_data}
                self.write_message(response)





        except Exception as e:
            response = {"t": "d", "d": str(e)}
            self.write_message(response)
    def check_origin(self, origin): 
        return True
    def on_close(self):
        super().on_close()
    

            
if __name__ == "__main__":
    application = tornado.web.Application([
        (r"/", MainHandlerxt),
        (r"/src/(.*)", tornado.web.StaticFileHandler, {"path": "src"}),
        (r"/ws", WebSocketHandler),

    ])
 
    application.listen(8888)
    io_loop.start()
