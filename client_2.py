from socket import *
from threading import Thread
import tkinter, sys, time
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
from Crypto.Hash import SHA256


def receive():
    """Handles receiving of messages."""
    msg_list.insert(tkinter.END, " Welcome! %s" % NAME)
    msg_list.insert(tkinter.END, " You are online!")
    while True:
        try:
            msg = CLIENT.recv(BUFFER_SIZE).decode("utf8")
            msg = msg.split("*")
            hash_msg = msg[2]
            rsa_dec = PKCS1_OAEP.new(private_key_2)
            aes_key = rsa_dec.decrypt(bytes.fromhex(msg[0]))
            aes_dec = AES.new(aes_key, AES.MODE_ECB)
            msg = aes_dec.decrypt(bytes.fromhex(msg[1])).decode("utf8")
            # remove padding
            msg = unpad(msg.encode("utf8"), 16)
            if SHA256.new(msg).hexdigest() == hash_msg:
                msg_list.insert(tkinter.END, msg)
            else:
                msg_list.insert(tkinter.END, "Message is corrupted!")
        except OSError:  # Possibly client has left the chat.
            break


def send(event=None):  # event is passed by binders.
    """Handles sending of messages."""
    msg = my_msg.get()
    my_msg.set("")  # Clears input field.
    msg = NAME + ": " + msg
    msg_list.insert(tkinter.END, msg)
    hash_msg = SHA256.new(msg.encode("utf8")).hexdigest()
    aes_key = get_random_bytes(16)
    aes_enc = AES.new(aes_key, AES.MODE_ECB)
    msg = aes_enc.encrypt(pad(msg.encode("utf8"), 16))
    rsa_enc = PKCS1_OAEP.new(public_key_1)
    aes_key = rsa_enc.encrypt(aes_key)
    # transform the aes_key and msg to hex string
    aes_key = aes_key.hex()
    msg = msg.hex()
    msg = aes_key + "*" + msg + "*" + hash_msg
    CLIENT.send(msg.encode("utf8"))


def on_closing(event=None):
    """This function is to be called when the window is closed."""
    msg_list.insert(tkinter.END, "going offline...")
    time.sleep(2)
    CLIENT.close()
    top.quit()
    sys.exit()


#----tkinter GUI----
top = tkinter.Tk()
top.title("Secure Business Channel")

messages_frame = tkinter.Frame(top)
# messages_frame.config(bg="blue")
messages_frame.pack()

my_msg = tkinter.StringVar()  # For the messages to be sent.
my_msg.set("Type your messages..")
scrollbar = tkinter.Scrollbar(messages_frame)  # To navigate through past messages.
# Following will contain the messages.
msg_list = tkinter.Listbox(messages_frame, height=25, width=100, background="grey",font="Helvetica 10 bold",yscrollcommand=scrollbar.set)
scrollbar.pack(side=tkinter.RIGHT, fill=tkinter.Y)
msg_list.pack(side=tkinter.LEFT, fill=tkinter.BOTH)
msg_list.pack()
messages_frame.pack()

entry_field = tkinter.Entry(top, textvariable=my_msg, background="red",width=40)


entry_field.bind("<Return>", send)
entry_field.pack()
send_button = tkinter.Button(top, text = "Send", command = send, background="grey",padx=20)
send_button.pack()

top.protocol("WM_DELETE_WINDOW", on_closing)


# ----SOCKET Part----
HOST = input("Enter host: ")
PORT = int(input("Enter port: "))
NAME = input("Enter your name: ")
BUFFER_SIZE = 1024
ADDRESS = (HOST, PORT)

CLIENT = socket(AF_INET, SOCK_STREAM)  # client socket object
CLIENT.connect(ADDRESS)  # to connect to the server socket address

private_key_2 = RSA.generate(2048)
public_key_2 = private_key_2.publickey().exportKey()
msg = public_key_2.decode("utf8")
CLIENT.send(bytes(msg, "utf8"))
m = CLIENT.recv(BUFFER_SIZE).decode("utf8")
public_key_1 = RSA.importKey(m)

receive_thread = Thread(target=receive)  # created a thread for receive method
receive_thread.start()
tkinter.mainloop()  # Starts GUI execution.
