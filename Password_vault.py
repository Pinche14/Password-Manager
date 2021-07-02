import sqlite3
import hashlib
from tkinter import *
from tkinter import simpledialog
from functools import partial

with sqlite3.connect("Password_vault.db") as db:
    cursor = db.cursor()

cursor.execute(""" 
CREATE TABLE IF NOT EXISTS primarypassword(
id INTEGER PRIMARY KEY,
password TEXT NOT NULL);
""")
cursor.execute(""" 
CREATE TABLE IF NOT EXISTS vault(
id INTEGER PRIMARY KEY,
website TEXT NOT NULL,
username TEXT NOT NULL,
password TEXT NOT NULL);
""")


def PopUp(text):
    answer = simpledialog.askstring("INPUT STRING", text)
    return answer


window = Tk()

window.title("Password Vault")


def hashPassword(input):
    hash = hashlib.md5(input)
    hash = hash.hexdigest()
    return hash


def FirstSpace():
    window.geometry("350x150")

    lbl = Label(window, text="Enter a password")
    lbl.config(anchor=CENTER)
    lbl.pack()

    txt = Entry(window, width=10)
    txt.pack()
    txt.focus()

    lbl1 = Label(window, text="Enter your password again")
    lbl1.config(anchor=CENTER)
    lbl1.pack()

    txt1 = Entry(window, width=10)
    txt1.pack()
    txt1.focus()

    lbl2 = Label(window)
    lbl2.pack()

    def SavePassword():
        if txt.get() == txt1.get():
            hashed_password = hashPassword(txt.get().encode('utf-8'))
            insert_password = """INSERT INTO primarypassword(password)
            VALUES(?)"""
            cursor.execute(insert_password, [(hashed_password)])
            db.commit()

            PasswordVault()
        else:
            lbl.config("Password should be same")

    btn = Button(window, text="Submit", command=SavePassword)
    btn.pack(pady=20)


def loginspace():
    window.geometry("350x150")

    lbl = Label(window, text="Enter Primary Password")
    lbl.config(anchor=CENTER)
    lbl.pack()

    txt = Entry(window, width=10, show="*")
    txt.pack()
    txt.focus()

    lbl1 = Label(window)
    lbl1.pack()

    def Checkmasterpassword():
        checkhashedpassword = txt.get()
        cursor.execute("SELECT * FROM primarypassword WHERE ID=1 AND password=?", [(checkhashedpassword)])
        print(checkhashedpassword)
        return cursor.fetchall()

    def CheckPassword():
        match = Checkmasterpassword()

        if match:
            PasswordVault()
        else:
            txt.delete(0, 'end')
            lbl1.config(text="Wrong Password")

    btn = Button(window, text="Submit", command=CheckPassword)
    btn.pack(pady=10)


def PasswordVault():
    for widget in window.winfo_children():
        widget.destroy()

    def addEntry():
        text1 = "Website"
        text2 = "Username"
        text3 = "Password"

        website = PopUp(text1)
        username = PopUp(text2)
        password = PopUp(text3)

        insert_fields = """INSERT INTO vault(website,username,password)
        VALUES(?, ?, ?)
        """
        cursor.execute(insert_fields, (website, username, password))
        db.commit()

        PasswordVault()

    def removeEnt(input):
        cursor.execute("DELETE FROM vault WHERE id = ?", (input,))
        db.commit()
        PasswordVault()

    window.geometry("560x240")

    lbl = Label(window, text="Password Vault")
    lbl.config(anchor=CENTER)
    lbl.pack()

    btn = Button(window, text="+", command=addEntry)
    btn.grid(column=1, pady=10)

    lbl = Label(window, text="Website")
    lbl.grid(row=2, column=0, padx=80)
    lbl = Label(window, text="Username")
    lbl.grid(row=2, column=1, padx=80)
    lbl = Label(window, text="Password")
    lbl.grid(row=2, column=0, padx=80)

    cursor.execute("SELECT * FROM vault")
    if (cursor.fetchall() != None):
        i = 0
        while True:
            cursor.execute("SELECT * FROM vault")
            array = cursor.fetchall()
            lbl1 = Label(window, text=(array[i][1]), font=("Bonbon", 14))
            lbl1.grid(column=0, row=i + 3)
            lbl2 = Label(window, text=(array[i][1]), font=("Bonbon", 14))
            lbl2.grid(column=1, row=i + 3)
            lbl3 = Label(window, text=(array[i][1]), font=("Bonbon", 14))
            lbl3.grid(column=2, row=i + 3)
            btn = Button(window, text="Delete", command=partial(removeEnt, array[i][0]))
            btn.grid(column=3, row=i + 3, pady=10)

            i = i + 1
            cursor.execute("SELECT * FROM vault")
            if len(cursor.fetchall()) <= i:
                break


cursor.execute("SELECT * FROM primarypassword")
if cursor.fetchall():
    loginspace()
else:
    FirstSpace()
window.mainloop()
