#SECRET MESSAGE ENCODER
from tkinter import *
from tkinter import messagebox
from PIL import Image,ImageTk
import base64
import hashlib
import sys
import os

#RESOURCE PATH
def resource_path(relative_path):
    try:
        base_path=sys._MEIPASS
    except Exception:
        base_path=os.path.abspath(".")
    return os.path.join(base_path,relative_path)

#SCREEN FUNCTION
screen=Tk()
screen.geometry("375x389")
screen.resizable(False,False)
screen.title("SECRET MESSAGE ENCODER")

#ICON1
icon1=Image.open(resource_path("SECRET.png"))
icon1=icon1.resize((256,256))
tk_icon1=ImageTk.PhotoImage(icon1)
screen.iconphoto(False,tk_icon1)

# ENCRYPTION FUNCTION
def ENCRYPT():
    
    password=code.get()
    message=text3.get(1.0,END).strip()

    if len(password)>=4 and message:
        try:
            hash_key=hashlib.sha256(password.encode()).hexdigest()
            combined=f"{hash_key}:{message}"
            encoded=base64.b64encode(combined.encode()).decode()

#LAYOUT ENCRYPTION
            screen1=Toplevel(screen)
            screen1.title("ENCRYPTION")
            screen1.geometry("400x200")
            screen1.configure(bg="RED")
            
            #ICON2
            icon2=Image.open(resource_path("ENCRYPTION.png"))
            icon2=icon2.resize((256,256))
            tk_icon2=ImageTk.PhotoImage(icon2)
            screen1.iconphoto(False,tk_icon2)

            Label1=Label(screen1,text="ENCRYPTED TEXT",font="ARIAL",fg="WHITE",bg="ORANGE")
            Label1.pack()
            
            text1=Text(screen1,font="ROBOTO 10",bg="WHITE")
            text1.pack(expand=True,fill=BOTH)
            text1.insert(END,encoded)
            
#ERROR FUNCTION
        except Exception as e:
            messagebox.showerror("ENCRYPTION ERROR",str(e))
    else:
        messagebox.showerror("ENCRYPTION","SECRET KEY MUST BE AT LEAST 4 CHARACTER.")

# DECRYPTION FUNCTION
def DECRYPT():
    
    password=code.get()
    message=text3.get(1.0,END).strip()

    if len(password)>=4 and message:
        try:
            decoded=base64.b64decode(message.encode()).decode()
            stored_hash,real_message=decoded.split(":",1)
            current_hash=hashlib.sha256(password.encode()).hexdigest()

#LAYOUT DECRYPTION
            if stored_hash==current_hash:
                screen2=Toplevel(screen)
                screen2.title("DECRYPTION")
                screen2.geometry("400x200")
                screen2.configure(bg="GREEN")
                
                #ICON3
                icon3=Image.open(resource_path("DECRYPTION.png"))
                icon3=icon3.resize((256,256))
                tk_icon3=ImageTk.PhotoImage(icon3)
                screen2.iconphoto(False,tk_icon3)

                Label2=Label(screen2,text="DECRYPTED TEXT",font="ARIAL",fg="WHITE",bg="BLACK")
                Label2.pack()
                
                text2=Text(screen2,font="ROBOTO 10",bg="WHITE")
                text2.pack(expand=True,fill=BOTH)
                text2.insert(END,real_message)

#ERROR FUNCTION
            else:
                messagebox.showerror("DECRYPTION ERROR","SECRET KEY DOESN'T MATCH!")
        except Exception as e:
            messagebox.showerror("DECRYPTION ERROR",f"FAILED TO DECRYPT.\n\n{str(e)}")
    else:
        messagebox.showerror("DECRYPTION","SECRET KEY MUST BE AT LEAST 4 CHARACTER.")

# RESET FUNCTION
def RESET():
    code.set("")
    text3.delete(1.0,END)

# GUI LAYOUT
Label3=Label(text="ENTER TEXT FOR ENCRYPTION & DECRYPTION",fg="BLACK",font=("CALIBRI 13"))
Label3.place(x=10,y=10)

text3=Text(font="ROBOTO 10",bg="WHITE")
text3.place(x=10,y=50,width=355,height=100)

Label4=Label(text="ENTER SECRET KEY",fg="BLACK",font=("CALIBRI 13"))
Label4.place(x=10,y=170)

code=StringVar()

entry1=Entry(textvariable=code,width=19,bd=0,font=("ARIAL 25"),show="*")
entry1.place(x=10,y=200)

Button1=Button(text="ENCRYPT",height=2,width=23,bg="ORANGE",fg="WHITE",bd=0,command=ENCRYPT)
Button1.place(x=20,y=250)

Button2=Button(text="DECRYPT",height=2,width=23,bg="BLACK",fg="WHITE",bd=0,command=DECRYPT)
Button2.place(x=200,y=250)

Button3=Button(text="RESET",height=2,width=50,bg="BLUE",fg="WHITE",bd=0,command=RESET)
Button3.place(x=10,y=310)

screen.mainloop()
