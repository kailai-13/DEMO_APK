import sqlite3
from kivy.app import App
from kivy.uix.screenmanager import ScreenManager, Screen
from kivy.uix.boxlayout import BoxLayout
from kivy.uix.label import Label
from kivy.uix.textinput import TextInput
from kivy.uix.button import Button
from kivy.uix.popup import Popup
import hashlib


# Initialize database
def ins_db():
    conn = sqlite3.connect('attendence.db')
    c = conn.cursor()
    c.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            roll_no TEXT NOT NULL UNIQUE,
            password TEXT NOT NULL
        )
    """)
    conn.commit()
    conn.close()


# Registration Screen
class RegisterScreen(Screen):
    def __init__(self, **kwargs):
        super().__init__(**kwargs)

        self.layout = BoxLayout(orientation='vertical', padding=20, spacing=10)

        # Roll Number Input
        self.layout.add_widget(Label(text="Enter Roll No:"))
        self.roll_no = TextInput(hint_text="ROLL NO", multiline=False)
        self.layout.add_widget(self.roll_no)

        # Password Input
        self.layout.add_widget(Label(text="Enter Password:"))
        self.pass_in = TextInput(hint_text="Password", multiline=False, password=True)
        self.layout.add_widget(self.pass_in)

        # Submit Button
        self.submit = Button(text="Register")
        self.submit.bind(on_release=self.register_user)
        self.layout.add_widget(self.submit)

        # Navigate to Login Screen
        self.to_login = Button(text="Go to Login")
        self.to_login.bind(on_release=self.go_to_login)
        self.layout.add_widget(self.to_login)

        self.add_widget(self.layout)

    def register_user(self, instance):
        roll_no = self.roll_no.text
        password = self.pass_in.text

        if roll_no == "" or password == "":
            self.show_popup("All fields are required.")
            return

        if len(password) < 8:
            self.show_popup("Password must be at least 8 characters long.")
            return

        # Hash password
        hashed_password = hashlib.sha256(password.encode()).hexdigest()

        # Store in database
        try:
            conn = sqlite3.connect('attendence.db')
            c = conn.cursor()
            c.execute("INSERT INTO users (roll_no, password) VALUES (?, ?)", (roll_no, hashed_password))
            conn.commit()
            conn.close()
            self.show_popup("Registration Successful!")
        except sqlite3.IntegrityError:
            self.show_popup("User already exists.")
        except Exception as e:
            self.show_popup(f"An error occurred: {str(e)}")

    def show_popup(self, message):
        popup = Popup(title="Info",
                      content=Label(text=message),
                      size_hint=(0.8, 0.4))
        popup.open()

    def go_to_login(self, instance):
        self.manager.current = "login"


# Login Screen
class LoginScreen(Screen):
    def __init__(self, **kwargs):
        super().__init__(**kwargs)

        self.layout = BoxLayout(orientation='vertical', padding=20, spacing=10)

        # Roll Number Input
        self.layout.add_widget(Label(text="Enter Roll No:"))
        self.roll_no = TextInput(hint_text="ROLL NO", multiline=False)
        self.layout.add_widget(self.roll_no)

        # Password Input
        self.layout.add_widget(Label(text="Enter Password:"))
        self.pass_in = TextInput(hint_text="Password", multiline=False, password=True)
        self.layout.add_widget(self.pass_in)

        # Login Button
        self.login = Button(text="Login")
        self.login.bind(on_release=self.login_user)
        self.layout.add_widget(self.login)

        # Navigate to Registration Screen
        self.to_register = Button(text="Go to Register")
        self.to_register.bind(on_release=self.go_to_register)
        self.layout.add_widget(self.to_register)

        self.add_widget(self.layout)

    def login_user(self, instance):
        roll_no = self.roll_no.text
        password = self.pass_in.text

        if roll_no == "" or password == "":
            self.show_popup("All fields are required.")
            return

        # Hash the entered password for comparison
        hashed_password = hashlib.sha256(password.encode()).hexdigest()

        # Verify credentials
        conn = sqlite3.connect('attendence.db')
        c = conn.cursor()
        c.execute("SELECT * FROM users WHERE roll_no = ? AND password = ?", (roll_no, hashed_password))
        user = c.fetchone()
        conn.close()

        if user:
            self.show_popup("Login Successful!")
        else:
            self.show_popup("Invalid credentials.")

    def show_popup(self, message):
        popup = Popup(title="Info",
                      content=Label(text=message),
                      size_hint=(0.8, 0.4))
        popup.open()

    def go_to_register(self, instance):
        self.manager.current = "register"


# Main App
class AttendanceApp(App):
    def build(self):
        ins_db()

        sm = ScreenManager()
        sm.add_widget(RegisterScreen(name="register"))
        sm.add_widget(LoginScreen(name="login"))
        return sm


if __name__ == '__main__':
    AttendanceApp().run()
