#!/usr/bin/env python3
"""
Modern MVC Password Manager
Requiere: pip install customtkinter
"""

import customtkinter as ctk
import tkinter as tk
from tkinter import ttk, messagebox
import sqlite3
import secrets, string, hashlib
from dataclasses import dataclass
from typing import List, Optional

# Configuración visual global
ctk.set_appearance_mode("Dark")  # Opciones: "System", "Dark", "Light"
ctk.set_default_color_theme("blue")  # Opciones: "blue", "green", "dark-blue"

DB_FILE = "passwords.db"

# --------------------------- Model (Igual que antes) ---------------------------
@dataclass
class EntryRecord:
    id: Optional[int]
    user: str
    service: str
    email: str
    password: str
    notes: Optional[str] = ""

class Model:
    def __init__(self, db_path=DB_FILE):
        self.db_path = db_path
        self._ensure_db()

    def _connect(self):
        return sqlite3.connect(self.db_path)

    def _ensure_db(self):
        with self._connect() as c:
            cur = c.cursor()
            cur.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY,
                username TEXT UNIQUE,
                password_hash TEXT,
                salt TEXT
            );
            """)
            cur.execute("""
            CREATE TABLE IF NOT EXISTS passwords (
                id INTEGER PRIMARY KEY,
                username TEXT,
                service TEXT,
                email TEXT,
                password TEXT,
                notes TEXT,
                FOREIGN KEY(username) REFERENCES users(username)
            );
            """)
            c.commit()

    def get_user(self, username):
        with self._connect() as c:
            cur = c.cursor()
            cur.execute("SELECT username, password_hash, salt FROM users WHERE username = ?", (username,))
            return cur.fetchone()

    def create_user(self, username, password):
        salt = secrets.token_hex(16)
        pw_hash = hashlib.sha256((salt + password).encode()).hexdigest()
        with self._connect() as c:
            cur = c.cursor()
            cur.execute("INSERT INTO users (username, password_hash, salt) VALUES (?, ?, ?)", (username, pw_hash, salt))
            c.commit()

    def add_entry(self, record: EntryRecord):
        with self._connect() as c:
            cur = c.cursor()
            cur.execute("""INSERT INTO passwords (username, service, email, password, notes)
                           VALUES (?, ?, ?, ?, ?)""", (record.user, record.service, record.email, record.password, record.notes or ""))
            c.commit()
            return cur.lastrowid

    def update_entry(self, record: EntryRecord):
        with self._connect() as c:
            cur = c.cursor()
            cur.execute("""UPDATE passwords SET service=?, email=?, password=?, notes=? WHERE id=?""",
                        (record.service, record.email, record.password, record.notes or "", record.id))
            c.commit()

    def delete_entry(self, entry_id: int):
        with self._connect() as c:
            cur = c.cursor()
            cur.execute("DELETE FROM passwords WHERE id = ?", (entry_id,))
            c.commit()

    def list_entries(self, username) -> List[EntryRecord]:
        with self._connect() as c:
            cur = c.cursor()
            cur.execute("SELECT id, username, service, email, password, notes FROM passwords WHERE username = ?", (username,))
            rows = cur.fetchall()
            return [EntryRecord(*row) for row in rows]

# --------------------------- Controller (Igual que antes) ---------------------------
class Controller:
    def __init__(self, model: Model):
        self.model = model
        self.current_user = None

    def login_or_register(self, username, password):
        row = self.model.get_user(username)
        if row is None:
            self.model.create_user(username, password)
            self.current_user = username
            return True, "Usuario creado y logueado exitosamente."
        else:
            username_db, pw_hash, salt = row
            check_hash = hashlib.sha256((salt + password).encode()).hexdigest()
            if check_hash == pw_hash:
                self.current_user = username
                return True, "Login exitoso."
            else:
                return False, "Contraseña incorrecta."

    def generate_password(self, length=16, use_symbols=True, use_numbers=True, use_upper=True, use_lower=True):
        alphabet = ""
        if use_lower: alphabet += string.ascii_lowercase
        if use_upper: alphabet += string.ascii_uppercase
        if use_numbers: alphabet += string.digits
        if use_symbols: alphabet += "!@#$%^&*()-_=+[]{};:,.<>?/"
        if not alphabet:
            raise ValueError("Selecciona al menos un tipo de caracter.")
        while True:
            pwd = ''.join(secrets.choice(alphabet) for _ in range(length))
            if use_numbers and not any(c.isdigit() for c in pwd): continue
            if use_symbols and not any(c in '!@#$%^&*()-_=+[]{};:,.<>?/' for c in pwd): continue
            if use_upper and not any(c.isupper() for c in pwd): continue
            if use_lower and not any(c.islower() for c in pwd): continue
            return pwd

    def add_entry(self, service, email, password, notes=""):
        if not self.current_user: raise RuntimeError("No user logged in.")
        record = EntryRecord(None, self.current_user, service, email, password, notes)
        return self.model.add_entry(record)

    def update_entry(self, entry_id, service, email, password, notes=""):
        record = EntryRecord(entry_id, self.current_user, service, email, password, notes)
        self.model.update_entry(record)

    def delete_entry(self, entry_id):
        self.model.delete_entry(entry_id)

    def list_entries(self):
        return self.model.list_entries(self.current_user)

# --------------------------- Modern View (CustomTkinter) ---------------------------
class AppView(ctk.CTk):
    def __init__(self, controller: Controller):
        super().__init__()
        self.controller = controller
        self.title("SPAY KEY - Gestor de Contraseñas")
        self.geometry("900x600")
        
        # Configurar grid principal
        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(0, weight=1)
        
        # Iniciar en Login
        self._build_login()

    def _clear(self):
        for w in self.winfo_children():
            w.destroy()

    # --- PANTALLA DE LOGIN ---
    def _build_login(self):
        self._clear()
        
        # Frame central tipo tarjeta
        login_frame = ctk.CTkFrame(self, width=350, corner_radius=15)
        login_frame.place(relx=0.5, rely=0.5, anchor="center")
        
        ctk.CTkLabel(login_frame, text="SPAY KEY", font=("Roboto Medium", 24)).pack(pady=(30, 10))
        ctk.CTkLabel(login_frame, text="Bienvenido de nuevo", font=("Roboto", 12), text_color="gray").pack(pady=(0, 20))

        username_entry = ctk.CTkEntry(login_frame, width=250, placeholder_text="Usuario")
        username_entry.pack(pady=10)
        
        password_entry = ctk.CTkEntry(login_frame, width=250, show="*", placeholder_text="Contraseña Maestra")
        password_entry.pack(pady=10)

        def submit():
            u = username_entry.get().strip()
            p = password_entry.get().strip()
            if not u or not p:
                return
            ok, msg = self.controller.login_or_register(u, p)
            if ok:
                self._build_main()
            else:
                messagebox.showerror("Error", msg)

        ctk.CTkButton(login_frame, text="Ingresar / Registrar", command=submit, width=250, height=35).pack(pady=20)
        ctk.CTkLabel(login_frame, text="Tus datos se guardan localmente.", font=("Arial", 10), text_color="gray50").pack(pady=(0, 20))

    # --- PANTALLA PRINCIPAL ---
    def _build_main(self):
        self._clear()
        
        # Layout: Sidebar (izquierda) y Contenido (derecha)
        self.grid_columnconfigure(1, weight=1)
        self.grid_rowconfigure(0, weight=1)

        # 1. Sidebar
        sidebar = ctk.CTkFrame(self, width=200, corner_radius=0)
        sidebar.grid(row=0, column=0, sticky="nsew")
        sidebar.grid_rowconfigure(6, weight=1) # Empujar logout abajo
        
        ctk.CTkLabel(sidebar, text="SecurePass", font=("Roboto Medium", 20)).grid(row=0, column=0, padx=20, pady=(20, 10))
        ctk.CTkLabel(sidebar, text=f"Hola, {self.controller.current_user}", text_color="gray70").grid(row=1, column=0, padx=20, pady=(0, 20))

        # Botones del Sidebar
        btn_config = {"width": 160, "height": 40, "anchor": "w", "fg_color": "transparent", "text_color": ("gray10", "gray90"), "hover_color": ("gray70", "gray30")}
        
        ctk.CTkButton(sidebar, text="  +  Nueva Contraseña", command=lambda: self._create_dialog(self.refresh_table), **btn_config).grid(row=2, column=0, pady=5)
        ctk.CTkButton(sidebar, text="  ✎  Editar Selección", command=lambda: self._edit_selected(), **btn_config).grid(row=3, column=0, pady=5)
        ctk.CTkButton(sidebar, text="  🗑  Borrar Selección", command=lambda: self._delete_selected(), **btn_config).grid(row=4, column=0, pady=5)
        ctk.CTkButton(sidebar, text="  📋  Copiar Password", command=lambda: self._copy_password(), **btn_config).grid(row=5, column=0, pady=5)
        
        # Logout al fondo
        ctk.CTkButton(sidebar, text="Cerrar Sesión", command=self._logout, fg_color="#bf3b3b", hover_color="#8f2c2c").grid(row=7, column=0, padx=20, pady=20, sticky="ew")

        # 2. Área de Contenido
        content = ctk.CTkFrame(self, corner_radius=0, fg_color="transparent")
        content.grid(row=0, column=1, sticky="nsew", padx=20, pady=20)
        
        ctk.CTkLabel(content, text="Mis Credenciales", font=("Roboto Medium", 22)).pack(anchor="w", pady=(0, 15))

        # Treeview personalizado (Tkinter estándar envuelto para que se vea oscuro)
        style = ttk.Style()
        style.theme_use("clam")
        
        # Colores para la tabla que coincidan con CustomTkinter Dark Theme
        bg_color = "#2b2b2b"
        fg_color = "white"
        sel_bg = "#1f538d"
        
        style.configure("Treeview",
                        background=bg_color,
                        foreground=fg_color,
                        fieldbackground=bg_color,
                        borderwidth=0,
                        rowheight=30,
                        font=("Arial", 11))
        style.configure("Treeview.Heading", background="#333333", foreground="white", borderwidth=0, font=("Arial", 11, "bold"))
        style.map("Treeview", background=[('selected', sel_bg)])

        # Frame contenedor para la tabla y el scrollbar
        table_frame = ctk.CTkFrame(content, fg_color="transparent")
        table_frame.pack(fill="both", expand=True)

        cols = ("ID", "Servicio", "Usuario/Email", "Contraseña", "Notas")
        self.tree = ttk.Treeview(table_frame, columns=cols, show="headings", selectmode="browse")
        
        # Scrollbar moderno
        scroll = ctk.CTkScrollbar(table_frame, orientation="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=scroll.set)
        
        scroll.pack(side="right", fill="y")
        self.tree.pack(side="left", fill="both", expand=True)

        # Encabezados
        self.tree.heading("ID", text="ID"); self.tree.column("ID", width=0, stretch=False) # Ocultar ID visualmente pero mantenerlo
        self.tree.heading("Servicio", text="Servicio", anchor="w")
        self.tree.heading("Usuario/Email", text="Usuario/Email", anchor="w")
        self.tree.heading("Contraseña", text="Contraseña", anchor="w")
        self.tree.heading("Notas", text="Notas", anchor="w")

        self.refresh_table()

    def refresh_table(self):
        for r in self.tree.get_children():
            self.tree.delete(r)
        for e in self.controller.list_entries():
            # Ocultar la contraseña real con asteriscos para privacidad visual, o mostrarla
            # Aquí la mostramos directo pero puedes poner '******'
            display_pwd = "••••••••" 
            # Guardamos el objeto real en 'tags' o lo buscamos por ID, 
            # pero Treeview guarda solo texto. Usaremos el ID hidden para buscar.
            self.tree.insert("", "end", values=(e.id, e.service, e.email, e.password, e.notes))

    def _logout(self):
        self.controller.current_user = None
        self._build_login()

    def _get_selected_entry(self):
        sel = self.tree.selection()
        if not sel:
            messagebox.showwarning("Selección", "Por favor selecciona una fila.")
            return None
        vals = self.tree.item(sel[0], "values")
        # Reconstruir objeto
        return EntryRecord(int(vals[0]), self.controller.current_user, vals[1], vals[2], vals[3], vals[4])

    # --- DIALOGS (Ventanas Emergentes Modernas) ---
    def _create_dialog(self, refresh_cb, entry_to_edit=None):
        dialog = ctk.CTkToplevel(self)
        dialog.title("Editar" if entry_to_edit else "Crear")
        dialog.geometry("400x550")
        dialog.grab_set() # Modal

        ctk.CTkLabel(dialog, text="Detalles de la cuenta", font=("Roboto Medium", 18)).pack(pady=20)

        ctk.CTkLabel(dialog, text="Servicio / Sitio Web:").pack(anchor="w", padx=20)
        svc_entry = ctk.CTkEntry(dialog, width=360)
        svc_entry.pack(padx=20, pady=(0, 10))

        ctk.CTkLabel(dialog, text="Usuario / Email:").pack(anchor="w", padx=20)
        email_entry = ctk.CTkEntry(dialog, width=360)
        email_entry.pack(padx=20, pady=(0, 10))

        ctk.CTkLabel(dialog, text="Contraseña:").pack(anchor="w", padx=20)
        pwd_entry = ctk.CTkEntry(dialog, width=360)
        pwd_entry.pack(padx=20, pady=(0, 10))

        # Generador mini
        def generate_mini():
            p = self.controller.generate_password(length=16)
            pwd_entry.delete(0, 'end')
            pwd_entry.insert(0, p)
        
        ctk.CTkButton(dialog, text="Generar Contraseña", command=generate_mini, height=24, fg_color="gray40").pack(padx=20, pady=(0, 15))

        ctk.CTkLabel(dialog, text="Notas:").pack(anchor="w", padx=20)
        notes_entry = ctk.CTkTextbox(dialog, width=360, height=80)
        notes_entry.pack(padx=20, pady=(0, 20))

        # Pre-llenar si es editar
        if entry_to_edit:
            svc_entry.insert(0, entry_to_edit.service)
            email_entry.insert(0, entry_to_edit.email)
            pwd_entry.insert(0, entry_to_edit.password)
            notes_entry.insert("1.0", entry_to_edit.notes)

        def save():
            s = svc_entry.get().strip()
            e = email_entry.get().strip()
            p = pwd_entry.get().strip()
            n = notes_entry.get("1.0", "end").strip()
            
            if not s or not e or not p:
                return # Validación simple
            
            if entry_to_edit:
                self.controller.update_entry(entry_to_edit.id, s, e, p, n)
            else:
                self.controller.add_entry(s, e, p, n)
            
            dialog.destroy()
            refresh_cb()

        ctk.CTkButton(dialog, text="Guardar Datos", command=save, width=360, height=40).pack(pady=10)

    def _edit_selected(self):
        entry = self._get_selected_entry()
        if entry:
            self._create_dialog(self.refresh_table, entry)

    def _delete_selected(self):
        entry = self._get_selected_entry()
        if entry:
            if messagebox.askyesno("Confirmar", f"¿Borrar {entry.service}?"):
                self.controller.delete_entry(entry.id)
                self.refresh_table()

    def _copy_password(self):
        entry = self._get_selected_entry()
        if entry:
            self.clipboard_clear()
            self.clipboard_append(entry.password)
            messagebox.showinfo("Copiado", "Contraseña copiada al portapapeles.")

if __name__ == "__main__":
    model = Model()
    controller = Controller(model)
    app = AppView(controller)
    app.mainloop()