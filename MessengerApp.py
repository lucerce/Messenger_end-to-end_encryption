import tkinter as tk
from tkinter import ttk, filedialog
import os
import base64
import io
from datetime import datetime
from cryptography.hazmat.primitives.asymmetric import x25519, ed25519
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from PIL import Image, ImageTk, ImageOps

class CryptoUtils:
    @staticmethod
    def generate_dh_keys():
        # Генерація пари ключів Діффі-Хеллмана (X25519) для асиметричного шифрування
        private = x25519.X25519PrivateKey.generate()
        return private, private.public_key()

    @staticmethod
    def generate_sign_keys():
        # Створення пари ключів (Ed25519) для формування та перевірки цифрового підпису
        private = ed25519.Ed25519PrivateKey.generate()
        return private, private.public_key()

    @staticmethod
    def derive_key(private_key, peer_public):
        # Обчислення спільного секретного ключа за допомогою алгоритму HKDF
        shared = private_key.exchange(peer_public)
        return HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=b'handshake').derive(shared)

    @staticmethod
    def encrypt(key, message):
        # Шифрування повідомлення алгоритмом AES-GCM та повернення зашифрованого тексту з випадковим вектором
        aes = AESGCM(key)
        nonce = os.urandom(12)
        ciphertext = aes.encrypt(nonce, message.encode(), None)
        return {"nonce": base64.b64encode(nonce).decode(), "ciphertext": base64.b64encode(ciphertext).decode()}

    @staticmethod
    def decrypt(key, payload):
        # Розшифровка отриманого повідомлення за допомогою алгоритму AES-GCM та перевірка цілісності
        aes = AESGCM(key)
        return aes.decrypt(base64.b64decode(payload["nonce"]), base64.b64decode(payload["ciphertext"]), None).decode()


class ChatWindow:
    # Графічний інтерфейс
    def __init__(self, title, partner_name, send_callback, bg_color, my_color, avatar_color):
        # Ініціалізація вікна чату, налаштування параметрів інтерфейсу, прив'язка подій та розміщення граф. елементів
        self.window = tk.Toplevel()
        self.window.title(title)
        self.window.geometry("400x600")
        self.bg_color = bg_color
        self.partner_name = partner_name
        self.send_callback = send_callback
        self.window.protocol("WM_DELETE_WINDOW", self.on_close)
        self.is_open = True

        # Верхня панель з ім'ям співрозмовника та його статусом
        header = tk.Frame(self.window, bg=bg_color)
        header.pack(fill="x")
        self.avatar_canvas = tk.Canvas(header, width=24, height=24, bg=bg_color, highlightthickness=0)
        self.avatar_canvas.create_oval(0, 0, 24, 24, fill=avatar_color, outline="")
        self.avatar_canvas.create_text(12, 12, text=partner_name[0], fill="white", font=("Arial", 10, "bold"))
        self.avatar_canvas.pack(side="left", padx=5, pady=5)

        self.name_label = tk.Label(header, text=partner_name, bg=bg_color, font=("Arial", 12, "bold"))
        self.name_label.pack(side="left")
        self.status_label = tk.Label(header, text="Online", bg=bg_color, fg="green")
        self.status_label.pack(side="left", padx=5)
        self.typing_label = tk.Label(header, text="", bg=bg_color, fg="blue", font=("Arial", 10, "italic"))
        self.typing_label.pack(side="left", padx=5)

        # Область для відображення повідомлень з можливістю прокручування
        self.chat_frame = tk.Frame(self.window, bg=bg_color)
        self.chat_frame.pack(fill="both", expand=True)
        self.canvas = tk.Canvas(self.chat_frame, bg=bg_color, highlightthickness=0)
        self.scrollbar = ttk.Scrollbar(self.chat_frame, orient="vertical", command=self.canvas.yview)
        self.messages_frame = tk.Frame(self.canvas, bg=bg_color)

        self.messages_frame.bind("<Configure>", lambda e: self.canvas.configure(scrollregion=self.canvas.bbox("all")))
        self.frame_id = self.canvas.create_window((0, 0), window=self.messages_frame, anchor="nw")
        self.canvas.bind("<Configure>", lambda e: self.canvas.itemconfig(self.frame_id, width=e.width))
        self.canvas.configure(yscrollcommand=self.scrollbar.set)
        self.window.bind("<MouseWheel>", lambda e: self.canvas.yview_scroll(int(-1 * (e.delta / 120)), "units"))

        self.canvas.pack(side="left", fill="both", expand=True)
        self.scrollbar.pack(side="right", fill="y")

        # Нижня панель з полем введення тексту та кнопками
        bottom = tk.Frame(self.window, bg=bg_color)
        bottom.pack(fill="x", side="bottom")

        tk.Button(bottom, text="➤", font=("Arial", 14), width=3, command=self.send_text_event,
                  bg=my_color, fg="white", relief="flat").pack(side="right", padx=5, pady=5)

        tools_frame = tk.Frame(bottom, bg=bg_color)
        tools_frame.pack(side="left", padx=(5, 0), pady=5)

        tk.Button(tools_frame, text="😁", font=("Arial", 14), width=2, command=self.open_sticker_panel,
                  bg=bg_color, fg="#ff9900", relief="flat").pack(side="left")

        tk.Button(tools_frame, text="📎", font=("Arial", 14), width=2, command=self.send_file_event,
                  bg=bg_color, fg="gray", relief="flat").pack(side="left")

        self.entry = tk.Text(bottom, height=2)
        self.entry.pack(side="left", fill="x", expand=True, padx=5, pady=5)
        self.entry.bind("<Return>", self.send_text_event)
        self.entry.bind("<KeyRelease>", lambda e: self.check_typing())

        self.my_color = my_color
        self.partner_window = None
        self.sticker_refs = []

    def send_text_event(self, event=None):
        # Подія відправки текстового повідомлення
        msg = self.entry.get("1.0", tk.END).strip()
        if msg:
            self.entry.delete("1.0", tk.END)
            self.send_callback(f"TXT|{msg}")
        return "break"

    def send_file_event(self):
        # Діалогове вікно для вибору зображення nf документів
        filepath = filedialog.askopenfilename(
            filetypes=[
                ("All supported files", "*.png *.jpg *.jpeg *.txt *.pdf *.docx"),
                ("Images", "*.png *.jpg *.jpeg"),
                ("Documents", "*.txt *.pdf *.docx")
            ]
        )
        if filepath:
            ext = os.path.splitext(filepath)[1].lower()
            if ext in ['.png', '.jpg', '.jpeg']:
                self._process_and_send_image(filepath)
            else:
                self._process_and_send_document(filepath)

    def _process_and_send_document(self, filepath):
        # Читання файлу, кодування в Base64 та відправка з тегом
        filename = os.path.basename(filepath)
        with open(filepath, "rb") as f:
            file_data = f.read()
        b64_data = base64.b64encode(file_data).decode()
        self.send_callback(f"DOC|{filename}|{b64_data}")

    def save_document(self, filename, b64_data):
        # Метод для завантаження файлу на комп'ютер співрозмовника
        filepath = filedialog.asksaveasfilename(initialfile=filename)
        if filepath:
            with open(filepath, "wb") as f:
                f.write(base64.b64decode(b64_data))

    def _process_and_send_image(self, filepath):
        with Image.open(filepath) as img:
            # Читаем EXIF и автоматически переворачиваем фото как надо!
            img = ImageOps.exif_transpose(img)

            # Отправляем в нормальном размере
            img.thumbnail((1024, 1024))
            if img.mode != 'RGBA':
                img = img.convert('RGBA')
            img_byte_arr = io.BytesIO()
            img.save(img_byte_arr, format='PNG')
            b64_img = base64.b64encode(img_byte_arr.getvalue()).decode()

        self.send_callback(f"IMG|{b64_img}")

    def _process_and_send_sticker(self, filepath):
        with Image.open(filepath) as img:
            img = ImageOps.exif_transpose(img)
            # Стикеры изначально делаем небольшими, чтобы они не весили много
            img.thumbnail((150, 150))
            if img.mode != 'RGBA':
                img = img.convert('RGBA')
            img_byte_arr = io.BytesIO()
            img.save(img_byte_arr, format='PNG')
            b64_img = base64.b64encode(img_byte_arr.getvalue()).decode()

        self.send_callback(f"STK|{b64_img}")

    def open_sticker_panel(self):
        # Додаткове вікно з панеллю стікерів (з папки 'stickers')
        if hasattr(self, 'sticker_panel') and self.sticker_panel.winfo_exists():
            self.sticker_panel.lift()
            return

        self.sticker_panel = tk.Toplevel(self.window)
        self.sticker_panel.title("Stickers")
        self.sticker_panel.geometry("260x300")
        self.sticker_panel.configure(bg=self.bg_color)

        sticker_dir = "stickers"
        if not os.path.exists(sticker_dir):
            os.makedirs(sticker_dir)
            tk.Label(self.sticker_panel,
                     text="Folder 'stickers' is empty!\n\nAdd images there\nto see them here.",
                     bg=self.bg_color, fg="gray").pack(expand=True)
            return

        files = [f for f in os.listdir(sticker_dir) if f.lower().endswith(('.png', '.jpg', '.jpeg'))]
        if not files:
            tk.Label(self.sticker_panel, text="Folder 'stickers' is empty!\n\nAdd images there.", bg=self.bg_color,
                     fg="gray").pack(expand=True)
            return

        canvas = tk.Canvas(self.sticker_panel, bg=self.bg_color, highlightthickness=0)
        scrollbar = ttk.Scrollbar(self.sticker_panel, orient="vertical", command=canvas.yview)
        grid_frame = tk.Frame(canvas, bg=self.bg_color)

        grid_frame.bind("<Configure>", lambda e: canvas.configure(scrollregion=canvas.bbox("all")))
        canvas.create_window((0, 0), window=grid_frame, anchor="nw")
        canvas.configure(yscrollcommand=scrollbar.set)

        canvas.pack(side="left", fill="both", expand=True, padx=10, pady=10)
        scrollbar.pack(side="right", fill="y", pady=10)
        self.sticker_panel.bind("<MouseWheel>", lambda e: canvas.yview_scroll(int(-1 * (e.delta / 120)), "units"))

        row, col = 0, 0
        self.sticker_refs.clear()

        for file in files:
            path = os.path.join(sticker_dir, file)
            try:
                img = Image.open(path)
                img.thumbnail((70, 70))
                photo = ImageTk.PhotoImage(img)
                self.sticker_refs.append(photo)

                btn = tk.Button(grid_frame, image=photo, relief="flat", bg=self.bg_color, cursor="hand2",
                                command=lambda p=path: [self._process_and_send_sticker(p), self.sticker_panel.destroy()])
                btn.grid(row=row, column=col, padx=5, pady=5)

                col += 1
                if col > 2:
                    col = 0
                    row += 1
            except Exception:
                pass

    def add_message(self, content, is_mine, sender_name, is_verified=False, msg_type="TXT"):
        # Додавання нового повідомлення (текст, зображення, документ) у вікно чату
        time_str = datetime.now().strftime("%H:%M")

        outer_frame = tk.Frame(self.messages_frame, bg=self.bg_color)
        outer_frame.pack(fill="x", pady=2)

        inner_frame = tk.Frame(outer_frame, bg=self.bg_color)
        inner_frame.pack(side="right" if is_mine else "left", anchor="e" if is_mine else "w", padx=5)

        msg_bg = self.my_color if is_mine else "#e5e5ea"
        fg = "white" if is_mine else "black"
        time_fg = "#d1d1d1" if is_mine else "#8e8e93"

        bubble = tk.Frame(inner_frame, bg=msg_bg)
        bubble.pack()

        tk.Label(bubble, text=f"{sender_name}:", bg=msg_bg, fg=fg, font=("Arial", 9, "bold")).pack(anchor="w", padx=10,
                                                                                                   pady=(5, 0))

        content_frame = tk.Frame(bubble, bg=msg_bg)
        content_frame.pack(fill="both", expand=True)

        status_text = time_str
        if not is_mine and is_verified:
            status_text += " ✓"

        if msg_type == "IMG":
            img_data = base64.b64decode(content)
            original_image = Image.open(io.BytesIO(img_data))

            # Мініатюра тільки для чату
            thumb_image = original_image.copy()
            thumb_image.thumbnail((150, 150))
            photo = ImageTk.PhotoImage(thumb_image)

            # Курсор змінюється на "руку"
            img_label = tk.Label(content_frame, image=photo, bg=msg_bg, cursor="hand2")
            img_label.image = photo
            img_label.pack(side="top", anchor="w", padx=10, pady=(5, 0))

            # Клік лівою кнопкою миші на відкриття нового вікна
            img_label.bind("<Button-1>", lambda e, data=img_data: self.open_image_viewer(data))

            tk.Label(content_frame, text=status_text, bg=msg_bg, fg=time_fg, font=("Arial", 8, "italic")).pack(
                side="right", anchor="e", padx=10, pady=(0, 5))

        elif msg_type == "STK":
            img_data = base64.b64decode(content)
            original_image = Image.open(io.BytesIO(img_data))
            photo = ImageTk.PhotoImage(original_image)

            # Звичайний курсор і жодних біндингів на клік
            img_label = tk.Label(content_frame, image=photo, bg=msg_bg)
            img_label.image = photo
            img_label.pack(side="top", anchor="w", padx=10, pady=(5, 0))

            tk.Label(content_frame, text=status_text, bg=msg_bg, fg=time_fg, font=("Arial", 8, "italic")).pack(
                side="right", anchor="e", padx=10, pady=(0, 5))

        elif msg_type == "DOC":
            filename, b64_data = content.split("|", 1)
            doc_frame = tk.Frame(content_frame, bg=msg_bg)
            doc_frame.pack(side="top", anchor="w", padx=10, pady=(5, 0))

            tk.Label(doc_frame, text="📄", bg=msg_bg, fg=fg, font=("Arial", 14)).pack(side="left")
            tk.Label(doc_frame, text=filename, bg=msg_bg, fg=fg, font=("Arial", 9, "underline")).pack(side="left",
                                                                                                      padx=(5, 10))

            tk.Button(doc_frame, text="💾", font=("Arial", 8),
                      command=lambda: self.save_document(filename, b64_data),
                      bg="white" if not is_mine else "#005bb5", fg="black" if not is_mine else "white",
                      relief="flat").pack(side="left")

            tk.Label(content_frame, text=status_text, bg=msg_bg, fg=time_fg, font=("Arial", 8, "italic")).pack(
                side="right", anchor="e", padx=10, pady=(0, 5))

        else:  # TXT
            tk.Label(content_frame, text=content, bg=msg_bg, fg=fg, wraplength=250, justify="left").pack(side="left",
                                                                                                         anchor="s",
                                                                                                         padx=(10, 5),
                                                                                                         pady=5)
            tk.Label(content_frame, text=status_text, bg=msg_bg, fg=time_fg, font=("Arial", 8, "italic")).pack(
                side="right", anchor="s", padx=(0, 10), pady=5)

        self.canvas.update_idletasks()
        self.canvas.yview_moveto(1.0)
        self.typing_label.config(text="")

    def open_image_viewer(self, img_data):
        # Вікно для перегляду фото у повному розмірі
        viewer = tk.Toplevel(self.window)
        viewer.title("Image Viewer")
        viewer.configure(bg="#1e1e1e")
        viewer.geometry("+%d+%d" % (self.window.winfo_rootx() + 50, self.window.winfo_rooty() + 50))

        image = Image.open(io.BytesIO(img_data))
        photo = ImageTk.PhotoImage(image)

        lbl = tk.Label(viewer, image=photo, bg="#1e1e1e")
        lbl.image = photo
        lbl.pack(padx=20, pady=20, expand=True, fill="both")

    def on_close(self):
        # Обробка події закриття вікна чату, оновлюючи статус співрозмовника
        self.is_open = False
        if self.partner_window:
            self.partner_window.update_status()
        self.window.destroy()

    def update_status(self):
        # Оновлення статуса співрозмовника (Online/Offline)
        if not self.is_open: return
        if self.partner_window and self.partner_window.is_open:
            self.status_label.config(text="Online", fg="green")
        else:
            self.status_label.config(text="Offline", fg="red")

    def check_typing(self):
        # Відстежування змін у полі введення тексту для оновлення статусу друку
        if self.entry.get("1.0", tk.END).strip() and self.partner_window and self.partner_window.is_open:
            self.partner_window.typing_label.config(text="typing...")
        elif self.partner_window:
            self.partner_window.typing_label.config(text="")


class MessengerApp:
    #Головний клас
    def __init__(self):
        # Ініціалізація головного циклу програми, генерація ключів та створення вікна чату
        self.root = tk.Tk()
        self.root.withdraw()

        self.alice_dh_priv, self.alice_dh_pub = CryptoUtils.generate_dh_keys()
        self.tom_dh_priv, self.tom_dh_pub = CryptoUtils.generate_dh_keys()

        self.alice_key = CryptoUtils.derive_key(self.alice_dh_priv, self.tom_dh_pub)
        self.tom_key = CryptoUtils.derive_key(self.tom_dh_priv, self.alice_dh_pub)

        self.alice_sign_priv, self.alice_sign_pub = CryptoUtils.generate_sign_keys()
        self.tom_sign_priv, self.tom_sign_pub = CryptoUtils.generate_sign_keys()

        self.alice = ChatWindow("Alice", "Tom",
                                lambda msg: self._process_message(self.alice, self.tom, self.alice_key, self.tom_key,
                                                                  "Alice", self.alice_sign_priv, self.alice_sign_pub,
                                                                  msg),
                                "#f0f0f0", "#0084ff", "#00aaff")
        self.tom = ChatWindow("Tom", "Alice",
                              lambda msg: self._process_message(self.tom, self.alice, self.tom_key, self.alice_key,
                                                                "Tom", self.tom_sign_priv, self.tom_sign_pub, msg),
                              "#f0f0f0", "#00c853", "#00ff88")
        self.alice.partner_window = self.tom
        self.tom.partner_window = self.alice

        self.log_window()
        self.log("Secure channel established.\n"
                 f"Shared AES Key: {self.alice_key.hex()[:32]}...\n")

        self.update_statuses()
        self.root.mainloop()

    def update_statuses(self):
        # Оновлення статусу активності вікон; завершення роботи програми, якщо обидва вікна закриті
        if not self.alice.is_open and not self.tom.is_open:
            self.root.quit()
            return
        self.alice.update_status()
        self.tom.update_status()
        self.root.after(500, self.update_statuses)

    def _process_message(self, sender, receiver, enc_key, dec_key, sender_name, sender_sign_priv, sender_sign_pub,
                         msg_data):
        # Повний цикл безпечної передачі даних: створення цифрового підпису, шифрування, передача, розшифрування та верифікація
        signature = sender_sign_priv.sign(msg_data.encode())
        sig_b64 = base64.b64encode(signature).decode()

        encrypted = CryptoUtils.encrypt(enc_key, msg_data)
        decrypted = CryptoUtils.decrypt(dec_key, encrypted)

        is_verified = False
        try:
            sender_sign_pub.verify(base64.b64decode(sig_b64), decrypted.encode())
            is_verified = True
            verify_status = "Ed25519 Signature valid ✓"
        except Exception:
            verify_status = "Signature verification failed ×"

        msg_type, content = decrypted.split("|", 1)

        sender.add_message(content, True, sender_name, is_verified=True, msg_type=msg_type)
        receiver.add_message(content, False, sender_name, is_verified, msg_type=msg_type)

        if msg_type == "IMG":
            log_preview = "[IMAGE]"
        elif msg_type == "STK":
            log_preview = "[STICKER]"
        elif msg_type == "DOC":
            log_preview = f"[DOCUMENT] {content.split('|')[0]}"
        else:
            log_preview = content
        self.log(f"[{sender_name} → {sender.partner_name}] 🔒\n"
                 f"Data: {log_preview}\n"
                 f"Signature: {sig_b64[:30]}...\n"
                 f"Ciphertext (truncated): {encrypted['ciphertext'][:50]}...\n"
                 f"Verification: {verify_status}\n")

    def log_window(self):
        # Окреме вікно для виведення системних логів та криптографічної інформації
        self.logger = tk.Toplevel()
        self.logger.title("Encryption Log (Console)")
        self.logger.geometry("600x450")
        self.logger.configure(bg="#f0f0f0")

        self.log_box = tk.Text(self.logger, bg="#2b2b2b", fg="#a9b7c6", font=("Consolas", 10), relief="flat")
        self.log_box.pack(side="top", fill="both", expand=True, padx=10, pady=10)

    def log(self, text):
        # Новий текстовий запис у вікно системних логів
        self.log_box.insert(tk.END, text + "\n")
        self.log_box.see(tk.END)


if __name__ == "__main__":
    MessengerApp()