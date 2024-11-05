import os
import config
import tkinter as tk
from tkinter import ttk
from tkinter import filedialog
from tkinter import Tk
from tkinter.scrolledtext import ScrolledText
from app.cipher import Magma



class App:

    root: Tk
    data: str|bytes = None
    password: str = ''
    cipher: str = ''
    datatype: str = 'text'

    def __init__(self):
        self.root: Tk = Tk()
        self.__configure()
        self.__create_screen_elements()

    def __configure(self):
        self.root.title('Блочное шифрование')
        self.root.geometry("500x600")

    def __create_screen_elements(self):
        common_label: tk.Label = tk.Label(self.root, text="Блочное шифрование")
        common_label.pack(pady=[10, 25])

        ##
        # Шифрование файла/текста
        label_text: tk.Label = tk.Label(self.root, text="Шифруемый текст:")
        label_text.pack(pady=5)

        self.scrolled_text = ScrolledText(self.root, width=40, height=4)
        self.scrolled_text.pack(pady=2)

        open_textfile: ttk.Button = ttk.Button(text="Выбрать файл", command=self.__openfile)
        open_textfile.pack(pady=5)

        # print(len(self.data))
        label_password: tk.Label = tk.Label(self.root, text="Пароль для шифрования:")
        label_password.pack(pady=5)

        self.entry_password: tk.Entry = tk.Entry(self.root, width=40)
        self.entry_password.pack(pady=5)

        self.label_error: tk.Label = tk.Label(self.root, text='')
        self.label_error.pack()

        # print(len(self.data))
        encrypt_text: ttk.Button = ttk.Button(text="Зашифровать данные", width=25, command=self.__encrypt)
        encrypt_text.pack(pady=[5, 30])

        ###
        # Дешифрование файла/текста
        label_cipher: tk.Label = tk.Label(self.root, text="Дешифруемый текст:")
        label_cipher.pack(pady=5)

        self.scrolled_cipher = ScrolledText(self.root, width=40, height=4)
        self.scrolled_cipher.pack(pady=2)

        label_decrypt_password: tk.Label = tk.Label(self.root, text="Пароль для дешифрования:")
        label_decrypt_password.pack(pady=5)

        self.entry_decrypt_password: tk.Entry = tk.Entry(self.root, width=40)
        self.entry_decrypt_password.pack(pady=5)

        self.label_decrypt_error: tk.Label = tk.Label(self.root)
        self.label_decrypt_error.pack()

        decrypt_text: ttk.Button = ttk.Button(text="Дешифровать данные", width=25, command=self.__decrypt)
        decrypt_text.pack(pady=5)
        
    def __openfile(self):
        """ Функция чтения файла с шифруемым текстом """
        filepath = filedialog.askopenfilename(title="Выбор файла", initialdir="./data/", defaultextension='txt', initialfile="")
        if len(filepath) != 0:
            if filepath.endswith('.txt'):
                self.datatype = "text"
                with open(filepath, 'r', encoding='utf-8') as file:
                    self.data: str = file.read()
                    self.scrolled_text.delete("1.0", tk.END)
                    self.scrolled_text.insert("1.0", self.data)
            else:
                self.datatype = "bytes"
                with open(filepath, 'rb') as file:
                    self.data: bytes = file.read()
                    print(len(self.data))
                    self.scrolled_text.delete("1.0", tk.END)
                    self.scrolled_text.insert("1.0", "Бинарные данные из файла считаны!")
             
    def __encrypt(self) -> None:
        """ Функция шифрования текста """
        if self.data is None:
            self.data: str = self.scrolled_text.get("1.0", tk.END)
            self.data = self.data[:len(self.data) - 1]
        self.password: str = self.entry_password.get()

        if len(self.data) < 2 or len(self.password) < 2:
            self.label_error['text'] = "Пустые данные или пароль"
            return

        cryptographer: Magma = Magma()
        encrypted_data: str = cryptographer.encrypt(self.data, self.password)
      
        with open(os.path.join(config.DATAPATH, 'encrypted.txt'), 'w+', encoding='utf-8') as file:
            file.write(encrypted_data)

        self.label_error['text'] = "Данные зашифрованы"
        return 

    def __decrypt(self) -> None:
        self.cipher: str = self.scrolled_cipher.get("1.0", tk.END)
        self.password: str = self.entry_decrypt_password.get()
        self.cipher = self.cipher[:len(self.cipher) - 1]
        if len(self.cipher) < 2 or len(self.password) < 2:
            self.label_decrypt_error['text'] = "Пустые данные или пароль"
            return

        cryptographer: Magma = Magma()
        try:
            decrypted_data: bytes = cryptographer.decrypt(self.cipher, self.password, self.datatype)
        except Exception as err:
            self.label_decrypt_error['text'] = "Не удалось дешифровать! \n(не верный пароль)"
            print(err)
            return

        if self.datatype == 'text':
            with open(os.path.join(config.DATAPATH, 'decrypted.txt'), 'w+', encoding='utf-8') as file:
                file.write(decrypted_data)
        else:
            with open(os.path.join(config.DATAPATH, 'decrypted.png'), 'wb+') as file:
                file.write(decrypted_data)
                
        self.data = None
        self.label_decrypt_error['text'] = "Данные дешифрованы"
        return 

    def run(self) -> None:
        self.root.mainloop()

    def test(self):
        cryptographer = Magma()
        data = "Привет мир!"
        password = 'GXmx1is7yNz53D8oe1uiF~OCar8K1OoP}ZL01HgR2p$UbJiVEV*ik%bCyJ5%?*R0'
        ciph = cryptographer.encrypt(data, password)
        res: bytes = cryptographer.decrypt(ciph, password)
        print(ciph, ' -> ', res, ' - ', password)
