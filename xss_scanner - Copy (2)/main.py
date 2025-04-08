import tkinter as tk
from gui.app import XSSScannerApp

if __name__ == "__main__":
    root = tk.Tk()
    root.title("XSS & Phishing Scanner")
    app = XSSScannerApp(root)
    root.mainloop()