import tkinter as tk
import threading
import time
import pyperclip
from gui.app import XSSScannerApp

def main():
    root = tk.Tk()
    root.title("XSS & Phishing Scanner - Test")
    app = XSSScannerApp(root)
    
    # Start clipboard monitoring
    app.monitor_var.set(True)
    app.toggle_clipboard_monitoring()
    
    # Wait a moment for monitoring to start
    time.sleep(2)
    
    # Copy a test URL to the clipboard
    def copy_test_url():
        test_url = "https://example.com/test-page"
        print(f"Copying test URL to clipboard: {test_url}")
        pyperclip.copy(test_url)
    
    # Schedule the clipboard copy in a separate thread after a delay
    clipboard_test_thread = threading.Thread(target=lambda: (time.sleep(3), copy_test_url()))
    clipboard_test_thread.daemon = True
    clipboard_test_thread.start()
    
    root.mainloop()

if __name__ == "__main__":
    main() 