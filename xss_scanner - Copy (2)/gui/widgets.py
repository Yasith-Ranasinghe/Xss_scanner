import tkinter as tk
from tkinter import ttk
import ttkthemes
from tkinter import font as tkfont
import os
import platform

class ThemedApp:
    """Base class for applying themes to the application"""
    def __init__(self, root):
        # Load available themes
        self.style = ttkthemes.ThemedStyle(root)
        self.available_themes = self.style.get_themes()
        self.current_theme = "clam"  # Default theme
        self.is_dark_mode = False
        self.apply_theme(self.current_theme)

    def apply_theme(self, theme_name):
        """Apply the selected theme to the application"""
        try:
            self.style.set_theme(theme_name)
            self.current_theme = theme_name
            return True
        except:
            return False

    def toggle_dark_mode(self):
        """Toggle between dark and light mode"""
        if self.is_dark_mode:
            # Switch to light mode
            self.style.set_theme("arc")
            self.configure_light_mode()
            self.is_dark_mode = False
        else:
            # Switch to dark mode
            self.style.set_theme("equilux")
            self.configure_dark_mode()
            self.is_dark_mode = True
            
    def configure_dark_mode(self):
        """Configure colors for dark mode"""
        self.style.configure('TFrame', background='#2d2d2d')
        self.style.configure('TLabel', background='#2d2d2d', foreground='#ffffff')
        self.style.configure('TButton', background='#444444', foreground='#ffffff')
        self.style.configure('TCheckbutton', background='#2d2d2d', foreground='#ffffff')
        self.style.configure('TRadiobutton', background='#2d2d2d', foreground='#ffffff')
        self.style.configure('TNotebook', background='#2d2d2d')
        self.style.configure('TNotebook.Tab', background='#2d2d2d', foreground='#ffffff', padding=[10, 2])
        
    def configure_light_mode(self):
        """Configure colors for light mode"""
        self.style.configure('TFrame', background='#f0f0f0')
        self.style.configure('TLabel', background='#f0f0f0', foreground='#000000')
        self.style.configure('TButton', background='#e0e0e0', foreground='#000000')
        self.style.configure('TCheckbutton', background='#f0f0f0', foreground='#000000')
        self.style.configure('TRadiobutton', background='#f0f0f0', foreground='#000000')
        self.style.configure('TNotebook', background='#f0f0f0')
        self.style.configure('TNotebook.Tab', background='#e0e0e0', foreground='#000000', padding=[10, 2])

class CustomProgressBar(ttk.Progressbar):
    """Enhanced progress bar with custom styling"""
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.configure(style="Custom.Horizontal.TProgressbar")
        
class CustomButton(ttk.Button):
    """Enhanced button with hover effects"""
    def __init__(self, master=None, **kwargs):
        self.default_style = kwargs.pop('style', 'TButton')
        super().__init__(master, style=self.default_style, **kwargs)
        
        # Create the hover style if it doesn't exist
        try:
            style = ttk.Style()
            style.map(f'{self.default_style}.Hover',
                background=[('active', '#4a6984')],
                foreground=[('active', 'white')])
        except Exception:
            # If style creation fails, use the default style
            pass
            
        self.bind('<Enter>', self._on_enter)
        self.bind('<Leave>', self._on_leave)
        
    def _on_enter(self, event):
        """Mouse enter effect"""
        try:
            self.configure(style=f'{self.default_style}.Hover')
        except Exception:
            # If hover style fails, keep the default style
            pass
        
    def _on_leave(self, event):
        """Mouse leave effect"""
        self.configure(style=self.default_style)
        
class TooltipBase:
    """Base class for tooltips"""
    def __init__(self, widget, text):
        self.widget = widget
        self.text = text
        self.tooltip = None
        self.widget.bind("<Enter>", self.on_enter)
        self.widget.bind("<Leave>", self.on_leave)
        
    def on_enter(self, event):
        x, y, _, _ = self.widget.bbox("insert")
        x += self.widget.winfo_rootx() + 25
        y += self.widget.winfo_rooty() + 25
        
        self.tooltip = tk.Toplevel(self.widget)
        self.tooltip.wm_overrideredirect(True)
        self.tooltip.wm_geometry(f"+{x}+{y}")
        
        label = ttk.Label(self.tooltip, text=self.text, justify=tk.LEFT,
                         background="#ffffe0", relief=tk.SOLID, borderwidth=1)
        label.pack(ipadx=4, ipady=2)
        
    def on_leave(self, event):
        if self.tooltip:
            self.tooltip.destroy()
            self.tooltip = None

class Tooltip(TooltipBase):
    """Tooltip for widgets"""
    def __init__(self, widget, text):
        super().__init__(widget, text)
        
def create_tooltip(widget, text):
    """Helper function to create tooltips"""
    return Tooltip(widget, text)

class StatusBar(ttk.Frame):
    """Enhanced status bar with multiple sections"""
    def __init__(self, master, **kwargs):
        super().__init__(master, **kwargs)
        self.columnconfigure(0, weight=2)
        self.columnconfigure(1, weight=1)
        
        self.status_text = tk.StringVar(value="Ready")
        self.left_label = ttk.Label(self, textvariable=self.status_text, relief=tk.SUNKEN, anchor=tk.W)
        self.left_label.grid(row=0, column=0, sticky="ew")
        
        self.right_text = tk.StringVar(value="")
        self.right_label = ttk.Label(self, textvariable=self.right_text, relief=tk.SUNKEN, anchor=tk.E)
        self.right_label.grid(row=0, column=1, sticky="ew")
        
    def set_status(self, text):
        """Set the main status text"""
        self.status_text.set(text)
        
    def set_right_text(self, text):
        """Set the right-aligned status text"""
        self.right_text.set(text)

class HyperlinkLabel(ttk.Label):
    """Label that acts as a hyperlink"""
    def __init__(self, master=None, **kwargs):
        self.link_color = kwargs.pop('link_color', 'blue')
        self.hover_color = kwargs.pop('hover_color', 'navy')
        self.clicked_color = kwargs.pop('clicked_color', 'purple')
        self.url = kwargs.pop('url', None)
        
        kwargs['foreground'] = self.link_color
        kwargs['cursor'] = 'hand2'
        
        super().__init__(master, **kwargs)
        
        font = tkfont.Font(self, self.cget("font"))
        font.configure(underline=True)
        self.configure(font=font)
        
        self.bind('<Enter>', self._on_enter)
        self.bind('<Leave>', self._on_leave)
        self.bind('<Button-1>', self._on_click)
        
    def _on_enter(self, event):
        self.configure(foreground=self.hover_color)
        
    def _on_leave(self, event):
        self.configure(foreground=self.link_color)
        
    def _on_click(self, event):
        self.configure(foreground=self.clicked_color)
        if self.url:
            self._open_url()
            
    def _open_url(self):
        """Open the URL in the default browser"""
        import webbrowser
        webbrowser.open(self.url)