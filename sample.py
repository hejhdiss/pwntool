import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext, filedialog
import subprocess
import threading
import os
import sys
import shutil
import platform
import signal # For sending signals like SIGINT (Ctrl+C) and SIGTSTP (Ctrl+Z)
import time # Import time for sleep

try:
    import fcntl # For non-blocking I/O (Linux/macOS)
    import termios # For non-blocking I/O (Linux/macOS)
    import pty # For true pseudo-terminal emulation (Linux/macOS)
    UNIX_LIKE = True
except ImportError:
    UNIX_LIKE = False

# --- Configuration Constants ---
# Base directory for all main tools
BASE_INSTALL_DIR = "/pwntool/tools/"

# Ettercap specific configurations
ETTERCAP_REPO = "https://github.com/Ettercap/ettercap"
ETTERCAP_INSTALL_DIR = os.path.join(BASE_INSTALL_DIR, "sniffing/ettercap")
ETTERCAP_DEPENDENCIES = [
    "build-essential", "debhelper", "bison", "check", "cmake", "flex", "groff",
    "libbsd-dev", "libcurl4-openssl-dev", "libmaxminddb-dev", "libgtk-3-dev",
    "libltdl-dev", "libluajit-5.1-dev", "libncurses5-dev", "libnet1-dev",
    "libpcap-dev", "libpcre2-dev", "libssl-dev"
]

# RedHawk specific configurations (placeholders)
REDHAWK_REPO = "https://github.com/Tuhinshubhra/RED_HAWK"
REDHAWK_INSTALL_DIR = os.path.join(BASE_INSTALL_DIR, "web/redhawk")

# RouterSploit specific configurations (placeholders)
ROUTERSPLOIT_REPO = "https://github.com/threats/routersploit.git"
ROUTERSPLOIT_INSTALL_DIR = os.path.join(BASE_INSTALL_DIR, "scanning/routersploit")


# --- Helper Functions and Classes ---

class TerminalTab(ttk.Frame):
    """
    A single tab representing a one-shot terminal execution.
    It runs a command once, displays its output, and provides Ctrl+C/Z controls.
    The 'Run as Sudo' checkbox and 'Command' display are static after creation.
    """
    def __init__(self, notebook, password, full_executable_command="", command_string_for_display_label="", title="Terminal", initial_sudo_state=False, **kwargs):
        super().__init__(notebook, **kwargs)
        self.notebook = notebook
        self.password = password # Password used for sudo operations (though not directly used for execution in this class anymore)
        self._full_executable_command = full_executable_command # The complete command to run
        self._command_string_for_display_label = command_string_for_display_label or full_executable_command # The string shown in the label
        self._initial_sudo_state = initial_sudo_state # Whether sudo was initially selected
        
        self.process = None
        self.master_fd = None # For pty
        self.running = False # To control the reading thread loop
        
        self.create_widgets()
        # Start the process immediately when the tab is initialized
        self.start_process_in_thread() 

        # Bind Ctrl+C and Ctrl+Z to the notebook for global shortcuts,
        # but the handling method will check if this tab is active.
        self.notebook.bind_all("<Control-c>", self.send_ctrl_c)
        self.notebook.bind_all("<Command-c>", self.send_ctrl_c) # For macOS
        self.notebook.bind_all("<Control-z>", self.send_ctrl_z)
        self.notebook.bind_all("<Command-z>", self.send_ctrl_z) # For macOS


    def create_widgets(self):
        # Top bar with sudo checkbox and control buttons
        control_frame = ttk.Frame(self, style="Terminal.TFrame")
        control_frame.pack(fill="x", padx=5, pady=5)

        # Sudo checkbox - now static
        sudo_checkbox = ttk.Checkbutton(control_frame, text="Run as Sudo", state=tk.DISABLED) # Start as DISABLED
        sudo_checkbox.pack(side="left", padx=5)
        if self._initial_sudo_state: # Set its value based on initial state
            sudo_checkbox.state(['selected'])
        else:
            sudo_checkbox.state(['!selected'])
        
        # Control buttons
        ttk.Button(control_frame, text="Ctrl+C", command=self.send_ctrl_c_button, style="Terminal.TButton").pack(side="right", padx=5)
        ttk.Button(control_frame, text="Ctrl+Z", command=self.send_ctrl_z_button, style="Terminal.TButton").pack(side="right", padx=5)
        
        # --- Display the full command that was passed to this tab ---
        self.command_display_label = ttk.Label(self, text=f"Command: {self._command_string_for_display_label}", style="CommandDisplay.TLabel")
        self.command_display_label.pack(fill="x", padx=5, pady=5)
        
        # Output display area
        self.output_text = scrolledtext.ScrolledText(self, wrap=tk.WORD, bg="black", fg="white", font=("Consolas", 10), relief="flat")
        self.output_text.pack(expand=True, fill="both")
        self.output_text.config(state="disabled")

        # Status label at the bottom
        self.status_label = ttk.Label(self, text="Status: Running initial command...", style="Terminal.TLabel", foreground="#ffff00")
        self.status_label.pack(fill="x", padx=5, pady=5)

    def start_process_in_thread(self):
        """Starts the subprocess in a separate thread."""
        if self.process and self.process.poll() is None:
            self.log_output("[INFO] Process already running.\n")
            return

        self.output_text.config(state="normal")
        self.output_text.delete(1.0, tk.END) # Clear previous output
        self.output_text.config(state="disabled")
        self.status_label.config(text="Status: Running initial command...", foreground="#ffff00")

        # The command is already fully constructed in self._full_executable_command
        command_to_execute = self._full_executable_command
        
        self.log_output(f"Executing: {command_to_execute}\n\n")

        try:
            self.running = True
            if UNIX_LIKE:
                master_fd, slave_fd = pty.openpty()
                self.process = subprocess.Popen(
                    command_to_execute,
                    shell=True, # Critical for 'echo password | sudo -S' to work
                    stdin=slave_fd,
                    stdout=slave_fd,
                    stderr=slave_fd,
                    preexec_fn=os.setsid, # Put process in new session for signal handling
                    text=True,
                    bufsize=1
                )
                os.close(slave_fd)
                self.master_fd = master_fd
                fl = fcntl.fcntl(self.master_fd, fcntl.F_GETFL)
                fcntl.fcntl(self.master_fd, fcntl.F_SETFL, fl | os.O_NONBLOCK)
                threading.Thread(target=self._read_pty_output, daemon=True).start()
            else: # Fallback for Windows
                self.process = subprocess.Popen(
                    command_to_execute,
                    shell=True,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                    bufsize=0
                )
                threading.Thread(target=self._read_pipe_output, daemon=True).start()
        except Exception as e:
            self.log_output(f"[ERROR] Failed to start process: {e}\n")
            self.status_label.config(text=f"Status: Failed ({e})", foreground="#ff0000")
            self.running = False

    def _read_pty_output(self):
        """Reads output from the PTY master file descriptor (Unix-like)."""
        while self.running and self.process and self.process.poll() is None:
            try:
                output = os.read(self.master_fd, 1024).decode('utf-8', errors='ignore')
                if output:
                    self.output_text.after(0, self.log_output, output)
            except OSError as e:
                if e.errno == 11: # EAGAIN (no data available right now) - expected for non-blocking
                    pass
                else:
                    self.output_text.after(0, self.log_output, f"[PTY READ ERROR] {e}\n")
                    self.running = False
                    break
            except Exception as e:
                self.output_text.after(0, self.log_output, f"[READ ERROR] {e}\n")
                self.running = False
                break
            finally:
                time.sleep(0.01) # Small delay to prevent high CPU usage

        if self.master_fd:
            os.close(self.master_fd)
            self.master_fd = None
        
        self.output_text.after(0, self._process_finished)


    def _read_pipe_output(self):
        """Reads output from subprocess pipes (Windows fallback)."""
        while self.running and self.process and self.process.poll() is None:
            output_line = self.process.stdout.readline()
            error_line = self.process.stderr.readline()
            if output_line:
                self.output_text.after(0, self.log_output, output_line)
            if error_line:
                self.output_text.after(0, self.log_output, f"[STDERR] {error_line}")
        
        # Ensure all remaining output is read after process exits
        final_output, final_error = self.process.communicate()
        if final_output:
            self.output_text.after(0, self.log_output, final_output)
        if final_error:
            self.output_text.after(0, self.log_output, f"[STDERR] {final_error}")
        
        self.output_text.after(0, self._process_finished)

    def _process_finished(self):
        """Called when the subprocess terminates."""
        if self.process:
            self.log_output(f"\nProcess exited with code: {self.process.returncode}\n")
            if self.process.returncode == 0:
                self.status_label.config(text="Status: Command completed successfully.", foreground="#00ff00")
            else:
                self.status_label.config(text=f"Status: Command finished with error code {self.process.returncode}.", foreground="#ff0000")
            self.process = None
        else:
            self.status_label.config(text="Status: Terminated.", foreground="#ff0000")
        self.running = False


    def log_output(self, message):
        """Appends a message to the text area and auto-scrolls."""
        self.output_text.config(state="normal")
        self.output_text.insert(tk.END, message)
        self.output_text.see(tk.END)
        self.output_text.config(state="disabled")

    def send_ctrl_c_button(self):
        """Handler for the Ctrl+C button."""
        self.send_ctrl_c()

    def send_ctrl_z_button(self):
        """Handler for the Ctrl+Z button."""
        self.send_ctrl_z()

    def send_ctrl_c(self, event=None):
        """Attempts to send Ctrl+C (SIGINT) to the subprocess."""
        # Only send signal to the currently active tab's process
        if self.notebook.nametowidget(self.notebook.select()) != self: 
            return

        if self.process and self.process.poll() is None:
            try:
                if platform.system() == "Windows":
                    self.process.terminate() # Windows equivalent of SIGINT for many processes
                else:
                    os.killpg(os.getpgid(self.process.pid), signal.SIGINT) # Send SIGINT to process group
                self.log_output("\n[INFO] Sent Ctrl+C (SIGINT) to the process.\n")
                self.status_label.config(text="Status: Sent Ctrl+C. Terminating...", foreground="#ffff00")
            except Exception as e:
                self.log_output(f"[ERROR] Could not send Ctrl+C: {e}\n")
        else:
            self.log_output("[INFO] No active process to send Ctrl+C to.\n")
        return "break" # Prevent default Ctrl+C behavior in Tkinter

    def send_ctrl_z(self, event=None):
        """Attempts to send Ctrl+Z (SIGTSTP) to the subprocess."""
        # Only send signal to the currently active tab's process
        if self.notebook.nametowidget(self.notebook.select()) != self: 
            return

        if self.process and self.process.poll() is None:
            try:
                if platform.system() == "Windows":
                    messagebox.showwarning("Ctrl+Z Not Supported", "Ctrl+Z (SIGTSTP) for suspending processes is generally not supported in this manner on Windows.", parent=self.master)
                    self.log_output("\n[INFO] Ctrl+Z (SIGTSTP) not supported on Windows for subprocesses.\n")
                else:
                    os.killpg(os.getpgid(self.process.pid), signal.SIGTSTP) # Send SIGTSTP to process group
                    self.log_output("\n[INFO] Sent Ctrl+Z (SIGTSTP) to the process.\n")
                    self.status_label.config(text="Status: Sent Ctrl+Z. Suspending...", foreground="#ffff00")
            except Exception as e:
                self.log_output(f"[ERROR] Could not send Ctrl+Z: {e}\n")
        else:
            self.log_output("[INFO] No active process to send Ctrl+Z to.\n")
        return "break" # Prevent default Ctrl+Z behavior in Tkinter

    def terminate_process(self):
        """Terminates the subprocess gracefully, then forcefully if needed."""
        self.running = False
        if self.process and self.process.poll() is None:
            self.log_output("\n[INFO] Terminating process...\n")
            try:
                self.process.terminate() # Send SIGTERM (or similar on Windows)
                self.process.wait(timeout=3) # Wait a bit for graceful exit
            except subprocess.TimeoutExpired:
                self.process.kill() # Force kill if it doesn't exit gracefully
                self.log_output("[INFO] Process killed (forced).\n")
            except Exception as e:
                self.log_output(f"[ERROR] Error during termination: {e}\n")
            finally:
                self.process = None
        self.status_label.config(text="Status: Terminated.", foreground="#ff0000")


class TabbedTerminalManager(tk.Toplevel):
    """A Toplevel window that manages multiple one-shot terminal tabs."""
    def __init__(self, parent, password):
        super().__init__(parent)
        self.title("PWNTOOL Terminal Manager")
        self.geometry("1000x700")
        self.transient(parent)
        self.grab_set()
        self.protocol("WM_DELETE_WINDOW", self.on_close)

        self.password = password

        # Frame for buttons (top)
        button_frame = ttk.Frame(self, style="Terminal.TFrame")
        button_frame.pack(fill="x", side="top", padx=5, pady=5)

        ttk.Button(button_frame, text="Create New Tab", command=self.create_new_tab_prompt, style="Terminal.TButton").pack(side="left", padx=5)
        ttk.Button(button_frame, text="Close Current Tab", command=self.close_current_tab, style="Terminal.TButton").pack(side="right", padx=5)
        ttk.Button(button_frame, text="Close All Tabs", command=self.on_close, style="Terminal.TButton").pack(side="right", padx=5)

        # Notebook for tabs (fills remaining space)
        self.notebook = ttk.Notebook(self)
        self.notebook.pack(expand=True, fill="both", padx=5, pady=5)
        
        # No default tab on startup now, as all tabs are user-defined one-shot
        # The user will initiate tab creation via "Create New Tab"

    def create_new_tab_prompt(self):
        """Opens a popup for the user to enter a command and select sudo for a new tab."""
        prompt_popup = tk.Toplevel(self)
        prompt_popup.title("Enter Command for New Tab")
        prompt_popup.geometry("400x200")
        prompt_popup.transient(self)
        prompt_popup.grab_set()
        prompt_popup.config(bg="#1a1a1a")

        ttk.Label(prompt_popup, text="Command to run in new tab (e.g., 192.168.1.1):", style="Popup.TLabel").pack(pady=(10, 5))
        command_entry = ttk.Entry(prompt_popup, style="TEntry", width=50)
        command_entry.pack(pady=5)
        command_entry.focus_set()

        sudo_var_popup = tk.BooleanVar(value=False) # Sudo checkbox for the new tab
        ttk.Checkbutton(prompt_popup, text="Run with Sudo", variable=sudo_var_popup,
                        style="TCheckbutton").pack(pady=5)


        def add_tab_with_command():
            cmd_input = command_entry.get().strip()
            # Removed the if not cmd_input: check as per user request to allow empty input
            
            # Get ettercap_path from the main application instance
            ettercap_exec_path = self.master.ettercap_path if hasattr(self.master, 'ettercap_path') else "ettercap"
            
            # Prepend 'ettercap -T ' to the user's input for *all* new tabs
            # This is the base command for this tab, before any sudo wrapping
            base_command_for_tab = f"{ettercap_exec_path} -T {cmd_input}"
            
            self.add_terminal_tab(base_command_for_tab, sudo_selected=sudo_var_popup.get())
            prompt_popup.destroy()
        
        ttk.Button(prompt_popup, text="Start Tab", command=add_tab_with_command, style="Install.TButton").pack(pady=10)
        prompt_popup.wait_window()

    def add_terminal_tab(self, base_command_to_run, title_suffix="", sudo_selected=False):
        """
        Adds a new TerminalTab to the notebook with a specific one-shot command.
        It constructs the *full executable command string* here including the sudo prefix.
        """
        full_executable_command = ""
        command_string_for_display_label = ""
        
        if sudo_selected:
            if not self.password:
                messagebox.showerror("Sudo Password Missing", "Cannot run with sudo: Terminal Manager was opened without a sudo password.", parent=self)
                return
            
            # The command for bash -c needs to be properly escaped
            escaped_inner_command = base_command_to_run.replace("'", "'\\''")
            
            # This is the command that will actually be run by subprocess.Popen
            full_executable_command = f"echo '{self.password}' | sudo -S bash -c '{escaped_inner_command}'"
            
            # This is the string we want to display in the tab's Command: label
            command_string_for_display_label = f"echo '********' | sudo -S bash -c '{escaped_inner_command}'"
        else:
            full_executable_command = base_command_to_run
            command_string_for_display_label = base_command_to_run

        # Create a descriptive title for the tab
        tab_title = f"Task {len(self.notebook.tabs()) + 1}: {base_command_to_run[:30]}"
        if len(base_command_to_run) > 30:
            tab_title += "..."
        if title_suffix:
            tab_title += title_suffix
        
        # Create the TerminalTab instance, passing both the executable and display strings
        tab_frame = TerminalTab(self.notebook, self.password, 
                                full_executable_command=full_executable_command, 
                                command_string_for_display_label=command_string_for_display_label,
                                title=tab_title, initial_sudo_state=sudo_selected)
        
        self.notebook.add(tab_frame, text=tab_title)
        self.notebook.select(tab_frame) # Make the new tab active

    def close_current_tab(self):
        """Closes the currently selected terminal tab, terminating its process."""
        selected_tab_id = self.notebook.select()
        if not selected_tab_id:
            messagebox.showinfo("No Tab Selected", "No terminal tab is currently selected.", parent=self)
            return

        current_tab_widget = self.notebook.nametowidget(selected_tab_id)
        if isinstance(current_tab_widget, TerminalTab):
            current_tab_widget.terminate_process() # Ensure process is stopped
            self.notebook.forget(selected_tab_id)
            # After closing a tab, if there are no more tabs, optionally close the manager window
            if not self.notebook.tabs():
                self.on_close()
        else:
            # This case should ideally not happen if only TerminalTab instances are added
            messagebox.showwarning("Invalid Tab", "The selected tab is not a valid terminal tab.", parent=self)


    def on_close(self):
        """Terminates all running subprocesses before closing the manager window."""
        for tab_id in self.notebook.tabs():
            tab_widget = self.notebook.nametowidget(tab_id)
            if isinstance(tab_widget, TerminalTab):
                tab_widget.terminate_process()
        self.grab_release()
        self.destroy()


def run_command_in_new_tab(parent_app, command, title_suffix="", sudo_required=False):
    """
    Helper function to launch a command in a new one-shot terminal tab.
    This function handles opening the Terminal Manager and passing the command.
    """
    if not (hasattr(parent_app, '_terminal_manager') and parent_app._terminal_manager and parent_app._terminal_manager.winfo_exists()):
        # Prompt for password and create manager if it doesn't exist
        password_holder = {"password": None} 

        password_popup = tk.Toplevel(parent_app)
        password_popup.title("Sudo Password for Terminals")
        password_popup.geometry("350x150")
        password_popup.transient(parent_app)
        password_popup.grab_set()
        password_popup.config(bg="#1a1a1a")

        ttk.Label(password_popup, text="Enter Sudo Password for Terminals:", style="Popup.TLabel").pack(pady=(15, 5))
        sudo_password_entry = ttk.Entry(password_popup, show="*", style="TEntry", width=30)
        sudo_password_entry.pack(pady=5)
        sudo_password_entry.focus_set()

        def set_terminal_password_and_create_manager_from_helper():
            password_holder["password"] = sudo_password_entry.get()
            password_popup.destroy()
        
        ttk.Button(password_popup, text="Set Password", command=set_terminal_password_and_create_manager_from_helper, style="Install.TButton").pack(pady=15)
        
        parent_app.wait_window(password_popup) 
        
        if password_holder["password"] is not None: 
            parent_app._terminal_password = password_holder["password"]
            parent_app._terminal_manager = TabbedTerminalManager(parent_app, parent_app._terminal_password)
        else:
            messagebox.showwarning("Launch Failed", "Sudo password required to open terminal manager.", parent=parent_app)
            return 


    if parent_app._terminal_manager and parent_app._terminal_manager.winfo_exists():
        # Pass the base command, and let add_terminal_tab handle sudo prefixing
        parent_app._terminal_manager.add_terminal_tab(command, title_suffix=title_suffix, sudo_selected=sudo_required)
        parent_app._terminal_manager.lift() # Bring terminal manager to front
    else:
        messagebox.showwarning("Launch Failed", "Terminal Manager window could not be opened.", parent=parent_app)


# --- Main Application Class ---

class HackerApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("PWNTOOL - Hacker's Toolkit")
        self.geometry("1200x800")
        self.configure(bg="#1a1a1a") # Darker background for main window
        self.current_content_frame = None
        self._terminal_manager = None
        self._terminal_password = ""
        self.ettercap_path = "ettercap" # Default, will be updated by check_initial_tool_statuses
        self.main_app_instance = self # Explicit reference to self for bindings

        self.tool_statuses = {
            "Ettercap": "Not Installed",
            "RedHawk": "Not Installed",
            "RouterSploit": "Not Installed"
        }

        self.create_styles()
        self.create_main_layout()
        self.check_initial_tool_statuses()
        self.show_tool_installer()

    def create_styles(self):
        """Configures custom styles for ttk widgets with a 'maximum look' dark theme."""
        style = ttk.Style(self)
        style.theme_use("clam") # A good dark base theme

        # --- General Frames and Backgrounds ---
        style.configure("TFrame", background="#1a1a1a") # Main frame background
        style.configure("TLabel", background="#1a1a1a", foreground="#e0e0e0", font=("Inter", 10)) # Default label
        style.configure("Heading.TLabel", background="#1a1a1a", foreground="#00e6e6", font=("Inter", 18, "bold")) # Aqua/cyan
        style.configure("SubHeading.TLabel", background="#1a1a1a", foreground="#00cccc", font=("Inter", 12, "bold")) # Slightly darker aqua

        # --- Sidebar Styles ---
        style.configure("Sidebar.TButton",
                        background="#2a2a2a", # Darker grey for sidebar buttons
                        foreground="#ffffff", # White text
                        font=("Inter", 11, "bold"),
                        relief="flat",
                        borderwidth=0,
                        padding=(15, 12), # More padding
                        focuscolor="#00e6e6" # Focus matches heading
                       )
        style.map("Sidebar.TButton",
                  background=[("active", "#3a3a3a"), ("pressed", "#1a1a1a")], # Subtle hover/press
                  foreground=[("active", "#00e6e6")] # Text brightens on hover
                 )

        # --- Tool Card Styles ---
        style.configure("ToolCard.TFrame",
                        background="#2a2a2a", # Medium dark grey
                        relief="flat", # Flat look
                        borderwidth=2,
                        bordercolor="#4a4a4a", # Subtle border
                        focusthickness=2,
                        focuscolor="#00e6e6",
                       )
        style.map("ToolCard.TFrame",
                  background=[("active", "#3a3a3a")] # Slight shade change on hover
                 )

        style.configure("ToolCard.TLabel", background="#2a2a2a", foreground="#e0e0e0", font=("Inter", 10))
        style.configure("ToolName.TLabel", background="#2a2a2a", foreground="#00e6e6", font=("Inter", 13, "bold"))
        style.configure("Status.TLabel", background="#2a2a2a", foreground="#00cc00", font=("Inter", 10, "bold")) # Bright green for status

        # --- Action Buttons (Install/Run) ---
        style.configure("Install.TButton",
                        background="#007acc", # Blue, slightly desaturated
                        foreground="white",
                        font=("Inter", 10, "bold"),
                        relief="raised",
                        borderwidth=0,
                        padding=(10, 8), # Generous padding
                        borderradius=5 # Rounded corners (if theme supports directly)
                       )
        style.map("Install.TButton",
                  background=[("active", "#005f99"), ("pressed", "#004066")], # Darker shades on interaction
                  foreground=[("active", "white")]
                 )

        style.configure("Run.TButton",
                        background="#28a745", # Green
                        foreground="white",
                        font=("Consolas", 10, "bold"),
                        relief="raised",
                        borderwidth=0,
                        padding=(10, 8),
                        borderradius=5
                       )
        style.map("Run.TButton",
                  background=[("active", "#1e8235"), ("pressed", "#17642a")], # Darker shades on interaction
                  foreground=[("active", "white")]
                 )

        # --- Popup Styles (Unified Look) ---
        style.configure("Popup.TFrame", background="#2a2a2a") # Popups are slightly lighter than main window
        style.configure("Popup.TLabel", background="#2a2a2a", foreground="#e0e0e0", font=("Inter", 10))
        style.configure("Popup.Heading.TLabel", background="#2a2a2a", foreground="#00e6e6", font=("Inter", 12, "bold")) # Popup specific heading
        
        # Radiobutton and Checkbutton
        style.configure("TRadiobutton", background="#2a2a2a", foreground="#e0e0e0", font=("Inter", 10))
        style.map("TRadiobutton", background=[("active", "#3a3a3a")], foreground=[("active", "#00e6e6")])
        style.configure("TCheckbutton", background="#2a2a2a", foreground="#e0e0e0", font=("Inter", 10))
        style.map("TCheckbutton", background=[("active", "#3a3a3a")], foreground=[("active", "#00e6e6")])

        # Entry Fields
        style.configure("TEntry",
                        fieldbackground="#0d0d0d", # Very dark, almost black input field
                        foreground="#00ff00", # Bright green text for input
                        insertcolor="#00ff00", # Matching cursor
                        font=("Consolas", 10), # Monospaced font for code/terminal input
                        borderwidth=1,
                        relief="solid",
                        bordercolor="#4a4a4a", # Subtle border
                       )
        style.map("TEntry", fieldbackground=[('focus', '#1a1a1a')]) # Slightly lighter on focus

        # Terminal specific styles (reusing popup styles for consistency)
        style.configure("Terminal.TFrame", background="#1a1a1a") # Matches main app background
        style.configure("Terminal.TLabel", background="#1a1a1a", foreground="#e0e0e0", font=("Inter", 10))
        style.configure("Terminal.TButton",
                        background="#3e3e3e", foreground="#ffffff", font=("Inter", 9, "bold"),
                        relief="raised", borderwidth=0, padding=(5, 3)
                       )
        style.map("Terminal.TButton",
                  background=[("active", "#555555"), ("pressed", "#222222")],
                  foreground=[("active", "#00ffff")])
        
        # New style for the displayed command in TerminalTab
        style.configure("CommandDisplay.TLabel", background="#1a1a1a", foreground="#00ffcc", font=("Consolas", 11, "bold"))


    def create_main_layout(self):
        """Sets up the main two-pane layout (sidebar + content area)."""
        self.sidebar_frame = ttk.Frame(self, width=220, style="TFrame", relief="flat", borderwidth=0) # Slightly wider sidebar, no border
        self.sidebar_frame.pack(side="left", fill="y", padx=5, pady=5)
        self.sidebar_frame.grid_propagate(False)

        ttk.Label(self.sidebar_frame, text="PWNTOOL", style="Heading.TLabel").pack(pady=(20, 20)) # Larger title

        ttk.Button(self.sidebar_frame, text="Tool Installer", style="Sidebar.TButton",
                   command=self.show_tool_installer).pack(fill="x", pady=4, padx=10) # Increased padding
        
        # This button now opens the manager for one-shot terminal tabs
        self.terminals_button = ttk.Button(self.sidebar_frame, text="Terminals", style="Sidebar.TButton",
                                           command=lambda: self.main_app_instance.open_tabbed_terminal_manager()) 
        self.terminals_button.pack(fill="x", pady=4, padx=10)


        ttk.Label(self.sidebar_frame, text="Categories", style="SubHeading.TLabel").pack(pady=(30, 10)) # More space
        categories = ["All", "Web", "Spoofing", "Sniffing", "Scanning"]
        for category in categories:
            ttk.Button(self.sidebar_frame, text=category, style="Sidebar.TButton",
                       command=lambda c=category: self.main_app_instance.show_category_placeholder(c)).pack(fill="x", pady=4, padx=10)

        self.content_container_frame = ttk.Frame(self, style="TFrame")
        self.content_container_frame.pack(side="right", fill="both", expand=True, padx=5, pady=5)

    def clear_content_frame(self):
        """Removes all widgets from the main content frame."""
        if self.current_content_frame:
            self.current_content_frame.destroy()
        self.current_content_frame = None

    def show_category_placeholder(self, category):
        """Displays a placeholder message for category views."""
        self.clear_content_frame()
        self.current_content_frame = ttk.Frame(self.content_container_frame, style="TFrame")
        self.current_content_frame.pack(expand=True, fill="both")
        ttk.Label(self.current_content_frame, text=f"Displaying tools for: {category}", style="Heading.TLabel").pack(pady=50)
        ttk.Label(self.current_content_frame, text="This section would filter tools based on the selected category.", style="TLabel").pack()

    def check_initial_tool_statuses(self):
        """Checks the installation status of all managed tools on app start."""
        # Check Ettercap
        result = subprocess.run(["which", "ettercap"], capture_output=True, text=True, check=False)
        if result.returncode == 0 and result.stdout.strip():
            self.tool_statuses["Ettercap"] = "Installed"
            self.ettercap_path = result.stdout.strip()
        else:
            self.tool_statuses["Ettercap"] = "Not Installed"
            self.ettercap_path = "ettercap" # Fallback, if not found, use just 'ettercap'
            
        # Check RedHawk
        result = subprocess.run(["which", "redhawk"], capture_output=True, text=True, check=False)
        if result.returncode == 0 and result.stdout.strip():
            self.tool_statuses["RedHawk"] = "Installed"
        else:
            self.tool_statuses["RedHawk"] = "Not Installed"

        # Check RouterSploit
        result = subprocess.run(["which", "routersploit"], capture_output=True, text=True, check=False)
        if result.returncode == 0 and result.stdout.strip():
            self.tool_statuses["RouterSploit"] = "Installed"
        else:
            self.tool_statuses["RouterSploit"] = "Not Installed"


    def update_tool_status(self, tool_name, status):
        """Updates the status in the tool_statuses dictionary and refreshes the UI."""
        self.tool_statuses[tool_name] = status
        self.show_tool_installer() # Re-render the installer to show updated status


    def create_tool_card(self, parent_frame, tool_name, install_method, repo_url=None):
        """Creates and returns a single tool card frame."""
        card_frame = ttk.Frame(parent_frame, style="ToolCard.TFrame", padding=20) # Increased padding
        card_frame.grid_columnconfigure(0, weight=1)

        ttk.Label(card_frame, text=tool_name, style="ToolName.TLabel").grid(row=0, column=0, sticky="w", pady=(0, 8)) # More vertical space

        status_text = f"Status: {self.tool_statuses[tool_name]}"
        ttk.Label(card_frame, text=status_text, style="Status.TLabel").grid(row=1, column=0, sticky="w", pady=4) # More vertical space

        ttk.Label(card_frame, text=f"Install Method: {install_method}", style="ToolCard.TLabel").grid(row=2, column=0, sticky="w", pady=4)

        if repo_url:
            ttk.Label(card_frame, text=repo_url, style="ToolCard.TLabel").grid(row=3, column=0, sticky="w", pady=4)

        install_btn = ttk.Button(card_frame, text="Install", style="Install.TButton",
                                 command=lambda tn=tool_name: self.main_app_instance.handle_install_button(tn))
        install_btn.grid(row=4, column=0, sticky="ew", pady=(15, 0)) # More vertical space

        if self.tool_statuses[tool_name] == "Installed":
            install_btn.config(text="Reinstall")
            run_btn = ttk.Button(card_frame, text="Run", style="Run.TButton",
                                 command=lambda tn=tool_name: self.main_app_instance.handle_run_button(tn))
            run_btn.grid(row=5, column=0, sticky="ew", pady=(8, 0)) # Padding between buttons
        else:
            install_btn.config(state=tk.NORMAL)

        return card_frame

    def show_tool_installer(self):
        """Displays the tool installer view with individual tool cards."""
        self.clear_content_frame()
        self.current_content_frame = ttk.Frame(self.content_container_frame, style="TFrame")
        self.current_content_frame.pack(expand=True, fill="both")

        ttk.Label(self.current_content_frame, text="Tool Installer", style="Heading.TLabel").pack(pady=25) # More padding

        search_frame = ttk.Frame(self.current_content_frame, style="TFrame")
        search_frame.pack(fill="x", padx=25, pady=15) # Increased padding
        ttk.Entry(search_frame, style="TEntry", width=50).pack(side="left", fill="x", expand=True, padx=(0,15)) # Increased padx
        ttk.Button(search_frame, text="Search", style="Install.TButton").pack(side="left")

        tools_grid_frame = ttk.Frame(self.current_content_frame, style="TFrame")
        tools_grid_frame.pack(padx=25, pady=15, fill="both", expand=True) # Increased padding

        for i in range(3):
            tools_grid_frame.grid_columnconfigure(i, weight=1)

        tools_data = [
            {"name": "Ettercap", "method": "prompt", "repo": ETTERCAP_REPO},
            {"name": "RedHawk", "method": "placeholder", "repo": REDHAWK_REPO}, # Changed method for clarity
            {"name": "RouterSploit", "method": "placeholder", "repo": ROUTERSPLOIT_REPO}, # Changed method for clarity
        ]

        row, col = 0, 0
        for tool in tools_data:
            card = self.create_tool_card(
                tools_grid_frame,
                tool["name"],
                tool["method"],
                tool["repo"]
            )
            card.grid(row=row, column=col, padx=15, pady=15, sticky="nsew") # Increased padding around cards

            col += 1
            if col > 2:
                col = 0
                row += 1

    def handle_install_button(self, tool_name):
        """Routes installation requests to the correct handler."""
        if tool_name == "Ettercap":
            self.open_ettercap_install_popup()
        elif tool_name == "RedHawk":
            messagebox.showinfo("Installation", "RedHawk installation will be updated soon!", parent=self)
        elif tool_name == "RouterSploit":
            messagebox.showinfo("Installation", "RouterSploit installation will be updated soon!", parent=self)
        else:
            messagebox.showinfo("Coming Soon", f"Installation for {tool_name} is not yet implemented.", parent=self)

    def handle_run_button(self, tool_name):
        """Routes run requests to the correct handler."""
        if tool_name == "Ettercap":
            self.open_ettercap_run_popup()
        else:
            messagebox.showinfo("Coming Soon", f"Run functionality for {tool_name} is not yet implemented.", parent=self)

    # --- Installation Popup Functions ---

    def open_ettercap_install_popup(self):
        popup = tk.Toplevel(self)
        popup.title("Ettercap Installation Options")
        popup.geometry("600x550")
        popup.transient(self)
        popup.grab_set()
        popup.config(bg="#1a1a1a") # Consistent popup background

        ttk.Label(popup, text="User Password:", style="Popup.TLabel").pack(pady=(15, 5)) # More padding
        password_entry = ttk.Entry(popup, show="*", style="TEntry", width=40)
        password_entry.pack(pady=5)
        password_entry.focus_set()

        ttk.Label(popup, text="Choose method:", style="Popup.TLabel").pack(pady=(15, 5)) # More padding

        ettercap_method_var = tk.StringVar(value="no_deps")
        radio_frame = ttk.Frame(popup, style="Popup.TFrame")
        radio_frame.pack(pady=10, padx=20, anchor="w") # Increased padding

        methods = [
            ("Install from Source (No Dependencies)", "no_deps"),
            ("Install from Source (With All Dependencies)", "all_deps"),
            ("Build from Source (With Selected Dependencies)", "select_deps"),
            ("Install via Apt (Auto Dependency Resolving)", "apt_install")
        ]

        ettercap_dependency_checkboxes = {}
        ettercap_deps_frame = ttk.Frame(popup, style="Popup.TFrame")

        def toggle_ettercap_deps_visibility():
            if ettercap_method_var.get() == "select_deps":
                ettercap_deps_frame.pack(pady=10, padx=20, anchor="w", fill="x", expand=True) # Increased padding
            else:
                ettercap_deps_frame.pack_forget()

        ttk.Label(ettercap_deps_frame, text="Select Dependencies:", style="SubHeading.TLabel").grid(row=0, column=0, columnspan=3, sticky="w", pady=5)
        grid_col = 0
        grid_row = 1
        for idx, dep in enumerate(ETTERCAP_DEPENDENCIES):
            var = tk.BooleanVar(value=True)
            chk = ttk.Checkbutton(ettercap_deps_frame, text=dep, variable=var, style="TCheckbutton")
            chk.grid(row=grid_row, column=grid_col, sticky="w", padx=10, pady=4) # Increased padding
            ettercap_dependency_checkboxes[dep] = var
            grid_col += 1
            if grid_col > 2:
                grid_col = 0
                grid_row += 1
        
        for i in range(3):
            ettercap_deps_frame.grid_columnconfigure(i, weight=1)

        toggle_ettercap_deps_visibility()

        for text, value in methods:
            ttk.Radiobutton(radio_frame, text=text, variable=ettercap_method_var, value=value,
                            command=toggle_ettercap_deps_visibility, style="TRadiobutton").pack(anchor="w", pady=4) # Increased padding

        def on_ettercap_install_confirm():
            password = password_entry.get()
            selected_method = ettercap_method_var.get()

            if not password:
                messagebox.showwarning("Missing Password", "Please enter your sudo password.", parent=popup)
                return

            popup.destroy()

            if selected_method == "no_deps":
                self.execute_ettercap_no_deps_install(password)
            elif selected_method == "all_deps":
                self.execute_ettercap_all_deps_install(password)
            elif selected_method == "select_deps":
                selected_deps_list = [dep for dep, var in ettercap_dependency_checkboxes.items() if var.get()]
                if not selected_deps_list:
                    messagebox.showwarning("No Dependencies Selected", "Please select at least one dependency, or choose another method.", parent=self)
                    return
                self.execute_ettercap_selected_deps_install(password, selected_deps_list)
            elif selected_method == "apt_install":
                self.execute_ettercap_apt_install(password)

        install_button = ttk.Button(popup, text="Start Installation", command=on_ettercap_install_confirm, style="Install.TButton")
        install_button.pack(pady=25) # More padding
        popup.wait_window()

    # --- Ettercap Installation Method Implementations ---
    def execute_ettercap_no_deps_install(self, password):
        rm_existing_folder_cmd = ""
        if os.path.exists(ETTERCAP_INSTALL_DIR):
            rm_existing_folder_cmd = f"rm -rf {ETTERCAP_INSTALL_DIR} && "
            print(f"Existing Ettercap folder found at {ETTERCAP_INSTALL_DIR} — removing...")

        # Construct the base command that will be executed in the shell
        base_command_for_shell = f"""
{rm_existing_folder_cmd}
mkdir -p "{ETTERCAP_INSTALL_DIR}" && \\
echo -e "\\033[96m[+] Cloning Ettercap repo...\\033[0m" && \\
cd {os.path.join(BASE_INSTALL_DIR, "sniffing/")} && \\
git clone "{ETTERCAP_REPO}" && \\
echo -e "\\033[96m[+] Building and installing...\\033[0m" && \\
cd ettercap && \\
make && \\
make install
echo -e "\\n\\033[94m[→] For help or issues, visit: {ETTERCAP_REPO}\\033[0m"
"""
        # Clean up newlines for shell execution, but keep for display readability if needed
        base_command_for_shell = " ".join(base_command_for_shell.splitlines()).strip()
        run_command_in_new_tab(self, base_command_for_shell, title_suffix=" (Ettercap No-Deps Install)", sudo_required=True)

    def execute_ettercap_all_deps_install(self, password):
        rm_existing_folder_cmd = ""
        if os.path.exists(ETTERCAP_INSTALL_DIR):
            rm_existing_folder_cmd = f"rm -rf {ETTERCAP_INSTALL_DIR} && "
            print(f"Existing Ettercap folder found at {ETTERCAP_INSTALL_DIR} — removing...")

        base_command_for_shell = f"""
{rm_existing_folder_cmd}
echo -e "\\033[96m[+] Installing dependencies...\\033[0m" && \\
apt-get install -y {" ".join(ETTERCAP_DEPENDENCIES)} && \\
mkdir -p "{ETTERCAP_INSTALL_DIR}" && \\
echo -e "\\033[96m[+] Cloning Ettercap repo...\\033[0m" && \\
cd {os.path.join(BASE_INSTALL_DIR, "sniffing/")} && \\
git clone "{ETTERCAP_REPO}" && \\
echo -e "\\033[96m[+] Building and installing...\\033[0m" && \\
cd ettercap && \\
mkdir build && cd build && \\
cmake ../ && \\
make && \\
make install
echo -e "\\n\\033[94m[→] For help or issues, visit: {ETTERCAP_REPO}\\033[0m"
"""
        base_command_for_shell = " ".join(base_command_for_shell.splitlines()).strip()
        run_command_in_new_tab(self, base_command_for_shell, title_suffix=" (Ettercap All-Deps Install)", sudo_required=True)

    def execute_ettercap_selected_deps_install(self, password, selected_deps_list):
        dep_string = " ".join(selected_deps_list)
        rm_existing_folder_cmd = ""
        if os.path.exists(ETTERCAP_INSTALL_DIR):
            rm_existing_folder_cmd = f"rm -rf {ETTERCAP_INSTALL_DIR} && "
            print(f"Existing Ettercap folder found at {ETTERCAP_INSTALL_DIR} — removing...")

        base_command_for_shell = f"""
{rm_existing_folder_cmd}
echo -e "\\033[96m[+] Installing selected dependencies...\\033[0m" && \\
apt-get install -y {dep_string} && \\
mkdir -p "{ETTERCAP_INSTALL_DIR}" && \\
echo -e "\\033[96m[+] Cloning Ettercap repo...\\033[0m" && \\
cd {os.path.join(BASE_INSTALL_DIR, "sniffing/")} && \\
git clone "{ETTERCAP_REPO}" && \\
echo -e "\\033[96m[+] Building and installing...\\033[0m" && \\
cd ettercap && \\
mkdir build && cd build && \\
cmake ../ && \\
make && \\
make install
echo -e "\\n\\033[94m[→] For help or issues, visit: {ETTERCAP_REPO}\\033[0m"
"""
        base_command_for_shell = " ".join(base_command_for_shell.splitlines()).strip()
        run_command_in_new_tab(self, base_command_for_shell, title_suffix=" (Ettercap Selected-Deps Install)", sudo_required=True)

    def execute_ettercap_apt_install(self, password):
        base_command_for_shell = f"""
apt update && \\
apt install ettercap-graphical -y
echo -e "\\n\\033[94m[→] For help or issues, visit: {ETTERCAP_REPO}\\033[0m"
"""
        base_command_for_shell = " ".join(base_command_for_shell.splitlines()).strip()
        run_command_in_new_tab(self, base_command_for_shell, title_suffix=" (Ettercap APT Install)", sudo_required=True)

    def open_ettercap_folder(self):
        """Opens the Ettercap installation directory in the system's file explorer."""
        if not os.path.exists(ETTERCAP_INSTALL_DIR):
            messagebox.showinfo("Folder Not Found", f"The Ettercap installation directory does not exist yet:\n{ETTERCAP_INSTALL_DIR}", parent=self)
            return
        try:
            if platform.system() == "Windows":
                os.startfile(ETTERCAP_INSTALL_DIR)
            elif platform.system() == "Darwin": # macOS
                subprocess.Popen(["open", ETTERCAP_INSTALL_DIR])
            else: # Linux and other Unix-like systems
                subprocess.Popen(["xdg-open", ETTERCAP_INSTALL_DIR])
            messagebox.showinfo("Open Folder", f"Opening folder: {ETTERCAP_INSTALL_DIR}", parent=self)
        except Exception as e:
            messagebox.showerror("Error", f"Could not open folder:\n{ETTERCAP_INSTALL_DIR}\nError: {e}", parent=self)


    # --- Run Ettercap Functionality ---

    def open_ettercap_run_popup(self):
        """Opens a popup to select how to run Ettercap."""
        popup = tk.Toplevel(self)
        popup.title("Run Ettercap Options")
        popup.geometry("450x300")
        popup.transient(self)
        popup.grab_set()
        popup.config(bg="#1a1a1a")

        run_mode_var = tk.StringVar(value="gui") # Default to GUI
        ettercap_args_var = tk.StringVar(value="") # For text-based arguments

        def toggle_args_entry_visibility():
            # Show args entry only for "text_based" option
            if run_mode_var.get() == "text_based":
                args_label.pack(pady=(10, 5))
                args_entry.pack(pady=5)
            else:
                args_label.pack_forget()
                args_entry.pack_forget()

        ttk.Label(popup, text="Select Ettercap Run Mode:", style="Popup.TLabel").pack(pady=(15, 5))

        radio_frame = ttk.Frame(popup, style="Popup.TFrame")
        radio_frame.pack(pady=10, padx=20, anchor="w")

        run_modes = [
            ("Graphical UI (Ettercap's Own Window)", "gui"),
            ("Text-based (All commands in popup, output in new tab)", "text_based"), # Clarified text and behavior
        ]

        for text, value in run_modes:
            ttk.Radiobutton(radio_frame, text=text, variable=run_mode_var, value=value,
                            command=toggle_args_entry_visibility, style="TRadiobutton").pack(anchor="w", pady=4)
        
        args_label = ttk.Label(popup, text="Ettercap Commands (e.g., -M arp:remote // // or h):", style="Popup.TLabel")
        args_entry = ttk.Entry(popup, textvariable=ettercap_args_var, style="TEntry", width=30)
        
        # Initial state based on default radio selection
        toggle_args_entry_visibility() 

        ttk.Label(popup, text="Sudo Password (if needed):", style="Popup.TLabel").pack(pady=(15, 5))
        password_entry = ttk.Entry(popup, show="*", style="TEntry", width=30)
        password_entry.pack(pady=5)

        def on_run_confirm():
            selected_mode = run_mode_var.get()
            password = password_entry.get()
            ettercap_args = ettercap_args_var.get().strip() # Get arguments
            popup.destroy()

            if selected_mode == "gui":
                self.run_ettercap_gui(password)
            elif selected_mode == "text_based":
                # The sudo_required for run_command_in_new_tab comes from the password_entry here.
                sudo_required_for_ettercap = bool(password) 
                self.run_ettercap_text_based_one_shot_in_tab(password, ettercap_args, sudo_required_for_ettercap)

        run_button = ttk.Button(popup, text="Launch Ettercap", command=on_run_confirm, style="Run.TButton")
        run_button.pack(pady=25)
        popup.wait_window()

    def run_ettercap_gui(self, password):
        """Launches Ettercap's graphical UI in its own window."""
        cmd_prefix = f"echo '{password}' | sudo -S " if password else ""
        command = f"{cmd_prefix}{self.ettercap_path} -G" # Use stored ettercap_path
        
        messagebox.showinfo("Launching Ettercap GUI", "Ettercap's graphical interface will attempt to launch in its own window.", parent=self)
        
        try:
            if platform.system() == "Windows":
                subprocess.Popen(command, shell=True, creationflags=subprocess.DETACHED_PROCESS)
            else:
                subprocess.Popen(command, shell=True)
            print(f"Attempted to launch: {command}")
        except Exception as e:
            messagebox.showerror("Launch Error", f"Failed to launch Ettercap GUI: {e}", parent=self)


    def open_tabbed_terminal_manager(self):
        """Opens the main window for managing one-shot terminal tabs."""
        if not hasattr(self, '_terminal_manager') or not (self._terminal_manager and self._terminal_manager.winfo_exists()):
            password_holder = {"password": None} 

            password_popup = tk.Toplevel(self)
            password_popup.title("Sudo Password for Terminals")
            password_popup.geometry("350x150")
            password_popup.transient(self)
            password_popup.grab_set()
            password_popup.config(bg="#1a1a1a")

            ttk.Label(password_popup, text="Enter Sudo Password for Terminals:", style="Popup.TLabel").pack(pady=(15, 5))
            sudo_password_entry = ttk.Entry(password_popup, show="*", style="TEntry", width=30)
            sudo_password_entry.pack(pady=5)
            sudo_password_entry.focus_set()

            def set_terminal_password_and_create_manager():
                password_holder["password"] = sudo_password_entry.get()
                password_popup.destroy()
            
            ttk.Button(password_popup, text="Set Password", command=set_terminal_password_and_create_manager, style="Install.TButton").pack(pady=15)
            
            self.wait_window(password_popup) 
            
            if password_holder["password"] is not None: 
                self._terminal_password = password_holder["password"]
                self._terminal_manager = TabbedTerminalManager(self, self._terminal_password)
            else:
                messagebox.showwarning("Terminal Manager Not Opened", "Sudo password required to open terminal manager.", parent=self)
                return 

        if self._terminal_manager and self._terminal_manager.winfo_exists():
            self._terminal_manager.lift() 
        else: 
            messagebox.showwarning("Terminal Manager Not Opened", "Terminal Manager window could not be opened.", parent=self)


    def run_ettercap_text_based_one_shot_in_tab(self, password, ettercap_args, sudo_required_for_ettercap):
        """
        Constructs and launches the Ettercap text-based command in a new one-shot terminal tab.
        This function now prepares the base command to be passed to add_terminal_tab,
        which handles the full command construction and display.
        """
        if not self.ettercap_path:
            messagebox.showerror("Ettercap Not Found", "Ettercap executable path not determined. Please install it first.", parent=self)
            return

        # This is the base command for Ettercap with its specific arguments.
        # add_terminal_tab will handle any sudo wrapping for execution and display.
        base_command_for_add_tab = f"{self.ettercap_path} -T {ettercap_args}"

        # Now pass the fully constructed command strings to add_terminal_tab
        self.open_tabbed_terminal_manager() # Ensure manager is open
        if self._terminal_manager and self._terminal_manager.winfo_exists():
            self._terminal_manager.add_terminal_tab(
                base_command_for_add_tab, # Pass the base command
                title_suffix=f" (Ettercap -T {ettercap_args})",
                sudo_selected=sudo_required_for_ettercap # Pass true sudo state for checkbox
            )
            self._terminal_manager.lift() # Bring terminal manager to front
        else:
            messagebox.showwarning("Launch Failed", "Terminal Manager window could not be opened to run Ettercap.", parent=self)


    # --- RedHawk Placeholder Functions ---
    def open_redhawk_install_popup(self):
        messagebox.showinfo("Installation", "RedHawk installation will be updated soon!", parent=self)

    # --- RouterSploit Placeholder Functions ---
    def open_routersploit_install_popup(self):
        messagebox.showinfo("Installation", "RouterSploit installation will be updated soon!", parent=self)


if __name__ == "__main__":
    app = HackerApp()
    app.mainloop()

