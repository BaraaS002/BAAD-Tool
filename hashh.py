import hashlib
import os
import tkinter as tk
from tkinter import filedialog, messagebox, scrolledtext, simpledialog
from tkinter.ttk import Combobox, Button, Label, Style
import subprocess

class HashToolApp:
    def __init__(self, root):
        """Initialize the application with the main window."""
        self.root = root
        self.root.title("File Integrity Verification Tool (Hash)")
        self.root.geometry("600x500")
        self.root.configure(bg="#2c3e50")  # Set background color

        # Define style for ttk widgets
        self.style = Style()
        self.style.theme_use("clam")
        self.style.configure("TButton", font=("Arial", 12, "bold"), background="#003366", foreground="white")
        self.style.map("TButton", background=[("active", "#2980b9")])

        self.style.configure("TLabel", font=("Arial", 12), background="#2c3e50", foreground="white")
        self.style.configure("TCombobox", font=("Arial", 12))

        # Create GUI widgets
        self.create_widgets()

        # Define common system files to check
        self.system_files = ["/etc/passwd", "/etc/shadow", "/bin/ls"]  # Add more as needed

        # Directory to save hashes
        self.hash_dir = "Hashh"
        os.makedirs(self.hash_dir, exist_ok=True)

    def create_widgets(self):
        """Create the GUI widgets for the application."""
        # Title label
        title_label = Label(self.root, text="File Integrity Verification Tool", style="TLabel")
        title_label.pack(pady=15)

        # Buttons for different functionalities
        Button(self.root, text="Calculate Hash", command=self.calculate_hash_gui).pack(pady=10)
        Button(self.root, text="Compare Hash", command=self.compare_hashes_gui).pack(pady=10)
        Button(self.root, text="Check System File Integrity", command=self.check_system_files_gui).pack(pady=10)

        # زر الرجوع مع اللون الأحمر
        tk.Button(self.root, text="Back", command=self.back_to_main, bg="red", fg="white", font=("Arial", 12, "bold")).pack(pady=10)

        # Text area for output
        self.output_area = scrolledtext.ScrolledText(self.root, width=60, height=15, bg="#ecf0f1", fg="#2c3e50", font=("Courier", 10))
        self.output_area.pack(pady=15)

    def back_to_main(self):
        """Return to the MainApp."""
        self.root.destroy()  # Close the current window
        subprocess.Popen(["python3", "main.py"])  # Open MainApp

    def calculate_hash_gui(self):
        """Open a file dialog to choose a file and calculate its hash."""
        file_path = self.open_file_dialog()
        if not file_path:
            messagebox.showwarning("Warning", "No file selected. Please choose a file.")
            return

        # Hash algorithm selection
        algorithm = self.select_hash_algorithm()
        if not algorithm:
            return

        # Calculate the hash
        hash_value = self.calculate_hash(file_path, algorithm)
        self.output_area.insert(tk.END, f"Hash ({algorithm}): {hash_value}\n")

        if messagebox.askyesno("Save Hash", "Would you like to save the hash?"):
            self.save_hash(file_path, hash_value, algorithm)

    def open_file_dialog(self):
        """Open a file dialog and return the selected file path."""
        return filedialog.askopenfilename()

    def select_hash_algorithm(self):
        """Open a dialog to select hash algorithm and return the selected algorithm."""
        algorithm_window = tk.Toplevel(self.root)
        algorithm_window.title("Select Hash Algorithm")
        algorithm_window.configure(bg="#34495e")

        Label(algorithm_window, text="Select Hash Algorithm:", style="TLabel").pack(pady=5)
        algorithm_var = tk.StringVar(value="sha256")

        # Dropdown for hash algorithm selection
        algorithm_combo = Combobox(algorithm_window, textvariable=algorithm_var)
        algorithm_combo['values'] = ('sha1', 'sha256', 'sha512')
        algorithm_combo.pack(pady=10)

        Button(algorithm_window, text="OK", command=algorithm_window.destroy).pack(pady=10)

        algorithm_window.wait_window(algorithm_window)
        return algorithm_var.get() if algorithm_var.get() else None

    def calculate_hash(self, file_path, algorithm="sha256"):
        """Calculate the hash of a file using the specified algorithm."""
        try:
            hash_func = getattr(hashlib, algorithm)()
            with open(file_path, "rb") as f:
                for byte_block in iter(lambda: f.read(4096), b""):
                    hash_func.update(byte_block)
            return hash_func.hexdigest()
        except AttributeError:
            return "Unsupported algorithm"
        except FileNotFoundError:
            return f"File not found: {file_path}"
        except Exception as e:
            return f"An error occurred: {str(e)}"

    def save_hash(self, file_path, hash_value, algorithm):
        """Save the calculated hash to a file in the hash directory."""
        with open(os.path.join(self.hash_dir, "hashes.txt"), "a") as f:
            f.write(f"{file_path} ({algorithm}): {hash_value}\n")
        self.output_area.insert(tk.END, "Hash value saved successfully.\n")

    def compare_hashes_gui(self):
        """Display options for comparing hashes."""
        compare_window = tk.Toplevel(self.root)
        compare_window.title("Compare Hash")
        compare_window.configure(bg="#34495e")

        Label(compare_window, text="Choose an option:", style="TLabel").pack(pady=5)

        Button(compare_window, text="Compare file with manual hash", command=self.compare_file_with_manual_hash).pack(pady=5)
        Button(compare_window, text="Compare file with saved hash", command=self.compare_file_with_saved_hash).pack(pady=5)

    def compare_file_with_manual_hash(self):
        """Compare a file with a manually entered hash."""
        file_path = self.open_file_dialog()
        if not file_path:
            messagebox.showwarning("Warning", "No file selected. Please choose a file.")
            return

        algorithm = self.select_hash_algorithm()
        if not algorithm:
            return

        manual_hash = simpledialog.askstring("Input", "Enter the hash to compare:")
        if manual_hash is None or manual_hash.strip() == "":
            messagebox.showwarning("Warning", "No hash entered. Please enter a valid hash.")
            return

        file_hash = self.calculate_hash(file_path, algorithm)
        self.show_comparison_result(file_hash, manual_hash)

    def show_comparison_result(self, file_hash, comparison_hash):
        """Display the result of hash comparison."""
        if isinstance(file_hash, str) and "error" in file_hash.lower():
            messagebox.showerror("Error", file_hash)
            return

        if file_hash == comparison_hash:
            messagebox.showinfo("Result", "The hash matches the provided hash.")
        else:
            messagebox.showinfo("Result", "The hash does not match the provided hash.")

    def compare_file_with_saved_hash(self):
        """Compare a file with a saved hash."""
        saved_hashes = self.load_saved_hashes()
        if not saved_hashes:
            messagebox.showinfo("Info", "No saved hashes found.")
            return

        compare_window = tk.Toplevel(self.root)
        compare_window.title("Select Saved Hash")
        compare_window.configure(bg="#34495e")

        Label(compare_window, text="Select a saved hash to compare:", style="TLabel").pack(pady=5)

        self.saved_hash_listbox = tk.Listbox(compare_window, height=10)
        for index, line in enumerate(saved_hashes):
            self.saved_hash_listbox.insert(tk.END, f"{index + 1}. {line.strip()}")
        self.saved_hash_listbox.pack(pady=10)

        Button(compare_window, text="Compare", command=lambda: self.process_saved_hash_selection(saved_hashes)).pack(pady=5)

    def process_saved_hash_selection(self, saved_hashes):
        """Process the selected saved hash for comparison."""
        selected_index = self.saved_hash_listbox.curselection()
        if selected_index:
            index = selected_index[0]
            selected_hash = saved_hashes[index].split(": ")[1].strip()

            file_path = self.open_file_dialog()
            if not file_path:
                messagebox.showwarning("Warning", "No file selected. Please choose a file.")
                return
            
            algorithm = self.select_hash_algorithm()
            if not algorithm:
                return

            file_hash = self.calculate_hash(file_path, algorithm)
            self.show_comparison_result(file_hash, selected_hash)
        else:
            messagebox.showwarning("Warning", "No hash selected. Please select a hash to compare.")

    def load_saved_hashes(self):
        """Load saved hashes from the hash file."""
        try:
            with open(os.path.join(self.hash_dir, "hashes.txt"), "r") as f:
                return f.readlines()
        except FileNotFoundError:
            return []

    def check_system_files_gui(self):
        """Display options for checking system file integrity."""
        options_window = tk.Toplevel(self.root)
        options_window.title("Check System File Integrity")
        options_window.configure(bg="#34495e")

        Label(options_window, text="Choose an option:", style="TLabel").pack(pady=5)

        Button(options_window, text="Save Current System Hash", command=self.save_current_system_hash).pack(pady=5)
        Button(options_window, text="Compare Current System Hash", command=self.compare_current_system_hash).pack(pady=5)

    def save_current_system_hash(self):
        """Save the current hash of predefined system files."""
        with open(os.path.join(self.hash_dir, "system_hashes.txt"), "w") as f:
            for file_path in self.system_files:
                file_hash = self.calculate_hash(file_path)
                f.write(f"{file_path}: {file_hash}\n")
        self.output_area.insert(tk.END, "System hashes saved successfully.\n")

    def compare_current_system_hash(self):
        """Compare current hash of system files with saved hash."""
        saved_hashes = self.load_system_hashes()
        if not saved_hashes:
            messagebox.showinfo("Info", "No saved system hashes found.")
            return

        mismatches = []
        for file_path in self.system_files:
            current_hash = self.calculate_hash(file_path)
            if saved_hashes.get(file_path) != current_hash:
                mismatches.append(file_path)

        if mismatches:
            self.output_area.insert(tk.END, f"Integrity check failed for files: {', '.join(mismatches)}\n")
        else:
            self.output_area.insert(tk.END, "All system files are intact.\n")

    def load_system_hashes(self):
        """Load saved system file hashes."""
        try:
            with open(os.path.join(self.hash_dir, "system_hashes.txt"), "r") as f:
                return {line.split(": ")[0]: line.split(": ")[1].strip() for line in f}
        except FileNotFoundError:
            return {}

if __name__ == "__main__":
    root = tk.Tk()
    app = HashToolApp(root)
    root.mainloop()
