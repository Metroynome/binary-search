import tkinter as tk
from tkinter import filedialog, messagebox
import os

def search_binary_file(file_path, search_bytes, offset=0, find_all=True):
    """
    Searches for a given sequence of bytes in a binary file and prints their addresses.

    :param file_path: Path to the binary file.
    :param search_bytes: Byte sequence to search for.
    :param offset: Offset to add or subtract from the output addresses.
    :param find_all: Boolean indicating whether to find all matches or stop after the first.
    """
    search_length = len(search_bytes)

    try:
        with open(file_path, "rb") as binary_file:
            address = 0
            chunk_size = 1024  # Adjust for performance

            results = []
            while True:
                chunk = binary_file.read(chunk_size)

                if not chunk:
                    break

                # Search for the sequence in the current chunk
                index = chunk.find(search_bytes)

                while index != -1:
                    results.append(f"0x{(address + index + offset):08x}")
                    if not find_all:
                        return results
                    # Continue searching within the same chunk
                    index = chunk.find(search_bytes, index + 1)

                address += chunk_size
            
            return results
    except FileNotFoundError:
        raise FileNotFoundError(f"File '{file_path}' not found.")
    except Exception as e:
        raise e

def browse_files(entry):
    file_paths = filedialog.askopenfilenames()
    entry.delete(0, tk.END)
    entry.insert(0, ";".join(file_paths))

def search():
    file_paths = file_path_entry.get().split(";")
    hex_sequence = hex_sequence_entry.get()
    offset = offset_entry.get()
    find_all = find_all_var.get()

    try:
        search_bytes = bytes.fromhex(hex_sequence)
        offset = int(offset) if offset else 0

        result_text.delete(1.0, tk.END)

        pal_results = []
        ntsc_results = []

        for file_path in file_paths:
            if not file_path:
                continue

            results = search_binary_file(file_path, search_bytes, offset, find_all=find_all)

            # Extract mapName and region from the file name
            _, file_name = os.path.split(file_path)
            parts = file_name.split(".")
            map_name = parts[2] if len(parts) > 2 else "unknown"
            region = parts[0] if len(parts) > 0 else "unknown"

            if results:
                formatted_results = "\n".join([f"\t.{map_name} = {address}" for address in results])
                if region.lower() == "pal":
                    pal_results.append(formatted_results)
                else:
                    ntsc_results.append(formatted_results)

        # Add #if and #endif for output formatting
        result_text.insert(tk.END, "VariableAddress_t vaName = {\n")
        result_text.insert(tk.END, "#if UYA_PAL\n")

        # Display PAL results first, add "#else" separator, then NTSC
        if pal_results:
            result_text.insert(tk.END, "\n".join(pal_results) + "\n")
            result_text.insert(tk.END, "#else\n")
        if ntsc_results:
            result_text.insert(tk.END, "\n".join(ntsc_results) + "\n")
        
        result_text.insert(tk.END, "#endif\n")
        result_text.insert(tk.END, "};\n")

    except FileNotFoundError as e:
        messagebox.showerror("Error", str(e))
    except ValueError:
        messagebox.showerror("Error", "Invalid hex sequence or offset.")
    except Exception as e:
        messagebox.showerror("Error", f"An error occurred: {e}")

# Create GUI
root = tk.Tk()
root.title("Binary File Byte Search")

frame = tk.Frame(root, padx=10, pady=10)
frame.pack(fill=tk.BOTH, expand=True)

# File path input
file_path_label = tk.Label(frame, text="Binary File Paths:")
file_path_label.grid(row=0, column=0, sticky=tk.W, pady=5)
file_path_entry = tk.Entry(frame, width=50)
file_path_entry.grid(row=0, column=1, pady=5)
browse_button = tk.Button(frame, text="Browse", command=lambda: browse_files(file_path_entry))
browse_button.grid(row=0, column=2, pady=5)

# Hex sequence input
hex_sequence_label = tk.Label(frame, text="Hex Sequence:")
hex_sequence_label.grid(row=1, column=0, sticky=tk.W, pady=5)
hex_sequence_entry = tk.Entry(frame, width=50)
hex_sequence_entry.grid(row=1, column=1, columnspan=2, pady=5)

# Offset input
offset_label = tk.Label(frame, text="Offset:")
offset_label.grid(row=2, column=0, sticky=tk.W, pady=5)
offset_entry = tk.Entry(frame, width=50)
offset_entry.grid(row=2, column=1, columnspan=2, pady=5)

# Find all checkbox
find_all_var = tk.BooleanVar(value=True)
find_all_checkbox = tk.Checkbutton(frame, text="Find all matches", variable=find_all_var)
find_all_checkbox.grid(row=3, column=0, columnspan=3, pady=5)

# Search button
search_button = tk.Button(frame, text="Search", command=search)
search_button.grid(row=4, column=0, columnspan=3, pady=10)

# Results display
result_text = tk.Text(frame, width=60, height=15)
result_text.grid(row=5, column=0, columnspan=3, pady=10)

root.mainloop()
