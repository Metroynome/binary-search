import tkinter as tk
from tkinter import filedialog, messagebox
import os

def search_binary_file(file_path, search_bytes, offset=0, find_all=True):
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
    file_paths = filedialog.askopenfilenames(filetypes=[("Binary files", "*.bin")])
    entry.delete(0, tk.END)
    entry.insert(0, ";".join(file_paths))

def process_hex_sequence(hex_sequence, endian_swap):
    hex_sequence = "".join(hex_sequence.split())  # Remove spaces and line breaks
    if len(hex_sequence) % 8 != 0:
        raise ValueError("Hex sequence length must be a multiple of 8 for 32-bit endianness swap.")

    # Convert to 4-byte chunks (32-bit words)
    chunks = [hex_sequence[i:i+8] for i in range(0, len(hex_sequence), 8)]

    if endian_swap:
        # Reverse each 4-byte chunk
        chunks = [chunk[6:8] + chunk[4:6] + chunk[2:4] + chunk[0:2] for chunk in chunks]

    return bytes.fromhex("".join(chunks))

def parse_offset(offset_input):
    if offset_input.startswith("0x"):
        return int(offset_input, 16)
    return int(offset_input)

def search():
    file_paths = file_path_entry.get().split(";")
    hex_sequence = hex_sequence_text.get(1.0, tk.END)
    offset = offset_entry.get()
    find_all = find_all_var.get()
    endian_swap = endian_var.get()

    search_bytes = process_hex_sequence(hex_sequence, endian_swap)
    offset = parse_offset(offset) if offset else 0

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
            formatted_results = "\n".join([f"\t.{map_name} = {address}," for address in results])
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

if __name__ == "__main__":
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
    hex_sequence_text = tk.Text(frame, width=50, height=5)
    hex_sequence_text.grid(row=1, column=1, columnspan=2, pady=5)

    # Offset input
    offset_label = tk.Label(frame, text="Offset: (+/-)")
    offset_label.grid(row=2, column=0, sticky=tk.W, pady=5)
    offset_entry = tk.Entry(frame, width=50)
    offset_entry.grid(row=2, column=1, columnspan=2, pady=5)

    # Checkboxes
    checkbox_frame = tk.Frame(frame)
    checkbox_frame.grid(row=3, column=0, columnspan=3, pady=5, sticky=tk.W)

    endian_var = tk.BooleanVar(value=True)  # Set default to True
    endian_checkbox = tk.Checkbutton(checkbox_frame, text="Reverse Endianness", variable=endian_var)
    endian_checkbox.pack(side=tk.LEFT, padx=5)

    find_all_var = tk.BooleanVar(value=False)  # Set default to False
    find_all_checkbox = tk.Checkbutton(checkbox_frame, text="Find all matches", variable=find_all_var)
    find_all_checkbox.pack(side=tk.LEFT, padx=5)

    # Search button
    search_button = tk.Button(frame, text="Search", width=25, command=search)
    search_button.grid(row=4, column=0, columnspan=3, pady=10)

    # Results display
    result_text = tk.Text(frame, width=60, height=15)
    result_text.grid(row=5, column=0, columnspan=3, pady=10)

    root.mainloop()
