import sys
import math
import secrets
import string
import argparse

# Check for tkinter availability (included with standard Python on Windows)
try:
    import tkinter as tk
    from tkinter import ttk, messagebox
    HAS_TKINTER = True
except ImportError:
    HAS_TKINTER = False

# Default built-in word list for generating memorable passphrases
DEFAULT_WORDLIST = [
    "amber", "anchor", "apple", "arrow", "autumn", "badge", "beacon", "breeze",
    "bridge", "cactus", "canvas", "canyon", "castle", "cedar", "cipher", "cobalt",
    "comet", "compass", "copper", "coral", "crater", "crystal", "cypress", "dawn",
    "delta", "desert", "dragon", "eagle", "echo", "ember", "falcon", "feather",
    "flame", "forest", "fossil", "galaxy", "garnet", "glacier", "granite", "harbor",
    "haven", "hazel", "horizon", "island", "jasper", "jungle", "lagoon", "lantern",
    "legend", "lotus", "lunar", "marble", "meadow", "meteor", "mirage", "monarch",
    "mountain", "nebula", "nectar", "oasis", "ocean", "octane", "olive", "onyx",
    "orbit", "orchid", "osprey", "pebble", "phoenix", "planet", "plasma", "prism",
    "quartz", "radar", "radiant", "raven", "ripple", "river", "ruby", "safari",
    "sapphire", "shadow", "signal", "silver", "solar", "spark", "spectrum", "sphere",
    "spirit", "star", "summit", "sunfall", "thunder", "timber", "titan", "topaz",
    "tower", "tundra", "valley", "velvet", "vortex", "whisper", "wildfire", "winter",
    "zenith", "zephyr"
]

AMBIGUOUS_CHARS = set("iI1lLo0O8B")

def calculate_entropy(password: str) -> tuple[float, str]:
    """
    Calculate the entropy of a given password in bits.
    Formula: Entropy = length * log2(pool_size)

    Returns:
        tuple of (entropy_bits, strength_rating)
    """
    if not password:
        return 0.0, "Empty"

    pool_size = 0
    has_lower = any(c in string.ascii_lowercase for c in password)
    has_upper = any(c in string.ascii_uppercase for c in password)
    has_digit = any(c in string.digits for c in password)
    has_symbol = any(c in string.punctuation for c in password)
    has_other = any(c not in string.printable for c in password)

    if has_lower:
        pool_size += 26
    if has_upper:
        pool_size += 26
    if has_digit:
        pool_size += 10
    if has_symbol:
        pool_size += 32
    if has_other:
        pool_size += 30

    if pool_size == 0:
        pool_size = len(set(password))

    entropy = len(password) * math.log2(pool_size)

    if entropy < 28:
        rating = "Very Weak"
    elif entropy < 36:
        rating = "Weak"
    elif entropy < 60:
        rating = "Moderate"
    elif entropy < 80:
        rating = "Strong"
    else:
        rating = "Very Strong"

    return round(entropy, 1), rating


def generate_password(
    length: int = 16,
    use_uppercase: bool = True,
    use_lowercase: bool = True,
    use_digits: bool = True,
    use_symbols: bool = True,
    exclude_ambiguous: bool = False,
    custom_symbols: str = None
) -> str:
    """
    Generates a cryptographically secure random password based on defined criteria.
    Guarantees at least one character from each enabled set.
    """
    if length < 4:
        raise ValueError("Password length should be at least 4 characters.")

    char_sets = []
    guaranteed_chars = []

    if use_lowercase:
        pool = string.ascii_lowercase
        if exclude_ambiguous:
            pool = ''.join(c for c in pool if c not in AMBIGUOUS_CHARS)
        if pool:
            char_sets.append(pool)
            guaranteed_chars.append(secrets.choice(pool))

    if use_uppercase:
        pool = string.ascii_uppercase
        if exclude_ambiguous:
            pool = ''.join(c for c in pool if c not in AMBIGUOUS_CHARS)
        if pool:
            char_sets.append(pool)
            guaranteed_chars.append(secrets.choice(pool))

    if use_digits:
        pool = string.digits
        if exclude_ambiguous:
            pool = ''.join(c for c in pool if c not in AMBIGUOUS_CHARS)
        if pool:
            char_sets.append(pool)
            guaranteed_chars.append(secrets.choice(pool))

    if use_symbols:
        pool = custom_symbols if custom_symbols else string.punctuation
        if exclude_ambiguous:
            pool = ''.join(c for c in pool if c not in AMBIGUOUS_CHARS)
        if pool:
            char_sets.append(pool)
            guaranteed_chars.append(secrets.choice(pool))

    if not char_sets:
        raise ValueError("At least one character set must be selected.")

    combined_pool = ''.join(char_sets)

    # Fill remaining characters
    remaining_length = length - len(guaranteed_chars)
    if remaining_length < 0:
        guaranteed_chars = guaranteed_chars[:length]
        remaining_length = 0

    random_fill = [secrets.choice(combined_pool) for _ in range(remaining_length)]
    full_list = guaranteed_chars + random_fill

    # Cryptographically secure shuffle
    secrets.SystemRandom().shuffle(full_list)

    return ''.join(full_list)


def generate_passphrase(
    num_words: int = 4,
    separator: str = "-",
    capitalize: bool = True,
    add_number: bool = True,
    word_list: list[str] = None
) -> str:
    """
    Generates a memorable passphrase using words chosen cryptographically at random.
    """
    if num_words < 2:
        raise ValueError("Passphrase should contain at least 2 words.")

    words = word_list if word_list else DEFAULT_WORDLIST
    chosen_words = [secrets.choice(words) for _ in range(num_words)]

    if capitalize:
        chosen_words = [w.capitalize() for w in chosen_words]

    result = separator.join(chosen_words)

    if add_number:
        result += f"{separator}{secrets.randbelow(90) + 10}"

    return result


class PasswordGeneratorGUI:
    """Tkinter Graphical User Interface for Password Generator."""

    def __init__(self, root: tk.Tk):
        self.root = root
        self.root.title("Cryptographic Password Generator")
        self.root.geometry("520x620")
        self.root.resizable(False, False)

        # Style configuration
        self.style = ttk.Style()
        self.style.theme_use("clam")
        self._setup_colors()

        # Variables
        self.mode_var = tk.StringVar(value="password") # "password" or "passphrase"
        self.length_var = tk.IntVar(value=16)
        self.num_words_var = tk.IntVar(value=4)
        self.uppercase_var = tk.BooleanVar(value=True)
        self.lowercase_var = tk.BooleanVar(value=True)
        self.digits_var = tk.BooleanVar(value=True)
        self.symbols_var = tk.BooleanVar(value=True)
        self.exclude_ambiguous_var = tk.BooleanVar(value=False)
        self.separator_var = tk.StringVar(value="-")
        self.passphrase_capitalize_var = tk.BooleanVar(value=True)
        self.passphrase_number_var = tk.BooleanVar(value=True)
        self.output_var = tk.StringVar()

        self._build_ui()
        self.on_generate()

    def _setup_colors(self):
        # Modern Dark-leaning Color Palette
        self.bg_color = "#1e1e2e"
        self.card_bg = "#252538"
        self.fg_color = "#cdd6f4"
        self.accent_color = "#89b4fa"
        self.accent_hover = "#b4befe"
        self.success_color = "#a6e3a1"
        self.warning_color = "#f9e2af"
        self.danger_color = "#f38ba8"

        self.root.configure(bg=self.bg_color)
        
        self.style.configure(".", background=self.bg_color, foreground=self.fg_color, font=("Segoe UI", 10))
        self.style.configure("Card.TFrame", background=self.card_bg, relief="flat")
        self.style.configure("TLabel", background=self.card_bg, foreground=self.fg_color)
        self.style.configure("Title.TLabel", background=self.bg_color, foreground=self.accent_color, font=("Segoe UI", 16, "bold"))
        self.style.configure("Subtitle.TLabel", background=self.bg_color, foreground="#a6adc8", font=("Segoe UI", 9))
        self.style.configure("TCheckbutton", background=self.card_bg, foreground=self.fg_color, font=("Segoe UI", 10))
        self.style.configure("TRadiobutton", background=self.card_bg, foreground=self.fg_color, font=("Segoe UI", 10, "bold"))

    def _build_ui(self):
        # Main Layout container
        main_frame = tk.Frame(self.root, bg=self.bg_color, padx=20, pady=20)
        main_frame.pack(fill=tk.BOTH, expand=True)

        # Header
        header = ttk.Label(main_frame, text="🔒 Password Generator", style="Title.TLabel")
        header.pack(anchor="w", pady=(0, 2))
        subheader = ttk.Label(main_frame, text="Cryptographically secure passwords & passphrases", style="Subtitle.TLabel")
        subheader.pack(anchor="w", pady=(0, 15))

        # Mode Selection
        mode_card = ttk.Frame(main_frame, style="Card.TFrame", padding=12)
        mode_card.pack(fill=tk.X, pady=(0, 12))

        ttk.Label(mode_card, text="Generator Mode:", font=("Segoe UI", 10, "bold")).pack(anchor="w", pady=(0, 6))
        mode_btn_frame = tk.Frame(mode_card, bg=self.card_bg)
        mode_btn_frame.pack(fill=tk.X)

        r1 = ttk.Radiobutton(mode_btn_frame, text="Random Password", value="password", variable=self.mode_var, command=self._toggle_mode_options)
        r1.pack(side=tk.LEFT, padx=(0, 20))
        r2 = ttk.Radiobutton(mode_btn_frame, text="Memorable Passphrase", value="passphrase", variable=self.mode_var, command=self._toggle_mode_options)
        r2.pack(side=tk.LEFT)

        # Output Box Frame
        output_card = ttk.Frame(main_frame, style="Card.TFrame", padding=15)
        output_card.pack(fill=tk.X, pady=(0, 12))

        self.output_entry = tk.Entry(
            output_card,
            textvariable=self.output_var,
            font=("Consolas", 14, "bold"),
            bg="#181825",
            fg="#a6e3a1",
            insertbackground="white",
            bd=0,
            relief="flat",
            justify="center"
        )
        self.output_entry.pack(fill=tk.X, ipady=8, pady=(0, 10))

        # Copy & Refresh Buttons
        btn_row = tk.Frame(output_card, bg=self.card_bg)
        btn_row.pack(fill=tk.X)

        self.gen_btn = tk.Button(
            btn_row,
            text="🔄 Generate",
            font=("Segoe UI", 10, "bold"),
            bg=self.accent_color,
            fg="#11111b",
            activebackground=self.accent_hover,
            activeforeground="#11111b",
            bd=0,
            padx=15,
            pady=6,
            cursor="hand2",
            command=self.on_generate
        )
        self.gen_btn.pack(side=tk.LEFT, expand=True, fill=tk.X, padx=(0, 5))

        self.copy_btn = tk.Button(
            btn_row,
            text="📋 Copy",
            font=("Segoe UI", 10, "bold"),
            bg="#313244",
            fg=self.fg_color,
            activebackground="#45475a",
            activeforeground=self.fg_color,
            bd=0,
            padx=15,
            pady=6,
            cursor="hand2",
            command=self.on_copy
        )
        self.copy_btn.pack(side=tk.RIGHT, expand=True, fill=tk.X, padx=(5, 0))

        # Strength Bar
        strength_frame = tk.Frame(output_card, bg=self.card_bg)
        strength_frame.pack(fill=tk.X, pady=(10, 0))

        self.strength_lbl = ttk.Label(strength_frame, text="Strength: -", font=("Segoe UI", 9, "bold"))
        self.strength_lbl.pack(side=tk.LEFT)

        self.entropy_lbl = ttk.Label(strength_frame, text="Entropy: 0 bits", font=("Segoe UI", 9))
        self.entropy_lbl.pack(side=tk.RIGHT)

        # Options Container Frame
        self.options_card = ttk.Frame(main_frame, style="Card.TFrame", padding=15)
        self.options_card.pack(fill=tk.BOTH, expand=True, pady=(0, 12))

        # -- Password Options Controls --
        self.pwd_options_frame = tk.Frame(self.options_card, bg=self.card_bg)
        self.pwd_options_frame.pack(fill=tk.BOTH, expand=True)

        len_label_row = tk.Frame(self.pwd_options_frame, bg=self.card_bg)
        len_label_row.pack(fill=tk.X, pady=(0, 5))
        ttk.Label(len_label_row, text="Password Length:").pack(side=tk.LEFT)
        self.len_val_label = ttk.Label(len_label_row, text=str(self.length_var.get()), font=("Segoe UI", 10, "bold"))
        self.len_val_label.pack(side=tk.RIGHT)

        self.len_slider = tk.Scale(
            self.pwd_options_frame,
            from_=6,
            to=64,
            orient=tk.HORIZONTAL,
            variable=self.length_var,
            bg=self.card_bg,
            fg=self.fg_color,
            troughcolor="#181825",
            highlightthickness=0,
            activebackground=self.accent_color,
            command=lambda val: self._on_length_change(val)
        )
        self.len_slider.pack(fill=tk.X, pady=(0, 10))

        chk_grid = tk.Frame(self.pwd_options_frame, bg=self.card_bg)
        chk_grid.pack(fill=tk.X)

        ttk.Checkbutton(chk_grid, text="Uppercase (A-Z)", variable=self.uppercase_var, command=self.on_generate).grid(row=0, column=0, sticky="w", pady=4, padx=5)
        ttk.Checkbutton(chk_grid, text="Lowercase (a-z)", variable=self.lowercase_var, command=self.on_generate).grid(row=0, column=1, sticky="w", pady=4, padx=5)
        ttk.Checkbutton(chk_grid, text="Digits (0-9)", variable=self.digits_var, command=self.on_generate).grid(row=1, column=0, sticky="w", pady=4, padx=5)
        ttk.Checkbutton(chk_grid, text="Symbols (!@#$)", variable=self.symbols_var, command=self.on_generate).grid(row=1, column=1, sticky="w", pady=4, padx=5)

        ttk.Checkbutton(
            self.pwd_options_frame,
            text="Avoid Ambiguous Characters (e.g. 1, l, I, 0, O)",
            variable=self.exclude_ambiguous_var,
            command=self.on_generate
        ).pack(anchor="w", pady=(10, 0))

        # -- Passphrase Options Controls --
        self.pass_options_frame = tk.Frame(self.options_card, bg=self.card_bg)

        word_len_row = tk.Frame(self.pass_options_frame, bg=self.card_bg)
        word_len_row.pack(fill=tk.X, pady=(0, 5))
        ttk.Label(word_len_row, text="Number of Words:").pack(side=tk.LEFT)
        self.word_val_label = ttk.Label(word_len_row, text=str(self.num_words_var.get()), font=("Segoe UI", 10, "bold"))
        self.word_val_label.pack(side=tk.RIGHT)

        self.word_slider = tk.Scale(
            self.pass_options_frame,
            from_=3,
            to=10,
            orient=tk.HORIZONTAL,
            variable=self.num_words_var,
            bg=self.card_bg,
            fg=self.fg_color,
            troughcolor="#181825",
            highlightthickness=0,
            activebackground=self.accent_color,
            command=lambda val: self._on_words_change(val)
        )
        self.word_slider.pack(fill=tk.X, pady=(0, 10))

        sep_frame = tk.Frame(self.pass_options_frame, bg=self.card_bg)
        sep_frame.pack(fill=tk.X, pady=(0, 10))
        ttk.Label(sep_frame, text="Separator Character:").pack(side=tk.LEFT, padx=(0, 10))
        sep_entry = tk.Entry(sep_frame, textvariable=self.separator_var, width=5, bg="#181825", fg="white", bd=0, justify="center")
        sep_entry.pack(side=tk.LEFT)
        self.separator_var.trace_add("write", lambda *args: self.on_generate())

        ttk.Checkbutton(self.pass_options_frame, text="Capitalize Words", variable=self.passphrase_capitalize_var, command=self.on_generate).pack(anchor="w", pady=4)
        ttk.Checkbutton(self.pass_options_frame, text="Append Random Number", variable=self.passphrase_number_var, command=self.on_generate).pack(anchor="w", pady=4)

    def _on_length_change(self, val):
        self.len_val_label.config(text=str(int(float(val))))
        self.on_generate()

    def _on_words_change(self, val):
        self.word_val_label.config(text=str(int(float(val))))
        self.on_generate()

    def _toggle_mode_options(self):
        if self.mode_var.get() == "password":
            self.pass_options_frame.pack_forget()
            self.pwd_options_frame.pack(fill=tk.BOTH, expand=True)
        else:
            self.pwd_options_frame.pack_forget()
            self.pass_options_frame.pack(fill=tk.BOTH, expand=True)
        self.on_generate()

    def on_generate(self):
        try:
            if self.mode_var.get() == "password":
                pwd = generate_password(
                    length=self.length_var.get(),
                    use_uppercase=self.uppercase_var.get(),
                    use_lowercase=self.lowercase_var.get(),
                    use_digits=self.digits_var.get(),
                    use_symbols=self.symbols_var.get(),
                    exclude_ambiguous=self.exclude_ambiguous_var.get()
                )
            else:
                pwd = generate_passphrase(
                    num_words=self.num_words_var.get(),
                    separator=self.separator_var.get() or "-",
                    capitalize=self.passphrase_capitalize_var.get(),
                    add_number=self.passphrase_number_var.get()
                )

            self.output_var.set(pwd)
            entropy, rating = calculate_entropy(pwd)
            self.strength_lbl.config(text=f"Strength: {rating}")
            self.entropy_lbl.config(text=f"Entropy: {entropy} bits")

            # Color coding rating
            if rating in ("Very Weak", "Weak"):
                self.strength_lbl.config(foreground=self.danger_color)
            elif rating == "Moderate":
                self.strength_lbl.config(foreground=self.warning_color)
            else:
                self.strength_lbl.config(foreground=self.success_color)

        except Exception as err:
            self.output_var.set("Select at least 1 option")
            self.strength_lbl.config(text="Strength: N/A", foreground=self.danger_color)
            self.entropy_lbl.config(text="Entropy: 0 bits")

    def on_copy(self):
        val = self.output_var.get()
        if val and val != "Select at least 1 option":
            self.root.clipboard_clear()
            self.root.clipboard_append(val)
            self.root.update()
            
            # Temporary UI feedback
            orig_text = self.copy_btn.cget("text")
            self.copy_btn.config(text="✅ Copied!", bg=self.success_color, fg="#11111b")
            self.root.after(1500, lambda: self.copy_btn.config(text=orig_text, bg="#313244", fg=self.fg_color))


def interactive_cli():
    """Interactive Command Line Menu."""
    print("=" * 55)
    print("      🔒 CRYPTOGRAPHIC PASSWORD GENERATOR (CLI)")
    print("=" * 55)
    print("1. Generate Random Password")
    print("2. Generate Memorable Passphrase")
    print("3. Exit")
    print("-" * 55)

    choice = input("Select an option (1-3): ").strip()
    if choice == "1":
        try:
            length = int(input("Enter length (default 16): ") or 16)
            upper = input("Include uppercase? (Y/n): ").strip().lower() != 'n'
            lower = input("Include lowercase? (Y/n): ").strip().lower() != 'n'
            digits = input("Include digits? (Y/n): ").strip().lower() != 'n'
            symbols = input("Include symbols? (Y/n): ").strip().lower() != 'n'
            no_ambig = input("Exclude ambiguous characters (1, l, I, 0, O)? (y/N): ").strip().lower() == 'y'

            pwd = generate_password(
                length=length,
                use_uppercase=upper,
                use_lowercase=lower,
                use_digits=digits,
                use_symbols=symbols,
                exclude_ambiguous=no_ambig
            )
            entropy, rating = calculate_entropy(pwd)
            print("\n" + "=" * 40)
            print(f"Generated Password : {pwd}")
            print(f"Entropy           : {entropy} bits")
            print(f"Strength Rating   : {rating}")
            print("=" * 40 + "\n")
        except Exception as e:
            print(f"\n❌ Error: {e}\n")

    elif choice == "2":
        try:
            words = int(input("Enter number of words (default 4): ") or 4)
            sep = input("Enter separator (default '-'): ") or "-"
            cap = input("Capitalize words? (Y/n): ").strip().lower() != 'n'
            num = input("Append random number? (Y/n): ").strip().lower() != 'n'

            phrase = generate_passphrase(num_words=words, separator=sep, capitalize=cap, add_number=num)
            entropy, rating = calculate_entropy(phrase)
            print("\n" + "=" * 40)
            print(f"Generated Passphrase : {phrase}")
            print(f"Entropy             : {entropy} bits")
            print(f"Strength Rating     : {rating}")
            print("=" * 40 + "\n")
        except Exception as e:
            print(f"\n❌ Error: {e}\n")
    elif choice == "3":
        print("Goodbye!")
        sys.exit(0)
    else:
        print("Invalid choice.")


def main():
    parser = argparse.ArgumentParser(
        description="Cryptographically Secure Password & Passphrase Generator."
    )
    parser.add_argument("--gui", action="store_true", help="Launch Graphical User Interface")
    parser.add_argument("-l", "--length", type=int, default=16, help="Password length (default: 16)")
    parser.add_argument("--no-upper", action="store_true", help="Exclude uppercase letters")
    parser.add_argument("--no-lower", action="store_true", help="Exclude lowercase letters")
    parser.add_argument("--no-digits", action="store_true", help="Exclude numbers")
    parser.add_argument("--no-symbols", action="store_true", help="Exclude special symbols")
    parser.add_argument("--exclude-ambiguous", action="store_true", help="Exclude ambiguous characters (1, l, I, 0, O)")
    parser.add_argument("--passphrase", action="store_true", help="Generate word-based passphrase instead")
    parser.add_argument("-w", "--words", type=int, default=4, help="Number of words for passphrase (default: 4)")
    parser.add_argument("-s", "--separator", type=str, default="-", help="Separator for passphrase (default: '-')")
    parser.add_argument("-n", "--count", type=int, default=1, help="Number of passwords to generate (default: 1)")
    parser.add_argument("-i", "--interactive", action="store_true", help="Run interactive CLI menu")

    args = parser.parse_args()

    # Launch GUI if requested or if run without arguments in standard Desktop environment
    if args.gui:
        if not HAS_TKINTER:
            print("Error: tkinter is not installed or available in your Python environment.")
            sys.exit(1)
        root = tk.Tk()
        app = PasswordGeneratorGUI(root)
        root.mainloop()
        return

    if args.interactive:
        while True:
            interactive_cli()
        return

    # If flags were supplied or command-line execution
    for _ in range(args.count):
        if args.passphrase:
            pwd = generate_passphrase(
                num_words=args.words,
                separator=args.separator
            )
        else:
            pwd = generate_password(
                length=args.length,
                use_uppercase=not args.no_upper,
                use_lowercase=not args.no_lower,
                use_digits=not args.no_digits,
                use_symbols=not args.no_symbols,
                exclude_ambiguous=args.exclude_ambiguous
            )
        entropy, rating = calculate_entropy(pwd)
        print(f"{pwd}  (Entropy: {entropy} bits | {rating})")


if __name__ == "__main__":
    main()
