import subprocess


# -------------------------
# Safe Function
# -------------------------
def greet_user():
    name = input("Enter your name: ")

    # Safe: using an f-string only for display
    print(f"Hello, {name}!")

    return name


# -------------------------
# Dangerous Function
# -------------------------
def execute_command():
    command = input("Enter a command: ")

    # Dangerous: user input is executed by the shell
    subprocess.run(command, shell=True)


# -------------------------
# Main
# -------------------------
if __name__ == "__main__":
    greet_user()
    execute_command()