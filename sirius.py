import os
import time
from sys import  exit
try:
    from termcolor import colored
    import pefile
    import easygui
except ModuleNotFoundError:
    os.system("py -3 -m pip install pefile")
    os.system("py -3 -m pip install easygui")
    os.system("py -3 -m pip install termcolor")
    input("Restart me")
    exit()

import struct
def asciishit(ascii):
        for letter in ascii:
            print(letter, end='')





# for those who want colors on the ascii
def print_colored(ascii, speed=0.001, color=None):
    for char in ascii:
        if color:
            print(colored(char, color), end='')
        else:
            print(char, end='')
        time.sleep(speed)
    print('')
def pe_to_shellcode(file_path):
    pe = pefile.PE(file_path)
    shellcode = bytearray()
    for section in pe.sections:
        for byte in section.get_data():
            shellcode.append(byte)
    return shellcode

def save_shellcode(shellcode, file_path):
    with open(file_path, 'wb') as f:
        f.write(struct.pack("<%dB" % len(shellcode), *shellcode))
def shellcode_to_hex(shellcode):
    hex_shellcode = ''.join([f"\\x{byte:02x}" for byte in shellcode])
    return hex_shellcode

def main():
    ascii = """
              
by usdchef
    """
    print_colored(ascii)
    print("""
1) Convert your PE to shellcode
99) About me    
""")
    option = int(input("Choose:"))
    if option == 1:
        fp = easygui.fileopenbox(default="*.exe", filetypes=["*.exe"])
        if fp:
            shellcode = pe_to_shellcode(fp)
            save_shellcode(shellcode, "Shellcode.bin")
            with open("shellcode_hex.txt", "w") as f:
                f.write(shellcode_to_hex(shellcode))
            main()
        else:
            print("you didn t choose any file -_-")
            main()

    elif option == 99:
        easygui.msgbox("Made By usdchef", title="Dev Infos")
        os.system("start https://github.com/usdchef")
        main()
    else:
        print("Invalid option")
        main()
main()
