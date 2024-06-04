import pefile

def encrypt_section(pe_file, section_name, xor_key):
    """
    加密PE文件中指定的区段
    """
    # 找到对应的section
    for section in pe_file.sections:
        if section.Name.decode().strip('\x00') == section_name:
            print(f"[*] Found {section_name} section at 0x{section.PointerToRawData:08x}")
            data = section.get_data()
            encrypted_data = bytes([data[i] ^ xor_key for i in range(len(data))])
            pe_file.set_bytes_at_offset(section.PointerToRawData, encrypted_data)
            print(f"[*] Encrypted {len(data)} bytes at 0x{section.PointerToRawData:08x}")
            return

    print(f"[!] {section_name} section not found!")


if __name__ == "__main__":
    filename = "smctest.exe"
    section_name = ".hello"
    xor_key = 0xff

    print(f"[*] Loading {filename}")
    pe_file = pefile.PE(filename)

    # 加密
    print("[*] Encrypting section")
    encrypt_section(pe_file, section_name, xor_key)

    # 保存文件
    new_filename = filename[:-4] + "_encrypted.exe"
    print(f"[*] Saving as {new_filename}")
    pe_file.write(new_filename)
    pe_file.close()
