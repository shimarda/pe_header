import struct
from datetime import datetime
import requests
from bs4 import BeautifulSoup

def table_match(pattern, num):
    #マシンの種類3
    #ヘッダーの特性4(別関数を使用する)
    #オプションヘッダーのマジックナンバー5
    #10Windonwsのサブシステム
    #11DLLの特性
    #14セクションフラグ
    #16x64プロセッサ
    #17ARMプロセッサ
    #18ARM64プロセッサ
    #19Hitachi SuperHプロセッサ
    #20IBMPowerPCプロセッサ
    #21Intel386プロセッサ
    #22IntelItaniumプロセッサファミリ(IPF)
    #23MIPSプロセッサ
    #24Mitsubishi M32R
    #↓COFFシンボルテーブル
    #29セクション番号の値
    #31型の表現
    #32波形型の表現
    #33ストレージクラス
    #39COMDATセクション(オブジェクトのみ)
    #40CLRトークン定義（オブジェクトのみ）
    #45セクション名(このテーブルは1列目でパターンマッチを行う)
    #47デバッグの種類
    #48拡張DLL特性
    #49.edataセクション(イメージのみ)
    #60ベース再配置の種類
    #62TLSコールバック関数
    #64.rsrcセクション
    #77nameフィールドの内容(1列目でパターンマッチ)
    #81インポートの種類
    #82インポート名の種類

    url = 'https://learn.microsoft.com/ja-jp/windows/win32/debug/pe-format#machine-types'
    res = requests.get(url, headers={'Accept-Language': 'ja'}, timeout=5)
    res.encoding = res.apparent_encoding

    if res.status_code == 200:
        soup = BeautifulSoup(res.text, 'html.parser')
    else:
        print('Webページにアクセスできませんでした')

    tables = soup.find_all('table')

    if len(tables) >= 0:
        table = tables[num-1]

        # テーブルの行ごとにループ
        for row in table.find_all('tr'):
        # 行のセルごとにループ
            cells = row.find_all(['th', 'td'])
            #for cell in cells:
            if len(cells) > 1:#セルが二つ以上ある場合
                cell = cells[1]#セルの値の部分のみアクセス
                if pattern in cell:
                    print(cells[2].text.strip(), end='\t')  # セルのテキストを取得して出力
        print()
    else:
        print('テーブルが見つかりませんでした')

#COFFHeaderの特性を表示する関数
def char_match(char_num,table_num):

    url = 'https://learn.microsoft.com/ja-jp/windows/win32/debug/pe-format#machine-types'
    res = requests.get(url, headers={'Accept-Language': 'ja'}, timeout=5)
    res.encoding = res.apparent_encoding

    if res.status_code == 200:
        soup = BeautifulSoup(res.text, 'html.parser')
    else:
        print('Webページにアクセスできませんでした')

    tables = soup.find_all('table')
    table = tables[table_num]#Charcteristicsテーブ
    lis = [str(ele) for ele in str(char_num)]

    right_lis = [0, 1, 2, 4, 8]

    if any(x in right_lis for x in lis):
        print("テーブルに含まれていないフラグが存在します。")

    for n in range(len(lis)):
        for i, row in enumerate(table.find_all('tr'), start=1):
            cells = row.find_all(['th', 'td'])
            cell = cells[2]

            if lis[3-n] == "1":
                if i == n*4 +2:
                    print(cell.text.strip())
            elif lis[3-n] ==  "2":
                if i == n*4 +3:
                    print(cell.text.strip())
            elif lis[3-n] == "4":
                if i == n*4 +34:
                    print(cell.text.strip())
            elif lis[3-n] == "8":
                if i == n*4 + 5:
                    print(cell.text.strip())

#DllCharacteriscticsの特性を表示する関数
def dll_char_match(char_num):
    url = 'https://learn.microsoft.com/ja-jp/windows/win32/debug/pe-format#machine-types'
    res = requests.get(url, headers={'Accept-Language': 'ja'}, timeout=5)
    res.encoding = res.apparent_encoding

    if res.status_code == 200:
        soup = BeautifulSoup(res.text, 'html.parser')
    else:
        print('Webページにアクセスできませんでした')

    tables = soup.find_all('table')
    table = tables[10]#DllCharcteristicsテーブ
    lis = [str(ele) for ele in str(char_num)]

    right_lis = [0, 1, 2, 4, 8]

    if any(x not in right_lis for x in lis):
        print("テーブルに含まれていないフラグが存在します。")

    for n in range(len(lis)):
            for i, row in enumerate(table.find_all('tr'), start=1):
                cells = row.find_all(['th', 'td'])
                cell = cells[2]

                if lis[3-n] == "1":
                    if i in [2, 6, 9, 13]:
                        print(cell.text.strip())
                elif lis[3-n] ==  "2":
                    if i in [3, 6, 10, 14]:
                        print(cell.text.strip())
                elif lis[3-n] == "4":
                    if i in [4, 7, 11, 15]:
                        print(cell.text.strip())
                elif lis[3-n] == "8":
                    if i in [5, 8, 12, 16]:
                        print(cell.text.strip())

def magic_class(magic_num):

    if '1' in magic_num:
        return 1
    else:
        return 0

def sec_char_match(hex_char, table_num):
    url = 'https://learn.microsoft.com/ja-jp/windows/win32/debug/pe-format#machine-types'
    res = requests.get(url, headers={'Accept-Language': 'ja'}, timeout=5)
    res.encoding = res.apparent_encoding

    if res.status_code == 200:
        soup = BeautifulSoup(res.text, 'html.parser')
    else:
        print('Webページにアクセスできませんでした')

    tables = soup.find_all('table')
    table = tables[table_num]#Charcteristicsテーブル

    lis = [ele for ele in str(hex_char)]

    hex_lis = ["A", "B", "C", "D", "E"]

    lis_2 = ["2", "4", "8"]

    #空の部分のリスト
    f = [2, 3, 4, 5, 7, 11, 13, 17, 18, 19, 20, ]

    for n in range(len(lis)):
        for i, row in enumerate(table.find_all('tr'), start=1):
            cells = row.find_all(['th', 'td'])
            cell = cells[2]
            if i not in f:
                if n in [0, 1, 5, 6]:
                    if lis[n] == "1":
                        if n in [0, 1]:
                            if i == 4*(8-n) + 7:
                                print(cell.text.strip())
                        elif n in [5, 6]:
                            if i == 4*(8-n) - 1:
                                print(cell.text.strip())
                    elif lis[n] == "2":
                        if n in [0,1]:
                            if i == 4*(8-n) + 8:
                                print(cell.text.strip())
                        elif n in [5, 6]:
                            if i == 4*(8-n):
                                print(cell.text.strip())
                    elif lis[n] == "4":
                        if n in [0,1]:
                            if i == 4*(8-n) + 9:
                                print(cell.text.strip())
                        else:
                            if i == 4*(8-n) + 1:
                                print(cell.text.strip())
                    elif lis[n] == "8":
                        if n in [0, 1]:
                            if i == 4*(8-n)+10:
                                print(cell.text.strip())
                        else:
                            if i == 4*(8-n)+2:
                                print(cell.text.strip())
                elif n == 4:
                    if lis[n] == "1":
                        if i == 15:
                            print(cell.text.strip())
                    elif lis[n] == "8":
                        if i == 16:
                            print(cell.text.strip())
                elif n == 3:
                    if lis[n] in ["2", "4", "8"]:
                        if i == 18:
                            print(cell.text.strip())
                    elif lis[n] == "4":
                        if i == 19:
                            print(cell.text.strip())
                    elif lis[n] == "8":
                        if i == 20:
                            print(cell.text.strip())
                elif n == 7:
                    if lis[n] == "0":
                        if i == 2:
                            print(cell.text.strip())
                    elif lis[n] == "1":
                        if i == 3:
                            print(cell.text.strip())
                    elif lis[n] == "2":
                        if i == 4:
                            print(cell.text.strip())
                    elif lis[n] == "4":
                        if i == 5:
                            print(cell.text.strip())
                    elif lis[n] == "8":
                        if i == 6:
                            print(cell.text.strip())
                elif n == 2:
                    if lis[n] in hex_lis:
                        if i == 30 + hex_lis.index(lis[n]):
                            print(cell.text.strip())
                    elif lis[n] in [1,2,3,4,5,6,7,8,9]:
                        if i == 20 + lis[n]:
                            print(cell.text.strip())

def dump_pe(file_path):
    try:
        with open(file_path,'rb') as f:

            #DOS_HEADER
            dos_header = f.read(64)
            e_magic = dos_header[0:2]#マジックナンバーの確認
            int_e_magic = int.from_bytes(e_magic, 'little')
            print("e_magic", end = ':')
            print(hex(int_e_magic))

            e_lfanew = dos_header[60:64]
            e_lfanew = int.from_bytes(e_lfanew, 'little')
            #print(e_lfanew)


            #COFF_Headerへの移動
            f.seek(e_lfanew)

            signature = f.read(4)#マジックナンバー
            print("signature:" + signature.hex())   #OK

            #Machine
            machine = f.read(2)
            machine = int.from_bytes(machine,'little')
            hex_machine = hex(machine)
            print("machine:" + hex(machine))
            table_match(hex_machine, 3)

            #NumberOfSections
            num_section = f.read(2)
            print("NumberOfSections", end = ":")
            print(int.from_bytes(num_section,'little'))

            #TimeDateStamp
            time_stamp_bytes = f.read(4)
            time_stamp = struct.unpack('<L', time_stamp_bytes)[0]
            datetime_result = datetime.utcfromtimestamp(time_stamp)
            print("TimeDateStamp", end = ":")
            print(datetime_result)

            #PointerToSymbolTable(PEファイルはシンボルテーブルを含まないため、0がセットされる)
            pointer_to_symbol_table = f.read(4)
            print("PointerToSymbolTable", end = ":")
            print(pointer_to_symbol_table)

            #NumberOfSymbolTable(PEファイルはシンボルテーブルを含まないため、0がセットされる)
            number_of_symbol_table = f.read(4)
            print("NumberOfSymbolTable", end = ":")
            print(number_of_symbol_table)

            #SizeOfOptionalHeader
            size_op_header = f.read(2)
            size_op_header = int.from_bytes(size_op_header, 'little')
            print("SizeOfOptionalHeader", end = ":")
            print(size_op_header)

            #Characteristics
            char_bytes = f.read(2)
            char = int.from_bytes(char_bytes, 'little')
            hex_char = format(char, '04X')
            print("Charcteristics", end = ":")
            print('0x' + hex_char)
            char_match(hex_char, 3)

            #StandardCOFFFields
            #Magic
            magic_bytes = f.read(2)
            int_magic = int.from_bytes(magic_bytes, 'little')
            hex_magic = format(int_magic, '03X')
            print("Magic", end = ':')
            print('0x' + hex_magic)
            if magic_class(hex_magic) == 1:
                pe = "32"
                print("PE32")
            else:
                pe = "32+"
                print("PE32+")

            #MajorLinkerVersion
            major_l_ver = f.read(1)

            #MinorLinkerVersion
            minor_l_ver = f.read(1)

            #SizeOfCode
            byte_size_code =  f.read(4)
            int_size_code = int.from_bytes(byte_size_code, 'little')
            print("SizeOfCode", end = ':')
            print(hex(int_size_code))

            #SizeOfInitializedData
            size_initial_data = f.read(4)

            #SizeOfUninitializedData
            size_uninitial_data = f.read(4)

            #addressofentrypoint
            add_entry_point = f.read(4)
            add_entry_point = int.from_bytes(add_entry_point, 'little')
            print("AddresOfEntryPoint", end = ":")
            print(hex(add_entry_point))

            #BaseOfCode
            base_code = f.read(4)
            int_base_code = int.from_bytes(base_code, 'little')
            print("BaseCode", end = ':')
            print(hex(int_base_code))

            #BaseOfData
            if pe == "32":
                base_data = f.read(4)
                int_base_data = int.from_bytes(base_data, 'little')
                print("BaseData", end = ':')
                print(hex(int_base_data))

            #WindowsSpecificFields


            #ImageBase
            if pe == "32":
                bytes_image_base = f.read(4)
                int_image_base = int.from_bytes(bytes_image_base, 'little')
                hex_image_base = format(int_image_base, '04X')
            else:
                bytes_image_base = f.read(8)
                int_image_base = int.from_bytes(bytes_image_base, 'little')
                hex_image_base = format(int_image_base, '08X')
            print("ImageBase", end = ':')
            print("0x" + hex_image_base)

            #SectionAlignment
            byte_sec_align = f.read(4)
            int_sec_align = int.from_bytes(byte_sec_align, 'little')
            print("SectionAlignment", end = ':')
            print(hex(int_sec_align))

            #FileAlignment
            file_align = f.read(4)
            int_file_align = int.from_bytes(file_align, 'little')
            print("FileAlignment", end = ':')
            print(hex(int_file_align))

            #MajorOperationgSystemVersion
            major_op_sys_ver = f.read(2)

            #MinorOperationgSystemVersion
            minor_op_sys_ver = f.read(2)

            #MajorImageVersion
            major_img_ver = f.read(2)

            #MinorImageVersion
            minor_img_ver = f.read(2)

            #MajorSubsystemVersion
            major_subsys_ver = f.read(2)

            #MinorSubsystemVersion
            minor_subsys_ver = f.read(2)

            #Win32VersionValue(Zeros filled)
            win32_ver_val = f.read(4)
            #print(win32_ver_val)

            #sizeOfImage
            size_img = f.read(4)
            int_size_img = int.from_bytes(size_img, 'little')
            print("SizeOfImage", end = ':')
            print(hex(int_size_img))

            #SizeOfHeaders
            size_headers = f.read(4)
            int_size_headers = int.from_bytes(size_headers, 'little')
            print("SizeOfHeader", end = ':')
            print(hex(int_size_headers))

            #CheckSum
            check_sum = f.read(4)
            int_check_sum = int.from_bytes(check_sum, 'little')
            print("CheckSum", end = ':')
            print(hex(int_check_sum))

            #Subsystem
            sub_sys = f.read(2)
            int_sub_sys = int.from_bytes(sub_sys, 'little')
            print("Windowsサブシステム", end = ':')
            print(int_sub_sys)
            table_match(str(int_sub_sys), 10)

            #DllCharcteristics
            dll_char_bytes = f.read(2)
            dll_char = int.from_bytes(dll_char_bytes, 'little')
            hex_dll_char = format(dll_char, '04X')
            print("DLL Charcteristics", end = ':')
            print("0x" + hex_dll_char)
            dll_char_match(hex_dll_char)

            #SizeOfStackReserve
            if magic_class(hex_magic) == 0:
                size_stack_res = f.read(8)
            else:
                size_stack_res = f.read(4)

            #SizeOfStackCommit
            if magic_class(hex_magic) == 0:
                size_stack_com = f.read(8)
            else:
                size_stack_com = f.read(4)

            #SizeOfHeapReserve
            if magic_class(hex_magic) == 0:
                size_heap_res = f.read(8)
            else:
                size_heap_res = f.read(4)

            #SizeOfHeapCommit
            if magic_class(hex_magic) == 0:
                size_heap_com = f.read(8)
            else:
                size_heap_com = f.read(4)

            #LoaderFlags(zeros Filled)(廃止)
            load_flag = f.read(4)

            #NumberOfRvaAndSizes
            num_rva_size = f.read(4)

            #section_tableへ移動
            goto_sec_table = size_op_header + e_lfanew + 24
            print(goto_sec_table)
            f.seek(goto_sec_table,0)

            for n in range(int.from_bytes(num_section,'little')):
                #name(セクション名)
                name = f.read(8).strip(b'\x00')
                str_name = name.decode()#.split('\x00')
                #VirtualSize(セクションのサイズ)
                virtual_size = f.read(4)
                virtual_size = int.from_bytes(virtual_size, 'little')
                #VirtualAddress
                virtual_add = f.read(4)
                virtual_add = int.from_bytes(virtual_add, 'little')
                #SizeOfRawData
                size_raw_data = f.read(4)
                size_raw_data = int.from_bytes(size_raw_data, 'little')
                #PointerToRawData
                #セクションが初期値の場合、ファイル内オフセットが格納
                pointer_raw_data = f.read(4)
                pointer_raw_data = int.from_bytes(pointer_raw_data, 'little')

                #PointerToRelocations
                #PEファイルでは使用しない
                pointer_relocations = f.read(4)
                pointer_relocations = int.from_bytes(pointer_relocations, 'little')

                #PointerToLinenumbers
                pointer_line_num = f.read(4)
                int_pointer_line_num = int.from_bytes(pointer_line_num, 'little')

                #NumberOfRelocations
                #再配置情報の数
                num_relocations = f.read(2)
                num_relocations = int.from_bytes(num_relocations, 'little')

                #NumberOfLinenumbers
                #行番号情報の数
                num_line = f.read(2)
                int_num_line = int.from_bytes(num_line, 'little')

                #Characteristics
                #セクションの特性を表す
                sec_char_bytes = f.read(4)
                sec_char = int.from_bytes(sec_char_bytes, 'little')
                hex_sec_char = format(sec_char, "08X")

                print("name", end = ":")
                print(str_name)

                print("     virtual size", end = ":")
                print(hex(virtual_size))

                print("     virtual_add", end = ":")
                print(hex(virtual_add))

                print("     size_raw_data", end = ":")
                print(hex(size_raw_data))

                print("     pointer_raw_data", end = ":")
                print(hex(pointer_raw_data))

                print("     PointerToRelocations", end = ':')
                print(pointer_relocations)

                print("     NumberOfRelocations", end = ':')
                print(num_relocations)

                print("     NumberOfLinenumbers", end = ':')
                print(int_pointer_line_num)

                print("     Characteristics", end = ':')
                print(hex(sec_char))
                sec_char_match(hex_sec_char, 13)

    except FileNotFoundError:
        print("File not found")

    except Exception as e:
        print("An error occurred:", str(e))


if __name__ == '__main__':
    #file_path = input('ファイルパスを入力してください>>>')
    file_path = "C:/Users/ryo10/Desktop/binary_experiment/no.4/sabaki-v0.52.2-win-x64-setup.exe"
    #file_path = "C:/Windows/notepad.exe"
    dump_pe(file_path)