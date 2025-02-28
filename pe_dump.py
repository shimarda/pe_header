import struct
import datetime
from dataclasses import dataclass
from typing import List, Optional
import requests
from bs4 import BeautifulSoup

# --- Webスクレイピング用関数 ---
def table_match(pattern: str, table_index: int) -> None:
    """
    指定したテーブル（table_index 番目）から、pattern に該当する説明を出力する関数。
    ※ table_index は 1 から始まる番号です。
    """
    url = 'https://learn.microsoft.com/ja-jp/windows/win32/debug/pe-format#machine-types'
    try:
        res = requests.get(url, headers={'Accept-Language': 'ja'}, timeout=5)
        res.encoding = res.apparent_encoding
        if res.status_code != 200:
            print('Webページにアクセスできませんでした')
            return
        soup = BeautifulSoup(res.text, 'html.parser')
        tables = soup.find_all('table')
        if len(tables) < table_index:
            print('テーブルが見つかりませんでした')
            return
        table = tables[table_index - 1]
        for row in table.find_all('tr'):
            cells = row.find_all(['th', 'td'])
            if len(cells) > 2:
                if pattern in cells[1].text:
                    print(cells[2].text.strip(), end='\t')
        print()
    except Exception as e:
        print("Webスクレイピング中にエラー:", e)

def char_match(char_num: str, table_index: int) -> None:
    """
    Characteristics の各フラグに対応する解説を出力する関数
    （table_index は固定のテーブル番号を想定しています）
    """
    url = 'https://learn.microsoft.com/ja-jp/windows/win32/debug/pe-format#machine-types'
    try:
        res = requests.get(url, headers={'Accept-Language': 'ja'}, timeout=5)
        res.encoding = res.apparent_encoding
        if res.status_code != 200:
            print('Webページにアクセスできませんでした')
            return
        soup = BeautifulSoup(res.text, 'html.parser')
        tables = soup.find_all('table')
        if len(tables) <= table_index:
            print('テーブルが見つかりませんでした')
            return
        table = tables[table_index]
        lis = list(str(char_num))
        right_lis = ['0', '1', '2', '4', '8']
        if any(x not in right_lis for x in lis):
            print("テーブルに含まれていないフラグが存在します。")
        for n in range(len(lis)):
            for i, row in enumerate(table.find_all('tr'), start=1):
                cells = row.find_all(['th', 'td'])
                if len(cells) > 2:
                    cell = cells[2]
                    # ※ 以下はセル位置を固定値で指定しているため、対象ページの構造変更に注意
                    if lis[3 - n] == "1" and i == n * 4 + 2:
                        print(cell.text.strip())
                    elif lis[3 - n] == "2" and i == n * 4 + 3:
                        print(cell.text.strip())
                    elif lis[3 - n] == "4" and i == n * 4 + 34:
                        print(cell.text.strip())
                    elif lis[3 - n] == "8" and i == n * 4 + 5:
                        print(cell.text.strip())
    except Exception as e:
        print("char_match エラー:", e)

def dll_char_match(char_num: str) -> None:
    """
    DLL Characteristics の各フラグに対応する解説を出力する関数
    """
    url = 'https://learn.microsoft.com/ja-jp/windows/win32/debug/pe-format#machine-types'
    try:
        res = requests.get(url, headers={'Accept-Language': 'ja'}, timeout=5)
        res.encoding = res.apparent_encoding
        if res.status_code != 200:
            print('Webページにアクセスできませんでした')
            return
        soup = BeautifulSoup(res.text, 'html.parser')
        tables = soup.find_all('table')
        if len(tables) < 11:
            print('DLL Characteristics テーブルが見つかりませんでした')
            return
        table = tables[10]
        lis = list(str(char_num))
        right_lis = ['0', '1', '2', '4', '8']
        if any(x not in right_lis for x in lis):
            print("テーブルに含まれていないフラグが存在します。")
        for n in range(len(lis)):
            for i, row in enumerate(table.find_all('tr'), start=1):
                cells = row.find_all(['th', 'td'])
                if len(cells) > 2:
                    cell = cells[2]
                    if lis[3 - n] == "1" and i in [2, 6, 9, 13]:
                        print(cell.text.strip())
                    elif lis[3 - n] == "2" and i in [3, 6, 10, 14]:
                        print(cell.text.strip())
                    elif lis[3 - n] == "4" and i in [4, 7, 11, 15]:
                        print(cell.text.strip())
                    elif lis[3 - n] == "8" and i in [5, 8, 12, 16]:
                        print(cell.text.strip())
    except Exception as e:
        print("dll_char_match エラー:", e)

def magic_class(magic_num: str) -> int:
    return 1 if '1' in magic_num else 0

def sec_char_match(hex_char: str, table_index: int) -> None:
    """
    Section Characteristics の各フラグに対応する解説を出力する関数
    （table_index は対象テーブルの番号を指定、例では 13 を想定）
    """
    url = 'https://learn.microsoft.com/ja-jp/windows/win32/debug/pe-format#machine-types'
    try:
        res = requests.get(url, headers={'Accept-Language': 'ja'}, timeout=5)
        res.encoding = res.apparent_encoding
        if res.status_code != 200:
            print('Webページにアクセスできませんでした')
            return
        soup = BeautifulSoup(res.text, 'html.parser')
        tables = soup.find_all('table')
        if len(tables) < table_index:
            print('テーブルが見つかりませんでした')
            return
        table = tables[table_index - 1]
        lis = list(hex_char)
        hex_lis = ["A", "B", "C", "D", "E"]
        # 空の部分を示すインデックス（例）
        f = [2, 3, 4, 5, 7, 11, 13, 17, 18, 19, 20]
        for n in range(len(lis)):
            for i, row in enumerate(table.find_all('tr'), start=1):
                cells = row.find_all(['th', 'td'])
                if len(cells) > 2:
                    cell = cells[2]
                    if i not in f:
                        if n in [0, 1, 5, 6]:
                            if lis[n] == "1":
                                if n in [0, 1]:
                                    if i == 4 * (8 - n) + 7:
                                        print(cell.text.strip())
                                elif n in [5, 6]:
                                    if i == 4 * (8 - n) - 1:
                                        print(cell.text.strip())
                            elif lis[n] == "2":
                                if n in [0, 1]:
                                    if i == 4 * (8 - n) + 8:
                                        print(cell.text.strip())
                                elif n in [5, 6]:
                                    if i == 4 * (8 - n):
                                        print(cell.text.strip())
                            elif lis[n] == "4":
                                if n in [0, 1]:
                                    if i == 4 * (8 - n) + 9:
                                        print(cell.text.strip())
                                else:
                                    if i == 4 * (8 - n) + 1:
                                        print(cell.text.strip())
                            elif lis[n] == "8":
                                if n in [0, 1]:
                                    if i == 4 * (8 - n) + 10:
                                        print(cell.text.strip())
                                else:
                                    if i == 4 * (8 - n) + 2:
                                        print(cell.text.strip())
                        elif n == 4:
                            if lis[n] == "1" and i == 15:
                                print(cell.text.strip())
                            elif lis[n] == "8" and i == 16:
                                print(cell.text.strip())
                        elif n == 3:
                            if lis[n] in ["2", "4", "8"] and i == 18:
                                print(cell.text.strip())
                        elif n == 7:
                            if lis[n] == "0" and i == 2:
                                print(cell.text.strip())
                            elif lis[n] == "1" and i == 3:
                                print(cell.text.strip())
                            elif lis[n] == "2" and i == 4:
                                print(cell.text.strip())
                            elif lis[n] == "4" and i == 5:
                                print(cell.text.strip())
                            elif lis[n] == "8" and i == 6:
                                print(cell.text.strip())
                        elif n == 2:
                            if lis[n] in hex_lis:
                                if i == 30 + hex_lis.index(lis[n]):
                                    print(cell.text.strip())
                            elif lis[n] in ['1','2','3','4','5','6','7','8','9']:
                                if i == 20 + int(lis[n]):
                                    print(cell.text.strip())
    except Exception as e:
        print("sec_char_match エラー:", e)

# --- 構造体を用いた PE ヘッダ解析 ---
@dataclass
class DOSHeader:
    e_magic: int
    e_lfanew: int

    @classmethod
    def parse(cls, data: bytes) -> "DOSHeader":
        if len(data) < 64:
            raise ValueError("DOS Header のサイズが不足しています")
        e_magic, = struct.unpack_from("<H", data, 0)
        e_lfanew, = struct.unpack_from("<I", data, 60)
        return cls(e_magic, e_lfanew)

    def is_valid(self) -> bool:
        return self.e_magic == 0x5A4D  # 'MZ'

@dataclass
class FileHeader:
    Machine: int
    NumberOfSections: int
    TimeDateStamp: datetime.datetime
    PointerToSymbolTable: int
    NumberOfSymbols: int
    SizeOfOptionalHeader: int
    Characteristics: int

    @classmethod
    def parse(cls, data: bytes) -> "FileHeader":
        if len(data) < 20:
            raise ValueError("FileHeader のサイズが不足しています")
        unpacked = struct.unpack("<HHLLLHH", data[:20])
        ts = datetime.datetime.utcfromtimestamp(unpacked[2])
        return cls(
            Machine=unpacked[0],
            NumberOfSections=unpacked[1],
            TimeDateStamp=ts,
            PointerToSymbolTable=unpacked[3],
            NumberOfSymbols=unpacked[4],
            SizeOfOptionalHeader=unpacked[5],
            Characteristics=unpacked[6]
        )

@dataclass
class OptionalHeader:
    Magic: int
    MajorLinkerVersion: int
    MinorLinkerVersion: int
    SizeOfCode: int
    SizeOfInitializedData: int
    SizeOfUninitializedData: int
    AddressOfEntryPoint: int
    BaseOfCode: int
    BaseOfData: Optional[int]  # PE32 のみ
    ImageBase: int
    SectionAlignment: int
    FileAlignment: int
    MajorOperatingSystemVersion: int
    MinorOperatingSystemVersion: int
    MajorImageVersion: int
    MinorImageVersion: int
    MajorSubsystemVersion: int
    MinorSubsystemVersion: int
    Win32VersionValue: int
    SizeOfImage: int
    SizeOfHeaders: int
    CheckSum: int
    Subsystem: int
    DllCharacteristics: int

    @classmethod
    def parse(cls, data: bytes) -> "OptionalHeader":
        if len(data) < 70:
            raise ValueError("OptionalHeader のサイズが不足しています")
        Magic, = struct.unpack_from("<H", data, 0)
        if Magic == 0x10B:  # PE32
            (Magic, MajorLinkerVersion, MinorLinkerVersion,
             SizeOfCode, SizeOfInitializedData, SizeOfUninitializedData,
             AddressOfEntryPoint, BaseOfCode, BaseOfData) = struct.unpack("<HBBLLLLLL", data[:28])
            ImageBase, SectionAlignment, FileAlignment = struct.unpack("<LLL", data[28:40])
            (MajorOperatingSystemVersion, MinorOperatingSystemVersion,
             MajorImageVersion, MinorImageVersion,
             MajorSubsystemVersion, MinorSubsystemVersion,
             Win32VersionValue, SizeOfImage, SizeOfHeaders, CheckSum,
             Subsystem, DllCharacteristics) = struct.unpack("<HHHHHHLLLLHH", data[40:70])
            return cls(
                Magic=Magic,
                MajorLinkerVersion=MajorLinkerVersion,
                MinorLinkerVersion=MinorLinkerVersion,
                SizeOfCode=SizeOfCode,
                SizeOfInitializedData=SizeOfInitializedData,
                SizeOfUninitializedData=SizeOfUninitializedData,
                AddressOfEntryPoint=AddressOfEntryPoint,
                BaseOfCode=BaseOfCode,
                BaseOfData=BaseOfData,
                ImageBase=ImageBase,
                SectionAlignment=SectionAlignment,
                FileAlignment=FileAlignment,
                MajorOperatingSystemVersion=MajorOperatingSystemVersion,
                MinorOperatingSystemVersion=MinorOperatingSystemVersion,
                MajorImageVersion=MajorImageVersion,
                MinorImageVersion=MinorImageVersion,
                MajorSubsystemVersion=MajorSubsystemVersion,
                MinorSubsystemVersion=MinorSubsystemVersion,
                Win32VersionValue=Win32VersionValue,
                SizeOfImage=SizeOfImage,
                SizeOfHeaders=SizeOfHeaders,
                CheckSum=CheckSum,
                Subsystem=Subsystem,
                DllCharacteristics=DllCharacteristics
            )
        elif Magic == 0x20B:  # PE32+
            (Magic, MajorLinkerVersion, MinorLinkerVersion,
             SizeOfCode, SizeOfInitializedData, SizeOfUninitializedData,
             AddressOfEntryPoint, BaseOfCode) = struct.unpack("<HBBLLLLL", data[:24])
            ImageBase, = struct.unpack_from("<Q", data, 24)
            SectionAlignment, FileAlignment = struct.unpack("<LL", data[32:40])
            (MajorOperatingSystemVersion, MinorOperatingSystemVersion,
             MajorImageVersion, MinorImageVersion,
             MajorSubsystemVersion, MinorSubsystemVersion,
             Win32VersionValue, SizeOfImage, SizeOfHeaders, CheckSum,
             Subsystem, DllCharacteristics) = struct.unpack("<HHHHHHLLLLHH", data[40:70])
            return cls(
                Magic=Magic,
                MajorLinkerVersion=MajorLinkerVersion,
                MinorLinkerVersion=MinorLinkerVersion,
                SizeOfCode=SizeOfCode,
                SizeOfInitializedData=SizeOfInitializedData,
                SizeOfUninitializedData=SizeOfUninitializedData,
                AddressOfEntryPoint=AddressOfEntryPoint,
                BaseOfCode=BaseOfCode,
                BaseOfData=None,
                ImageBase=ImageBase,
                SectionAlignment=SectionAlignment,
                FileAlignment=FileAlignment,
                MajorOperatingSystemVersion=MajorOperatingSystemVersion,
                MinorOperatingSystemVersion=MinorOperatingSystemVersion,
                MajorImageVersion=MajorImageVersion,
                MinorImageVersion=MinorImageVersion,
                MajorSubsystemVersion=MajorSubsystemVersion,
                MinorSubsystemVersion=MinorSubsystemVersion,
                Win32VersionValue=Win32VersionValue,
                SizeOfImage=SizeOfImage,
                SizeOfHeaders=SizeOfHeaders,
                CheckSum=CheckSum,
                Subsystem=Subsystem,
                DllCharacteristics=DllCharacteristics
            )
        else:
            raise ValueError(f"未知の Optional Header Magic: 0x{Magic:04X}")

@dataclass
class NTHeaders:
    Signature: bytes
    FileHeader: FileHeader
    OptionalHeader: OptionalHeader

    @classmethod
    def parse(cls, data: bytes) -> "NTHeaders":
        if len(data) < 24:
            raise ValueError("NTHeaders のサイズが不足しています")
        Signature = data[:4]
        if Signature != b"PE\x00\x00":
            raise ValueError("無効な PE signature")
        file_header = FileHeader.parse(data[4:24])
        opt_header_data = data[24:24 + file_header.SizeOfOptionalHeader]
        optional_header = OptionalHeader.parse(opt_header_data)
        return cls(Signature, file_header, optional_header)

@dataclass
class SectionHeader:
    Name: str
    VirtualSize: int
    VirtualAddress: int
    SizeOfRawData: int
    PointerToRawData: int
    PointerToRelocations: int
    PointerToLinenumbers: int
    NumberOfRelocations: int
    NumberOfLinenumbers: int
    Characteristics: int

    @classmethod
    def parse(cls, data: bytes) -> "SectionHeader":
        if len(data) < 40:
            raise ValueError("SectionHeader のサイズが不足しています")
        unpacked = struct.unpack("<8sLLLLLLHHI", data[:40])
        name = unpacked[0].rstrip(b'\x00').decode(errors='replace')
        return cls(
            Name=name,
            VirtualSize=unpacked[1],
            VirtualAddress=unpacked[2],
            SizeOfRawData=unpacked[3],
            PointerToRawData=unpacked[4],
            PointerToRelocations=unpacked[5],
            PointerToLinenumbers=unpacked[6],
            NumberOfRelocations=unpacked[7],
            NumberOfLinenumbers=unpacked[8],
            Characteristics=unpacked[9]
        )

def dump_pe(file_path: str):
    try:
        with open(file_path, "rb") as f:
            # DOS Header の読み込み
            dos_data = f.read(64)
            dos_header = DOSHeader.parse(dos_data)
            if not dos_header.is_valid():
                print("無効な DOS ヘッダーです")
                return
            print(f"e_magic: 0x{dos_header.e_magic:04X}")
            print(f"e_lfanew (PE ヘッダーオフセット): {dos_header.e_lfanew}")

            # NT Headers の読み込み
            f.seek(dos_header.e_lfanew)
            nt_header_base = f.read(24)
            file_header = FileHeader.parse(nt_header_base[4:24])
            total_nt_size = 4 + 20 + file_header.SizeOfOptionalHeader
            f.seek(dos_header.e_lfanew)
            nt_headers_data = f.read(total_nt_size)
            nt_headers = NTHeaders.parse(nt_headers_data)

            print("\n--- NT Headers ---")
            print(f"Signature: {nt_headers.Signature}")
            print(f"Machine: 0x{nt_headers.FileHeader.Machine:04X}")
            # Webスクレイピング：Machine に対応する解説（テーブル 3）
            table_match(f"0x{nt_headers.FileHeader.Machine:04X}", 3)

            print(f"Number of Sections: {nt_headers.FileHeader.NumberOfSections}")
            print(f"TimeDateStamp: {nt_headers.FileHeader.TimeDateStamp}")
            print(f"SizeOfOptionalHeader: {nt_headers.FileHeader.SizeOfOptionalHeader}")
            print(f"Characteristics: 0x{nt_headers.FileHeader.Characteristics:04X}")
            # Webスクレイピング：Characteristics の各フラグ解説（例：テーブル 3）
            char_match(format(nt_headers.FileHeader.Characteristics, '04X'), 3)

            print("\n--- Optional Header ---")
            print(f"Magic: 0x{nt_headers.OptionalHeader.Magic:04X}")
            print(f"AddressOfEntryPoint: 0x{nt_headers.OptionalHeader.AddressOfEntryPoint:08X}")
            print(f"BaseOfCode: 0x{nt_headers.OptionalHeader.BaseOfCode:08X}")
            if nt_headers.OptionalHeader.BaseOfData is not None:
                print(f"BaseOfData: 0x{nt_headers.OptionalHeader.BaseOfData:08X}")
            print(f"ImageBase: 0x{nt_headers.OptionalHeader.ImageBase:X}")
            print(f"SectionAlignment: 0x{nt_headers.OptionalHeader.SectionAlignment:X}")
            print(f"FileAlignment: 0x{nt_headers.OptionalHeader.FileAlignment:X}")
            print(f"Subsystem: {nt_headers.OptionalHeader.Subsystem}")
            # Webスクレイピング：Subsystem の解説（テーブル 10）
            table_match(str(nt_headers.OptionalHeader.Subsystem), 10)
            print(f"DLL Characteristics: 0x{nt_headers.OptionalHeader.DllCharacteristics:04X}")
            dll_char_match(format(nt_headers.OptionalHeader.DllCharacteristics, '04X'))

            print("\n--- Section Headers ---")
            sections: List[SectionHeader] = []
            num_sections = nt_headers.FileHeader.NumberOfSections
            f.seek(dos_header.e_lfanew + total_nt_size)
            for i in range(num_sections):
                sec_data = f.read(40)
                section = SectionHeader.parse(sec_data)
                sections.append(section)

            for i, sec in enumerate(sections, start=1):
                print(f"\nSection {i}: {sec.Name}")
                print(f"  Virtual Size:      0x{sec.VirtualSize:X}")
                print(f"  Virtual Address:   0x{sec.VirtualAddress:X}")
                print(f"  Size Of Raw Data:  0x{sec.SizeOfRawData:X}")
                print(f"  Pointer To RawData:0x{sec.PointerToRawData:X}")
                print(f"  Characteristics:   0x{sec.Characteristics:08X}")
                # Webスクレイピング：Section Characteristics の解説（例：テーブル 13）
                sec_char_match(format(sec.Characteristics, '08X'), 13)
    except FileNotFoundError:
        print("ファイルが見つかりません")
    except Exception as e:
        print("エラーが発生しました:", e)

if __name__ == "__main__":
    # 解析する PE ファイルのパスを指定してください（例: notepad.exe）
    file_path = "/mnt/c/Windows/notepad.exe"
    dump_pe(file_path)
