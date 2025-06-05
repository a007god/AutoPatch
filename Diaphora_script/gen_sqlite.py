# 生成sqlite文件

import os
import sys
from pathlib import Path

import idaapi
import ida_kernwin
import ida_auto

# 设置 Diaphora 路径
DIAPHORA_DIR = "/mnt/data/AutoPatch/Diaphora/diaphora"
if DIAPHORA_DIR not in sys.path:
    sys.path.insert(0, DIAPHORA_DIR)

try:
    import diaphora_ida
except ImportError:
    # 不弹出窗口，只写日志
    print("[-] 无法导入 diaphora_ida，请检查路径")
    idaapi.qexit(1)

def export_sqlite_via_api():
    input_file = idaapi.get_input_file_path()
    if not input_file:
        print("[-] 无法获取输入文件路径。")
        idaapi.qexit(1)

    input_path = Path(input_file)
    output_path = input_path.with_suffix(f"{input_path.suffix}.sqlite")

    # 自动等待分析完成
    ida_auto.auto_wait()

    # 尽可能关闭弹窗
    ida_kernwin.hide_wait_box()

    if output_path.exists():
        print(f"[+] SQLite 文件已存在，跳过导出: {output_path}")
    else:
        print(f"[+] 导出到: {output_path}")
        bd = diaphora_ida.CIDABinDiff(str(output_path))
        bd.export()
        print("[+] 导出完成")

    # 自动退出 IDA
    idaapi.qexit(0)

# 兼容 -S 执行
export_sqlite_via_api()
