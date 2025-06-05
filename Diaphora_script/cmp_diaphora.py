import ida_kernwin
import idaapi
import sys
import os

# 添加 Diaphora 模块路径
sys.path.append('/mnt/data/AutoPatch/Diaphora/diaphora')
import diaphora

def run_diaphora_comparison(tgt_db, ref_db):
    """
    使用 Diaphora 对两个 SQLite 数据库进行二进制差异比对。
    """
    try:
        bd = diaphora.CBinDiff(str(tgt_db))
        bd.slow_heuristics = False
        bd.diff(str(ref_db))
        ida_kernwin.hide_wait_box()
        print("差异比对完成。")
    except Exception as e:
        print(f"执行 Diaphora 时发生错误: {str(e)}")

def main():
    args_file = os.path.join(os.path.dirname(__file__), "args.txt")
    #  args.txt 放在运行的 Python 脚本所在的目录下
    
    if not os.path.isfile(args_file):
        print(f"未找到参数文件: {args_file}")
        idaapi.qexit(1)

    with open(args_file, "r", encoding="utf-8") as f:
        lines = [line.strip() for line in f if line.strip()]
    
    if len(lines) < 2:
        print("args.txt 中应包含两行：目标DB和参考DB的路径")
        idaapi.qexit(1)

    tgt_db = lines[0]
    ref_db = lines[1]

    print(f"开始比对:\n 目标数据库: {tgt_db}\n 参考数据库: {ref_db}")
    run_diaphora_comparison(tgt_db, ref_db)

    idaapi.qexit(0)

if __name__ == "__main__":
    print("??")
    main()
