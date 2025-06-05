from __future__ import annotations
import shutil
import subprocess
import tempfile
import time
from pathlib import Path

# ========= 路径配置 =========
IDA_BIN     = "/mnt/data/AutoPatch/ida9/idat"                       # IDA headless
GEN_SCRIPT  = "/mnt/data/AutoPatch/Diaphora_script/gen_sqlite.py"   # 导出脚本
DIFF_SCRIPT = "/mnt/data/AutoPatch/Diaphora_script/cmp_diaphora.py" # 比对脚本

ROOT_DATA = Path("/mnt/zhoujunlin/Linux_patch_data/linux_data")      # 补丁数据根
LOG_ROOT  = Path("/mnt/data/AutoPatch/Diaphora_script/LOG")          # Diaphora 默认日志目录

TMP_FS = Path("/dev/shm") if Path("/dev/shm").exists() else Path(tempfile.gettempdir())

# ========= 工具函数 =========

def ida_headless(script: str, binary: Path, work_dir: Path) -> None:
    """调用 IDA 执行 *script* 处理 *binary*。"""
    cmd = [IDA_BIN, "-A", "-B", "-L/mnt/data/AutoPatch/ida9/1.log",f"-S{script}", str(binary)]
    subprocess.run(cmd, check=True, cwd=work_dir)


def gen_sqlite(binary: Path, work_dir: Path) -> Path:
    ida_headless(GEN_SCRIPT, binary, work_dir)
    sqlite_path = binary.with_suffix(binary.suffix + ".sqlite")
    if not sqlite_path.exists():
        raise RuntimeError(f"SQLite not found: {sqlite_path}")
    return sqlite_path


def diaphora_diff(sqlite_after: Path, sqlite_before: Path, carrier_bin: Path, work_dir: Path) -> None:
    """调用 cmp_diaphora.py 进行比对。"""
    args_file = Path(DIFF_SCRIPT).with_name("args.txt")
    with open(args_file, "w", encoding="utf-8") as fp:
        fp.write(f"{sqlite_after}\n{sqlite_before}\n")

    ida_headless(DIFF_SCRIPT, carrier_bin, work_dir)

    # 清理临时产物（忽略不存在）
    for p in (
        sqlite_after,
        sqlite_before,
        carrier_bin.with_suffix(".i64"),
        sqlite_after.with_suffix(".i64"),
        sqlite_before.with_suffix(".i64"),
    ):
        p.unlink(missing_ok=True)


def ensure_dir(path: Path) -> None:
    path.mkdir(parents=True, exist_ok=True)

# ========= 主流程 =========

def main() -> None:
    for version_dir in ROOT_DATA.iterdir():
        if not (version_dir.is_dir() and version_dir.name.startswith("linux-")):
            continue

        before_dir = version_dir / "file_o" / "patch_before"
        after_dir  = version_dir / "file_o" / "patch_after"
        if not before_dir.is_dir() or not after_dir.is_dir():
            continue

        print(f"\n=== {version_dir.name} ===")
        version_log_dir = LOG_ROOT / version_dir.name
        ensure_dir(version_log_dir)

        for after_file in after_dir.glob("*.o"):
            before_file = before_dir / after_file.name
            if not before_file.exists():
                continue

            diff_name = f"{after_file.stem}_diaphora_diff.txt"
            dst_log   = version_log_dir / diff_name
            dst_data  = version_dir / diff_name

            # ---- 幂等：已存在则跳过 ----
            if dst_log.exists() or dst_data.exists():
                print(f"  -> {diff_name} already exists, skip.")
                continue

            print(f"  -> diff {after_file.name}")

            # ---- 临时工作目录 ----
            tmp_dir = Path(tempfile.mkdtemp(prefix="ida_", dir=TMP_FS))
            try:
                aft_tmp = tmp_dir / f"after_{after_file.name}"
                bef_tmp = tmp_dir / f"before_{after_file.name}"
                shutil.copy2(after_file, aft_tmp)
                shutil.copy2(before_file, bef_tmp)

                t_start = time.time()

                # ---- 导出 .sqlite 并比对 ----
                aft_sql = gen_sqlite(aft_tmp, tmp_dir)
                bef_sql = gen_sqlite(bef_tmp, tmp_dir)
                diaphora_diff(aft_sql, bef_sql, aft_tmp, tmp_dir)

                # ---- 轮询寻找 Diaphora 输出日志 ----
                pattern = f"*after_{after_file.name}_diff_log.txt"
                diff_src: Path | None = None
                for _ in range(5):  # 最多 5 次 × 1 s
                    cands = list(LOG_ROOT.glob(pattern))
                    if cands:
                        latest = max(cands, key=lambda p: p.stat().st_mtime)
                        if latest.stat().st_mtime >= t_start - 1:
                            diff_src = latest
                            break
                    time.sleep(1)

                if diff_src is not None:
                    shutil.move(diff_src, dst_log)
                    shutil.copy2(dst_log, dst_data)
                else:
                    # --- 未找到日志 → 写占位并登记失败 ---
                    msg = (
                        "Diaphora failure: no diff log generated for "
                        f"{after_file.name} in {version_dir.name}\n"
                    )
                    dst_log.write_text(msg)
                    shutil.copy2(dst_log, dst_data)

                    with open(LOG_ROOT / "failure.log", "a", encoding="utf-8") as fp:
                        fp.write(f"{version_dir.name}/{after_file.name}\n")

                    print(f"  !! No diff log for {after_file.name}, placeholder created.")
            finally:
                # pass
                shutil.rmtree(tmp_dir, ignore_errors=True)
        # break

    print("\n✅ All jobs finished; outputs sorted under", LOG_ROOT)


if __name__ == "__main__":
    main()
