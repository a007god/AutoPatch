#!/usr/bin/env fish
# -----------------------------------------------------------------------------
# run_all.fish — 批量导出 BinExport 并做 BinDiff（改版：用 --output_dir）
# -----------------------------------------------------------------------------

# ========= ① 路径配置 =========
set -gx IDA_BATCH  "/mnt/data/AutoPatch/ida9/idat"
set -gx IDA_GUI  "/mnt/data/AutoPatch/ida9/ida"
set -gx BINDIFF  "/usr/bin/bindiff"
set -gx OUT_ROOT "/mnt/data/AutoPatch/Bindiff_script/LOG"
set -gx LOG_ROOT "/mnt/data/AutoPatch/Bindiff_script/logs"
set -gx ROOT_DIR "/mnt/zhoujunlin/Linux_patch_data/linux_data"
# ==============================

function _log
    echo (date "+%F %T")" | $argv"
end

function export_db
    set bin  $argv[1]   # 输入的 .o 文件
    set base $argv[2]   # 不带后缀的输出前缀
    env QT_QPA_PLATFORM=offscreen TVHEADLESS=1 \
        $IDA_BATCH -A \
                   -B"{$base}" \
                   "$bin" \
        &> /dev/null
end

# 导出 BinExport + 数据库
function export_be
    set bin $argv[1]; set base $argv[2]; set log $argv[3]
    env QT_QPA_PLATFORM=offscreen TVHEADLESS=1 \
        $IDA_GUI -A -c -o$base \
        -OBinExportAutoAction:BinExportBinary \
        -OBinExportModule:"$base.BinExport" \
        "$bin" &> "$log"
end

mkdir -p "$LOG_ROOT"
:> "$LOG_ROOT/failure.log"
_log "开始遍历 $ROOT_DIR"

for proj in $ROOT_DIR/linux-*
    test -d "$proj"; or continue
    set proj_name (basename "$proj")
    set out_proj    "$OUT_ROOT/$proj_name"
    set proj_logdir "$LOG_ROOT/$proj_name"
    mkdir -p "$out_proj" "$proj_logdir"

    set patch_count (count (find "$proj" -path "*/patch_after/*.o" -type f))
    if test $patch_count -eq 0
        _log "!!! $proj_name 无 patch_after/*.o，跳过"
        continue
    end

    _log ">>> 处理 $proj_name ($patch_count 对)"

    for obj_after in (find "$proj" -path "*/patch_after/*.o" -type f)
        set obj_before (string replace "patch_after" "patch_before" -- $obj_after)
        if not test -f "$obj_before"
            _log "    [跳过] before 缺失：$obj_after"
            continue
        end

        set bin_name (basename $obj_after .o)
        set out_dir "$out_proj/{$bin_name}_bindiff"
        set dataset_copy "$proj/{$bin_name}_bindiff"

        if test -e "$out_dir/$bin_name.bindiff"; or test -e "$out_dir/fail.txt"
            _log "    [跳过] 已存在结果或占位：$bin_name"
            continue
        end

        set jobdir "/dev/shm/bd_{$proj_name}_{$bin_name}"
        rm -rf "$jobdir"; mkdir -p "$jobdir"
        cp "$obj_before" "$jobdir/before.o"
        cp "$obj_after"  "$jobdir/after.o"

        set log_before "$jobdir/{$bin_name}_ida_before.log"
        set log_after  "$jobdir/{$bin_name}_ida_after.log"

        _log "    [1/4] 导出 before"
        export_db "$jobdir/before.o" "$jobdir/before"
        export_db "$jobdir/after.o"  "$jobdir/after"

        export_be "$jobdir/before.o" "$jobdir/before" "$log_before"
        _log "    [2/4] 导出 after"
        export_be "$jobdir/after.o"  "$jobdir/after"  "$log_after"

        set waited 0
        while test $waited -lt 90
            if test -s "$jobdir/before.BinExport"; and test -s "$jobdir/after.BinExport"
                break
            end
            sleep 1
            set waited (math $waited + 1)
        end
        if not test -s "$jobdir/before.BinExport"; or not test -s "$jobdir/after.BinExport"
            _log "    [失败] BinExport 生成失败：$bin_name"
            mkdir -p "$out_dir" "$dataset_copy"
            touch "$out_dir/fail.txt" "$dataset_copy/fail.txt"
            echo "$proj_name/$bin_name" >> "$LOG_ROOT/failure.log"
            rm -rf "$jobdir"
            continue
        end

        _log "    [3/4] BinDiff 比对"
        $BINDIFF --primary="$jobdir/before.BinExport" \
                 --secondary="$jobdir/after.BinExport" \
                 --output_dir="$jobdir" --output_format=bin \
                 2>> "$proj_logdir/{$bin_name}_bindiff.log"

        set diff_file (ls "$jobdir"/*.BinDiff 2>/dev/null | head -n 1)

        if not test -s "$diff_file"
            _log "    [失败] BinDiff 未生成：$bin_name"
            mkdir -p "$out_dir" "$dataset_copy"
            touch "$out_dir/fail.txt" "$dataset_copy/fail.txt"
            echo "$proj_name/$bin_name" >> "$LOG_ROOT/failure.log"
            rm -rf "$jobdir"
            continue
        end

        mv "$diff_file" "$jobdir/$bin_name.bindiff"
        set diff_file "$jobdir/$bin_name.bindiff"

        mkdir -p "$out_dir" "$dataset_copy"
        set db_before (ls "$jobdir"/before.o.i64 2>/dev/null | head -n1)
        if test -f "$db_before"
            cp "$db_before" "$out_dir/"
            cp "$db_before" "$dataset_copy/"
        end

        for f in "$jobdir/before.BinExport" "$jobdir/after.BinExport" "$jobdir/$bin_name.bindiff"
            cp "$f" "$out_dir/"
            cp "$f" "$dataset_copy/"
        end

        cp "$log_before" "$proj_logdir/{$bin_name}_before.log"
        cp "$log_after"  "$proj_logdir/{$bin_name}_after.log"
        _log "    [完成] $bin_name"
        rm -rf "$jobdir"
        # break
    end
    # break
end

_log "全部处理完毕，结果 → $OUT_ROOT，日志 → $LOG_ROOT (failure.log 汇总失败文件)"
