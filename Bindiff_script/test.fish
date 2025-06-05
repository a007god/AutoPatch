#!/usr/bin/env fish
# —— diff_one_pair.fish —— 仅对 bzip2_fixed-new vs bzip2_vuln-new 生成 BinDiff

### 基础路径 ###
set -l BEFORE "/mnt/data/AutoPatch/Bindiff_script/DATA/VERSION1/bzip2_fixed-new"
set -l AFTER  "/mnt/data/AutoPatch/Bindiff_script/DATA/VERSION2/bzip2_vuln-new"

set -l IDA    "/mnt/data/AutoPatch/ida9/ida"     # GUI 内核
set -l BDIFF  "/usr/bin/bindiff"                 # BinDiff CLI

### 临时工作目录（缓存盘） ###
set -l WORK "/dev/shm/bd_onepair"
rm -rf $WORK; mkdir -p $WORK
cp $BEFORE $WORK/before.o
cp $AFTER  $WORK/after.o

### 1) 导出 before.BinExport ###
env QT_QPA_PLATFORM=offscreen TVHEADLESS=1 $IDA -A -c \
    -OBinExportAutoAction:BinExportBinary \
    -OBinExportModule:$WORK/before.BinExport \
    $WORK/before.o

### 2) 导出 after.BinExport ###
env QT_QPA_PLATFORM=offscreen TVHEADLESS=1 $IDA -A -c \
    -OBinExportAutoAction:BinExportBinary \
    -OBinExportModule:$WORK/after.BinExport \
    $WORK/after.o

### 3) 生成 .BinDiff ###
$BDIFF --primary=$WORK/before.BinExport \
       --secondary=$WORK/after.BinExport \
       --output_dir=$WORK \
       --output_format=bin

### 4) 把三件文件拷回当前目录 ###
cp $WORK/before.BinExport ./before.BinExport
cp $WORK/after.BinExport  ./after.BinExport
cp $WORK/fixed-vs-vuln.bindiff ./fixed-vs-vuln.bindiff

echo
echo "✅  已生成："
echo "   ./before.BinExport"
echo "   ./after.BinExport"
echo "   ./fixed-vs-vuln.bindiff"
