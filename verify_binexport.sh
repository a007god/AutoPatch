mkdir -p /dev/shm/tmp
cp /mnt/data/AutoPatch/Diaphora_script/DATA/VERSION1/xattr.o /dev/shm/tmp/

TVHEADLESS=1 \
/mnt/data/AutoPatch/ida9/idat \
  -A \
  -S/dev/shm/tmp/export_binexport.idc \
  -OBinExportModule:/dev/shm/tmp/xattr.binexport \
  /dev/shm/tmp/xattr.o ; \
and test -s /dev/shm/tmp/xattr.binexport ; \
and echo "✅ BinExport OK" ; or echo "❌ BinExport FAILED"
