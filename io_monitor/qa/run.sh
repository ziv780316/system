#!/bin/bash
program=../io_monitor

#output_dir=result1
#rm -rf $output_dir
#cmd="ruby -e 'printf \"#{Math.exp(1)}\\n\"'"
#$program -c "$cmd" -o $output_dir -t ascii -m both
#
#output_dir=result2
#rm -rf $output_dir
#cmd="ruby test.rb"
#$program -c "$cmd" -o $output_dir -t ascii -m both
#
#output_dir=result3
#rm -rf $output_dir
#cmd="echo 123"
#$program -c "$cmd" -o $output_dir -t ascii -m write
#
#output_dir=result4
#rm -rf $output_dir
#cmd="cat run.sh > /dev/null"
#$program -c "$cmd" -o $output_dir -t ascii -m both
#
#output_dir=result5
#rm -rf $output_dir
#cmd="readelf -a $program > /dev/null"
#$program -c "$cmd" -o $output_dir -t hex -m both
#
#output_dir=result6
#rm -rf $output_dir
#gcc -O0 -g case6.c -o case6.exe
#cmd="./case6.exe"
#$program -c "$cmd" -o $output_dir -t ascii -m both
#
#output_dir=result7
#rm -rf $output_dir
#gcc -O0 -g case7.c `readlink -m ../libio_both.so` -o case7.exe 
#export IO_MONITOR_REPORT_DIR=`pwd`/$output_dir
#mkdir $output_dir
#valgrind ./case7.exe >& case7.valgrind 
#unset IO_MONITOR_REPORT_DIR
#
#output_dir=result8
#rm -rf $output_dir
#cmd="echo 1111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111"
#$program -c "$cmd" -o $output_dir -t ascii -m both
#
#output_dir=result9
#rm -rf $output_dir
#gcc -O0 -g case9.c `readlink -m ../libio_both.so` -o case9.exe 
#export IO_MONITOR_REPORT_DIR=`pwd`/$output_dir
#mkdir $output_dir
#valgrind --leak-check=full --show-leak-kinds=all ./case9.exe >& case9.valgrind 
#unset IO_MONITOR_REPORT_DIR
#
#output_dir=result9
#rm -rf $output_dir
#gcc -O0 -g case9.c -o case9.exe
#cmd="./case9.exe"
#$program -c "$cmd" -o $output_dir -t ascii -m both

output_dir=result10
rm -rf $output_dir
gcc -O0 -g case10.c -o case10.exe
cmd="./case10.exe"
$program -c "$cmd" -o $output_dir -t ascii -m both
