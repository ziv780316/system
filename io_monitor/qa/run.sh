#!/bin/bash
program=../io_monitor

output_dir=result1
rm -rf $output_dir
cmd="ruby -e 'printf \"#{Math.exp(1)}\\n\"'"
$program -c "$cmd" -o $output_dir -t ascii -m both

output_dir=result2
rm -rf $output_dir
cmd="ruby test.rb"
$program -c "$cmd" -o $output_dir -t ascii -m both

output_dir=result3
rm -rf $output_dir
cmd="echo 123"
$program -c "$cmd" -o $output_dir -t ascii -m write

output_dir=result4
rm -rf $output_dir
cmd="cat run.sh > /dev/null"
$program -c "$cmd" -o $output_dir -t ascii -m both

output_dir=result5
rm -rf $output_dir
cmd="readelf -a $program > /dev/null"
$program -c "$cmd" -o $output_dir -t hex -m both

output_dir=result6
rm -rf $output_dir
cmd="./a.out 1 22 333"
$program -c "$cmd" -o $output_dir -t ascii -m both
