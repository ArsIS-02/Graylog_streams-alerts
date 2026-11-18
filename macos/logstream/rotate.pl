#!/usr/bin/perl
# Пишет stdin в файл и сам ротирует его по размеру: file -> file.YYYYmmdd-HHMMSS -> .gz
# Предыдущий архив сжимается только при следующей ротации, чтобы Filebeat успел дочитать файл.
use strict; use warnings; use POSIX qw(strftime);
my ($path, $max_mb, $keep) = @ARGV;
my $max = $max_mb * 1024 * 1024;
my ($fh, $size);
sub reopen { open($fh, '>>', $path) or die "open $path: $!"; my $o = select($fh); $| = 1; select($o); $size = -s $path || 0 }
sub compress_old {
  my $newest = shift;
  for my $f (glob("$path.*")) {
    next unless $f =~ /\.\d{8}-\d{6}(?:-\d+)?$/;
    next if defined $newest && $f eq $newest;
    my $pid = fork(); if (defined $pid && $pid == 0) { exec('/usr/bin/gzip', '-6', '-f', $f) or exit 1 }
  }
  my @arch = sort grep { /\.\d{8}-\d{6}(?:-\d+)?\.gz$/ } glob("$path.*.gz");
  unlink splice(@arch, 0, @arch - $keep) if @arch > $keep;
}
$SIG{CHLD} = 'IGNORE';
$SIG{TERM} = $SIG{INT} = sub { close $fh if $fh; exit 0 };
reopen(); compress_old(undef);
while (my $line = <STDIN>) {
  print $fh $line; $size += length $line;
  if ($size >= $max) {
    close $fh;
    my $arch = "$path." . strftime('%Y%m%d-%H%M%S', localtime);
    my $n = 1; my $base = $arch; $arch = "$base-" . $n++ while -e $arch || -e "$arch.gz";
    rename($path, $arch);
    reopen();
    compress_old($arch);
  }
}
