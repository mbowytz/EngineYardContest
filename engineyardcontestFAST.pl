#!/usr/bin/perl
srand;
use Digest::SHA1  qw(sha1_hex);
$match_phrase = 'I would much rather hear more about your whittling project';
$match_sha1 = sha1_hex($match_phrase);
print "MATCH SHA1: ${match_sha1}\n";
$timeDataBegin = localtime();
$timeNumberBegin = time();
$lowest = 1000000;

my @data = qw(solo flex scalable rubyonrails rails cloud web hosting ec2 aws git 3des abbrev accessor actionpack active activereload addon adjoin aes agile ajax alberti algol alias allen allman aloha amazon AMI amp andreessen android apache apple applet apricot ar arcade array assert assoc atbash atkinson awk awsm awstats babbage backus balancers bartle base64 based bash bazeries bdd beck becker behavior behlendorf bell benchmark benchmarks berkeleydb berners beta betas bford bigdecimal bignum bigtable biham bin bina binaries binary bitsweat bizstone blank bletchley block blocks blog blogs boole boolean bot box bricklin bridge brin browser browsers bsd bug bugs build builder builders builds bytesize c10k cache caches caching caesar call camp capistrano cardelli carmack carribault case catalyst center cerf cgi chabaud chain channel chars cheezburger chef chen child chomp chop chore church ci city class classes cleanup clear client clients clone closures cluster clusters cmd cochran code coder codes codex collect collossus colocated colocation combine combines fixnum fixture flowers floyd flush footer foreign form format formt formula formulas fowler fragment fragments fraser free freebsd freeware freeze friedman front frozen ftools ftp function functional gadget gate gem gems generator generators generic gentoo gets gfs ginsburg github gitignore glob global globals glue godel goldberg golden golub gosling gray greater greenblatt grep grok group groups grove gsub gutmans h1 h2 h3 habtm hack hacker hackers hacks haml hamming handler handlers handling hansson haproxy hash hashing hawkes headers headius heinemeier hejlsberg hellman hello helper hex hexadecimal hibernate hillis hoedown hopper host hosted hosts howcast hpricot href html htonl http https i10n i18n icanhaz icann ichbiah icon iconv id ietf imap include index ingalls inject injection inline inode insert inspect install instance integer integration intern internet internets interpreter interpreters invalid io iphone iphones ipsec irb irbrc is iterators stonebraker storage strachey string stringio strings stroustrup struct structure structures struts sub subclass subversion summit support suppress suraski sussman svn sweeper sync syntax syslog syslogs sysoev tab table tables tag taguri tanenbaum tatham tcpip tdd tech technical template tender tesler test testing tests textmate theory thin thompson thread threaded threading threads ticket tickets tiered tmp tokyo torvalds trithemius trubshaw tsort tube tubes tukey turing typedef typex tyrant ubuntu ulysses unicode union uniq unit unix upcase upto url utc utf utf8 velocity venema vernam vi vigenere vm voynich vps vsphere w3c wadler wall wang watson webcal webdav webrat webrick welchman wep whitfield whittling wiki williams win32 winer winograd wirth wolfram wozniak wsdl www wycats wysiwyg xal xkcd xml yamauchi yaml yin yu zakalwe zawinski zehm zimmerman zlib zygalski );
fisher_yates_shuffle( \@data );
my $permutations = 999999999;
print "Permutations:".$permutations."\n";

$foo5 = hex2bin($match_sha1);
print "Testing:".$foo5."\n";

for($i=0;$i<=$permutations;$i++) {
  my @shuffle = @data [ n2perm( 1+int(rand $permutations), 11 ) ];

  my @new_shuffle = qw();
  foreach $word (@shuffle) {
    @arr = split('', $word);
    $new_word = '';
     push(@new_shuffle,$word);
  }

  $word = join(' ', @new_shuffle) . ' ' . randchrs();
  $hamming = hd(hex2bin(sha1_hex($word)), $foo5);
  if ($hamming < $lowest) {
    $lowest = $hamming;
    print "\n\n${word} == NEW LOWEST: ${lowest}\n\n"
  }
  if ($i % 100000 == 0) { 
    $timeNumberEnd = time();
    $elapsed = $timeNumberEnd - $timeNumberBegin;
    print "---------------------------------\nTotal Calcs:" . $i . "\nElapsed Seconds:" . $elapsed . "\n";
    $calcsPerSecond = $i / ($timeNumberEnd - $timeNumberBegin + 1);
    print "Calcs Per Second: " . $calcsPerSecond . "\n";
  }
}
#print join('',randchrs());

$timeDataEnd = localtime();
$timeNumberEnd = time();
print "Started at " . $timeDataBegin . " and ended at " . $timeDataEnd. "\n";

$timeNumberEnd = time();
$calcsPerSecond = $i / ($timeNumberEnd - $timeNumberBegin);
print "Calcs Per Second: " . $calcsPerSecond . "\nDone.\n";

exit;


sub fisher_yates_shuffle {
  my $array = shift;
  my $i;
  for ($i = @$array; --$i; ) {
    my $j = int rand ($i+1);
    next if $i == $j;
    @$array[$i,$j] = @$array[$j,$i];
  }
}

sub randchrs {
  return 
    #(33, 126)
    chr(random_int_between(65, 122)) .
    chr(random_int_between(65, 122)) . 
    chr(random_int_between(65, 122)) . 
    chr(random_int_between(65, 122)) .
    chr(random_int_between(65, 122));
}

sub random_int_between {
	my($min, $max) = @_;
	# Assumes that the two arguments are integers themselves!
	return $min if $min == $max;
	($min, $max) = ($max, $min)  if  $min > $max;
	return $min + int rand(1 + $max - $min);
}

#print hd(sha1_hex('Rubinius one eight six active active record memcached exception JRuby DHH TOKYO sdfe9'), 'c89afb8107a21d49d76e2d6e7c426a3658bf5255');
sub hd {
    return ($_[0] ^ $_[1]) =~ tr/\001-\255//;
}

# Utility function: factorial with memoizing
BEGIN {
  my @fact = (1);
  sub factorial($) {
      my $n = shift;
      return $fact[$n] if defined $fact[$n];
      $fact[$n] = $n * factorial($n - 1);
  }
}

# n2pat($N, $len) : produce the $N-th pattern of length $len
sub n2pat {
    my $i   = 1;
    my $N   = shift;
    my $len = shift;
    my @pat;
    while ($i <= $len + 1) {   # Should really be just while ($N) { ...
        push @pat, $N % $i;
        $N = int($N/$i);
        $i++;
    }
    return @pat;
}

# pat2perm(@pat) : turn pattern returned by n2pat() into
# permutation of integers.  XXX: splice is already O(N)
sub pat2perm {
    my @pat    = @_;
    my @source = (0 .. $#pat);
    my @perm;
    push @perm, splice(@source, (pop @pat), 1) while @pat;
    return @perm;
}

# n2perm($N, $len) : generate the Nth permutation of $len objects
sub n2perm {
    pat2perm(n2pat(@_));
}

sub hex2bin {
        my $h = shift;
        my $hlen = length($h);
        my $blen = $hlen * 4;
        return unpack("B$blen", pack("H$hlen", $h));
}