#!/usr/bin/perl
srand;
use Digest::SHA1  qw(sha1_hex);

$match_phrase1 = 'I would much rather hear more about your whittling project';
$match_sha1 = sha1_hex($match_phrase1);
print "MATCH Phrase:".${match_phrase1}." SHA1: ${match_sha1}\n\n";

#$match_phrase2 = 'MemcACHed rUbY ReCoRd aCTIvE ToKYo one EiGht one mEMCAChED RaIlS ruBY meMcaChEd ntEo>';
$match_phrase2 = 'grOk raymOND scCs MeTaProgrAMMIng eDITOr dONGARra veRNaM uniCODe SoaP repLacE liB RJUST';
$match_sha2 = sha1_hex($match_phrase2);
print "MATCH Phrase:".${match_phrase2}." SHA1: ${match_sha2}\n";


$binary1 = hex2bin($match_sha1);
$binary2 = hex2bin($match_sha2);

$hamming = hd($binary1, $binary2); 

print "Hamming Distance:".${hamming}."\nDone.\n";

exit;

#print hd(sha1_hex('Rubinius one eight six active active record memcached exception JRuby DHH TOKYO sdfe9'), 'c89afb8107a21d49d76e2d6e7c426a3658bf5255');
sub hd {
    return ($_[0] ^ $_[1]) =~ tr/\001-\255//;
}

sub hex2bin {
        my $h = shift;
        my $hlen = length($h);
        my $blen = $hlen * 4;
        return unpack("B$blen", pack("H$hlen", $h));
}