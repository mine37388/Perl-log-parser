#!/usr/bin/perl
#Author: Jeffrey Norris
use strict;
use warnings;

my %seen = ();
my @uniq = ();
my %user = ();
my @users = ();
my @per = ();
my %per = ();
my @files = glob("/var/log/auth.log*");

foreach my $items(@files)
{
	next if $items =~ /gz/;
	open(LOG,$items) || die "Unable to open firewall log$!\n";
	while (<LOG>)
	{
		my $foo = $_;
		if (($foo =~ /(\d+)(\.\d+){3}/ && (/Failed password/)) && ($foo !~ #<ip address of local server>))
		{
		        my @lin = split(/ +/,$foo);
		        my $fld = @lin;
		        for (my $lp = 0; $lp < $fld; $lp++)
		        {
		                if ($lin[$lp] eq  "from")
		                {
								push(@per,"$lin[$lp - 1],$lin[$lp + 1]$") unless $per{"$lin[$lp - 1],$lin[$lp + 1]$"}++;
		                        push(@uniq, $lin[$lp + 1]) unless $seen{$lin[$lp + 1]}++;
		                        push(@users, $lin[$lp - 1]) unless $user{$lin[$lp - 1]}++;
		                }
		        }
		}
	}
	close (LOG);
}

print "\n\# of login attempts\t:\tIP address\n\n";
foreach my $item (sort { $seen{$b} <=> $seen{$a} } keys %seen)
{
        print "$seen{$item}\t\t\t\t$item\n";
}

print "\n\# of login attempts\t:\tUser Name used\n\n";
foreach my $itm(sort { $user{$b} <=> $user{$a} } keys %user )
{
        print "$user{$itm}\t\t\t\t$itm\n";
}