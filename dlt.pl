#!/usr/bin/env perl
# usage:   ./dnsleaktest.pl [-d dns_server_ip]
# example: ./dnsleaktest.pl -i eth1
#          ./dnsleaktest.pl -i 10.0.0.2

use strict;
use warnings;
use Getopt::Std;
use Term::ANSIColor qw(:constants);
use JSON;
use MIME::Base64;

my %opts;
getopts('d:', \%opts);
my $dns_server = $opts{d} || '';
my $api_domain = 'bash.ws';
my $error_code = 1;

sub echo_bold {
    print BOLD, $_[0], RESET, "\n";
}

sub increment_error_code {
    $error_code++;
}

sub echo_error {
    print STDERR RED, $_[0], RESET, "\n";
}

sub get_hostname_for_ip {
    my $ip = shift;
    my $output = `nslookup $ip 2>/dev/null`;
    
    # Check for hostname in nslookup output
    if ($output =~ /Resolved Address 1#\s*([^\s]+)/) {
        my $hostname = $1;
        return $hostname if $hostname && $hostname ne $ip;
    }
    return undef;
}

my $result_json;
sub print_servers {
    my $type = shift;
    my @results;
    
    my $data = decode_json($result_json);
    foreach my $entry (@$data) {
        next unless $entry->{type} eq $type;
        
        my $ip = $entry->{ip};
        my $output = $ip;
        
        # Add hostname if available
        if($type ne "conclusion") {
            my $hostname = get_hostname_for_ip($ip);
            if ($hostname) {
                $output .= " ($hostname)";
            } else {
                $output .= " (reverse lookup failed)";
            }
        }
        
        if ($entry->{country_name} && $entry->{country_name} ne "false") {
            $output .= " [" . $entry->{country_name};
            if ($entry->{asn} && $entry->{asn} ne "false") {
                $output .= " " . $entry->{asn};
            }
            $output .= "]";
        }
        
        push @results, $output;
    }
    
    return @results;
}

sub nslookup {
    my $host=shift;
    my $server=shift || '';
    my $cmd = "nslookup $host $server";
    my $output=`$cmd 2>/dev/null`;
    if ($output =~ /can't resolve/) {
        print("NXDOMAIN received\n");
        return 1;
    }
    if ($output =~ /connection timed out/) {
        print("DNS server not responding\n");
        return 2;
    }
    if ($output =~ /Resolved Address 1#\s*("[^"]+")/) {
        print("Success. Response message - ");
        print(decode_base64($1)."\n");
        return 0;
    }

}

sub do_test {
    my $dns_server = shift;
    if($dns_server eq '') {
        echo_bold("Leak test for queries to default DNS server...")
    } else {
        echo_bold("Leak test for queries to $dns_server...")
    }

    # Get ID
    my $id;
    {
        my $cmd = "curl " . "--silent https://$api_domain/id";
        $id = `$cmd`;
        chomp $id;
    }

    # Ping servers
    for my $i (1..10) {
    #    my $cmd = "ping -c 1 " . ($interface ? "-I $interface " : "") . "$i.$id.$api_domain > /dev/null 2>&1";
        my $cmd = "nslookup $i.$id.$api_domain $dns_server > /dev/null 2>&1";
        system($cmd);
    }

    # Get results
    my $cmd = "curl " . "--silent https://$api_domain/dnsleak/test/$id?json";
    $result_json = `$cmd`;

    my @dns_servers = print_servers("dns");
    my $dns_count = scalar(@dns_servers);

    echo_bold("Your IP address for accessing the leak test HTTPS server:");
    print "$_\n" for print_servers("ip");

    print "\n";
    if ($dns_count == 0) {
        echo_bold("No DNS servers found");
    } else {
        echo_bold("Your queries are being resolved by $dns_count DNS server".($dns_count==1?"":"s").":");
        print "$_\n" for @dns_servers;
    }

    print "\n";
}

if($dns_server eq '') {
    echo_bold("Checking queries to 193.84.4.4 are answered by DNS Protection");
    nslookup("7AA3F4DC-5264-4AF1-8CA0-60D5127F3BBE.sfos.dns.access.sophos.com","193.84.4.4");
    echo_bold("Checking queries to 193.84.5.5 are answered by DNS Protection");
    nslookup("7AA3F4DC-5264-4AF1-8CA0-60D5127F3BBE.sfos.dns.access.sophos.com","193.84.4.4");
    print("\n");

    do_test('193.84.4.4');
    do_test(''); # test with the system's default resolver
    do_test('127.0.0.1');
} else {
    do_test($dns_server);
}


exit 0;
