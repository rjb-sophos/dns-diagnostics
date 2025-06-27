#!/usr/bin/env perl
# This script is tailored for running on SFOS using commands and modules that are
# available (tested on 21.5 GA)
#
# usage:   dlt.pl [-s dns_server_ip]

# example: dlt.pl                <- 3-way auto test against DNS Protection direct, 
#                                   locally configured DNS servers then System resolver    
#          dlt.pl -s 193.84.4.4  <- leak test against DNS Protection
#          dlt.pl -s 127.0.0.1   <- leak test against the SFOS DNS resolver
#          dlt.pl -s default     <- leak test against the shell's default resolver from /etc/resolv.conf
#                                   (should be 127.0.0.1)                                             

use strict;
use warnings;
use Getopt::Std;
use Term::ANSIColor qw(:constants);
use JSON;
use MIME::Base64;
use Net::IP;
use SFOS::Common::Central::CustomerInfo;

my %opts;
getopts('s:', \%opts);
my $dns_server = $opts{s} || 'auto';
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
# SFOS's nslookup doesn't automatically handle IPv6 reverse lookups, so we have to
# convert the address to a reverse lookup name ourselves
    my $reverse_ip = Net::IP->new($ip)->reverse_ip;
    my $output = qx{nslookup -type=PTR '$reverse_ip'};
    
    # Check for hostname in nslookup output
    if ($output =~ /Resolved Address 1#\s*([^\s]+)/) {
        my $hostname = $1;
        return $hostname if $hostname && $hostname ne $ip;
    }
    return;
}

sub print_servers {
    my ($type, $data) = @_;
    my @results;
    
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

sub do_statuslookup {
    my $host=shift;
    my $server=shift || '';
    my $server_desc=($server eq '') ? 'default server' : $server;

    echo_bold("Checking queries to $server_desc are answered by DNS Protection");

    my $output=qx{nslookup -type=TXT '$host' '$server'};
    if ($output =~ /can't resolve/) {
        echo_error("NXDOMAIN received - suggests you're reaching a DNS server that's not Sophos DNS Protection");
        return 1;
    }
    if ($output =~ /connection timed out/) {
        echo_error("DNS server not responding - suggests traffic is blocked");
        return 2;
    }
    if ($output =~ /Resolved Address 1#\s*("[^"]+")/) {
        print("Success. Response message - ");
        print(decode_base64($1)."\n");
        return 0;
    }
    return 3;
}

sub do_test {
    my $dns_server = shift;
    my $proto = shift || 'udp';
    my $proto_switch = ($proto eq 'tcp') ? '-vc':'';
    if($dns_server eq '') {
        echo_bold("Leak test for $proto queries to default DNS server...")
    } else {
        echo_bold("Leak test for $proto queries to $dns_server...")
    }

    # Get ID
    my $id= qx{curl --silent https://$api_domain/id};
    chomp $id;

    # Ping servers
    for my $i (1..10) {
        my $ignore=qx{nslookup $proto_switch $i.$id.$api_domain $dns_server};
    }

    # Get results
    my $result_json = qx{curl --silent https://$api_domain/dnsleak/test/$id?json};
    my $dnsleak_data = decode_json($result_json);

    my @dns_servers = print_servers("dns", $dnsleak_data);
    my $dns_count = scalar(@dns_servers);

    echo_bold("Your IP address for accessing the leak test HTTPS server:");
    print "$_\n" for print_servers("ip", $dnsleak_data);

    print "\n";
    if ($dns_count == 0) {
        echo_bold("No DNS servers found");
    } else {
        echo_bold("Your queries are being resolved by $dns_count DNS server".($dns_count==1?"":"s").":");
        print "$_\n" for @dns_servers;
    }

    print "\n";
}

if($dns_server eq 'auto') {
    # Do a quick check to see if queries to DNS Protection IP addresses are actually reaching
    # DNS Protection resolvers and not being redirected.
    #
    # This test tries to get the customer's actual tenant ID. If this fails (e.g. they're not
    # registered to Central)  it uses an arbitrary UUID for the tenant ID portion. It still gives
    # valuable feedback about whether it's genuinely reaching a DNS Protection resolver, even
    # if it seems like it's saying there's a location clash, or something.
 
    my $customer_info = SFOS::Common::Central::CustomerInfo::get([qw(customer_id)]);
    my $tenant_id = $customer_info->{customer_id} // '7AA3F4DC-5264-4AF1-8CA0-60D5127F3BBE';
    if(defined $customer_info->{customer_id}) {
        print("Using this device's tenant ID $tenant_id\n");
    } else {
        print("Not joined to central - using a generic tenant id\n");
    }
    do_statuslookup("$tenant_id.sfos.dns.access.sophos.com","193.84.4.4");
    do_statuslookup("$tenant_id.sfos.dns.access.sophos.com","193.84.5.5");
    print("\n");

    # Now do the actual leak tests to see where queries are being resolved
    do_test('127.0.0.1');
    do_test('193.84.4.4');
    do_test('193.84.4.4','tcp');
} else {
    if($dns_server eq 'default') {
        do_test('');
    } else {
        do_test($dns_server);    
    }
}

exit 0;
