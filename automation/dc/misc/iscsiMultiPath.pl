#!/usr/bin/perl -w

use strict;
use warnings;
use VMware::VILib;
use VMware::VIRuntime;
use Data::Dumper;

# validate options, and connect to the server
Opts::parse();
Opts::validate();
Util::connect();

my $hname = undef;

if (scalar(@ARGV) == 1) {
        $hname = $ARGV[0];
}

my @iscsiHosts = ();

if ($hname) {
        my $vmhost = Vim::find_entity_view(
                view_type => 'HostSystem',
                filter    => {name => $hname}
        );
        if (!$vmhost) {
                print "Failed to find host $hname\n";
                exit(1);
        }

        push @iscsiHosts, $vmhost;
} else {
        my $vmhosts = Vim::find_entity_views(view_type => 'HostSystem',);

        foreach (@$vmhosts) {
                push @iscsiHosts, $_;
        }
}

my $error = 0;

foreach my $host (@iscsiHosts) {
        my $ss = Vim::get_view(mo_ref => $host->configManager->storageSystem,);

        my $hbas = $ss->storageDeviceInfo->hostBusAdapter;
        my $hba  = undef;

        foreach my $h (@$hbas) {
                if ($h->isa('HostInternetScsiHba')) {
                        $hba = $h;
                        print $hba->device, "\n";
                        last;
                }
        }

        if (!$hba) {
                print "Did not find HBA for $host->{'name'}\n";
		$error = 1;
                next;
        }
}

Util::disconnect();

if ($error) {
	exit(1);
}
