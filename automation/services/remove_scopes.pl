#!/usr/bin/env perl
#
# Copyright (c) 2025  Joe Clarke <jclarke@cisco.com>
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions
# are met:
# 1. Redistributions of source code must retain the above copyright
#    notice, this list of conditions and the following disclaimer.
# 2. Redistributions in binary form must reproduce the above copyright
#    notice, this list of conditions and the following disclaimer in the
#    documentation and/or other materials provided with the distribution.
#
# THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
# ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
# IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
# ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
# FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
# DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
# OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
# HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
# LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
# OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
# SUCH DAMAGE.
#
use strict;
use warnings;
use 5.026;
use Fcntl qw(:DEFAULT);
use File::Spec;
use File::Basename;

sub run_command {
    my ($command) = @_;
    
    # Use system's open for command execution
    my $output = `$command 2>&1`;
    my $exit_code = $? >> 8;
    
    return ($output, $exit_code);
}

# Main script
my $match = $ARGV[0] // undef;

# Prompt for confirmation
my $prompt_text = defined $match 
    ? qq{Really delete all scopes that match "$match" (y/N): }
    : "Really delete all scopes (y/N): ";

print $prompt_text;
my $ans = <STDIN>;
chomp $ans;

unless ($ans =~ /^[yY]/) {
    say "Exiting...";
    exit 0;
}

# List scopes
my $list_command = "/root/nrcmd.sh -r scope listnames";
my ($out, $exit_code) = run_command($list_command);

unless ($out =~ /^100/) {
    say qq{Query for scopes failed: "$out"};
    exit 1;
}

# Process scopes
my @scopes = grep { $_ =~ /^\w/ && $_ !~ /100 Ok/ } split(/\n/, $out);

for my $scope (@scopes) {
    $scope =~ s/^\s+|\s+$//g;  # Trim whitespace
    
    my $delete = 1;
    if (defined $match && $scope !~ /$match/) {
        $delete = 0;
    }
    
    if ($delete) {
        say "Deleting scope $scope";
        
        my $delete_command = "/root/nrcmd.sh -r scope '\"$scope\"' delete";
        my ($delete_out, $delete_exit) = run_command($delete_command);
        
        unless ($delete_out =~ /^10[01]/) {
            say "ERROR: Deleting scope $scope failed: $delete_out";
        }
    } else {
        say qq{Skipping scope $scope as it did not match "$match"};
    }
}