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

use strict;
use warnings;
use v5.32;
use feature qw(say signatures);
no warnings 'experimental::signatures';

use English qw(-no_match_vars);

# Constants
use constant {
    NRCMD_PATH             => '/root/nrcmd.sh',
    SUCCESS_CODE_PATTERN   => qr/^10[01]/,
    QUERY_SUCCESS_PATTERN  => qr/^100/,
};

sub run_command($command) {
    # Execute command and capture output
    my $output = qx($command 2>&1);
    my $exit_code = $CHILD_ERROR >> 8;
    
    return ($output, $exit_code);
}

sub get_user_confirmation($match) {
    my $prompt_text = defined $match 
        ? qq{Really delete all scopes that match "$match" (y/N): }
        : "Really delete all scopes (y/N): ";
    
    print $prompt_text;
    my $answer = <STDIN>;
    chomp $answer;
    
    return $answer =~ /^[yY]/;
}

sub list_scopes() {
    my $list_command = NRCMD_PATH . ' -r scope listnames';
    my ($output, $exit_code) = run_command($list_command);
    
    unless ($output =~ QUERY_SUCCESS_PATTERN) {
        die qq{ERROR: Query for scopes failed: "$output"\n};
    }
    
    # Extract scope names (lines that start with word characters, excluding status line)
    my @scopes = grep { /^\w/ && !/100 Ok/ } split /\n/, $output;
    
    # Trim whitespace from each scope name
    return map { s/^\s+|\s+$//gr } @scopes;
}

sub should_delete_scope($scope, $match) {
    return 1 unless defined $match;
    return $scope =~ /$match/;
}

sub delete_scope($scope) {
    say "Deleting scope $scope";
    
    my $delete_command = NRCMD_PATH . qq{ -r scope '"$scope"' delete};
    my ($output, $exit_code) = run_command($delete_command);
    
    unless ($output =~ SUCCESS_CODE_PATTERN) {
        warn "ERROR: Deleting scope $scope failed: $output\n";
        return 0;
    }
    
    return 1;
}

sub main() {
    my $match = $ARGV[0];
    
    # Get user confirmation
    unless (get_user_confirmation($match)) {
        say "Exiting...";
        return 0;
    }
    
    # Retrieve list of scopes
    my @scopes = list_scopes();
    
    unless (@scopes) {
        say "No scopes found.";
        return 0;
    }
    
    # Process each scope
    my $deleted_count = 0;
    my $skipped_count = 0;
    
    for my $scope (@scopes) {
        if (should_delete_scope($scope, $match)) {
            if (delete_scope($scope)) {
                $deleted_count++;
            }
        } else {
            say qq{Skipping scope $scope as it did not match "$match"};
            $skipped_count++;
        }
    }
    
    # Summary
    say "\n--- Summary ---";
    say "Deleted: $deleted_count scope(s)";
    say "Skipped: $skipped_count scope(s)";
    
    return 0;
}

# Run main
exit main();