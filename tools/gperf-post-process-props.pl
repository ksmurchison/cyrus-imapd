#!/usr/bin/perl

use strict;
use warnings;

# Parse a gperf-generated property array and generate
# static ptrarray_t of the wildcard, mandatory, and always_get properties,
# and a jmap_property_set_t for the object type.
#
# Example gperf-generated property array format:
#
# static const jmap_property_t sieve_prop_array[] =
#   {
#     {(char*)0,NULL,0}, {(char*)0,NULL,0},
# #line 27 "imap/jmap_sieve_props.gperf"
#     {"id",       NULL, JMAP_PROP_SERVER_SET | JMAP_PROP_IMMUTABLE | JMAP_PROP_ALWAYS_GET},
#     {(char*)0,NULL,0},
# #line 28 "imap/jmap_sieve_props.gperf"
#     {"name",     NULL, 0},
#     {(char*)0,NULL,0},
# line 30 "imap/jmap_sieve_props.gperf"
#     {"blobId",   NULL, 0},
#     {(char*)0,NULL,0},
# #line 29 "imap/jmap_sieve_props.gperf"
#     {"isActive", NULL, JMAP_PROP_SERVER_SET}
#   };

my %special_props = (
    'wildcards'  => [],
    'always_get' => [],
    'mandatory'  => []
);

my $obj_type = "";
my $idx      = 0;
my $in_hash  = 0;
my $in_array = 0;

while (my $line = <STDIN>) {
    # Some property arrays are small/unique enough
    # that just the length of the string can be used as the hash key,
    # E.g:
    #
    # static unsigned int
    # sieve_prop_hash (register const char *str, register size_t len)
    # {
    #   (void) str;  <- only included by gperf 3.2+
    #   return len;
    # }
    #
    # Older gperf versions do not include "(void) str;" which can results in
    # unused 'str' variable compiler errors.
    # Check to see if we need to include this ourselves.

    if ($line =~ /^.+_prop_hash \(/) {
        $in_hash = 1;
    }
    elsif ($in_hash) {
        if ($line =~ /^\{/) {
            # Skip opening brace
        }
        else {
            # The first statement of the hash() function is definitive
            if ($line =~ /\(void\) str;/) {
                # Already included by newer gperf
            }
            elsif ($line =~ /return len;/) {
                # Older gperf - add error suppression statement
                print "  (void) str;\n";
            }
            $in_hash = 0;
        }
    }

    print $line;

    # Look for and process the property array.
    # We track each special property by its index into the array.
    chomp $line;

    next if $line =~ /^#/;   # Skip declarations and comments

    if ($line =~ /^static const jmap_property_t (.+)_prop_array\[] =/) {
        $obj_type = $1;
        $in_array = 1;
        next;
    }
    
    next unless $in_array;

    $line =~ s/\s+//g;       # Remove whitespace

    next if $line eq '';     # Skip empty lines
    next if ($line eq '{');  # Skip opening brace

    if ($line eq '};') {     # Skip closing brace
        $in_array = 0;
        next;
    }

    if ($line =~ /{".+",/) {
        # Actual named property - split the line into the jmap_propery_t fields
        my @fields = split(/,/, $line);

        if ($fields[0] =~ /".+\*"/) {
            push(@{$special_props{'wildcards'}}, $idx);
        }
        elsif ($fields[2] =~ /JMAP_PROP_ALWAYS_GET/) {
            push(@{$special_props{'always_get'}}, $idx);
        }
        elsif ($fields[2] =~ /JMAP_PROP_MANDATORY/) {
            push(@{$special_props{'mandatory'}}, $idx);
        }

        $idx++;
    }
    else {
        # Count the number of empty entries which appear on the line
        my $count = () = $line =~ /{\(char\*\)0,NULL,0},/g;
        $idx += $count;
    }
}

# Output special property arrays
foreach my $name ('wildcards', 'always_get', 'mandatory') {
    my @array = @{$special_props{$name}};

    next if (!scalar(@array));

    print "\nstatic const jmap_property_t *${obj_type}_${name}_array[] = {\n";

    foreach $idx (@array) {
        print "    (jmap_property_t *) &${obj_type}_prop_array[${idx}],\n";
    }
    print "};\n";
}

# Output jmap_property_set_t
my $uc_obj_type = uc($obj_type);

print <<EOF;

static const jmap_property_set_t ${obj_type}_props = {
    // jmap_prop_hash_table_t
    {
        ${obj_type}_prop_array,
        &${obj_type}_prop_lookup,
        ${uc_obj_type}_PROP_TOTAL_KEYWORDS,
        ${uc_obj_type}_PROP_MIN_HASH_VALUE,
        ${uc_obj_type}_PROP_MAX_HASH_VALUE,
    },
    // special property ptrarray_t
EOF

foreach my $name ('wildcards', 'always_get', 'mandatory') {
    my $count = scalar(@{$special_props{$name}});
    my $array = !$count ? "NULL /* $name */" : "${obj_type}_${name}_array";

    print "    { ${count}, 0, (void **) $array },\n";
}
print "};\n";
