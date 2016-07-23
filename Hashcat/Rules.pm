# (c) mhasbini 2016
package Hashcat::Rules;
use strict;
use warnings;
use vars qw($VERSION);
$VERSION = '0.01';

sub new {
    my $class = shift;
    my %parm  = @_;
    my $this  = {};
    bless $this, $class;
    $this->{verbose} = $parm{verbose} || 0;
    $this->{rules} = {

        # General
        ':' => sub {
            my @rule_ref = @{ shift; };
            splice( @rule_ref, 0, 1 );
            return \@rule_ref,
              length( $_[0] ) > 32 ? $this->{skip} = 1 : $_[0];
        },
        'l' => sub {
            my @rule_ref = @{ shift; };
            splice( @rule_ref, 0, 1 );
            return \@rule_ref,
              length( $_[0] ) > 32 ? $this->{skip} = 1 : lc( $_[0] );
        },
        'u' => sub {
            my @rule_ref = @{ shift; };
            splice( @rule_ref, 0, 1 );
            return \@rule_ref,
              length( $_[0] ) > 32 ? $this->{skip} = 1 : uc( $_[0] );
        },
        'c' => sub {
            my @rule_ref = @{ shift; };
            splice( @rule_ref, 0, 1 );
            return \@rule_ref,
              length( $_[0] ) > 32 ? $this->{skip} = 1 : _ucfirst( $_[0] );
        },
        'C' => sub {
            my @rule_ref = @{ shift; };
            splice( @rule_ref, 0, 1 );
            return \@rule_ref,
              length( $_[0] ) > 32 ? $this->{skip} = 1 : _lcfirst( $_[0] );
        },
        'r' => sub {
            my @rule_ref = @{ shift; };
            splice( @rule_ref, 0, 1 );
            my $rev = reverse( $_[0] );
            return \@rule_ref, length( $_[0] ) > 32 ? $this->{skip} = 1 : $rev;
        },    # TODO: minimize reverse expression
        't' => sub {
            my @rule_ref = @{ shift; };
            splice( @rule_ref, 0, 1 );
            return \@rule_ref,
              length( $_[0] ) > 32 ? $this->{skip} = 1 : _toogle_case( $_[0] );
        },
        'T' => sub {
            my @rule_ref = @{ shift; };
            my $pos = &to_pos( $rule_ref[1] );
            splice( @rule_ref, 0, 2 );
            return \@rule_ref,
              length( $_[0] ) > 32
              ? $this->{skip} = 1
              : _toogle_case_pos( $_[0], $pos );
        },
        'd' => sub {
            my @rule_ref = @{ shift; };
            splice( @rule_ref, 0, 1 );
            return \@rule_ref,
                length( $_[0] ) > 15
              ? length( $_[0] ) > 32
                  ? $this->{skip} = 1
                  : $_[0]
              : $_[0] x 2;
        },
        'p' => sub {
            my @rule_ref = @{ shift; };
            my $n = &to_pos( $rule_ref[1] );
            splice( @rule_ref, 0, 2 );
            return \@rule_ref,
              length( $_[0] ) > 32 ? $this->{skip} =
                1
              : length( $_[0] ) * ( $n + 1 ) >= 32 ? $_[0]
              :                                      $_[0] x ( $n + 1 );
        },
        'f' => sub {
            my @rule_ref = @{ shift; };
            splice( @rule_ref, 0, 1 );
            my $rev = reverse( $_[0] );
            return \@rule_ref,
                length( $_[0] ) * 2 > 31
              ? length( $_[0] ) > 32
                  ? $this->{skip} = 1
                  : $_[0]
              : $_[0] . $rev;
        },
        '{' => sub {
            my @rule_ref = @{ shift; };
            splice( @rule_ref, 0, 1 );
            my @plain_ref = &plain_ref( $_[0] );
            my $first_char =
              scalar( @{ $plain_ref[0] } ) == 0 ? '' : shift @{ $plain_ref[0] };
            return \@rule_ref,
              length( $_[0] ) > 32
              ? $this->{skip} = 1
              : join( '', @{ $plain_ref[0] } ) . $first_char;
        },
        '}' => sub {
            my @rule_ref = @{ shift; };
            splice( @rule_ref, 0, 1 );
            my @plain_ref = &plain_ref( $_[0] );
            my $last_char =
              scalar( @{ $plain_ref[0] } ) == 0 ? '' : pop @{ $plain_ref[0] };
            return \@rule_ref,
              length( $_[0] ) > 32
              ? $this->{skip} = 1
              : $last_char . join( '', @{ $plain_ref[0] } );
        },
        '$' => sub {
            my @rule_ref = @{ shift; };
            my $c = $rule_ref[1];
            splice( @rule_ref, 0, 2 );
            return \@rule_ref,
                length( $_[0] ) >= 31
              ? length( $_[0] ) > 32
                  ? $this->{skip} = 1
                  : $_[0]
              : $_[0] . $c;
        },
        '^' => sub {
            my @rule_ref = @{ shift; };
            my $c = $rule_ref[1];
            splice( @rule_ref, 0, 2 );
            return \@rule_ref,
                length( $_[0] ) >= 31
              ? length( $_[0] ) > 32
                  ? $this->{skip} = 1
                  : $_[0]
              : $c . $_[0];
        },
        '[' => sub {
            my @rule_ref = @{ shift; };
            splice( @rule_ref, 0, 1 );
            my @plain_ref = &plain_ref( $_[0] );
            shift @{ $plain_ref[0] };
            return \@rule_ref,
              length( $_[0] ) > 32 ? $this->{skip} =
                1
              : scalar( @{ $plain_ref[0] } ) == 0 ? ''
              :   join( '', @{ $plain_ref[0] } );
        },
        ']' => sub {
            my @rule_ref = @{ shift; };
            splice( @rule_ref, 0, 1 );
            my @plain_ref = &plain_ref( $_[0] );
            pop @{ $plain_ref[0] };
            return \@rule_ref,
              length( $_[0] ) > 32 ? $this->{skip} =
                1
              : scalar( @{ $plain_ref[0] } ) == 0 ? ''
              :   join( '', @{ $plain_ref[0] } );
        },
        'D' => sub {
            my @rule_ref = @{ shift; };
            my $n = &to_pos( $rule_ref[1] );
            splice( @rule_ref, 0, 2 );
            my @plain_ref = &plain_ref( $_[0] );
            if ( $n <= scalar( @{ $plain_ref[0] } ) ) {
                splice( @{ $plain_ref[0] }, $n, 1 );
            }
            return \@rule_ref,
              length( $_[0] ) > 32
              ? $this->{skip} = 1
              : join( '', @{ $plain_ref[0] } );
        },
        'x' => sub {
            my @rule_ref = @{ shift; };
            my ( $n, $m ) = &to_pos_double( $rule_ref[1], $rule_ref[2] );
            splice( @rule_ref, 0, 3 );
            return \@rule_ref,
              length( $_[0] ) > 32 ? $this->{skip} =
                1
              : ( $n + $m <= length( $_[0] ) ) ? substr( $_[0], $n, $m )
              :                                  $_[0];
        },

# no warnings; is for error in substr when feeded with Int. Int shouldn't be feeded but Perl
# doesn't handle types, so i can't force the type to be Str. Duh.
        'O' => sub {
            no warnings;
            my @rule_ref = @{ shift; };
            my ( $n, $m ) = &to_pos_double( $rule_ref[1], $rule_ref[2] );
            splice( @rule_ref, 0, 3 );
            if ( $n < length( $_[0] ) - 1 && length( $_[0] ) <= 32 ) {
                substr( $_[0], $n, $m, '' );
            }
            return \@rule_ref,
              length( $_[0] ) > 32 ? $this->{skip} = 1 : $_[0];
        },
        'i' => sub {
            no warnings;
            my @rule_ref = @{ shift; };
            my ( $n, $c ) = ( &to_pos( $rule_ref[1] ), $rule_ref[2] );
            splice( @rule_ref, 0, 3 );
            if ( $n <= length( $_[0] ) && length( $_[0] ) < 31 ) {
                substr( $_[0], $n, 0, $c );
            }
            return \@rule_ref,
              length( $_[0] ) > 32 ? $this->{skip} = 1 : $_[0];
        },
        'o' => sub {
            no warnings;
            my @rule_ref = @{ shift; };
            my ( $n, $c ) = ( &to_pos( $rule_ref[1] ), $rule_ref[2] );
            splice( @rule_ref, 0, 3 );
            if ( $n <= length( $_[0] ) - 1 && length( $_[0] ) <= 32 ) {
                substr( $_[0], $n, 1, $c );
            }
            return \@rule_ref,
              length( $_[0] ) > 32 ? $this->{skip} = 1 : $_[0];
        },
        "'" => sub {
            my @rule_ref = @{ shift; };
            my $n = &to_pos( $rule_ref[1] );
            splice( @rule_ref, 0, 2 );
            return \@rule_ref,
              length( $_[0] ) > 32 ? $this->{skip} = 1 : substr( $_[0], 0, $n );
        },
        's' => sub {
            my @rule_ref = @{ shift; };
            my ( $x, $y ) = ( $rule_ref[1], $rule_ref[2] );
            splice( @rule_ref, 0, 3 );
            if ( length( $_[0] ) <= 32 ) { $_[0] =~ s/\Q$x/$y/g; }
            return \@rule_ref,
              length( $_[0] ) > 32 ? $this->{skip} = 1 : $_[0];
        },
        '@' => sub {
            my @rule_ref = @{ shift; };
            my $c = $rule_ref[1];
            splice( @rule_ref, 0, 2 );
            $_[0] =~ s/\Q$c//g;
            return \@rule_ref, $_[0];
        },
        'z' => sub {
            my @rule_ref = @{ shift; };
            my $n = &to_pos( $rule_ref[1] );
            splice( @rule_ref, 0, 2 );
            my @plain_ref = &plain_ref( $_[0] );
            my $first_char =
              scalar( @{ $plain_ref[0] } ) == 0 ? '' : shift @{ $plain_ref[0] };
            return \@rule_ref,
              length( $_[0] ) > 32 ? $this->{skip} =
                1
              : length( $_[0] ) + $n >= 32 ? $_[0]
              :   $first_char x ( $n + 1 ) . join( '', @{ $plain_ref[0] } );
        },
        'Z' => sub {
            my @rule_ref = @{ shift; };
            my $n = &to_pos( $rule_ref[1] );
            splice( @rule_ref, 0, 2 );
            my @plain_ref = &plain_ref( $_[0] );
            my $last_char =
              scalar( @{ $plain_ref[0] } ) == 0 ? '' : pop @{ $plain_ref[0] };
            my $return =
              join( '', @{ $plain_ref[0] } ) . $last_char x ( $n + 1 );
            return \@rule_ref,
              length( $_[0] ) > 32 ? $this->{skip} =
              1 : length( $_[0] ) + $n >= 32 ? $_[0] : $return;
        },
        'q' => sub {
            my @rule_ref = @{ shift; };
            splice( @rule_ref, 0, 1 );
            my @plain_ref = &plain_ref( $_[0] );
            return \@rule_ref,
              length( $_[0] ) > 32 ? $this->{skip} =
                1
              : length( $_[0] ) > 15 ? $_[0]
              :   join( '', map { $_ = $_ x 2 } @{ $plain_ref[0] } );
        },
        'M' => sub {
            my @rule_ref = @{ shift; };
            splice( @rule_ref, 0, 1 );
            $this->{mem_rule} = $_[0];
            return \@rule_ref, $_[0];
        },
        '4' => sub {
            my @rule_ref = @{ shift; };
            splice( @rule_ref, 0, 1 );
            return \@rule_ref, $_[0] . $this->{mem_rule};
        },
        '6' => sub {
            my @rule_ref = @{ shift; };
            splice( @rule_ref, 0, 1 );
            return \@rule_ref, $this->{mem_rule} . $_[0];
        },
        'X' => sub {
            my @rule_ref = @{ shift; };
            my ( $n, $m, $i ) =
              &to_pos_double( $rule_ref[1], $rule_ref[2], $rule_ref[3] );
            splice( @rule_ref, 0, 4 );
            if (   $n <= length( $this->{mem_rule} )
                && $i <= length( $this->{mem_rule} )
                && $n + $m <= length( $this->{mem_rule} ) )
            {
                substr( $_[0], $i, 0, substr( $this->{mem_rule}, $n, $m ) );
            }
            else { $this->{skip} = 1; }
            return \@rule_ref, $_[0];
        },

        #Skip
        '<' => sub {
            my @rule_ref = @{ shift; };
            my $n = &to_pos( $rule_ref[1] );
            splice( @rule_ref, 0, 2 );
            return \@rule_ref,
              length( $_[0] ) > $n ? $this->{skip} = 1 : $_[0];
        },
        '>' => sub {
            my @rule_ref = @{ shift; };
            my $n = &to_pos( $rule_ref[1] );
            splice( @rule_ref, 0, 2 );
            return \@rule_ref,
              length( $_[0] ) < $n ? $this->{skip} = 1 : $_[0];
        },
        '!' => sub {
            my @rule_ref = @{ shift; };
            my $x = $rule_ref[1];
            splice( @rule_ref, 0, 2 );
            return \@rule_ref,
              index( $_[0], $x ) != -1 ? $this->{skip} = 1 : $_[0];
        },
        '/' => sub {
            my @rule_ref = @{ shift; };
            my $x = $rule_ref[1];
            splice( @rule_ref, 0, 2 );
            return \@rule_ref,
              index( $_[0], $x ) == -1 ? $this->{skip} = 1 : $_[0];
        },
        '(' => sub {
            my @rule_ref = @{ shift; };
            my $x = $rule_ref[1];
            splice( @rule_ref, 0, 2 );
            return \@rule_ref,
              substr( $_[0], 0, 1 ) ne $x ? $this->{skip} = 1 : $_[0];
        },
        ')' => sub {
            my @rule_ref = @{ shift; };
            my $x = $rule_ref[1];
            splice( @rule_ref, 0, 2 );
            return \@rule_ref,
              substr( $_[0], -1 ) ne $x ? $this->{skip} = 1 : $_[0];
        },
        '=' => sub {
            my @rule_ref = @{ shift; };
            my ( $n, $x ) = ( &to_pos( $rule_ref[1] ), $rule_ref[2] );
            splice( @rule_ref, 0, 3 );
            return \@rule_ref,
              substr( $_[0], $n, 1 ) ne $x ? $this->{skip} = 1 : $_[0];
        },
        '%' => sub {
            my @rule_ref = @{ shift; };
            my ( $n, $x ) = ( &to_pos( $rule_ref[1] ), $rule_ref[2] );
            splice( @rule_ref, 0, 3 );
            my $temp = $_[0];
            my $return = $temp =~ s/$x//g < $n ? $this->{skip} = 1 : $_[0];
            return \@rule_ref, $return;
        },
        'Q' => sub {
            my @rule_ref = @{ shift; };
            splice( @rule_ref, 0, 1 );
            return \@rule_ref,
              $_[0] eq $this->{mem_rule} ? $this->{skip} = 1 : $_[0];
        },

        #Specific
        'k' => sub {
            my @rule_ref = @{ shift; };
            splice( @rule_ref, 0, 1 );
            my @plain_ref = &plain_ref( $_[0] );
            if ( length( $_[0] ) > 32 ) { $this->{skip} = 1; }
            if ( 2 > $plain_ref[1] ) { return \@rule_ref, $_[0]; }
            ( @{ $plain_ref[0] }[0], @{ $plain_ref[0] }[1] ) =
              ( @{ $plain_ref[0] }[1], @{ $plain_ref[0] }[0] );
            return \@rule_ref, join( '', @{ $plain_ref[0] } );
        },
        'K' => sub {
            my @rule_ref = @{ shift; };
            splice( @rule_ref, 0, 1 );
            my @plain_ref = &plain_ref( $_[0] );
            if ( length( $_[0] ) > 32 ) { $this->{skip} = 1; }
            if ( 2 > $plain_ref[1] || length( $_[0] ) == 32 ) {
                return \@rule_ref, $_[0];
            }
            ( @{ $plain_ref[0] }[-1], @{ $plain_ref[0] }[-2] ) =
              ( @{ $plain_ref[0] }[-2], @{ $plain_ref[0] }[-1] );
            return \@rule_ref, join( '', @{ $plain_ref[0] } );
        },
        '*' => sub {
            my @rule_ref = @{ shift; };
            my ( $x, $y ) = &to_pos_double( $rule_ref[1], $rule_ref[2] );
            splice( @rule_ref, 0, 3 );
            my @plain_ref = &plain_ref( $_[0] );
            if (   defined( @{ $plain_ref[0] }[$x] )
                && defined( @{ $plain_ref[0] }[$y] )
                && length( $_[0] ) <= 32 )
            {
                ( @{ $plain_ref[0] }[$x], @{ $plain_ref[0] }[$y] ) =
                  ( @{ $plain_ref[0] }[$y], @{ $plain_ref[0] }[$x] );
            }
            return \@rule_ref,
              length( $_[0] ) > 32
              ? $this->{skip} = 1
              : join( '', @{ $plain_ref[0] } );
        },
        'L' => sub {
            my @rule_ref = @{ shift; };
            my $n = &to_pos( $rule_ref[1] );
            splice( @rule_ref, 0, 2 );
            my @plain_ref = &plain_ref( $_[0] );
            if ( defined( @{ $plain_ref[0] }[$n] ) ) {
                @{ $plain_ref[0] }[$n] =
                  chr( ord( @{ $plain_ref[0] }[$n] ) << 1 );
            }
            return \@rule_ref,
              length( $_[0] ) > 32
              ? $this->{skip} = 1
              : join( '', @{ $plain_ref[0] } );
        },
        'R' => sub {
            my @rule_ref = @{ shift; };
            my $n = &to_pos( $rule_ref[1] );
            splice( @rule_ref, 0, 2 );
            my @plain_ref = &plain_ref( $_[0] );
            if ( defined( @{ $plain_ref[0] }[$n] ) ) {
                @{ $plain_ref[0] }[$n] =
                  chr( ord( @{ $plain_ref[0] }[$n] ) >> 1 );
            }
            return \@rule_ref,
              length( $_[0] ) > 32
              ? $this->{skip} = 1
              : join( '', @{ $plain_ref[0] } );
        },
        '+' => sub {
            my @rule_ref = @{ shift; };
            my $n = &to_pos( $rule_ref[1] );
            splice( @rule_ref, 0, 2 );
            my @plain_ref = &plain_ref( $_[0] );
            if ( defined( @{ $plain_ref[0] }[$n] ) ) {
                @{ $plain_ref[0] }[$n] =
                  chr( ord( @{ $plain_ref[0] }[$n] ) + 1 );
            }
            return \@rule_ref,
              length( $_[0] ) > 32
              ? $this->{skip} = 1
              : join( '', @{ $plain_ref[0] } );
        },
        '-' => sub {
            my @rule_ref = @{ shift; };
            my $n = &to_pos( $rule_ref[1] );
            splice( @rule_ref, 0, 2 );
            my @plain_ref = &plain_ref( $_[0] );
            if ( defined( @{ $plain_ref[0] }[$n] ) ) {
                @{ $plain_ref[0] }[$n] =
                  chr( ord( @{ $plain_ref[0] }[$n] ) - 1 );
            }
            return \@rule_ref,
              length( $_[0] ) > 32
              ? $this->{skip} = 1
              : join( '', @{ $plain_ref[0] } );
        },
        '.' => sub {
            my @rule_ref = @{ shift; };
            my $n = &to_pos( $rule_ref[1] );
            splice( @rule_ref, 0, 2 );
            my @plain_ref = &plain_ref( $_[0] );
            if ( $n + 1 < $plain_ref[1] ) {
                @{ $plain_ref[0] }[$n] = @{ $plain_ref[0] }[ $n + 1 ];
            }
            return \@rule_ref,
              length( $_[0] ) > 32
              ? $this->{skip} = 1
              : join( '', @{ $plain_ref[0] } );
        },
        ',' => sub {
            my @rule_ref = @{ shift; };
            my $n = &to_pos( $rule_ref[1] );
            splice( @rule_ref, 0, 2 );
            my @plain_ref = &plain_ref( $_[0] );
            if (   defined( @{ $plain_ref[0] }[$n] )
                && defined( @{ $plain_ref[0] }[ $n - 1 ] ) )
            {
                @{ $plain_ref[0] }[$n] = @{ $plain_ref[0] }[ $n - 1 ];
            }
            return \@rule_ref,
              length( $_[0] ) > 32
              ? $this->{skip} = 1
              : join( '', @{ $plain_ref[0] } );
        },
        'y' => sub {
            my @rule_ref = @{ shift; };
            my $n = &to_pos( $rule_ref[1] );
            splice( @rule_ref, 0, 2 );
            my @plain_ref = &plain_ref( $_[0] );
            my $return;
            if (
                defined(
                    @{ $plain_ref[0] }[ 0 .. ( $n - 1 ) ] && defined(
                        @{ $plain_ref[0] }[ $n .. ( $plain_ref[1] - 1 ) ]
                    )
                )
              )
            {
                my $dup = join( '', @{ $plain_ref[0] }[ 0 .. ( $n - 1 ) ] ) x 2;
                $return =
                  $dup
                  . join( '',
                    @{ $plain_ref[0] }[ $n .. ( $plain_ref[1] - 1 ) ] );
            }
            else { $return = $_[0]; }
            return \@rule_ref,
              length( $_[0] ) > 32 ? $this->{skip} =
              1 : length( $_[0] ) + $n >= 32 ? $_[0] : $return;
        },
        'Y' => sub {
            my @rule_ref = @{ shift; };
            my $n = &to_pos( $rule_ref[1] );
            splice( @rule_ref, 0, 2 );
            my @plain_ref = &plain_ref( $_[0] );
            if ( $n > $plain_ref[1] ) { return \@rule_ref, $_[0]; }
            my $dup = join( '', @{ $plain_ref[0] }[ -1 * $n .. -1 ] ) x 2;
            my $return =
              join( '', @{ $plain_ref[0] }[ 0 .. ( $plain_ref[1] - $n - 1 ) ] )
              . $dup;
            return \@rule_ref,
              length( $_[0] ) > 32 ? $this->{skip} =
              1 : length( $_[0] ) + $n >= 32 ? $_[0] : $return;
        },
        'E' => sub {
            my @rule_ref = @{ shift; };
            splice( @rule_ref, 0, 1 );
            return \@rule_ref,
              length( $_[0] ) > 32
              ? $this->{skip} = 1
              : join( ' ', map { $_ = _ucfirst($_) } split( ' ', $_[0] ) );
        },

        # Exeptions
        # used for space separated rules:
        ' ' => sub {
            my @rule_ref = @{ shift; };
            splice( @rule_ref, 0, 1 );
            return \@rule_ref, $_[0];
        },
    };

    return $this;
}

sub gen {
    my $self   = shift;
    my @rules  = @{ shift; };
    my @plains = @{ shift; };
    foreach my $plain (@plains) {
        foreach my $rule (@rules) {
            print "#Rule: $rule\n" if $self->{verbose};
            next
              if ( substr( $rule, 0, 1 ) eq '#' || $rule eq '' )
              ;    # skip if comment
            my $nplain = $plain;
            my $rule_ref = [ split '', $rule ];
            $self->{mem_rule} = '';
            while (1) {
                last if !@{$rule_ref}[0];
                print "Executing @{$rule_ref}[0]: \n" if $self->{verbose};
                ( $rule_ref, $nplain ) =
                  $self->{rules}->{ @{$rule_ref}[0] }->( $rule_ref, $nplain );
                print $nplain, "\n" if $self->{verbose};
            }
            if ( defined( $self->{skip} ) ) { $self->{skip} = undef; next; }
            print $nplain, "\n";
        }
    }
}

sub gen_single_rule {
    my $self = shift;
    my $rule = shift;
    print "#Main rule: q{$rule}\n" if $self->{verbose};
    my @plains = @{ shift; };
    my @return = ();
    return if ( substr( $rule, 0, 1 ) eq '#' || $rule eq '' ); # skip if comment
    foreach my $plain (@plains) {
        print "#Rule: $rule\n" if $self->{verbose};
        my $nplain = $plain;
        my $rule_ref = [ split '', $rule ];
        $self->{mem_rule} = '';
        while (1) {
            last unless defined @{$rule_ref}[0];
            print "Executing @{$rule_ref}[0]: \n" if $self->{verbose};
            ( $rule_ref, $nplain ) =
              $self->{rules}->{ @{$rule_ref}[0] }->( $rule_ref, $nplain );
            print $nplain, "\n" if $self->{verbose};
        }
        if ( defined( $self->{skip} ) ) { $self->{skip} = undef; next; }
        push @return, $nplain;
    }
    return @return;
}

sub gen_from_file_single_rule {
    my $self  = shift;
    my $rule  = shift;
    my $wlist = shift;
    my $plain;
    print "#Rule: $rule\n" if $self->{verbose};
    return if ( substr( $rule, 0, 1 ) eq '#' || $rule eq '' ); # skip if comment
    open my $in_list, '<', $wlist or die $!;
    while ( $plain = <$in_list> ) {
        chomp $plain;
        my $rule_ref = [ split '', $rule ];
        $self->{mem_rule} = '';
        while (1) {
            last if !@{$rule_ref}[0];
            print "Executing @{$rule_ref}[0]: \n" if $self->{verbose};
            ( $rule_ref, $plain ) =
              $self->{rules}->{ @{$rule_ref}[0] }->( $rule_ref, $plain );
            print $plain, "\n" if $self->{verbose};
        }
        if ( defined( $self->{skip} ) ) { $self->{skip} = undef; next; }
        print $plain, "\n";
    }
    close $in_list;
}

sub gen_from_file_rule_file {
    my $self      = shift;
    my $rule_file = shift;
    my $wlist     = shift;
    my $plain;
    my $rule;
    open my $in_list, '<', $wlist or die $!;
    while ( $plain = <$in_list> ) {
        chomp $plain;
        open my $in_rule_list, '<', $rule_file or die $!;
        while ( $rule = <$in_rule_list> ) {
            print "#Rule: $rule\n" if $self->{verbose};
            next
              if ( substr( $rule, 0, 1 ) eq '#' || $rule eq '' )
              ;    # skip if comment
            my $nplain = $plain;
            chomp $rule;
            my $rule_ref = [ split '', $rule ];
            $self->{mem_rule} = '';
            while (1) {
                last if !@{$rule_ref}[0];
                print "Executing @{$rule_ref}[0]: \n" if $self->{verbose};
                ( $rule_ref, $nplain ) =
                  $self->{rules}->{ @{$rule_ref}[0] }->( $rule_ref, $nplain );
                print $nplain, "\n" if $self->{verbose};
            }
            if ( defined( $self->{skip} ) ) { $self->{skip} = undef; next; }
            print $nplain, "\n";
        }
        close $in_rule_list;
    }
    close $in_list;
}

sub _lcfirst {
    my $str = $_[0];
    my @str = split '', $str;
    my $len = scalar(@str);
    return '' if ( $len == 0 );
    $str[0] = lc( $str[0] );
    for ( my $i = 1 ; $i < $len ; $i++ ) {
        $str[$i] = uc( $str[$i] );
    }
    return join( '', @str );
}

sub _ucfirst {
    my $str = $_[0];
    my @str = split '', $str;

    # my $first_char = shift @str;
    return '' if ( scalar(@str) == 0 );
    return uc( shift @str ) . lc( join( '', @str ) );
}

sub _toogle_case {
    my $str = $_[0];
    my @str = split '', $str;
    my $len = scalar(@str);
    return '' if ( $len == 0 );
    for ( my $i = 0 ; $i < $len ; $i++ ) {
        $str[$i] =
          ( $str[$i] eq lc( $str[$i] ) ) ? uc( $str[$i] ) : lc( $str[$i] );
    }
    return join( '', @str );
}

sub _toogle_case_pos {
    my $str = $_[0];
    my $pos = $_[1];
    my @str = split '', $str;
    return '' if ( scalar(@str) == 0 );
    if ( $pos + 1 > scalar(@str) ) {
        return $str;
    }
    $str[$pos] =
      ( $str[$pos] eq lc( $str[$pos] ) ) ? uc( $str[$pos] ) : lc( $str[$pos] );
    return join( '', @str );
}

sub plain_ref {
    my @str = split '', $_[0];
    return \@str, scalar(@str);
}

sub to_pos_double {
    my @res;
    foreach my $pos (@_) {
        if ( $pos =~ /\d/ ) { push @res, $pos; next; }
        push @res, 10 + ord($pos) - 65;
    }
    return @res;
}

sub to_pos {
    my $pos = $_[0];
    if ( $pos =~ /\d/ ) { return $pos; }
    return 10 + ord($pos) - 65;
}

1;
