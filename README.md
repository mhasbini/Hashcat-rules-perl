Perl binding for Hashcat rule engine. Only support GPU compatible rules (
  CPU rules are supported but length limitation is not applied so output may difer from Hashcat rule engine).

## Available parameters
* verbose => 1 true, 0 false
  * print rule name and current plain foreach executed rule function

## Available methods
* `$rulesEngine->gen(\@rules, \@plains);`
* `$rulesEngine->gen_single_rule($rule, \@plains);`
* `$rulesEngine->gen_from_file_single_rule($rule, 'plains.txt');`
* `$rulesEngine->gen_from_file_rule_file('rules.rule', 'plains.txt');`

*N.b. Output will be printed to STDOUT*

## Example
```
use Hashcat::Rules;
my $rulesEngine = Hashcat::Rules->new(verbose => 0);
$rulesEngine->gen(['$a', 'dx12o32p2'], ['abc', '123456']);
__DATA__
Output:
abca
bcbcbc
123456a
232323
```
