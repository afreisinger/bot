import re

command_pattern = r"(?P<command>\w+)"
value_pattern = r"(( )(?P<value>.+))?$"
pattern = rf"^! {command_pattern}{value_pattern}"


regex = re.compile(pattern)


examples = [
    "!fping",
    "! fping",
    "! fping r100",
    "! fping r100-a",
    "! fping -test"
]

for example in examples:
    match = regex.match(example)
    if match:
        print(f"Input: {example}")
        print(f"  Command: {match.group('command')}")
        print(f"  Value: {match.group('value')}")
    else:
        print(f"Input: {example} - No match")
