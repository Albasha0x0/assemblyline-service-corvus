rule names_the_fixture { strings: $a = "fixture note" condition: $a }
rule names_the_endpoint { strings: $u = "example.com/api/items" wide condition: $u }
rule absent_text { strings: $n = "not in the fixture" condition: $n }
