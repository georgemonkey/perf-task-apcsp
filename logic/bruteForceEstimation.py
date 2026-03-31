def combinations(pwd):
    length = len(pwd)
    poolSize= 0
    has_lowercase = any(char.islower() for char in pwd)
    if has_lowercase:
        poolSize += 26

    has_uppercase = any(char.isupper() for char in pwd)

    if has_uppercase:
        poolSize += 26

    has_numbers = any(char.isdigit() for char in pwd)

    if has_numbers:
        poolSize += 9

    has_symbols = any(not char.isalnum() for char in pwd)

    if has_symbols:
        poolSize += 32

    combinations = poolSize**length
    return combinations

print(combinations("ilovesigmas.com"))