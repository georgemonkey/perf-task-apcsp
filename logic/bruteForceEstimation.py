# input the password and returns the number of combinations
def combinations(pwd):
    # pulls the length of a password using len()
    length = len(pwd)
    # sets the pool size of the password based on the what types of characters are in the password
    poolSize= 0
    # checks if there are lowercase letters in the password and adds 26 to pool size 
    has_lowercase = any(char.islower() for char in pwd)
    if has_lowercase:
        poolSize += 26
        
    # checks if there are uppercase letters in the password and adds 26 to pool size 
    has_uppercase = any(char.isupper() for char in pwd)
    if has_uppercase:
        poolSize += 26

     # checks if there are numbers in the password and adds 9 to the pool size
    has_numbers = any(char.isdigit() for char in pwd)
    if has_numbers:
        poolSize += 9

    # checks if there are symbols in the password and adds 32 to the pool size
    has_symbols = any(not char.isalnum() for char in pwd)
    if has_symbols:
        poolSize += 32

    # sets the pool size to the power of the length
    combinations = poolSize**length
    # returns the number of combinations possible
    return combinations

# testing
print(combinations("ilovesigmas"))
