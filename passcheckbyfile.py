import requests
import hashlib
import sys

def request_data(query):
    """
    Given the first 5 characters of a sha1 hash (query), request_data returns the request response after
    trying to access the Pwnedpasswords API.

    Keyword arguments:
    query: a 5 charachter string corresponding to the first 5 characters of our sha1 encrypted password.

    Return:
    res: a Response object. Its status_code indicates whether the request was successful (code: 200) or not.
    """

    url = 'https://api.pwnedpasswords.com/range/' + query
    res = requests.get(url)

    if res.status_code != 200:
        raise RuntimeError('Something went wrong. Please check your password again and read the API documentation.')

    return res

def check_num_leaks(hashes, our_hash):
    """
    Checks the number of times a (hashed) password has been leaked and returns its count.

    Keyword arguments:
    hashes: a string text containing a number of hashed passwords tails, each followed by 
        a colon and an integer (the number of times this password has been leaked). The format
        is similar to this: A5B800C301FEE5A:56
    our_hash: the tail of our password (all the characters except the first 5)

    Returns: an integer with the number of times our password has been leaked.
    """
    for line in hashes.splitlines():
        hashcount = line.split(':')     # tail on hashcount[0]; count on hashcount[1]

        if hashcount[0] == our_hash:
            hashcount[1] = int(hashcount[1])
            
            return hashcount[1]
    return 0

def pwned_api_check(password):
    """
    Hashes the password into SHA1, splits it into a head and a tail and calls the other two functions. It requests information
    from the API using the head, and checks the number of leaks using the tail.

    Keyword argument:
    password: a string with the password to check.

    Returns: an integer with the number of times our password has been leaked.
    """
    sha1pass =  hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
    first_char, tail = sha1pass[:5], sha1pass[5:]
    response = request_data(first_char)
   
    return check_num_leaks(response.text, tail)

def main(text_file):

    with open(f'.\\{text_file}', 'r') as file:
        for password in file.readlines():
            password = password.rstrip()
            count = pwned_api_check(password)
            if count:
                print(f'\'{password}\' has been leaked {count} times. Try another one.')
            else:
                print(f'\'{password}\' has never been leaked before. Well chosen!')
        return '\n---Leak checking finished.---\n'

if __name__ == '__main__':
    
    try:
        sys.exit(main(sys.argv[1]))
    except IndexError as ie:
        print('You need to specify a text file as an argument. Example: python passcheckbyfile.py textfile.txt')
