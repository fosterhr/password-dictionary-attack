from urllib.request import urlopen
from hashlib import md5, sha1, sha224, sha256, sha384, sha512
from datetime import datetime
from sys import argv

class Cracker:
    algorithms = {
        "md5": md5,
        "sha1": sha1,
        "sha224": sha224,
        "sha256": sha256,
        "sha384": sha384,
        "sha512": sha512
    }
    url = "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Passwords/Common-Credentials/10-million-password-list-top-1000000.txt"

    def __init__(self, hash, algorithm, url):
        self.hash = hash
        self.url = url

        self.algorithm = algorithm

        self.data = urlopen(self.url).read()
        self.passwords = self.data.splitlines()

        self.result = None

        self.attempts = 0
        self.elapsed = 0

    def run(self):
        print(f"Attempting dictionary attack on {self.hash}...")
        
        start = datetime.now()

        for p in self.passwords:
            temp = self.algorithm(p).hexdigest()
            if self.hash == temp:
                self.result = p.decode()
                break
            self.attempts += 1

        end = datetime.now()
        self.elapsed = round((end - start).total_seconds(), 2)

        print("")
        if self.result:
            print("------------ DONE ------------")
            print(f"Password: {self.result}")
        else:
            print("------------ FAIL ------------")
        print(f"Time Elapsed: {self.elapsed}s")
        print(f"Attempts: {self.attempts}")
        print("------------------------------")

def main():
    if len(argv) > 0:
        hash_index = None
        if "-h" in argv: hash_index = argv.index("-h")
        elif "-hash" in argv: hash_index = argv.index("-hash")

        algorithm_index = None
        if "-a" in argv: algorithm_index = argv.index("-a")
        elif "-algorithm" in argv: algorithm_index = argv.index("-algorithm")

        url_index = None
        url = None
        if "-u" in argv: url_index = argv.index("-u")
        elif "-url" in argv: url_index = argv.index("-url")

        try:
            hash = argv[hash_index + 1]
        except:
            print("Missing required argument: -h or -hash")
            return
        try:
            algorithm = argv[algorithm_index + 1]
        except:
            print("Missing required argument: -a or -algorithm")
            return
        try:
            url = argv[url_index + 1]
        except:
            pass
        finally:
            if not url:
                url = Cracker.url
            print(f"Loaded url: {url}")

        if algorithm in Cracker.algorithms:
            algorithm = Cracker.algorithms[algorithm]
        else:
            print("The specified algorithm is not supported.")
            return

        c = Cracker(hash, algorithm, url)
        c.run()

if __name__ == "__main__": main()
