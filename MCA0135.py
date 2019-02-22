import random, string, sys
import math


#A custom character map table of 65 characters and which are mapped in 65 int range
char_std_65 = {'0': 0, '1': 1, '2': 2, '3': 3, '4': 4, '5': 5, '6': 6, '7': 7, '8': 8, '9': 9,
                'A': 10, 'B': 11, 'C': 12, 'D': 13, 'E': 14, 'F': 15, 'G': 16, 'H': 17, 'I': 18,
                'J': 19, 'K': 20, 'L': 21, 'M': 22, 'N': 23, 'O': 24, 'P': 25, 'Q': 26, 'R': 27,
                'S': 28, 'T': 29, 'U': 30, 'V': 31, 'W': 32, 'X': 33, 'Y': 34, 'Z': 35, 'a': 36, 'b': 37,
                'c': 38, 'd': 39, 'e': 40, 'f': 41, 'g': 42, 'h': 43, 'i': 44, 'j': 45, 'k': 46, 'l': 47,
                'm': 48, 'n': 49, 'o': 50, 'p': 51, 'q': 52, 'r': 53,'s': 54, 't': 55, 'u': 56, 'v': 57,
                'w': 58, 'x': 59, 'y': 60, 'z': 61, ' ': 62, ',': 63, '.': 64}

def _getKey(keyName):
    '''
        Function for retrieving character from the char-map table using it's numeric value
    '''
    return list(char_std_65.keys())[list(char_std_65.values()).index(keyName)]

class Encryption:
    '''
        MCA0135 Product cipher
    '''
    plain_text = ''
    key = ''
    transposition_key = ''
    
    def __init__(self, plain_text, key, transposition_key):
        self.plain_text = plain_text
        self.key = key
        self.transposition_key = transposition_key
    
    def addRoundKey(self, plain_text):
        '''
           The addRoundKey function will xor plain text with key in character level,
           Then the xore value is wrapped between 0 and 65 to match with our finite 65 character map table'''
        xored = []
        for i in range(0, len(plain_text)):
            char_in_pt = char_std_65[plain_text[i]]
            char_in_key = char_std_65[self.key[i]]
            xored_value = _getKey((char_in_pt ^ char_in_key) % 65)
            
            xored.append(xored_value)
        return ''.join(xored)
    
    def oneTimePad(self, message):
        '''
            The One-Time Pad encrypt function will encrypt a message using the randomly generated private key that is then decrypted by the receiver using a matching one-time pad and key
        '''
        cipher = ''
        for c in range(0, len(self.key)):
            #Sum of key and message value is wrapped between 0 and 65 to use our finite char field
            subst_value = (char_std_65[message[c]] + char_std_65[self.key[c]]) % 65
            cipher = cipher + _getKey(subst_value)
        return cipher
    
    def rowTransposition(self, message):
        # Each string in ciphertext represents a column in the grid.
        cipher_text = [''] * self.transposition_key
        # Loop through each column in ciphertext.
        for col in range(self.transposition_key):
            pointer = col
            # Keep looping until pointer goes past the length of the message
            while pointer < len(message):
                # Place the character at pointer in message at the end of the
                # current column in the ciphertext list.
                cipher_text[col] += message[pointer]
                # move pointer over
                pointer += self.transposition_key
        return ''.join(cipher_text)
    
    def railFenceCipher(self, message):
        '''
            The railFenceCipher function will write message letters out diagonally
            over a number of rows. Then read off cipher by row.
        '''
        upper_row = ''
        lower_row = ''
        for m in range(1, len(message)+1):
            #Here we are reading from the grid with two rows but usually 
            #as many rows as the key is, and as many columns as the length of the ciphertext. 
            if (m % 2 != 0):
                upper_row = upper_row + message[m-1]
            else:
                lower_row = lower_row + message[m-1]
        return upper_row + lower_row
    
    def endToEndEncryptionProcess(self):
        '''
           The endToEndEncryptionProcess function will execute the whole end to end execution of
           the algorithm round by round and provide the cipher text.
        '''
        cipher_text = self.addRoundKey(self.plain_text)
        encry_logs = []
        encry_logs.append('Cipher text after addRoundkey: "{}"'.format(cipher_text))
        '''
           first round - substitution
        '''
        cipher_text = self.oneTimePad(cipher_text)
        encry_logs.append('cipher text after first round(one-time pad): "{}"'.format(cipher_text))
        '''
           second round - transposition
        '''
        cipher_text = self.rowTransposition(cipher_text)
        encry_logs.append('Cipher text after rowTransposition in the second round: "{}"'.format(cipher_text))
        cipher_text = self.railFenceCipher(cipher_text)
        encry_logs.append('Final cipher text after railFenceCipher in the second round: "{}"'.format(cipher_text))
        _log('ENCRYPTION', encry_logs)
        return cipher_text

class Decryption:
    cipher_text = ''
    key = ''
    transposition_key = ''
    
    def __init__(self, cipher_text, key, transposition_key):
        self.cipher_text = cipher_text
        self.key = key
        self.transposition_key = transposition_key
    
    def reverseRailFenceCipher(self, message):
        '''
            The reverseRailFenceCipher function will decrypt the message.
        '''
        #The middle index for splitting the cipher
        split_index = int(len(message)/2 + 1) if len(message) % 2 != 0 else int(len(message)/2)
        reverse_text = ''
        for i in range(0, split_index):
            #Reads the character from the first half and the second half in a 
            reverse_text = reverse_text + message[i]
            if (split_index + i) <= len(message)-1:
                reverse_text = reverse_text + message[split_index + i]
        return reverse_text
    
    def reverseRowTransposition(self, message):
        ''' 
         The transposition decrypt function will simulate the "columns" and
         "rows" of the grid that the plaintext is written on by using a list
         of strings.
        '''
        #The number of "columns" in our transposition grid:
        numOfColumns = math.ceil(len(message) / self.transposition_key)
        # The number of "rows" in our grid will need:
        numOfRows = self.transposition_key
        # The number of "shaded boxes" in the last "column" of the grid:
        numOfShadedBoxes = (numOfColumns * numOfRows) - len(message)
        # Each string in plaintext represents a column in the grid.
        plaintext = [''] * numOfColumns
        # The col and row variables point to where in the grid the next character in the encrypted message will go.
        col = 0
        row = 0
        
        for symbol in message:
            plaintext[col] += symbol
            col += 1 # point to next column
            # If there are no more columns OR we're at a shaded box, go back to the first column and the next row.
            if (col == numOfColumns) or (col == numOfColumns - 1 and row >= numOfRows - numOfShadedBoxes):
                col = 0
                row += 1
        return ''.join(plaintext)
    
    def reverseOneTimePad(self, message):
        plain_text = ''
        for c in range(0, len(self.key)):
            rev_value = (char_std_65[message[c]] + 65) - char_std_65[self.key[c]]
            if rev_value > 65:
                rev_value = (char_std_65[message[c]] - char_std_65[self.key[c]])
            plain_text = plain_text + _getKey(rev_value)
        return plain_text
    
    def reverseAddRoundKey(self, message):
        xored = []
        for i in range(0, len(message)):
            char_in_ct = char_std_65[message[i]]
            char_in_key = char_std_65[self.key[i]]
            if char_in_key == 65 or char_in_key == char_in_ct:
                xored_value = _getKey((char_in_ct + 65 ^ char_in_key))
            else:
                xored_value = _getKey((char_in_ct ^ char_in_key))
            xored.append(xored_value)
        return ''.join(xored)
    
    def endToEndDecryptionProcess(self):
        rev_text = self.reverseRailFenceCipher(self.cipher_text)
        decry_logs = []
        decry_logs.append('Cipher text after reverseRailFenceCipher operation: "{}"'.format(rev_text))
        rev_text = self.reverseRowTransposition(rev_text)
        decry_logs.append('Cipher text after reverseRowTransposition operation: "{}"'.format(rev_text))
        rev_text = self.reverseOneTimePad(rev_text)
        decry_logs.append('Cipher text after reverseOneTimePad operation: "{}"'.format(rev_text))
        rev_text = self.reverseAddRoundKey(rev_text)
        decry_logs.append('Plain text after reverseAddRoundKey operation: "{}"'.format(rev_text))
        _log('DECRYPTION' ,decry_logs)

def _log(title, content):
    '''
       Function for logging all the traces in a wrapped box.
    '''
    msg_size = max(len(word) for word in content) #msg_size/2
    msg_half_size = int((msg_size/2)+1) if msg_size % 2 !=0 else int(msg_size/2)
    title_size = len(title)
    title_half_size = int(title_size/2)+1 if title_size % 2 !=0 else int(title_size/2)
    title_pos = (msg_half_size-title_half_size)
    print('+'+'-' * (msg_size + 2)+'+')
    print('|{}{}{}|'.format(' '*(msg_half_size-title_half_size),title, ' '*(msg_size-(title_pos+title_size)+2)))
    for word in content:
        print('| {:<{}} |'.format(word, msg_size))
    print('+'+'-' * (msg_size + 2)+'+')

if __name__ == '__main__':
    plain_text = input('Please enter a message for encryption:')
    key = ''.join(random.choice(string.ascii_uppercase + string.ascii_lowercase + string.digits) for _ in range(len(plain_text)))
    row_transposition_key = random.randrange(2 , (int(len(key)/2)+1))
    encryption = Encryption(plain_text, key, row_transposition_key)
    print('Plain message for encryption: "{}" & Key: "{}"'.format(plain_text, key)) #& rowTransposition key: {}
    cipher_text = encryption.endToEndEncryptionProcess()
    decryption = Decryption(cipher_text, key, row_transposition_key)
    decryption.endToEndDecryptionProcess()