#include <iostream>
using namespace std;

string encryptDecrypt(string toEncrypt) {
    char key = 'K'; //Any char will work
    string output = toEncrypt;
    for (int i = 0; i < toEncrypt.size(); i++)
    
    output[i] = toEncrypt[i] ^ key;
    return output;
}


/* int main(int argc, const char * argv[])
{
    string encrypted = encryptDecrypt("kylewbanks.com");
    // cout << "Encrypted:" << encrypted << "\n";
    string decrypted = encryptDecrypt(encrypted);
    cout << "Decrypted:" << decrypted << "\n";
    return 0;
}*/

int main() {
    string plaintext;

    cout << "Enter plaintext: ";
    getline(cin, plaintext);

    string encrypted = encryptDecrypt(plaintext);
    cout << "Encrypted: " << encrypted << endl;

    string decrypted = encryptDecrypt(encrypted);
    cout << "Decrypted: " << decrypted << endl;

    return 0;
}