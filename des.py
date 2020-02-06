import random
import constants
import helper

def encryption(key, plain_text):
    """ Encrypt text with a given key.

    :param key: key 
    :type: list
    :param plain_text: message to be encrypted
    :type: str
    
    :return: encrypted message, key
    :rtype: str, list
    """
    byte_output = []
    byte_input = helper.str_to_byte(plain_text)
    assert (len(key) == 8), "Klucz jest zlej dlugosci!"
    assert (all(i <= 255 for i in key)), "Klucz ma za duza wartosc!"
    assert (all(i >= 0 for i in key)), "Klucz ma za mala wartosc!"
    subkeys = helper.set_subkeys(key)
    for i in range(0, len(byte_input), 8):
        byte_output += helper.transform_block(byte_input[i:i+8], subkeys, "ENCRYPT")
    return byte_output


def decryption(key, cipher_text):
    """ Decrypt text with a given key.

    :param key: key
    :type: list
    :param cipher_text: message to be decrypted (byte form)
    :type: str

    :return: decrypted message
    :rtype: str
    """
    byte_output = []
    assert (len(key) == 8), "Klucz jest zlej dlugosci!"
    assert (all(i <= 255 for i in key)), "Klucz ma za duza wartosc!"
    assert (all(i >= 0 for i in key)), "Klucz ma za mala wartosc!"
    subkeys = helper.set_subkeys(key)
    for i in range(0,len(cipher_text), 8):
        byte_output += helper.transform_block(
            cipher_text[i:i+8], subkeys, "DECRYPT")
    return helper.byte_to_str(byte_output)
