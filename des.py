import random
import constants
import helper

def manipulate(key, byte_input, option):
    """ Check the key correctness , generate subkeys and perform a desired block transformation.

    :param key: key - default to 0 meaning that a random one will be generated
    :type: list
    :param byte_input: message to be manipulated in the byte form
    :type: list
    :param byte_input: "ENCRYPT" or "DECRYPT"
    :type: str  
    
    :return: result of transformation in byte form
    :rtype: list
    """
    byte_output = []
    assert (len(key) == 8), "Klucz jest zlej dlugosci!"
    assert (all(i <= 255 for i in key)), "Klucz ma za duza wartosc!"
    assert (all(i >= 0 for i in key)), "Klucz ma za mala wartosc!"
    subkeys = helper.set_subkeys(key)
    for i in range(0, len(byte_input), 8):
        byte_output += helper.transform_block(
            byte_input[i:i+8], subkeys, option)
    return byte_output

def encrypt(key, plain_text):
    """ Encrypt text with a given key.

    :param key: key - default to 0 meaning that a random one will be generated
    :type: list
    :param plain_text: message to be encrypted
    :type: str
    
    :return: encrypted message
    :rtype: str
    """
    return manipulate(key, helper.str_to_byte(plain_text), "ENCRYPT")


def decrypt(key, byte_input):
    """ Decrypt text with a given key.

    :param key: key
    :type: list
    :param byte_input: message to be decrypted (byte form)
    :type: list

    :return: decrypted message
    :rtype: str
    """
    return helper.byte_to_str(manipulate(key, byte_input, "DECRYPT"))
