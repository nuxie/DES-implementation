"""
DES IMPLEMENTATION
------------------
Steps - encryption:
1. Convert string to bytes list with padding.
2. Set sub keys - permute the main key with PC1_TABLE and then generate 16 subkeys:
    a) shift the permuted key x times to the left (x = 1 or 2, given in the SHIFTS list for each round)
    b) permute that key with PC2_TABLE - this is the sub key for a given round (len = 48 bits)
    c) shifted key is now the new permuted key
    d) repeat 16 times to obtain 16 subkeys
3. Divide a given message to 8 byte blocks and encrypt each one of them separately:
    a) permute the block with initial permutation,
    b) divide the block into two equal 32-bits parts,
    c) make 16 Feistel cycles:
        I. permute right part with expansion table to get 48-bits (to fit the sub key; 8 * 6 bits)
        II. xor the permuted right part with sub key
        III. for every 6 bits first and last one represent the row, the middle ones represent the column
                of one of the 8 S-Boxes - find the number in the given S-Box and add it to the other ones
        IV. after 8 repetitions permute the result with P_TABLE
        V. xor the permuted result with left part - now this will be the new right part, the new left will
                be the former left part
    d) at the end connect left and right part and permute it with final permutation
4. To decrypt a message you only need to reverse the sub keys list.
"""

import random
import constants


def str_to_byte(string):
    """ Turn a string to its byte representation.
    Each character is represented by a byte - ASCII num.
    As DES requires the input to be an exact multiple of the block size, the padding is applied.
    The last block is padded with null characters (0x00).
    
    :param s: string to be converted
    :type: str

    :return: byte representation of the string
    :rtype: list
    """
    byte_list = [ord(s) for s in string]
    padding = (8 - (len(byte_list) % 8)) * [0]
    return byte_list + padding


def byte_to_str(byte_list):
    """ Convert byte list to string. 
    Each byte - ASCII num is decoded to a char.
    Null padding is removed.

    :param byte_list: bytes to be converted
    :type: list

    :return: string decoded from the byte representation
    :rtype: str
    """
    return "".join(chr(e) for e in byte_list if e != 0)


def byte_to_bit(byte_list):
    """ Convert byte list to bit list. 
    Each byte is converted to 8 bits regardless of its value (padded with 0's where necessary).

    :param byte_list: bytes to be converted
    :type: list

    :return: bits representation of the bytes
    :rtype: list
    """
    bit_list = []
    for i in range(len(byte_list)):
        bit_list += map(int, f'{byte_list[i]:08b}')
    return bit_list


def bit_to_byte(bit_list):
    """ Convert bit list to byte list.
    
    :param bit_list: bits to be converted
    :type: list

    :return: bytes representation of the bits
    :rtype: list
    """
    byte_list = []
    for i in range(len(bit_list) // 8):
        byte_list.append(int("".join(map(str, (bit_list[i*8:(i+1)*8]))), 2))
    return byte_list


def permute_bits(bit_list, perm_table):
    """ Permute bit list according to a given permutation table.

    :param perm_table: permutation table
    :type: list
    :param bit_list: bits to be permuted
    :type: list

    :return: permuted bits
    :rtype: list
    """
    output_list = []
    for a in perm_table:
        output_list.append(bit_list[a-1])
    return output_list


def permute_bytes(byte_list, perm_table):
    """ Permute byte list according to a given permutation table.

    :param perm_table: permutation table
    :type: list
    :param byte_list: bytes to be permuted
    :type: list

    :return: permuted bytes
    :rtype: list
    """
    return bit_to_byte(permute_bits(byte_to_bit(byte_list), perm_table))


def left_shift(key, val):
    """ Independently shift two halves of a 56-bit key to the left by a given number.

    :param key: 56-bit key
    :type: list
    :param val: how many positions to shift - 1 or 2
    :type: int

    :return: key with shifted values 
    :rtype: list
    """
    left_half = key[:28]
    right_half = key[28:]
    for x in range(val):
        left_half.append(left_half.pop(0))
        right_half.append(right_half.pop(0))
    return left_half + right_half


def set_subkeys(key):
    """ Obtain subkeys by doing initial key permutation followed by 16 independent shifts and permutations.
    
    :param key: key
    :type: list

    :return: 16 subkeys
    :rtype: list
    """
    subkey_list = 16 * [[0] * 8]
    bit_key = byte_to_bit(key)
    # 64-bit key is reduced to 56-bit
    permuted_key = permute_bits(bit_key, constants.PC1_TABLE)
    for i in range(16):
        tmp_key = left_shift(permuted_key, constants.SHIFTS[i])
        # 56-bit key is reduced to 48-bit
        subkey_list[i] = bit_to_byte(
            permute_bits(tmp_key, constants.PC2_TABLE))
        permuted_key = tmp_key
    return subkey_list


def sbox_lookup(box_number, block):
    """ Look for a number in a given S-Box.
    For a given 6-bit block, first and last bit represent row, the rest represents the column number.
    
    :param box_number: number of the s-box to be used
    :type: int
    :param block: 6-bit block
    :type: list

    :return: number from a given column and row from s-box
    :rtype: int
    """

    row = int(str(block[0]) + str(block[5]), 2)  # first+last bit = row number
    col_str = ""
    for j in range(1, 5):
        col_str += str(block[j])
    col = int(col_str, 2)
    return constants.S_BOX[box_number][row][col]


def transform_block(block, subkey_list, option):
    """ Encrypt or decrypt a message block (8 bytes), according to a given option (ENCRYPT or DECRYPT). 
    
    :param block: message block (8 bytes)
    :type: list
    :param key: 64-bit key
    :type: list
    :param option: encryption/decryption indicator
    :type: str

    :return: decrypted/encrypted block
    :rtype: list
    """
    permuted_block = permute_bytes(block, constants.INIT_PERM)
    left_part = permuted_block[:4]
    right_part = permuted_block[4:]
    for i in range(16):  # Feistel cycles
        # 32-bit expanded to 48-bit
        expright_part = permute_bytes(right_part, constants.EXP_TABLE)
        if option == "DECRYPT":
            xor = byte_to_bit([i ^ j for i, j in zip(
                subkey_list[15-i], expright_part)])
        if option == "ENCRYPT":
            xor = byte_to_bit(
                [i ^ j for i, j in zip(subkey_list[i], expright_part)])
        result = []
        for j in range(8):
            result.append(sbox_lookup(j, xor[j*6: (j+1)*6]))
        tmp = permute_bytes(result, constants.P_BOX)
        new_right = [i ^ j for i, j in zip(tmp, left_part)]
        left_part = right_part
        right_part = new_right
    return permute_bytes(right_part + left_part, constants.FINAL_PERM)
