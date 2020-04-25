from des import encrypt, decrypt
import unit_tests


def main_menu():
    print("Prosze wybrac opcje:")
    print("1 - Zaszyfrowanie tekstu")
    print("2 - Odszyfrowanie tekstu")
    print("3 - Testy jednostkowe i wyjscie")
    print("0 - Wyjscie")
    choice = input(" >>  ")
    exec_menu(choice)


def exec_menu(choice):

    if choice == "1":
        key = []
        print("Prosze wprowadzic nazwe pliku z kluczem - kazdy bajt klucza podaj w osobnej linii...")
        key_file_name = input(" >> ")
        print("Prosze wprowadzic nazwe pliku z tekstem...")
        msg_file_name = input(" >> ")
        with open(key_file_name, 'r') as key_file:
            key = [int(line.strip()) for line in key_file]
        with open(msg_file_name, 'r') as msg_file:
            msg = msg_file.read().replace('\n', ' ')
        print("Zaszyfrowany tekst w postaci bajtow zapisano w pliku encrypted.txt.")
        encrypted = encrypt(key, msg)
        with open('encrypted.txt', 'w') as output_file:
            for byte in encrypted:
                output_file.write("%s\n" % byte)
        main_menu()

    if choice == "2":
        key = []
        print("Prosze wprowadzic nazwe pliku z kluczem - kazdy bajt klucza podaj w osobnej linii...")
        key_file_name = input(" >> ")
        print("Prosze wprowadzic nazwe pliku z zaszyfrowanymi bajtami...")
        msg_file_name = input(" >> ")
        with open(key_file_name, 'r') as key_file:
            key = [int(line.strip()) for line in key_file]
        with open(msg_file_name, 'r') as msg_file:
            msg = [int(line.strip()) for line in msg_file]
        print("Odszyfrowany tekst zapisano w pliku decrypted.txt.")
        encrypted = decrypt(key, msg)
        with open('decrypted.txt', 'w') as output_file:
            for byte in encrypted:
                output_file.write("%s" % byte)
        main_menu()

    if choice == "3":
        unit_tests.unittest.main()

    if choice == "0":
        return


if __name__ == "__main__":
    main_menu()
