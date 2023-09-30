import os
import argparse
from pefile import PE, PEFormatError


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("-f", "--file", required=True,
                        type=open, help="PE file to read")
    args = parser.parse_args()
    file = args.file
    print("[+] Reading PE file...")

    try:
        image_size = 0
        pefile = PE(file.name)

        # check if pe file is valid,e_magic must be 0x5a4d
        if (hex(pefile.DOS_HEADER.e_magic) != "0x5a4d"):
            print("[+] PE file is invalid!")
        else:
            print("[+] PE file is valid!")

        architecture = 32 if hex(pefile.FILE_HEADER.Machine) == "0x14c" else 64
        print("[+] Image architecture is %sbit." % architecture)
        # adding the IMAGE_DIRERCTORY_ENTRY_SECURITY if target application is signed otherwise the full image size wont match.
        image_size += (pefile.OPTIONAL_HEADER.SizeOfHeaders +
                       pefile.OPTIONAL_HEADER.DATA_DIRECTORY[4].Size)

        # enumerate each section and add to current mesured image size.
        for section in pefile.sections:
            image_size += section.SizeOfRawData

        AFileSize = os.path.getsize(file.name)
        eof_size = (AFileSize - image_size)

        if eof_size > 0:  # checking if eof data is present in target file.
            print("[+] %s bytes of EOF data detected." % eof_size)
            # read eof data #
            file.seek(-eof_size, 2)
            eof_data = file.read(eof_size)
            prompt = input(
                "Do you want to print the EOF data? (y/n): ")
            if prompt == "y" or prompt == "yes":
                print("[+] Printing EOF data: \n%s" % eof_data)

            prompt = input("Do you want to dump the EOF data? (y/n): ")
            if prompt == "y" or prompt == "yes":
                with open("%s.dump" % file.name, "wb") as dump:
                    dump.write(eof_data)
                    print("[+] EOF data successfully dumped!")
        else:
            print("[+] No EOF data detected.")
    except PEFormatError:
        print("Are you sure you're trying to read a PE file?")
    except OSError:
        print("[+] %s does not exist or is inaccessible." % file.name)


if __name__ == "__main__":
    main()
