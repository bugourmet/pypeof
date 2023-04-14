from pefile import PE ,PEFormatError
import argparse
import os

parser = argparse.ArgumentParser()
parser.add_argument("-f", "--file", required=True, type=open,help="PE file to read")
args = parser.parse_args()
file = args.file

def readEof(filepath):
    try:
        imageSize = 0
        pefile = PE(filepath)

        if(hex(pefile.DOS_HEADER.e_magic) != "0x5a4d"): # check if pe file is valid,e_magic must be 0x5a4d
            print("PE FILE IS INVALID")
        else:
            print("PE FILE IS VALID") 

        if hex(pefile.FILE_HEADER.Machine) == "0x14c":  # checking architecture
            print("Image architecture is 32bit.")
            imageSize += (pefile.OPTIONAL_HEADER.SizeOfHeaders + pefile.OPTIONAL_HEADER.DATA_DIRECTORY[4].Size ) # adding the IMAGE_DIRERCTORY_ENTRY_SECURITY if target application is signed otherwise the full image size wont match.
        else:
            print("Image architecture is 64bit.")
            imageSize += (pefile.OPTIONAL_HEADER.SizeOfHeaders + pefile.OPTIONAL_HEADER.DATA_DIRECTORY[4].Size ) # adding the IMAGE_DIRERCTORY_ENTRY_SECURITY if target application is signed otherwise the full image size wont match.

        for section in pefile.sections: # enumerate each section and add to current mesured image size.
            imageSize += section.SizeOfRawData
            
        AFileSize = os.path.getsize(filepath)
        EOFSize = (AFileSize - imageSize)

        if EOFSize>0 :         #checking if eof data is present in target file.
            print("%s bytes of EOF data detected." %EOFSize)
            # read eof data #
            with open(filepath,"rb") as fp:
                fp.seek(-EOFSize, 2)
                eofdata = fp.read(EOFSize)
                prompt = input("Do you want to print the EOF data? (y/n): ")
                if prompt == "y" or prompt == "yes":
                    print("Printing EOF data: \n%s" %eofdata)
                
                prompt = input("Do you want to dump the EOF data? (y/n): ")
                if prompt == "y" or prompt == "yes":
                    with open("%s.dump"%filepath,"wb") as dump:
                        dump.write(eofdata)
                        print("EOF data successfully dumped!")
        else:       
            print("No EOF data detected.")
    except  PEFormatError:
        print("Are you sure you're trying to read a PE file?")
    except OSError:
        print("%s does not exist or is inaccessible." %filepath) 

readEof(file.name)