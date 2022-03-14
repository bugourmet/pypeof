# pyPEof

pyPEof is a Python script for dealing with presence of suspicious EOF data on a valid PE file.


Malware often appends to EOF payloads,C2 configuration and other malicious data.

This script checks if the PE file is valid then checks image architecture. 

If we are facing a valid PE file we then determine the file size on the disk and then calculate the expected size of the file trough the PE Header.

If the size on disk is not equal to the size described by the PE Header then we likely have an infected file.

Script then prints the EOF data and prompts user to dump it to a file.

Main goal was learning more about the PE file system and common malware techniques.

Code is not perfect and improvements/suggestions are welcome.

![alt text](https://i.imgur.com/VFMNLUZ.png)



## Contributing
Pull requests are welcome. For major changes, please open an issue first to discuss what you would like to change.

## License









[MIT](https://choosealicense.com/licenses/mit/)
