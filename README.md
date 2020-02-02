Yara rule, samples, and unpacked shellcodes for a recent visual basic packer that loads an interesting shellcode.

I have seen different variants of the shellcode, but all of them share characteristics. Here some strings foreach variant:

https://github.com/p3pperp0tts/Filename1Subfolder1Shellcode/blob/master/94fd43cb8420c389b3172f70ce149da7_icedid_gdrive_package_vb_shellcode/shellcode_injected_ieinstal_230000.txt

https://github.com/p3pperp0tts/Filename1Subfolder1Shellcode/blob/master/5a9ba965428e58dc4b456fbf6acb1601_agenttesla_vb_regasm_shellcode/70000.txt

https://github.com/p3pperp0tts/Filename1Subfolder1Shellcode/blob/master/32CC105556B537396211849ADA5F996A_lokibot_nogdrive_vb_shellcode/shellcode_150000.txt

All of them have a couple of strings:

\filename1.exe
\subfolder1

Because of that I have set this name for the shellcode (i dont know if this packer has another different name). 
