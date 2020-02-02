rule filename1_subfolder1_loader_gen {

strings:
	$a1="windir=" wide ascii
	$a2="USERPROFILE=" wide ascii
	$a3="\\system32\\" wide ascii
	$a4="\\syswow64\\" wide ascii
	$a5="\\filename1.exe" wide ascii
	$a6="\\subfolder1" wide ascii
	$a7="Mozilla/5.0 (Windows NT 6.1; WOW64; Trident/7.0; rv:11.0) like Gecko" wide ascii
	$a8="Startup key" wide ascii
	$a9="Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce" wide ascii
	$b1="NtGetContextThread" wide ascii
	$b2="NtSetContextThread" wide ascii
	$b3="NtProtectVirtualMemory" wide ascii
	$b4="NtAllocateVirtualMemory" wide ascii
	$b5="NtWriteVirtualMemory" wide ascii
	$b6="DbgUiRemoteBreakin" wide ascii
	$b7="NtSetInformationThread" wide ascii
	$b8="CreateProcessInternalW" wide ascii

condition:
	8 of ($a*) and 7 of ($b*)
}


rule filename1_subfolder1_loader_v1 {

strings:
	$s1="windir=" wide ascii
	$s2="USERPROFILE=" wide ascii
	$s3="msvbvm60.dll" wide ascii
	$s4="\\system32\\" wide ascii
	$s5="\\syswow64\\" wide ascii
	$s6="\\filename1.exe" wide ascii
	$s7="\\subfolder1" wide ascii
	$s8="Mozilla/5.0 (Windows NT 6.1; WOW64; Trident/7.0; rv:11.0) like Gecko" wide ascii
	$s9="NtGetContextThread" wide ascii
	$s10="NtSetContextThread" wide ascii
	$s11="NtProtectVirtualMemory" wide ascii
	$s12="NtAllocateVirtualMemory" wide ascii
	$s13="NtWriteVirtualMemory" wide ascii
	$s17="DbgUiRemoteBreakin" wide ascii
	$s18="NtSetInformationThread" wide ascii
	$s19="CreateProcessInternalW" wide ascii
	$s20="Set W = CreateObject(\"WScript.Shell\")" wide ascii
	$s21="Set C = W.Exec (\"" wide ascii
	$s22="Startup key" wide ascii
	$s23="Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce" wide ascii

condition:
	all of them
}



rule filename1_subfolder1_loader_v2 {

strings:
	$s1="windir=" wide ascii
	$s2="USERPROFILE=" wide ascii
	$s3="msvbvm60.dll" wide ascii
	$s4="\\system32\\" wide ascii
	$s5="\\syswow64\\" wide ascii
	$s6="\\filename1.exe" wide ascii
	$s7="\\subfolder1" wide ascii
	$s8="Mozilla/5.0 (Windows NT 6.1; WOW64; Trident/7.0; rv:11.0) like Gecko" wide ascii
	$s9="NtGetContextThread" wide ascii
	$s10="NtSetContextThread" wide ascii
	$s11="NtProtectVirtualMemory" wide ascii
	$s12="NtAllocateVirtualMemory" wide ascii
	$s13="NtWriteVirtualMemory" wide ascii
	$s17="DbgUiRemoteBreakin" wide ascii
	$s18="NtSetInformationThread" wide ascii
	$s19="CreateProcessInternalW" wide ascii
	$s20="\\internet explorer\\iexplore.exe" wide ascii
	$s21="\\internet explorer\\ieinstal.exe" wide ascii
	$s22="\\internet explorer\\ielowutil.exe" wide ascii
	$s23="Startup key" wide ascii
	$s24="Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce" wide ascii

condition:
	all of them
}



rule filename1_subfolder1_loader_v3 {

strings:
	$s1="windir=" wide ascii
	$s2="USERPROFILE=" wide ascii
	$s4="\\system32\\" wide ascii
	$s5="\\syswow64\\" wide ascii
	$s6="\\filename1.exe" wide ascii
	$s7="\\subfolder1" wide ascii
	$s8="Mozilla/5.0 (Windows NT 6.1; WOW64; Trident/7.0; rv:11.0) like Gecko" wide ascii
	$s9="NtGetContextThread" wide ascii
	$s10="NtSetContextThread" wide ascii
	$s11="NtProtectVirtualMemory" wide ascii
	$s12="NtAllocateVirtualMemory" wide ascii
	$s13="NtWriteVirtualMemory" wide ascii
	$s17="DbgUiRemoteBreakin" wide ascii
	$s18="NtSetInformationThread" wide ascii
	$s19="CreateProcessInternalW" wide ascii
	$s20="RegAsm.exe" wide ascii
	$s21="RegSvcs.exe" wide ascii
	$s22="MSBuild.exe" wide ascii
	$s23="Startup key" wide ascii
	$s24="Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce" wide ascii

condition:
	all of them
}