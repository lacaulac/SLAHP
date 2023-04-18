.\PerfTests protectorsigned yes
for ($num = 1 ; $num -le 500 ; $num++) { .\PerfTests.exe protectorsigned yes >> logs/initprotector_cached_signed.log }
for ($num = 1 ; $num -le 500 ; $num++) { .\PerfTests.exe protector yes >> logs/initprotector_cached_unsigned.log }
rm policy*
echo "Witness for lib_0_deps_main "; for ($num = 1 ; $num -le 500 ; $num++){.\PerfTests.exe ldlib ./dll_unsigned/lib_0_deps_main.dll >> logs/lib_0_deps_main-witness.log }
echo "./dll_unsigned/lib_0_deps_main.dll + allowhash = AllowHash"; for ($num = 1 ; $num -le 500 ; $num++){.\PerfTests.exe ldlibproturl ./dll_unsigned/lib_0_deps_main.dll /stage3a/perfv2/allowhash.cfg >> logs/lib_0_deps_main-allowhash-AllowHash.log }
echo "./dll_unsigned/lib_0_deps_main.dll + disallowhash = DisallowHash"; for ($num = 1 ; $num -le 500 ; $num++){.\PerfTests.exe ldlibproturl ./dll_unsigned/lib_0_deps_main.dll /stage3a/perfv2/disallowhash.cfg >> logs/lib_0_deps_main-disallowhash-DisallowHash.log }
echo "./dll_signed/lib_0_deps_main.dll + sig = AllowSigned"; for ($num = 1 ; $num -le 500 ; $num++){.\PerfTests.exe ldlibproturl ./dll_signed/lib_0_deps_main.dll /stage3a/perfv2/sig.cfg >> logs/lib_0_deps_main-sig-AllowSigned.log }
echo "./dll_signed_invalid/lib_0_deps_main.dll + sig = DisallowSigned"; for ($num = 1 ; $num -le 500 ; $num++){.\PerfTests.exe ldlibproturl ./dll_signed_invalid/lib_0_deps_main.dll /stage3a/perfv2/sig.cfg >> logs/lib_0_deps_main-sig-DisallowSigned.log }
echo "Witness for lib_6_deps_main "; for ($num = 1 ; $num -le 500 ; $num++){.\PerfTests.exe ldlib ./dll_unsigned/lib_6_deps_main.dll >> logs/lib_6_deps_main-witness.log }
echo "./dll_unsigned/lib_6_deps_main.dll + allowhash = AllowHash"; for ($num = 1 ; $num -le 500 ; $num++){.\PerfTests.exe ldlibproturl ./dll_unsigned/lib_6_deps_main.dll /stage3a/perfv2/allowhash.cfg >> logs/lib_6_deps_main-allowhash-AllowHash.log }
echo "./dll_unsigned/lib_6_deps_main.dll + disallowhash = DisallowHash"; for ($num = 1 ; $num -le 500 ; $num++){.\PerfTests.exe ldlibproturl ./dll_unsigned/lib_6_deps_main.dll /stage3a/perfv2/disallowhash.cfg >> logs/lib_6_deps_main-disallowhash-DisallowHash.log }
echo "./dll_signed/lib_6_deps_main.dll + sig = AllowSigned"; for ($num = 1 ; $num -le 500 ; $num++){.\PerfTests.exe ldlibproturl ./dll_signed/lib_6_deps_main.dll /stage3a/perfv2/sig.cfg >> logs/lib_6_deps_main-sig-AllowSigned.log }
echo "./dll_signed_invalid/lib_6_deps_main.dll + sig = DisallowSigned"; for ($num = 1 ; $num -le 500 ; $num++){.\PerfTests.exe ldlibproturl ./dll_signed_invalid/lib_6_deps_main.dll /stage3a/perfv2/sig.cfg >> logs/lib_6_deps_main-sig-DisallowSigned.log }
echo "Witness for lib_12_deps_main "; for ($num = 1 ; $num -le 500 ; $num++){.\PerfTests.exe ldlib ./dll_unsigned/lib_12_deps_main.dll >> logs/lib_12_deps_main-witness.log }
echo "./dll_unsigned/lib_12_deps_main.dll + allowhash = AllowHash"; for ($num = 1 ; $num -le 500 ; $num++){.\PerfTests.exe ldlibproturl ./dll_unsigned/lib_12_deps_main.dll /stage3a/perfv2/allowhash.cfg >> logs/lib_12_deps_main-allowhash-AllowHash.log }
echo "./dll_unsigned/lib_12_deps_main.dll + disallowhash = DisallowHash"; for ($num = 1 ; $num -le 500 ; $num++){.\PerfTests.exe ldlibproturl ./dll_unsigned/lib_12_deps_main.dll /stage3a/perfv2/disallowhash.cfg >> logs/lib_12_deps_main-disallowhash-DisallowHash.log }
echo "./dll_signed/lib_12_deps_main.dll + sig = AllowSigned"; for ($num = 1 ; $num -le 500 ; $num++){.\PerfTests.exe ldlibproturl ./dll_signed/lib_12_deps_main.dll /stage3a/perfv2/sig.cfg >> logs/lib_12_deps_main-sig-AllowSigned.log }
echo "./dll_signed_invalid/lib_12_deps_main.dll + sig = DisallowSigned"; for ($num = 1 ; $num -le 500 ; $num++){.\PerfTests.exe ldlibproturl ./dll_signed_invalid/lib_12_deps_main.dll /stage3a/perfv2/sig.cfg >> logs/lib_12_deps_main-sig-DisallowSigned.log }
