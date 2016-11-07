REM STEVEN ROGERS 
REM 2016-11-4
	
cls
@ECHO OFF
echo **REG QUERY FOR OFFICE 2016 DRAFT STIG**
echo V-70855
REG QUERY HKCU\Software\Policies\Microsoft\Office\16.0\common\ptwatson /v PTWOptIn 
pause
echo V-70857
REG QUERY HKCU\Software\Policies\Microsoft\Office\16.0\common /V UpdateReliabilityData
pause
echo V-70859
REG QUERY HKCU\Software\Policies\Microsoft\Office\16.0\common\trustcenter /v TrustBar
pause
echo V-70861
REG QUERY HKCU\Software\Policies\Microsoft\Office\16.0\common\security /v DRMEncryptProperty 
pause
echo V-70863
REG QUERY HKCU\Software\Policies\Microsoft\Office\16.0\common\security /v OpenXMLEncryptProperty  
pause
echo V-70865
REG QUERY HKCU\Software\Policies\Microsoft\Office\16.0\common\security /v OpenXMLEncryption
pause
echo V-70867
REG QUERY HKCU\Software\Policies\Microsoft\Office\16.0\common\security /v DefaultEncryption12
pause
echo V-70869
REG QUERY HKCU\Software\Policies\Microsoft\Office\Common\Security /v UFIControls 
pause
echo V-70871
REG QUERY HKCU\keycupoliciesmsvbasecurity /v LoadControlsInForms 
pause
echo V-70873
REG QUERY HKCU\Software\Policies\Microsoft\Office\Common\Security /v AutomationSecurity
pause
echo V-70875
REG QUERY "HKCU\Software\Policies\Microsoft\Office\16.0\common\security\trusted locations" /v "Allow User Locations"
pause
echo V-70877
REG QUERY "HKCU\Software\Policies\Microsoft\Office\Common\Smart Tag" /v NeverLoadManifests 
pause
echo V-70881
REG QUERY "HKCU\Software\Policies\Microsoft\Office\16.0\common\drm" /v RequireConnection
pause
echo V-70883
REG QUERY HKCU\Software\Policies\Microsoft\Office\16.0\common\fixedformat /v DisableFixedFormatDocProperties 
pause
echo V-70885
REG QUERY HKCU\Software\Policies\Microsoft\Office\16.0\common\security /v EncryptDocProps
pause
echo V-70889
REG QUERY HKCU\software\policies\Microsoft\office\16.0\common\broadcast /v disabledefaultservice
pause
echo V-70891
REG QUERY HKCU\software\policies\Microsoft\office\16.0\common\broadcast /v disableprogrammaticaccess 
pause
echo V-70893
REG QUERY HKCU\software\policies\Microsoft\office\16.0\common\feedback /v includescreenshot 
pause
echo V-70895
REG QUERY HKCU\software\policies\Microsoft\office\16.0\wef\trustedcatalogs /v requireserververification
pause
echo V-70897
REG QUERY HKCU\software\policies\Microsoft\office\16.0\osm /v enablefileobfuscation
pause
echo V-70899
REG QUERY HKCU\software\policies\Microsoft\office\16.0\common /v sendcustomerdata 
pause
echo ***REG QUERY COMPLETE***
echo **HIT ANY KEY TO CLOSE**
pause