# STEVEN ROGERS 
# 2016-11-4
	
cls
echo **QUERY FOR OFFICE 2016 DRAFT STIG**
echo V-70855
Get-ItemPropertyValue -path 'HKCU:Software\Policies\Microsoft\Office\16.0\common\ptwatson' PTWOptIn 
pause
echo V-70857
Get-ItemPropertyValue -path 'HKCU\Software\Policies\Microsoft\Office\16.0\common' UpdateReliabilityData
pause
echo V-70859
Get-ItemPropertyValue -path ' HKCU\Software\Policies\Microsoft\Office\16.0\common\trustcenter' TrustBar
pause
echo V-70861
Get-ItemPropertyValue -path 'HKCU\Software\Policies\Microsoft\Office\16.0\common\security' DRMEncryptProperty 
pause
echo V-70863
Get-ItemPropertyValue -path 'HKCU\Software\Policies\Microsoft\Office\16.0\common\security' OpenXMLEncryptProperty  
pause
echo V-70865
Get-ItemPropertyValue -path 'HKCU\Software\Policies\Microsoft\Office\16.0\common\security' OpenXMLEncryption
pause
echo V-70867
Get-ItemPropertyValue -path 'HKCU\Software\Policies\Microsoft\Office\16.0\common\security' DefaultEncryption12
pause
echo V-70869
Get-ItemPropertyValue -path 'HKCU\Software\Policies\Microsoft\Office\Common\Security' UFIControls 
pause
echo V-70871
Get-ItemPropertyValue -path 'HKCU\keycupoliciesmsvbasecurity' LoadControlsInForms 
pause
echo V-70873
Get-ItemPropertyValue -path 'HKCU\Software\Policies\Microsoft\Office\Common\Security' AutomationSecurity
pause
echo V-70875
Get-ItemPropertyValue -path 'HKCU\Software\Policies\Microsoft\Office\16.0\common\security\trusted locations' 'Allow User Locations'
pause
echo V-70877
Get-ItemPropertyValue -path 'HKCU\Software\Policies\Microsoft\Office\Common\Smart Tag' NeverLoadManifests 
pause
echo V-70881
Get-ItemPropertyValue -path 'HKCU\Software\Policies\Microsoft\Office\16.0\common\drm' RequireConnection
pause
echo V-70883
Get-ItemPropertyValue -path 'HKCU\Software\Policies\Microsoft\Office\16.0\common\fixedformat' DisableFixedFormatDocProperties 
pause
echo V-70885
Get-ItemPropertyValue -path 'HKCU\Software\Policies\Microsoft\Office\16.0\common\security' EncryptDocProps
pause
echo V-70889
Get-ItemPropertyValue -path 'HKCU\software\policies\Microsoft\office\16.0\common\broadcast' disabledefaultservice
pause
echo V-70891
Get-ItemPropertyValue -path 'HKCU\software\policies\Microsoft\office\16.0\common\broadcast' disableprogrammaticaccess 
pause
echo V-70893
Get-ItemPropertyValue -path 'HKCU\software\policies\Microsoft\office\16.0\common\feedback' includescreenshot 
pause
echo V-70895
Get-ItemPropertyValue -path 'HKCU\software\policies\Microsoft\office\16.0\wef\trustedcatalogs' requireserververification
pause
echo V-70897
Get-ItemPropertyValue -path 'HKCU\software\policies\Microsoft\office\16.0\osm' enablefileobfuscation
pause
echo V-70899
Get-ItemPropertyValue -path 'HKCU\software\policies\Microsoft\office\16.0\common' sendcustomerdata 
pause
echo *****QUERY COMPLETE*****
echo **HIT ANY KEY TO CLOSE**
pause