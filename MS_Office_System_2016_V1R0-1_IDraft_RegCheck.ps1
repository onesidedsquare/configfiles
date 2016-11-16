# STEVEN ROGERS 
# 2016-11-4
	
cls
echo **QUERY_FOR_OFFICE_2016_DRAFT_STIG**

$officeMultiArray = @(
             ("V-70855", "HKCU\Software\Policies\Microsoft\Office\16.0\common\ptwatson", "PTWOptIn"),
             ("V-70857", "HKCU\Software\Policies\Microsoft\Office\16.0\common", "UpdateReliabilityData")
             ("V-70859", "HKCU\Software\Policies\Microsoft\Office\16.0\common\trustcenter", "TrustBar")
             ("V-70861", "HKCU\Software\Policies\Microsoft\Office\16.0\common\security", "DRMEncryptProperty")
             ("V-70863", "HKCU\Software\Policies\Microsoft\Office\16.0\common\security", "OpenXMLEncryptProperty")
             ("V-70865", "HKCU\Software\Policies\Microsoft\Office\16.0\common\security", "OpenXMLEncryption")
             ("V-70867", "HKCU\Software\Policies\Microsoft\Office\16.0\common\security", "DefaultEncryption12")
             ("V-70869", "HKCU\Software\Policies\Microsoft\Office\Common\Security", "UFIControls")
             ("V-70871", "HKCU\keycupoliciesmsvbasecurity", "LoadControlsInForms")
             ("V-70873", "HKCU\Software\Policies\Microsoft\Office\Common\Security", "AutomationSecurity")
             ("V-70875", "HKCU\Software\Policies\Microsoft\Office\16.0\common\security\trusted locations", "Allow User Locations")
             ("V-70877", "HKCU\Software\Policies\Microsoft\Office\Common\Smart Tag", "NeverLoadManifests")
             ("V-70881", "HKCU\Software\Policies\Microsoft\Office\16.0\common\drm", "RequireConnection")
             ("V-70883", "HKCU\Software\Policies\Microsoft\Office\16.0\common\fixedformat", "DisableFixedFormatDocProperties")
             ("V-70885", "HKCU\Software\Policies\Microsoft\Office\16.0\common\security", "EncryptDocProps")
             ("V-70889", "HKCU\software\policies\Microsoft\office\16.0\common\broadcast", "disabledefaultservice")
             ("V-70891", "HKCU\software\policies\Microsoft\office\16.0\common\broadcast", "disableprogrammaticaccess")
             ("V-70893", "HKCU\software\policies\Microsoft\office\16.0\common\feedback", "includescreenshot")
             ("V-70895", "HKCU\software\policies\Microsoft\office\16.0\wef\trustedcatalogs", "requireserververification")
             ("V-70897", "HKCU\software\policies\Microsoft\office\16.0\osm", "enablefileobfuscation")
             ("V-70899", "HKCU\software\policies\Microsoft\office\16.0\common", "sendcustomerdata")
   )

For ($i=0; $i -lt $officeMultiArray.Length; $i++) {
    echo $officeMultiArray[$i][0]
    Get-ItemPropertyValue -path $officeMultiArray[$i][1] $officeMultiArray[$i][2]
    }

pause
echo *****QUERY_COMPLETE*****
echo **HIT_ANY_KEY_TO_CLOSE**
pause
