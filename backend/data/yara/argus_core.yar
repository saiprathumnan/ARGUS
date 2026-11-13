/*
  ARGUS bundled YARA rules. Each rule declares:
    argus_class  = "test_fixture" | "suspicious" | "malicious"
    description  = what the rule matches
  Only "malicious" rules may produce a confirmed_malicious finding. Add your own .yar files to this directory.
*/

rule ARGUS_Test_Fixture
{
    meta:
        description = "Harmless marker string used to verify that the ARGUS YARA engine is working"
        argus_class = "test_fixture"
        author = "ARGUS"
    strings:
        $marker = "ARGUS-YARA-TEST-FIXTURE-7f3a9c21-harmless" ascii wide
    condition:
        $marker
}

rule ARGUS_PowerShell_Encoded_Downloader
{
    meta:
        description = "Script or shortcut content launching PowerShell with hidden window / encoded command and a download primitive"
        argus_class = "suspicious"
        author = "ARGUS"
    strings:
        $ps = "powershell" ascii wide nocase
        $h1 = "-w hidden" ascii wide nocase
        $h2 = "-windowstyle hidden" ascii wide nocase
        $e1 = "-enc " ascii wide nocase
        $e2 = "-encodedcommand" ascii wide nocase
        $d1 = "DownloadString" ascii wide nocase
        $d2 = "DownloadFile" ascii wide nocase
        $d3 = "Invoke-WebRequest" ascii wide nocase
        $d4 = "FromBase64String" ascii wide nocase
        $x = "IEX" ascii wide
    condition:
        $ps and (1 of ($h*) or 1 of ($e*)) and (1 of ($d*) or $x)
}

rule ARGUS_PDF_AutoAction_JavaScript
{
    meta:
        description = "PDF containing JavaScript together with an automatic action trigger"
        argus_class = "suspicious"
        author = "ARGUS"
    strings:
        $pdf = "%PDF-"
        $js1 = "/JavaScript" ascii
        $js2 = "/JS" ascii
        $a1 = "/OpenAction" ascii
        $a2 = "/AA" ascii
        $a3 = "/Launch" ascii
    condition:
        $pdf at 0 and 1 of ($js*) and 1 of ($a*)
}

rule ARGUS_Office_Macro_AutoExec_Shell
{
    meta:
        description = "Macro source combining an auto-execution entry point with shell execution"
        argus_class = "suspicious"
        author = "ARGUS"
    strings:
        $a1 = "AutoOpen" ascii wide nocase
        $a2 = "Document_Open" ascii wide nocase
        $a3 = "Workbook_Open" ascii wide nocase
        $s1 = "WScript.Shell" ascii wide nocase
        $s2 = "Shell(" ascii wide nocase
        $s3 = "CreateObject(" ascii wide nocase
    condition:
        1 of ($a*) and 2 of ($s*)
}

rule ARGUS_Webshell_Eval_Request
{
    meta:
        description = "Server-side script that evaluates request-supplied input (minimal web shell pattern)"
        argus_class = "suspicious"
        author = "ARGUS"
    strings:
        $p1 = /eval\s*\(\s*(base64_decode\s*\()?\s*\$_(POST|GET|REQUEST|COOKIE)/ nocase
        $p2 = /(system|passthru|shell_exec|exec)\s*\(\s*\$_(POST|GET|REQUEST)/ nocase
    condition:
        any of them
}
