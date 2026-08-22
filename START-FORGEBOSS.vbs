Option Explicit
Dim shell, fso, root, pyw, scriptPath, commandLine, rc
Set shell = CreateObject("WScript.Shell")
Set fso = CreateObject("Scripting.FileSystemObject")
root = fso.GetParentFolderName(WScript.ScriptFullName)
scriptPath = root & "\\ForgeBoss-Internal\\dashboard\\pro_shell.py"
pyw = shell.ExpandEnvironmentStrings("%USERPROFILE%") & "\\.forgeboss\\runtime\\venv\\Scripts\\pythonw.exe"
If Not fso.FileExists(scriptPath) Then
  MsgBox "ForgeBoss files are incomplete." & vbCrLf & vbCrLf & "Extract the entire ZIP to a normal folder before launching.", vbCritical, "ForgeBoss"
  WScript.Quit 2
End If
If Not fso.FileExists(pyw) Then
  MsgBox "ForgeBoss desktop runtime is not installed yet." & vbCrLf & vbCrLf & "Run SETUP-FORGEBOSS-ENGINES.cmd from ForgeBoss-Internal first.", vbExclamation, "ForgeBoss"
  WScript.Quit 2
End If
commandLine = Chr(34) & pyw & Chr(34) & " " & Chr(34) & scriptPath & Chr(34)
On Error Resume Next
rc = shell.Run(commandLine, 0, False)
If Err.Number <> 0 Then
  MsgBox "ForgeBoss could not start." & vbCrLf & Err.Description, vbCritical, "ForgeBoss"
  WScript.Quit 3
End If
On Error GoTo 0
