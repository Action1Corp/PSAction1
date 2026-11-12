# Action1 Public Repository Material
# Subject to TERMS_OF_USE.md (https://github.com/Action1Corp/PSAction1/blob/main/TERMS_OF_USE.md)
# Provided AS IS
# Use at your own risk
# Review and test before production deployment
# (c) Action1 Corporation

[Diagnostics.CodeAnalysis.SuppressMessageAttribute(
    'PSAvoidUsingConvertToSecureStringWithPlainText', '',
    Justification = 'Convert string arguments to SecureString during parameter binding.'
)]
[Diagnostics.CodeAnalysis.SuppressMessageAttribute(
    'PSAction1.AnalyzerRules\Measure-PSAction1CmdletName', '',
    Justification = 'Transform is the required argument transformation override name.'
)]
class Action1SecureStringTransformationAttribute : System.Management.Automation.ArgumentTransformationAttribute {
    [object] Transform(
        [System.Management.Automation.EngineIntrinsics]$EngineIntrinsics,
        [object]$InputData
    ) {
        if ($InputData -is [System.Security.SecureString] -and $InputData.Length -gt 0) {
            return $InputData
        }
        if ($InputData -is [string] -and $InputData.Length -gt 0) {
            # -AsPlainText wraps supplied text in a SecureString. Without it,
            # ConvertTo-SecureString expects an encrypted string representation.
            return (ConvertTo-SecureString -String $InputData -AsPlainText -Force `
                -ErrorAction Stop)
        }
        throw 'Supply a nonempty string or SecureString.'
    }
}
