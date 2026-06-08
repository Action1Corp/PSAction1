function Set-Action1Locale {
    [Obsolete("Please use Set-Action1Region instead.")]
    param (
        [Parameter(Mandatory)]
        [ValidateSet('NorthAmerica', 'Europe', 'Australia')]
        [String]$Region
    )
    Set-Action1Region -Region $Region
}