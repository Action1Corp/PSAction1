function Set-Action1Region {
    param (
        [Parameter(Mandatory)]
        [ValidateSet('NorthAmerica', 'Europe', 'Australia')]
        [String]$Region
    )
    $Script:Action1_BaseURI = $Script:Action1_Hosts[$Region]
}