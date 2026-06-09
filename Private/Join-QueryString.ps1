function Join-QueryString {
    param(
        [string]$QueryString,
        [string]$Argument
    )

    if ($QueryString) {
        "$QueryString&$Argument"
    }
    else {
        $Argument
    }
}