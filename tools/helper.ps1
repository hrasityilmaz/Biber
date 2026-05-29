
function hex($v){
    $n = if ($v -is [string]) {
        if ($v.StartsWith("0x")) {
            [Convert]::ToInt64($v.Substring(2), 16)
        } else {
            [int64]$v
        }
    } else {
        [int64]$v
    }

    "0x{0:X}" -f $n
}

function ascii($hex) {
    if ($hex -is [string]) {

        $hex = $hex -replace '^0x',''
        $hex = $hex -replace '[^0-9A-Fa-f]',''

        if ($hex.Length % 2) {
            throw "Hex length must be even"
        }

        $bytes = for ($i=0; $i -lt $hex.Length; $i += 2) {
            [Convert]::ToByte($hex.Substring($i,2),16)
        }

        [Text.Encoding]::ASCII.GetString($bytes)
    }
}

function asc($v){
    ascii $v
}
