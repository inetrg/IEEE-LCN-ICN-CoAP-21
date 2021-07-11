declare -A NODES=(
    [186]="E6:B3:71:9D:D1:8B:FF:E1 /temperature       0"
    [189]="A6:21:9A:9A:8A:65:FE:2D /temperature/A6:21 1"
    [191]="66:53:38:CA:94:0D:00:E1 /temperature/66:53 1"
    [193]="BA:FC:F8:A1:20:8D:9C:01 /temperature/BA:FC 1"
    [197]="EE:A6:60:5B:94:81:10:15 /temperature/EE:A6 1"
    [200]="FA:DC:B8:81:E0:CD:5C:C1 /temperature/FA:DC 1"
    [203]="5E:42:66:9B:26:DF:72:93 /temperature/5E:42 1"
    [205]="66:4E:6F:87:A1:FA:2D:3E /temperature/66:4E 2"
    [207]="AA:68:F5:29:93:2C:BF:00 /temperature/AA:68 1"
    [217]="DA:C0:4B:A4:FD:A9:27:0F /temperature/DA:C0 1"
    [226]="E6:C1:FE:70:EA:8B:E6:FF /temperature/E6:C1 1"
    [227]="A6:ED:03:4F:A7:85:BD:6B /temperature/A6:ED 1"
    [236]="A6:95:F5:5E:59:64:0D:F4 /temperature/A6:95 1"
    [237]="5E:3E:00:A6:2C:95:E8:59 /temperature/5E:3E 1"
    [238]="BE:D3:BD:94:A5:AC:61:A4 /temperature/BE:D3 1"
    [246]="E6:65:5B:D4:CB:CC:87:00 /temperature/E6:65 1"
    [247]="EE:66:70:1B:A4:B1:20:05 /temperature/EE:66 1"
    [248]="5E:83:CB:7F:BB:A7:ED:B5 /temperature/5E:83 1"
    [249]="DE:63:C7:19:47:E1:95:37 /temperature/DE:63 1"
    [256]="DA:BC:46:C7:AA:B4:68:3A /temperature/DA:BC 1"
    [257]="5A:2C:5A:C2:F6:70:24:66 /temperature/5A:2C 1"
    [258]="AE:2A:8E:D1:76:5C:6C:52 /temperature/AE:2A 1"
    [259]="A6:3E:5A:4B:42:EF:3E:A3 /temperature/A6:3E 1"
    [260]="A6:6E:B2:88:7A:D0:60:A6 /temperature/A6:6E 1"
    [266]="EA:48:25:09:63:7C:6F:30 /temperature/EA:48 1"
    [267]="DA:A4:1C:23:84:AF:80:67 /temperature/DA:A4 1"
    [268]="DE:BE:43:6A:69:D9:F3:AF /temperature/DE:BE 1"
    [269]="5A:6C:0D:7C:C3:3F:75:3D /temperature/5A:6C 1"
    [270]="66:01:9A:25:9A:F2:8C:B8 /temperature/66:01 1"
    [271]="EA:A4:3E:9B:E6:71:62:39 /temperature/EA:A4 1"
    [276]="5E:A5:DC:62:40:7F:34:BF /temperature       0"
    [277]="7E:57:B4:6F:54:90:3E:06 /temperature       0"
    [278]="6E:CB:7A:AF:7E:0A:E8:68 /temperature       0"
    [279]="AE:95:72:D9:EA:A2:5C:E8 /temperature       0"
    [280]="5E:BF:81:EF:E9:D5:1B:9B /temperature       0"
    [281]="EE:66:70:A7:AC:0D:18:81 /temperature       0"
    [283]="DA:A0:25:85:5B:F0:07:04 /temperature       0"
    [290]="BE:93:F6:36:EA:07:D6:0B /temperature/BE:93 1"
    [295]="A6:77:31:58:29:B8:2D:70 /temperature/A6:77 1"
    [297]="A6:9A:5F:20:ED:17:EB:9D /temperature/A6:9A 1"
    [300]="FA:50:90:3C:B0:0C:22:E2 /temperature/FA:50 1"
    [302]="5E:7F:D3:A2:4B:C0:F7:14 /temperature/5E:7F 1"
    [307]="BE:EF:C0:32:24:31:A0:85 /temperature/BE:EF 1"
    [311]="A6:F1:8E:AF:F2:58:E8:5E /temperature/A6:F1 1"
    [316]="AE:A7:D0:C9:48:A5:B4:69 /temperature       0"
)

declare -a ROUTES=(
    # 1
    "316 205 311 down"

    "311 205 307 down"

    "307 205 302 down"

    "302 205 300 down"

    "300 205 297 down"

    "297 205 295 down"

    "295 205 290 down"

    "290 205 205 down"

    # 2
    "186 205 189 down"

    "189 205 191 down"

    "191 205 193 down"

    "193 205 197 down"

    "197 205 200 down"

    "200 205 203 down"

    "203 205 207 down"

    "207 205 205 down"

    # 3
    "277 205 267 down"

    "267 205 257 down"

    "257 205 247 down"

    "247 205 237 down"

    "237 205 227 down"

    "227 205 217 down"

    "217 205 207 down"

    # 4
    "276 205 266 down"

    "266 205 256 down"

    "256 205 246 down"

    "246 205 236 down"

    "236 205 226 down"

    "226 205 217 down"

    # 5
    "278 205 268 down"

    "268 205 258 down"

    "258 205 248 down"

    "248 205 238 down"

    "238 205 226 down"

    # 6
    "279 205 269 down"

    "269 205 259 down"

    "259 205 249 down"

    "249 205 238 down"

    # 7
    "280 205 270 down"

    "270 205 260 down"

    "260 205 249 down"

    # 8
    "281 205 271 down"

    "271 205 260 down"

    # 9
    "283 205 271 down"
)
