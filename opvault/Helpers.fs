namespace OPVault

[<RequireQualifiedAccess>]
module String =
  open Errors
  let removeWhitespace (str: string) =
    str.Replace("\r\n","").Replace("\r","").Replace("\n","").Replace(" ", "").Replace("\t","").Trim()

  let makeJSON (prefix: string) (suffix: string) (content: string) =
    let content = content |> removeWhitespace
    if (content.StartsWith prefix) && (content.EndsWith suffix)
    then 
      let json = content.Substring (prefix |> String.length)
      let json = json.Substring (0, (json |> String.length) - (suffix |> String.length))
      let json = sprintf "{%s}" json
      Ok json
    else WrongFormatError |> ParserError |> Error

[<RequireQualifiedAccess>]
module ByteArray =
  let fromBase64 (str: string) =
    System.Convert.FromBase64String str

[<RequireQualifiedAccess>]
module DateTime =
  let fromUnixTimeStamp (value: int) =
    let dtDateTime = System.DateTime(1970, 1, 1, 0, 0, 0, 0, System.DateTimeKind.Utc)
    (dtDateTime.AddSeconds (float value)).ToLocalTime()

