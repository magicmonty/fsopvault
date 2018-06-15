namespace Pagansoft.OPVault

[<RequireQualifiedAccess>]
module String =
  let trim (str: string) = str.Trim()
  
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

  let bytesAsString (bytes: byte array) : string =
    System.Text.Encoding.UTF8.GetString bytes

[<RequireQualifiedAccess>]
module ByteArray =
  let fromBase64 (str: string) =
    System.Convert.FromBase64String str

[<RequireQualifiedAccess>]
module DateTime =
  let fromUnixTimeStamp (value: int) =
    let dtDateTime = System.DateTime(1970, 1, 1, 0, 0, 0, 0, System.DateTimeKind.Utc)
    (dtDateTime.AddSeconds (float value)).ToLocalTime()

[<RequireQualifiedAccess>]
module JSON =
  open FSharp.Data
  open FSharp.Data.JsonExtensions

  let asInteger (v: JsonValue) = v.AsInteger()
  let asBool (v: JsonValue) = v.AsBoolean()
  let asString (v: JsonValue) = v.AsString()
  let asByteArray (v: JsonValue) = v |> asString |> ByteArray.fromBase64
  let asDateTime (v: JsonValue) = v |> asInteger |> DateTime.fromUnixTimeStamp
