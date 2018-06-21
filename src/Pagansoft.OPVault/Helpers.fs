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

module Array =
  let fromNullable (value: 'a array) : 'a array =
    match value with
    | null -> [||]
    | v -> v

[<RequireQualifiedAccess>]
module Option=
  let fromNullable (value: System.Nullable<'a>) : 'a option =
    if value.HasValue
    then Some value.Value
    else None

  let fromNullableString (value: string) : string option =
    match value with
    | null -> None
    | _ -> Some value

[<RequireQualifiedAccess>]
module File = 
  let read filename = 
    try
      Ok (System.IO.File.ReadAllText filename)
    with
    | :? System.IO.FileNotFoundException -> FileNotFound filename |> FileError |> Error
    | :? System.IO.DirectoryNotFoundException -> FileNotFound filename |> FileError |> Error
    | e -> UnknownError (sprintf "%s: %s" ((e.GetType()).Name) e.Message) |> Error

module ResultOperators =
  let inline (|=>) result mapping = Result.map mapping result
  let inline (|->) result binder = Result.bind binder result

module Json = 
  open Newtonsoft.Json
  open Newtonsoft.Json.Linq
  
  let deserialize<'a> (json: string) = 
    try
      JsonConvert.DeserializeObject<'a> json |> Ok
    with
    | _ -> JSONParserError json |> ParserError |> Error

  let serialize<'a> (o: 'a) = 
    try
      Ok (JsonConvert.SerializeObject o)
    with
    | e -> UnknownError e.Message |> Error

  let tryGetString (key:string) (object: JObject) =
    match object.TryGetValue key with
    | false, _ -> None
    | true, token -> token.ToString () |> Some

  let tryGetInt (key:string) (object: JObject) =
    match object.TryGetValue key with
    | false, _ -> None
    | true, token -> 
      let r = token.CreateReader()
      r.ReadAsInt32 () |> Option.fromNullable