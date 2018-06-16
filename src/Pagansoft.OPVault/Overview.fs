namespace Pagansoft.OPVault
open Chiron

type Overview = { Title: string option
                  Info: string option
                  PS: int option
                  Tags: string list
                  Urls: string list }
                
                static member FromJson (_ : Overview) : Json<Overview> =
                  json {
                    let! title = Json.tryRead "title"
                    let! info = Json.tryRead "ainfo"
                    let! ps = Json.tryRead "ps"
                    let! tags = Json.readOrDefault "tags" []
                    let! urls = Json.readOrDefault "URLs" []
                    let! url = Json.tryRead "url"
                    let urls = match url with
                               | Some url -> url :: urls
                               | None -> urls
                    return { Title = title
                             Info = info
                             PS = ps
                             Tags = tags
                             Urls = urls }
                  }

[<RequireQualifiedAccess>]
module Overview =
  open FSharp.Results.Results

  let private parseJSON (json: string) : Result<Overview, OPVaultError>=
    try
      Json.parse json |> Json.deserialize |> Ok
    with
    | e -> JSONParserError e.Message |> ParserError |> Result.Error

  let decrypt overviewKey encryptedData =
    trial {
      let! encryptedOverviewData = encryptedData |> OPData.parseBytes
      let! decryptedOverviewData = encryptedOverviewData |> OPData.authenticateAndDecrypt overviewKey
      let! plainText = decryptedOverviewData.PlainTextAsString ()
      return! parseJSON plainText
    }

  let decryptString overviewKey encryptedData =
    encryptedData
    |> ByteArray.fromBase64
    |> decrypt overviewKey 

