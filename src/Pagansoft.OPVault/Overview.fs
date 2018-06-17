namespace Pagansoft.OPVault

type Overview = { Title: string option
                  Info: string option
                  PS: int option
                  Tags: string list
                  Urls: string list }

[<RequireQualifiedAccess>]
module Overview =
  open FSharp.Results.Results
  open Newtonsoft.Json

  type OverviewUrl = { u: string }
  type OverviewDTO = { title: string
                       ainfo: string
                       ps: System.Nullable<int>
                       tags: string array
                       URLs: OverviewUrl array
                       url: string }

  let convertToOverview (dto: OverviewDTO) : Overview =
    let urls = match dto.URLs with
               | null -> []
               | urls -> urls |> Array.toList |> List.map (fun url -> url.u)
    let urls = match (dto.url |> Option.fromNullableString), urls with 
               | None, urls -> urls
               | Some url, urls -> url :: urls
    { Title = dto.title |> Option.fromNullableString
      Info = dto.ainfo |> Option.fromNullableString
      PS = dto.ps |> Option.fromNullable
      Tags = match dto.tags with
             | null -> []
             | v -> v |> Array.toList
      Urls = urls }

  let private parseJSON (json: string) : Result<Overview, OPVaultError>=
    try
      JsonConvert.DeserializeObject<OverviewDTO> json
      |> convertToOverview 
      |> Ok
    with
    | e -> JSONParserError json |> ParserError |> Result.Error

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

