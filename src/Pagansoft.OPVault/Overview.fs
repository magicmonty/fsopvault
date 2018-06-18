namespace Pagansoft.OPVault

type Overview = { Title: string option
                  Info: string option
                  PS: int option
                  Tags: string list
                  Urls: string list }

and OverviewUrl = { u: string }

and OverviewDTO = { title: string
                    ainfo: string
                    ps: System.Nullable<int>
                    tags: string array
                    URLs: OverviewUrl array
                    url: string }

                  member this.ToDomainObject =
                    let urls = match this.URLs with
                               | null -> []
                               | urls -> urls |> Array.toList |> List.map (fun url -> url.u)
                    let urls = match (this.url |> Option.fromNullableString), urls with 
                               | None, urls -> urls
                               | Some url, urls -> url :: urls
                    { Title = this.title |> Option.fromNullableString
                      Info = this.ainfo |> Option.fromNullableString
                      PS = this.ps |> Option.fromNullable
                      Tags = match this.tags with
                             | null -> []
                             | v -> v |> Array.toList
                      Urls = urls }


[<RequireQualifiedAccess>]
module Overview =
  open FSharp.Results.Results
  
  module private JSON =
    open ResultOperators

    let deserializeDTO = Json.deserialize<OverviewDTO>

    let parse (json: string) : Result<Overview, OPVaultError>=
        json 
        |> deserializeDTO 
        |=> fun d -> d.ToDomainObject 

  let decrypt overviewKey encryptedData =
    trial {
      let! encryptedOverviewData = encryptedData |> OPData.parseBytes
      let! decryptedOverviewData = encryptedOverviewData |> OPData.authenticateAndDecrypt overviewKey
      let! plainText = decryptedOverviewData.PlainTextAsString ()
      return! JSON.parse plainText
    }

  let decryptString overviewKey encryptedData =
    encryptedData
    |> ByteArray.fromBase64
    |> decrypt overviewKey 

