namespace Pagansoft.OPVault

type Overview = { Title: string option
                  Info: string option
                  PS: int option
                  Tags: string list
                  Urls: string list }

[<RequireQualifiedAccess>]
module Overview =
  open FSharp.Results.Results

  type private OverviewJSON = FSharp.Data.JsonProvider<""" 
    [
      {"ps":0},
      {"title":"Title","ps":0,"ainfo":"ainfo"},
      {"title":"Title","ainfo":"ainfo"},
      {"title":"Title","ainfo":"ainfo","ps":0},
      {"title":"Title","ainfo":"","tags":["Tag1"],"ps":0},
      {"title":"Title","ainfo":"ainfo","tags":["Tag1"],"ps":0},
      {"title":"Title","ainfo":"ainfo","tags":["Tag1","Tag2"],"ps":0},
      {"URLs":[{"u":"https://www.foo.com/"}],"tags":["Tag1"],"title":"Title","url":"http://www.foo.com","ainfo":"ainfo","ps":78},
      {"title":"Title","URLs":[{"u":"https://www.foo.com/"}],"ainfo":"ainfo","url":"https://www.foo.com/","tags":["Tag1"],"ps":66},
      {"title":"Title","URLs":[{"u":"https://www.foo.com/"}],"ainfo":"ainfo","url":"https://www.foo.com/","tags":["Tag1","Tag2"],"ps":66}
    ] """, SampleIsList = true>

  let private parseOverviewItem (item: OverviewJSON.Root) =
    { Title = item.Title
      Info = item.Ainfo
      PS = item.Ps
      Tags = item.Tags |> Array.toList
      Urls = seq {
        match item.Url with 
        | Some url -> yield url
        | None -> ()

        for url in item.UrLs do
          yield url.U
      } |> Seq.distinct |> Seq.toList  }

  let private parseJSON (json: string) =
    try
      Ok (OverviewJSON.Parse json |> parseOverviewItem)
    with
    | e -> JSONParserError e.Message |> ParserError |> Error

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

