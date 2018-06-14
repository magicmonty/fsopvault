namespace OPVault

type BandFileItem = { Overview: Overview
                      Category: Category }

type BandFile = { Filename: string
                  Items: BandFileItem list }

[<RequireQualifiedAccess>]
module BandFile =
  open Errors
  open FSharp.Data
  open FSharp.Data.JsonExtensions
  open FSharp.Results.Result
  
  type BandFileJson = FSharp.Data.JsonProvider<"""{"FOO":{"uuid":"FOO","category":"099","o":"FOO","hmac":"FOO","updated":1386214150,"trashed":true,"k":"FOO","d":"FOO","created":1386214097,"tx":1386214431},"BAR":{"category":"004","k":"BAR","updated":1325483949,"tx":1373753421,"d":"BAR","hmac":"BAR","created":1325483949,"uuid":"BAR","o":"BAR"}}""">

  let private makeJSON =
    let startMarker = "ld({"
    let endMarker = "});"

    String.makeJSON startMarker endMarker

  let private parseBandFileJSON (json: string) =
    try
      Ok (BandFileJson.Parse json)
    with
    | e -> JSONParserError e.Message |> ParserError |> Error

  let private parseBandItem (overviewKey: KeyPair) (prop: JsonValue) =
    trial {
      let! overview = prop?o.AsString() |> Overview.decryptString overviewKey
      let! category = prop?category.AsString() |> Category.fromCode

      return { Overview = overview
               Category = category }
    }

  let readBandFile (profile: DecryptedProfileData) bandfilename = 
    let contents =
      match File.read bandfilename with
      | Ok content ->
        trial {
          let! json = content |> makeJSON
          let! json = json |> parseBandFileJSON
          let items = [ for prop in json.JsonValue.Properties ->
                          match prop |> snd |> parseBandItem profile.OverviewKey  with
                          | Ok item -> Ok item
                          | Error e -> Error e ] 

          return! items |> List.fold FSharp.Results.Result.combine (Ok [])
        } 
      | Error e ->
        match e with
        | FileError (FileNotFound _) -> Ok []
        | _ -> Error e


    match contents  with
    | Ok contents ->  
        Ok { Filename = bandfilename 
             Items = contents }
    | Error e -> Error e

