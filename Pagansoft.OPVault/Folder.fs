namespace OPVault

open System

type Folder = { UUID: string
                Overview: string
                Created: DateTime
                TransactionTimeStamp: DateTime
                Updated: DateTime 
                IsSmartFolder: bool }

module Folder =
  open Errors
  open FSharp.Data
  open FSharp.Data.JsonExtensions
  open FSharp.Results
  open Result

  type private FolderFileJson = FSharp.Data.JsonProvider<"""{"FOO":{"created":0,"overview":"FOO","tx":1373753421,"updated":0,"uuid":"FOO"},"BAR":{"created":1373754128,"overview":"BAZ","smart":true,"tx":1373754523,"updated":1373754134,"uuid":"BAZ"}}""">
  
  let parseFolderItem (overviewKey: KeyPair) (prop: JsonValue) =
    trial {
      let! overview = prop?overview |> JSON.asByteArray |> overviewKey.DecryptByteArray false
      
      return { UUID = prop?uuid |> JSON.asString
               Overview = overview |> Array.skipWhile (fun b -> b = 0uy) |> String.bytesAsString
               Created = prop?created |> JSON.asDateTime
               TransactionTimeStamp = prop?tx |> JSON.asDateTime
               Updated = prop?updated |> JSON.asDateTime
               IsSmartFolder = prop.TryGetProperty("smart") |> Option.map JSON.asBool |> Option.defaultValue false }
    }
  
  let makeJSON content = 
    let startMarker = "loadFolders({"
    let endMarker = "});"

    content |> String.makeJSON startMarker endMarker

  let parseFolderFileJSON (json: string) =
    try
      Ok (FolderFileJson.Parse json)
    with
    | e -> JSONParserError e.Message |> ParserError |> Error

  let read (profile: DecryptedProfileData) (vaultDir: string) =
    let filename = sprintf "%s/folders.js" vaultDir
    match File.read filename with
    | Ok content ->
      trial {
        let! json = content |> makeJSON
        let! json = json |> parseFolderFileJSON
        let items = [ for prop in json.JsonValue.Properties ->
                        match prop |> snd |> parseFolderItem profile.OverviewKey  with
                        | Ok item -> Ok item
                        | Error e -> Error e ] 

        return! items |> Result.fold
      } 
    | Error e ->
      match e with
      | FileError (FileNotFound _) -> Ok []
      | _ -> Error e