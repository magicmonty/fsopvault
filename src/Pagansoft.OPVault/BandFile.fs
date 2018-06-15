namespace Pagansoft.OPVault

open System
open FSharp.Results
open FSharp.Results.Results

type BandFileItemData = BandFileItemData of string

type BandFileItem = { Overview: Overview
                      Category: Category
                      Created: DateTime
                      Data: byte array
                      FavoriteOrder: int option
                      FolderId: string option
                      HMAC: byte array
                      EncryptedKeys: byte array
                      IsTrashed: bool
                      TransactionTimeStamp: DateTime option
                      Updated: DateTime option
                      UUID: string }

                    member this.Decrypt (masterKeys: KeyPair) : Result<BandFileItemData, OPVaultError> =
                      let checkKeyData keyData =
                        let calculated = (2 * Crypto.KeySizeInBytes) + Crypto.HMACSizeInBytes + Crypto.IVSizeInBytes
                        let actual = keyData |> Array.length
                        if actual <> calculated
                        then CouldNotDecryptItemKey |> OPDataError |> Error
                        else Ok ()

                      trial {
                        do! checkKeyData this.EncryptedKeys
                        let! keyData = masterKeys.DecryptByteArray true this.EncryptedKeys
                        let itemKey = { EncryptionKey = keyData |> Array.take Crypto.KeySizeInBytes
                                        AuthenticationKey = keyData |> Array.skip Crypto.KeySizeInBytes }

                        let! itemData = this.Data |> OPData.parseBytes
                        let! decryptedData = itemData.Decrypt itemKey

                        return!
                          match decryptedData with
                          | Decrypted data ->  data.PlainText |> String.bytesAsString |> BandFileItemData |> Ok
                          | Encrypted _ -> CouldNotDecryptItem |> OPDataError |> Error
                      }

type BandFile = { Filename: string
                  Items: BandFileItem list }

[<RequireQualifiedAccess>]
module BandFile =
  open FSharp.Data
  open FSharp.Data.JsonExtensions
  
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
      let! overview = prop?o |> JSON.asString |> Overview.decryptString overviewKey
      let! category = prop?category |> JSON.asString |> Category.fromCode

      return { Overview = overview
               Category = category
               Created = prop?created |> JSON.asDateTime
               Data = prop?d |> JSON.asByteArray
               FavoriteOrder = prop.TryGetProperty("fave") |> Option.map JSON.asInteger
               FolderId = prop.TryGetProperty("folder")  |> Option.map JSON.asString
               HMAC = prop?hmac |> JSON.asByteArray
               EncryptedKeys = prop?k |> JSON.asByteArray
               IsTrashed = prop.TryGetProperty("trashed") |> Option.map JSON.asBool |> Option.defaultValue false
               TransactionTimeStamp = prop.TryGetProperty("tx") |> Option.map JSON.asDateTime
               Updated = prop.TryGetProperty("updated") |> Option.map JSON.asDateTime
               UUID = prop?uuid |> JSON.asString }
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

          return! items |> Result.fold
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

